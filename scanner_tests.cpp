// Unit tests for plc_passive_observer: feed hand-built frames to processPacket()
// and check the resulting inventory. Build with `make test` (or `make asan-test`
// to run the same cases under AddressSanitizer + UBSan).
#define main observer_main
#include "plc_passive_observer.cpp"
#undef main

#include <initializer_list>

static int g_fail = 0, g_pass = 0;
#define CHECK(cond) do { if (cond) g_pass++; else { g_fail++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

using Bytes = std::vector<uint8_t>;
static void put16(Bytes &b, uint16_t v) { b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v)); }
static void put16le(Bytes &b, uint16_t v) { b.push_back(uint8_t(v)); b.push_back(uint8_t(v >> 8)); }
static void put32(Bytes &b, uint32_t v) { put16(b, uint16_t(v >> 16)); put16(b, uint16_t(v)); }
static void put32le(Bytes &b, uint32_t v) { put16le(b, uint16_t(v)); put16le(b, uint16_t(v >> 16)); }
static void putMac(Bytes &b, uint64_t m) { for (int i = 5; i >= 0; i--) b.push_back(uint8_t(m >> (i * 8))); }
static uint32_t ip4(int a, int b, int c, int d) { return uint32_t(a << 24 | b << 16 | c << 8 | d); }

static void reset() {
    g_ipDev.clear(); g_macDev.clear(); g_macToIps.clear(); g_arpMacToIps.clear(); g_st = Stats{};
}
static void feed(const Bytes &f, time_t t = 1) {
    pcap_pkthdr h{};
    h.caplen = h.len = bpf_u_int32(f.size());
    h.ts.tv_sec = t;
    processPacket(&h, f.data());
}

static const uint64_t MAC_A = 0x02AABBCCDDEEull, MAC_B = 0x0000BC445566ull, GW = 0x001A2B3C4D5Eull;

static Bytes eth(uint64_t src, uint64_t dst, uint16_t type) {
    Bytes b; putMac(b, dst); putMac(b, src); put16(b, type); return b;
}
// IPv4 + TCP/UDP. `frag` is the raw flags/fragment-offset field.
static Bytes ipPkt(uint64_t smac, uint64_t dmac, uint32_t sip, uint32_t dip, uint8_t proto,
                   uint16_t sp, uint16_t dp, const Bytes &payload, uint8_t tcpFlags = 0x18,
                   uint16_t frag = 0, uint8_t tcpOffWords = 5) {
    Bytes l4;
    put16(l4, sp); put16(l4, dp);
    if (proto == 6) {
        put32(l4, 1); put32(l4, 0);
        l4.push_back(uint8_t(tcpOffWords << 4)); l4.push_back(tcpFlags);
        put16(l4, 1024); put16(l4, 0); put16(l4, 0);
    } else {
        put16(l4, uint16_t(8 + payload.size())); put16(l4, 0);
    }
    l4.insert(l4.end(), payload.begin(), payload.end());
    Bytes b = eth(smac, dmac, 0x0800);
    b.push_back(0x45); b.push_back(0); put16(b, uint16_t(20 + l4.size()));
    put16(b, 0); put16(b, frag); b.push_back(64); b.push_back(proto); put16(b, 0);
    put32(b, sip); put32(b, dip);
    b.insert(b.end(), l4.begin(), l4.end());
    return b;
}
static Bytes arp(uint64_t ethSrc, uint64_t sha, uint32_t spa) {
    Bytes b = eth(ethSrc, 0xFFFFFFFFFFFFull, 0x0806);
    put16(b, 1); put16(b, 0x0800); b.push_back(6); b.push_back(4); put16(b, 1);
    putMac(b, sha); put32(b, spa); putMac(b, 0); put32(b, ip4(10, 0, 0, 1));
    return b;
}
static Bytes modbusReadReq() {
    Bytes m; put16(m, 1); put16(m, 0); put16(m, 6); m.push_back(1); m.push_back(3); put16(m, 0); put16(m, 10);
    return m;
}
static const ProtoObs *obs(uint32_t ip, Proto p) {
    auto d = g_ipDev.find(ip);
    if (d == g_ipDev.end()) return nullptr;
    auto o = d->second.protos.find(p);
    return o == d->second.protos.end() ? nullptr : &o->second;
}

int main() {
    const uint32_t CLI = ip4(10, 0, 0, 1), SRV = ip4(10, 0, 0, 2);

    // 1. Client SYN to 502: client gets a client role, server a server role, port-only.
    reset();
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, {}, 0x02));
    CHECK(obs(CLI, Proto::MODBUS) && obs(CLI, Proto::MODBUS)->roles == ROLE_CLIENT);
    CHECK(obs(SRV, Proto::MODBUS) && obs(SRV, Proto::MODBUS)->roles == ROLE_SERVER);
    CHECK(obs(SRV, Proto::MODBUS)->portEv == Evidence::PORT);
    CHECK(classify(g_ipDev[SRV]) == "Unconfirmed - ICS port only");

    // 2. Invalid TCP data offset (15 words > segment): rejected, no new evidence.
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, modbusReadReq(), 0x18, 0, 15));
    CHECK(g_st.malformed == 1);
    CHECK(obs(SRV, Proto::MODBUS)->portEv == Evidence::PORT);

    // 3. Valid Modbus request upgrades both ends to validated.
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, modbusReadReq()));
    CHECK(obs(SRV, Proto::MODBUS)->portEv == Evidence::VALIDATED);
    CHECK(obs(SRV, Proto::MODBUS)->serverPorts.count(502) == 1);
    CHECK(classify(g_ipDev[CLI]) == "ICS client (HMI/EWS/SCADA candidate)");
    CHECK(classify(g_ipDev[SRV]) == "ICS server (PLC/RTU/gateway candidate)");

    // 4. Garbage on port 502 stays port-only.
    reset();
    Bytes http = {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '0', '\r', '\n', '\r', '\n'};
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, http));
    CHECK(obs(SRV, Proto::MODBUS)->portEv == Evidence::PORT);

    // 5. Non-initial IPv4 fragment: counted, never parsed.
    reset();
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, modbusReadReq(), 0x18, 0x0010));
    CHECK(g_st.fragments == 1 && obs(SRV, Proto::MODBUS) == nullptr);

    // 6. Ethernet padding is not treated as payload (IPv4 total length wins).
    reset();
    Bytes padded = ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 20000, {}, 0x10);
    Bytes dnpLike = {0x05, 0x64, 0x05, 0xC9, 0, 0};
    padded.insert(padded.end(), dnpLike.begin(), dnpLike.end());
    feed(padded);
    CHECK(obs(SRV, Proto::DNP3)->portEv == Evidence::PORT);

    // 7. EtherNet/IP encapsulation is little-endian; options must be zero.
    {
        Bytes e; put16le(e, 0x0063); put16le(e, 0); for (int i = 0; i < 20; i++) e.push_back(0);
        Ctx c; Device d; c.src = &d;
        CHECK(validateEnipEncap(Span(e.data(), e.size()), c, true));
        Bytes be = e; be[0] = 0x00; be[1] = 0x63;                 // big-endian 0x0063
        CHECK(!validateEnipEncap(Span(be.data(), be.size()), c, true));
        Bytes opt = e; opt[20] = 1;                                // options != 0
        CHECK(!validateEnipEncap(Span(opt.data(), opt.size()), c, true));
        Bytes len = e; len[2] = 1;                                 // declared body missing
        CHECK(!validateEnipEncap(Span(len.data(), len.size()), c, true));
    }

    // 8. UDP ListIdentity reply yields identity and the PLC classification.
    reset();
    {
        std::string name = "1756-L83E/B";
        Bytes item; put16le(item, 1);                              // encap protocol version
        put16(item, 2); put16(item, 44818); put32(item, ip4(10, 0, 0, 30)); for (int i = 0; i < 8; i++) item.push_back(0);
        put16le(item, 1); put16le(item, 0x0E); put16le(item, 166); item.push_back(33); item.push_back(11);
        put16le(item, 0); put32le(item, 0xC0FFEE01); item.push_back(uint8_t(name.size()));
        item.insert(item.end(), name.begin(), name.end()); item.push_back(3);
        Bytes cpf; put16le(cpf, 1); put16le(cpf, 0x000C); put16le(cpf, uint16_t(item.size()));
        cpf.insert(cpf.end(), item.begin(), item.end());
        Bytes enc; put16le(enc, 0x0063); put16le(enc, uint16_t(cpf.size())); for (int i = 0; i < 20; i++) enc.push_back(0);
        enc.insert(enc.end(), cpf.begin(), cpf.end());
        const uint32_t PLC = ip4(10, 0, 0, 30);
        feed(ipPkt(MAC_B, MAC_A, PLC, CLI, 17, 44818, 50000, enc));
        Device &d = g_ipDev[PLC];
        CHECK(d.id.product == name);
        CHECK(d.id.serial == "0xC0FFEE01");
        CHECK(classify(d) == "PLC (self-reported CIP device type)");
        // Item length shorter than its fixed fields must be rejected, not over-read.
        reset();
        Bytes bad = enc; bad[24 + 4] = 10; bad[24 + 5] = 0;
        feed(ipPkt(MAC_B, MAC_A, PLC, CLI, 17, 44818, 50000, bad));
        CHECK(g_ipDev[PLC].id.product.empty());
    }

    // 9. DNP3 header CRC is checked.
    reset();
    {
        Bytes h = {0x05, 0x64, 0x05, 0xC9, 10, 0, 1, 0};
        uint16_t crc = crcDnp(h.data(), h.size());
        Bytes good = h; put16le(good, crc);
        Bytes bad = h; put16le(bad, uint16_t(crc ^ 1));
        feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 20000, bad));
        CHECK(obs(SRV, Proto::DNP3)->portEv == Evidence::PORT);
        feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 20000, good));
        CHECK(obs(SRV, Proto::DNP3)->portEv == Evidence::VALIDATED);
        CHECK(obs(SRV, Proto::DNP3)->validatedRoles == ROLE_SERVER);   // DIR bit: sender is master
    }

    // 10. MAC attribution: ARP must match the Ethernet source; gateway MACs are
    //     never assigned; a unique IP-traffic MAC is shown but labelled unconfirmed.
    reset();
    feed(arp(GW, MAC_B, SRV));                                      // relayed/forged ARP
    CHECK(g_st.arpMismatch == 1 && g_ipDev.empty());
    feed(arp(MAC_B, MAC_B, SRV));
    CHECK(chooseMac(g_ipDev[SRV]).primary == MAC_B && chooseMac(g_ipDev[SRV]).src == MacSrc::ARP);
    feed(arp(GW, GW, ip4(10, 0, 0, 254)));                          // gateway announces itself
    feed(ipPkt(GW, MAC_A, ip4(192, 168, 5, 10), CLI, 6, 502, 49152, modbusReadReq()));
    CHECK(chooseMac(g_ipDev[ip4(192, 168, 5, 10)]).primary == 0);
    feed(ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, {}, 0x10));
    CHECK(chooseMac(g_ipDev[CLI]).src == MacSrc::IP_TRAFFIC);

    // 11. Two MACs claiming one IP via ARP are flagged.
    reset();
    feed(arp(MAC_B, MAC_B, SRV));
    feed(arp(MAC_A, MAC_A, SRV));
    reconcile();
    CHECK(!g_ipDev[SRV].notes.empty());

    // 12. Hostnames: only records bound to the sender's own address count, and a
    //     DNS compression-pointer loop terminates.
    {
        Bytes m; put16(m, 0); put16(m, 0x8400); put16(m, 0); put16(m, 1); put16(m, 0); put16(m, 0);
        for (const char *lbl : {"eng-ws01", "local"}) { m.push_back(uint8_t(strlen(lbl))); m.insert(m.end(), lbl, lbl + strlen(lbl)); }
        m.push_back(0); put16(m, 1); put16(m, 0x8001); put32(m, 120); put16(m, 4); put32(m, CLI);
        CHECK(nameFromDns(Span(m.data(), m.size()), CLI, NameProto::MDNS) == "eng-ws01");
        CHECK(nameFromDns(Span(m.data(), m.size()), SRV, NameProto::MDNS).empty());
        Bytes loop; put16(loop, 0); put16(loop, 0x8400); put16(loop, 1); put16(loop, 0); put16(loop, 0); put16(loop, 0);
        loop.push_back(0xC0); loop.push_back(12);                  // pointer to itself
        CHECK(nameFromDns(Span(loop.data(), loop.size()), CLI, NameProto::MDNS).empty());
    }

    // 13. Stacked VLAN tags (802.1ad + 802.1Q) are unwrapped.
    reset();
    {
        Bytes f = ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, modbusReadReq());
        Bytes tags = {0x88, 0xA8, 0x00, 0x64, 0x81, 0x00, 0x00, 0x0A};
        f.insert(f.begin() + 12, tags.begin(), tags.end());
        feed(f);
        CHECK(g_st.vlanTagged == 1 && obs(SRV, Proto::MODBUS)->portEv == Evidence::VALIDATED);
    }

    // 14. Every truncation of a valid frame is handled without reading past it
    //     (run under `make asan-test` to make over-reads fatal).
    reset();
    {
        Bytes f = ipPkt(MAC_A, GW, CLI, SRV, 6, 49152, 502, modbusReadReq());
        for (size_t n = 0; n <= f.size(); n++) {
            Bytes cut(f.begin(), f.begin() + long(n));
            pcap_pkthdr h{}; h.caplen = h.len = bpf_u_int32(n); h.ts.tv_sec = 1;
            processPacket(&h, cut.data());
        }
        CHECK(true);
    }

    // 15. CSV quoting and spreadsheet-formula neutralisation.
    CHECK(csv("=x,\"y") == "\"'=x,\"\"y\"");
    CHECK(csv("plain") == "plain");
    CHECK(csv("-1+2") == "'-1+2");

    // 16. Strict duration parsing.
    int secs = 0;
    CHECK(parseSeconds("300", secs) && secs == 300);
    CHECK(!parseSeconds("-5", secs) && !parseSeconds("12abc", secs) && !parseSeconds("", secs));

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
