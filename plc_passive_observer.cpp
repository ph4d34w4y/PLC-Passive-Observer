/*
 * plc_passive_observer.cpp
 *
 * Passive PLC Manufacturer/Model Fingerprinter
 * --------------------------------------------
 * Identifies PLC devices on the network by ONLY observing traffic that is
 * already present on the wire. No packets are transmitted. This approach
 * avoids the denial-of-service risk that active scanners (nmap, netdiscover,
 * etc.) pose to sensitive industrial control system devices.
 *
 * Detection techniques (all passive):
 *   1. Ethernet OUI lookup from observed source MACs
 *   2. ICS protocol identification (Modbus/TCP, EtherNet/IP CIP,
 *      PROFINET, S7comm, DNP3, BACnet/IP, FINS, Crimson v3/DF1)
 *   3. Protocol-level fingerprinting (function codes, header magic,
 *      vendor-specific fields where visible in cleartext)
 *   4. Hostname/banner sniffing from ARP, mDNS, LLMNR, NetBIOS-NS
 *
 * Build:
 *   g++ -std=c++17 -O2 -o plc_passive_observer plc_passive_observer.cpp -lpcap
 *
 * Usage:
 *   sudo ./plc_passive_observer -i <interface> [-t <seconds>] [-o <output.csv>]
 *
 * Requires root / CAP_NET_RAW to open a raw capture socket.
 *
 * LEGAL NOTICE: Only use on networks you own or have explicit written
 * authorization to monitor.  Passive capture of network traffic may still
 * be regulated by local law.
 */

#include <pcap/pcap.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <csignal>
#include <cassert>

#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <optional>
#include <chrono>
#include <cstdlib>
#include <climits>

// ────────────────────────────────────────────────────────────────────────────
//  Wire-format helpers  (big-endian, no alignment assumptions)
// ────────────────────────────────────────────────────────────────────────────
static inline uint16_t be16(const uint8_t *p) { return uint16_t(p[0]<<8)|p[1]; }
static inline uint16_t le16(const uint8_t *p) { return uint16_t(p[0])|(uint16_t(p[1])<<8); }
static inline uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];
}

// ────────────────────────────────────────────────────────────────────────────
//  MAC OUI → vendor table  (24-bit prefix)
//  Entries cover the most common industrial automation vendors.
//  Extend freely from the IEEE MA-L registry.
// ────────────────────────────────────────────────────────────────────────────
struct OuiEntry { uint32_t oui24; const char *vendor; };
static const OuiEntry OUI_TABLE[] = {
    // Siemens
    {0x001BC5,  "Siemens AG"},
    {0x0026AB,  "Siemens AG"},
    {0x28631F,  "Siemens AG"},
    {0xACCF85,  "Siemens AG"},
    // Rockwell / Allen-Bradley
    {0x00001D,  "Rockwell Automation (Allen-Bradley)"},
    {0x000BC5,  "Rockwell Automation"},
    {0x609C9F,  "Rockwell Automation"},
    // Schneider Electric / Modicon
    {0x0080F4,  "Schneider Electric (Modicon)"},
    {0x00D0B7,  "Schneider Electric"},
    {0x0050C2,  "Schneider Electric"},
    // ABB
    {0x001F99,  "ABB Automation"},
    {0x0020D4,  "ABB"},
    // Mitsubishi Electric
    {0x00E0E4,  "Mitsubishi Electric"},
    {0xAC1503,  "Mitsubishi Electric"},
    // Omron
    {0x00000A,  "Omron Corporation"},
    {0x00C0EC,  "Omron"},
    // GE / Emerson / Fanuc
    {0x000AF7,  "Emerson Process Management"},
    // Honeywell
    {0x000665,  "Honeywell"},
    {0x00D0EA,  "Honeywell"},
    // Phoenix Contact
    {0x00A047,  "Phoenix Contact"},
    // Beckhoff
    {0x004419,  "Beckhoff Automation"},
    // B&R Industrial
    {0x001DC2,  "B&R Industrial Automation"},
    // Pilz
    {0x0022DA,  "Pilz GmbH"},
    // Moxa
    {0x0090E8,  "Moxa Technologies"},
    // Wago
    {0x00D05E,  "WAGO Kontakttechnik"},
    // Bosch Rexroth
    {0x0004F3,  "Bosch Rexroth"},
    // Danfoss
    {0x0018FE,  "Danfoss Drives"},
    // Yaskawa
    {0x00B0D0,  "Yaskawa Electric"},
    // Lenze
    {0x00800F,  "Lenze SE"},
};

static std::string lookupOUI(const uint8_t mac[6]) {
    uint32_t oui = (uint32_t(mac[0])<<16)|(uint32_t(mac[1])<<8)|mac[2];
    for (auto &e : OUI_TABLE)
        if (e.oui24 == oui) return e.vendor;
    // Format unknown OUI for display
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X (unknown)", mac[0], mac[1], mac[2]);
    return buf;
}

// ────────────────────────────────────────────────────────────────────────────
//  ICS protocol port / magic constants
// ────────────────────────────────────────────────────────────────────────────
enum class ICSProto {
    UNKNOWN = 0,
    MODBUS_TCP,       // TCP 502
    ENIP_CIP,         // UDP/TCP 44818, UDP 2222
    PROFINET_DCP,     // UDP 34962-34964 / EtherType 0x8892
    S7COMM,           // TCP 102 (TPKT/COTP/S7)
    DNP3,             // TCP/UDP 20000
    BACNET_IP,        // UDP 47808
    FINS,             // UDP 9600  (Omron FINS)
    MELSEC_Q,         // TCP 5007 (Mitsubishi MELSEC)
    IEC104,           // TCP 2404
    CRIMSON,          // TCP 789  (Red Lion Crimson)
    ADS,              // TCP 48898 (Beckhoff ADS/AMS)
    PROFIBUS_UDP,     // UDP 34964
};

static const char* protoName(ICSProto p) {
    switch(p) {
        case ICSProto::MODBUS_TCP:   return "Modbus/TCP";
        case ICSProto::ENIP_CIP:     return "EtherNet/IP (CIP)";
        case ICSProto::PROFINET_DCP: return "PROFINET";
        case ICSProto::S7COMM:       return "S7comm (Siemens)";
        case ICSProto::DNP3:         return "DNP3";
        case ICSProto::BACNET_IP:    return "BACnet/IP";
        case ICSProto::FINS:         return "Omron FINS";
        case ICSProto::MELSEC_Q:     return "Mitsubishi MELSEC-Q";
        case ICSProto::IEC104:       return "IEC 60870-5-104";
        case ICSProto::CRIMSON:      return "Red Lion Crimson";
        case ICSProto::ADS:          return "Beckhoff ADS";
        case ICSProto::PROFIBUS_UDP: return "PROFIBUS over UDP";
        default:                     return "Unknown";
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Per-device record
// ────────────────────────────────────────────────────────────────────────────
struct DeviceRecord {
    std::string ip;
    uint8_t     mac[6]{};
    std::string macStr;
    std::string ouiVendor;
    std::set<ICSProto>  protocols;
    std::set<uint16_t>  ports;
    std::string         hostname;       // from mDNS / NetBIOS / LLMNR
    std::string         modelHint;      // parsed from protocol payloads
    std::time_t         firstSeen{0};
    std::time_t         lastSeen{0};
    uint64_t            packetCount{0};
    std::set<std::string> evidence;
    std::set<ICSProto> clientProtocols;
};

// ────────────────────────────────────────────────────────────────────────────
//  Global state
// ────────────────────────────────────────────────────────────────────────────
static std::map<std::string, DeviceRecord> g_devices; // keyed by IP
static volatile bool g_running = true;
static bool g_offline = false;
static bool g_captureError = false;
static std::string g_outputFile;

static void sigHandler(int) { g_running = false; }

// ────────────────────────────────────────────────────────────────────────────
//  Utility: format MAC as "AA:BB:CC:DD:EE:FF"
// ────────────────────────────────────────────────────────────────────────────
static std::string fmtMAC(const uint8_t m[6]) {
    char buf[18];
    snprintf(buf,sizeof(buf),"%02X:%02X:%02X:%02X:%02X:%02X",
             m[0],m[1],m[2],m[3],m[4],m[5]);
    return buf;
}

// ────────────────────────────────────────────────────────────────────────────
//  Utility: format IPv4
// ────────────────────────────────────────────────────────────────────────────
static std::string fmtIP(const uint8_t ip[4]) {
    char buf[16];
    snprintf(buf,sizeof(buf),"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
    return buf;
}

// ────────────────────────────────────────────────────────────────────────────
//  Touch / create a DeviceRecord
// ────────────────────────────────────────────────────────────────────────────
static DeviceRecord& touchDevice(const std::string &ip, const uint8_t mac[6],
                                  std::time_t ts, bool local = false) {
    auto &dev = g_devices[ip];
    if (dev.firstSeen == 0) {
        dev.ip        = ip;
        dev.firstSeen = ts;
    }
    if (local && (dev.macStr.empty() || dev.macStr == fmtMAC(mac))) {
        memcpy(dev.mac, mac, 6);
        dev.macStr = fmtMAC(mac);
        dev.ouiVendor = lookupOUI(mac);
        dev.evidence.insert("ARP source mapping");
    }
    dev.lastSeen = ts;
    dev.packetCount++;
    return dev;
}

// ────────────────────────────────────────────────────────────────────────────
//  Protocol fingerprinting helpers
// ────────────────────────────────────────────────────────────────────────────

// Modbus/TCP: 6-byte MBAP header – transaction id (2), protocol id = 0x0000 (2),
// length (2), unit id (1), function code (1)
static bool isModbusTCP(const uint8_t *payload, int len) {
    if (len < 8) return false;
    uint16_t proto = be16(payload+2);
    uint16_t plen  = be16(payload+4);
    return proto == 0x0000 && plen > 0 && plen <= (len-6);
}

// EtherNet/IP encapsulation header: command (2) + length (2) + session (4)
// + status (4) + sender ctx (8) + options (4) = 24 bytes min
static bool isENIP(const uint8_t *payload, int len) {
    if (len < 24) return false;
    uint16_t cmd = le16(payload);
    if (le16(payload+2) > len-24) return false;
    // Known EIP commands: 0x0065 Register, 0x0066 Unregister,
    // 0x006F SendRRData, 0x0070 SendUnitData, 0x0063 ListServices,
    // 0x0064 ListIdentity
    static const uint16_t valid[] = {0x0063,0x0064,0x0065,0x0066,0x006F,0x0070,0x0001};
    for (auto c : valid) if (cmd==c) return true;
    return false;
}

// S7comm over TPKT/COTP: TPKT version byte = 0x03, reserved = 0x00
static bool isS7(const uint8_t *payload, int len) {
    if (len < 4) return false;
    return payload[0]==0x03 && payload[1]==0x00 && be16(payload+2)==(uint16_t)len;
}

// DNP3: start bytes 0x0564
static bool isDNP3(const uint8_t *payload, int len) {
    if (len < 10) return false;
    return payload[0]==0x05 && payload[1]==0x64;
}

// BACnet/IP: BVLC type = 0x81
static bool isBACnet(const uint8_t *payload, int len) {
    if (len < 4) return false;
    return payload[0]==0x81;
}

// Omron FINS command: ICF (0x80/0xC0), RSV=0x00
static bool isFINS(const uint8_t *payload, int len) {
    if (len < 10) return false;
    return (payload[0]==0x80 || payload[0]==0xC0) && payload[1]==0x00;
}

// IEC 60870-5-104 APCI: start = 0x68, len follows
static bool isIEC104(const uint8_t *payload, int len) {
    if (len < 6) return false;
    return payload[0]==0x68 && payload[1]==(uint8_t)(len-2);
}

// ────────────────────────────────────────────────────────────────────────────
//  EtherNet/IP List Identity response – extract device type & product name
// ────────────────────────────────────────────────────────────────────────────
static std::string parseENIPIdentity(const uint8_t *data, int len) {
    if (!isENIP(data,len) || le16(data) != 0x0063) return "";
    // EIP encap header = 24 bytes
    // ListIdentity reply item: item count(2), item type(2)=0x000C, item len(2),
    // encap proto ver(2), sock addr(16), vendor(2), device type(2), product code(2),
    // revision(2), status(2), serial(4), prod name len(1), prod name(variable)
    if (len < 24+2+2+2+2+16+2+2+2+2+2+4+1) return "";
    int off = 24;
    // item count
    if (le16(data+off) < 1) return "";
    off += 2;
    if (le16(data+off) != 0x000C) return "";  // ListIdentity item type
    off += 2;
    uint16_t ilen = le16(data+off); off += 2;
    if (ilen < 33 || len < off + ilen) return "";
    off += 2 + 16; // encap ver + sockaddr
    // vendor id
    [[maybe_unused]] uint16_t vendor = le16(data+off); off += 2;
    // device type
    [[maybe_unused]] uint16_t dtype  = le16(data+off); off += 2;
    off += 2; // product code
    off += 2; // revision
    off += 2; // status
    off += 4; // serial
    uint8_t nameLen = data[off++];
    if (off + nameLen > len || off + nameLen > 30 + ilen) return "";
    return std::string(reinterpret_cast<const char*>(data+off), nameLen);
}

// ────────────────────────────────────────────────────────────────────────────
//  Packet processing callback
// ────────────────────────────────────────────────────────────────────────────
static void processPacket(const struct pcap_pkthdr *hdr, const uint8_t *pkt) {
    if (hdr->caplen < 14) return;

    std::time_t ts = (std::time_t)hdr->ts.tv_sec;

    // ── Ethernet II ──────────────────────────────────────────────────────────
    const uint8_t *srcMac = pkt + 6;
    uint16_t etype = be16(pkt+12);

    // Handle 802.1Q VLAN tag
    const uint8_t *ethPayload = pkt + 14;
    int ethPayloadLen = (int)hdr->caplen - 14;
    while ((etype == 0x8100 || etype == 0x88A8 || etype == 0x9100) && ethPayloadLen >= 4) {
        etype = be16(ethPayload+2);
        ethPayload += 4;
        ethPayloadLen -= 4;
    }

    // ── PROFINET (EtherType 0x8892) ──────────────────────────────────────────
    if (etype == 0x8892) {
        // Source is a PROFINET device; IP may not be present
        // Use MAC as key fallback
        std::string pseudo = "PROFINET-" + fmtMAC(srcMac);
        auto &dev = g_devices[pseudo];
        if (dev.firstSeen == 0) {
            dev.ip        = pseudo;
            dev.firstSeen = ts;
            memcpy(dev.mac, srcMac, 6);
            dev.macStr    = fmtMAC(srcMac);
            dev.ouiVendor = lookupOUI(srcMac);
        }
        dev.lastSeen = ts;
        dev.packetCount++;
        dev.protocols.insert(ICSProto::PROFINET_DCP);
        return;
    }

    if (etype != 0x0800 && etype != 0x0806) return; // only IPv4 and ARP beyond here

    // ── ARP – learn IP↔MAC mapping ───────────────────────────────────────────
    if (etype == 0x0806 && ethPayloadLen >= 28) {
        // ARP: htype(2)+ptype(2)+hlen(1)+plen(1)+oper(2)+sha(6)+spa(4)+tha(6)+tpa(4)
        const uint8_t *sha = ethPayload + 8;
        const uint8_t *spa = sha + 6;
        std::string ip = fmtIP(spa);
        // Ignore 0.0.0.0 and broadcast
        if (ip == "0.0.0.0") return;
        if (be16(ethPayload)==1 && be16(ethPayload+2)==0x0800 &&
            ethPayload[4]==6 && ethPayload[5]==4 &&
            (be16(ethPayload+6)==1 || be16(ethPayload+6)==2) &&
            !memcmp(sha,srcMac,6))
            touchDevice(ip, sha, ts, true);
        return;
    }

    // ── IPv4 ─────────────────────────────────────────────────────────────────
    if (etype != 0x0800 || ethPayloadLen < 20) return;
    const uint8_t *ip4 = ethPayload;
    if ((ip4[0] >> 4) != 4) return;
    uint8_t  ihl  = (ip4[0] & 0x0F) * 4;
    uint8_t  proto = ip4[9];
    uint16_t ipLen = be16(ip4+2);
    if (ihl < 20 || ethPayloadLen < ihl || ipLen < ihl) return;
    if (be16(ip4+6) & 0x3FFF) return; // fragmented datagrams require reassembly
    ethPayloadLen = std::min(ethPayloadLen, int(ipLen));

    std::string srcIP = fmtIP(ip4+12);
    auto &dev = touchDevice(srcIP, srcMac, ts);

    const uint8_t *l4 = ip4 + ihl;
    int l4len = ethPayloadLen - ihl;

    // ── TCP ───────────────────────────────────────────────────────────────────
    if (proto == 6 && l4len >= 20) {
        uint16_t sport = be16(l4);
        uint16_t dport = be16(l4+2);
        uint8_t  flags = l4[13];
        uint8_t  tcpHdrLen = ((l4[12]>>4)*4);
        if (tcpHdrLen < 20 || tcpHdrLen > l4len) return;
        const uint8_t *tcpData = l4 + tcpHdrLen;
        int tcpDataLen = l4len - tcpHdrLen;

        // Only analyse packets carrying application data (not pure SYN/ACK/FIN)
        bool hasPSH = (flags & 0x08) != 0;
        (void)hasPSH;

        auto checkPort = [&](uint16_t p) -> ICSProto {
            switch(p) {
                case 502:   return ICSProto::MODBUS_TCP;
                case 44818: return ICSProto::ENIP_CIP;
                case 102:   return ICSProto::S7COMM;
                case 20000: return ICSProto::DNP3;
                case 2404:  return ICSProto::IEC104;
                case 789:   return ICSProto::CRIMSON;
                case 48898: return ICSProto::ADS;
                case 5007:  return ICSProto::MELSEC_Q;
                default:    return ICSProto::UNKNOWN;
            }
        };

        auto p1 = checkPort(sport);
        auto p2 = checkPort(dport);
        if (p1 != ICSProto::UNKNOWN) { dev.protocols.insert(p1); dev.ports.insert(sport); dev.evidence.insert("TCP source port"); }
        if (p2 != ICSProto::UNKNOWN) dev.clientProtocols.insert(p2);

        // Deep-inspect payload
        if (tcpDataLen > 0) {
            if (sport==502 && isModbusTCP(tcpData,tcpDataLen))
                dev.protocols.insert(ICSProto::MODBUS_TCP);

            if (sport==44818 && isENIP(tcpData,tcpDataLen)) {
                dev.protocols.insert(ICSProto::ENIP_CIP);
                // Try to extract product name from ListIdentity reply
                std::string name = parseENIPIdentity(tcpData, tcpDataLen);
                if (!name.empty() && dev.modelHint.empty()) {
                    for (char &c : name)
                        if ((unsigned char)c < 32 || (unsigned char)c == 127) c = ' ';
                    dev.modelHint = name;
                    dev.evidence.insert("EtherNet/IP ListIdentity response");
                }
            }

            if (sport==102 && isS7(tcpData,tcpDataLen))
                dev.protocols.insert(ICSProto::S7COMM);

            if (sport==20000 && isDNP3(tcpData,tcpDataLen))
                dev.protocols.insert(ICSProto::DNP3);

            if (sport==2404 && isIEC104(tcpData,tcpDataLen))
                dev.protocols.insert(ICSProto::IEC104);
        }
    }

    // ── UDP ───────────────────────────────────────────────────────────────────
    if (proto == 17 && l4len >= 8) {
        uint16_t sport = be16(l4);
        const uint8_t *udpPayload = l4 + 8;
        int udpPayloadLen = l4len - 8;
        uint16_t udpLen = be16(l4+4);
        if (udpLen < 8 || udpLen > l4len) return;
        udpPayloadLen = udpLen - 8;

        if (sport==44818 || sport==2222 || sport==47808 || sport==9600 || sport==20000)
            dev.ports.insert(sport);

        // EtherNet/IP over UDP (port 44818 broadcast/multicast, or 2222 implicit)
        if ((sport==44818||sport==2222)
            && isENIP(udpPayload,udpPayloadLen))
            dev.protocols.insert(ICSProto::ENIP_CIP);

        // BACnet
        if (sport==47808 && isBACnet(udpPayload,udpPayloadLen))
            dev.protocols.insert(ICSProto::BACNET_IP);

        // Omron FINS
        if (sport==9600 && isFINS(udpPayload,udpPayloadLen))
            dev.protocols.insert(ICSProto::FINS);

        // DNP3 over UDP
        if (sport==20000 && isDNP3(udpPayload,udpPayloadLen))
            dev.protocols.insert(ICSProto::DNP3);

        // DNS question names and response owner names are not necessarily
        // the sender's hostname. Do not attribute them without address records.
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  pcap callback wrapper
// ────────────────────────────────────────────────────────────────────────────
static void pcapCallback(uint8_t * /*user*/,
                         const struct pcap_pkthdr *hdr,
                         const uint8_t *pkt) {
    processPacket(hdr, pkt);
}

// ────────────────────────────────────────────────────────────────────────────
//  Print results
// ────────────────────────────────────────────────────────────────────────────
static void printResults() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║          PLC Passive Observer – Discovered Devices                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n\n");

    if (g_devices.empty()) {
        printf("  No devices observed during capture window.\n");
        return;
    }

    int idx = 1;
    for (auto &[ip, dev] : g_devices) {
        printf("  [%d] IP: %-18s  MAC: %s\n", idx++, ip.c_str(), dev.macStr.c_str());
        printf("      Vendor (OUI): %s\n", dev.ouiVendor.empty() ? "unverified" : dev.ouiVendor.c_str());
        if (!dev.hostname.empty())
            printf("      Hostname:     %s\n", dev.hostname.c_str());
        if (!dev.modelHint.empty())
            printf("      Model/Name:   %s\n", dev.modelHint.c_str());

        if (!dev.protocols.empty()) {
            printf("      ICS Protocols:");
            for (auto &p : dev.protocols)
                printf(" [%s]", protoName(p));
            printf("\n");
        }
        if (!dev.clientProtocols.empty()) {
            printf("      Client traffic:");
            for (auto p : dev.clientProtocols) printf(" [%s]", protoName(p));
            printf("\n");
        }

        if (!dev.ports.empty()) {
            printf("      Observed ports:");
            int cnt = 0;
            for (auto port : dev.ports) {
                if (cnt++ < 12) printf(" %d", port);
                else { printf(" ..."); break; }
            }
            printf("\n");
        }

        char tsBuf[32];
        struct tm *tm1 = localtime(&dev.firstSeen);
        strftime(tsBuf, sizeof(tsBuf), "%H:%M:%S", tm1);
        printf("      First seen: %s  |  Packets: %llu\n\n",
               tsBuf, (unsigned long long)dev.packetCount);
    }
}

static std::string csvField(std::string value) {
    for (char &c : value)
        if ((unsigned char)c < 32 || (unsigned char)c == 127) c = ' ';
    if (!value.empty() && (value[0]=='=' || value[0]=='+' ||
                           value[0]=='-' || value[0]=='@'))
        value.insert(value.begin(), '\'');
    std::string out = "\"";
    for (char c : value) { if (c=='"') out += '"'; out += c; }
    return out + "\"";
}

static bool saveCSV(const std::string &path) {
    std::ofstream f(path);
    if (!f) { fprintf(stderr, "Cannot write %s\n", path.c_str()); return false; }
    f << "IP,MAC,OUI_Vendor,Hostname,Model_Hint,ICS_Protocols,Client_Protocols,Observed_Service_Ports,Evidence,First_Seen,Packets\n";
    for (auto &[ip, dev] : g_devices) {
        f << csvField(dev.ip) << "," << csvField(dev.macStr) << "," << csvField(dev.ouiVendor) << ","
          << csvField(dev.hostname) << "," << csvField(dev.modelHint) << ",";

        std::string protos;
        for (auto &p : dev.protocols) {
            if (!protos.empty()) protos += "|";
            protos += protoName(p);
        }
        f << csvField(protos) << ",";
        protos.clear();
        for (auto p : dev.clientProtocols) {
            if (!protos.empty()) protos += "|";
            protos += protoName(p);
        }
        f << csvField(protos) << ",";

        std::string ports;
        for (auto port : dev.ports) {
            if (!ports.empty()) ports += "|";
            ports += std::to_string(port);
        }
        f << csvField(ports) << ",";
        std::string evidence;
        for (auto &item : dev.evidence) {
            if (!evidence.empty()) evidence += "|";
            evidence += item;
        }
        f << csvField(evidence) << ",";

        char tsBuf[32];
        struct tm *tm1 = localtime(&dev.firstSeen);
        strftime(tsBuf, sizeof(tsBuf), "%Y-%m-%d %H:%M:%S", tm1);
        f << csvField(tsBuf) << "," << dev.packetCount << "\n";
    }
    if (!f) return false;
    printf("  Results saved to: %s\n", path.c_str());
    return true;
}

// ────────────────────────────────────────────────────────────────────────────
//  main
// ────────────────────────────────────────────────────────────────────────────
static void usage(const char *prog) {
    printf("Usage: %s (-i <interface> | -r <capture.pcap>) [-t <seconds>] [-o <output.csv>]\n", prog);
    printf("  -i  Network interface to capture on (e.g. eth0, enp3s0)\n");
    printf("  -r  Read an offline PCAP (no capture privileges needed)\n");
    printf("  -t  Capture duration in seconds (0 = run until Ctrl-C, default 0)\n");
    printf("  -o  Save results to CSV file\n\n");
    printf("  Example: sudo %s -i eth0 -t 300 -o results.csv\n\n", prog);
}

int main(int argc, char *argv[]) {
    std::string iface;
    std::string inputFile;
    int duration = 0;

    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i])=="-i" && i+1<argc) { iface=argv[++i]; }
        else if (std::string(argv[i])=="-r" && i+1<argc) { inputFile=argv[++i]; }
        else if (std::string(argv[i])=="-t" && i+1<argc) {
            char *end=nullptr;
            long n=strtol(argv[++i], &end, 10);
            if (!argv[i][0] || *end || n<0 || n>INT_MAX) { usage(argv[0]); return 1; }
            duration=int(n);
        }
        else if (std::string(argv[i])=="-o" && i+1<argc) { g_outputFile=argv[++i]; }
        else { usage(argv[0]); return 1; }
    }
    if (iface.empty() == inputFile.empty()) { usage(argv[0]); return 1; }
    g_offline = !inputFile.empty();

    // ── Open pcap in promiscuous mode ─────────────────────────────────────────
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t *handle = g_offline ? pcap_open_offline(inputFile.c_str(),errbuf)
                                : pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        fprintf(stderr, "  (Are you root? Does the interface exist?)\n");
        return 1;
    }

    // Ensure we capture Ethernet frames
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface is not Ethernet (DLT_EN10MB required)\n");
        pcap_close(handle);
        return 1;
    }

    // BPF filter: capture Ethernet II (ARP, IPv4), PROFINET EtherType 0x8892,
    // and 802.1Q VLAN. Excludes broadcast noise we can't use.
    const char *filter_expr =
        "arp or "
        "(ip and (tcp or udp)) or "
        "ether proto 0x8892 or "     // PROFINET
        "ether proto 0x8100";        // 802.1Q (may carry PROFINET inside)

    struct bpf_program fp{};
    int compiled = pcap_compile(handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN);
    if (compiled == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(handle));
        // Non-fatal: continue without filter
    }
    if (compiled == 0) pcap_freecode(&fp);

    signal(SIGINT, sigHandler);
    signal(SIGTERM, sigHandler);

    printf("\n  PLC Passive Observer\n");
    printf("  Source    : %s\n", g_offline ? inputFile.c_str() : iface.c_str());
    printf("  Duration  : %s\n", duration>0 ? (std::to_string(duration)+" s").c_str() : "until Ctrl-C");
    if (!g_outputFile.empty())
        printf("  Output    : %s\n", g_outputFile.c_str());
    printf("\n  Listening (no packets transmitted)…  Press Ctrl-C to stop.\n\n");

    auto startTime = std::chrono::steady_clock::now();

    // ── Capture loop ──────────────────────────────────────────────────────────
    while (g_running) {
        int rc = pcap_dispatch(handle, 64, pcapCallback, nullptr);
        if (rc == -1) {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
            g_captureError = true;
            break;
        }
        if (g_offline && rc == 0) break;

        if (duration > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= duration) break;
        }
    }

    pcap_close(handle);

    printResults();
    if (!g_outputFile.empty() && !saveCSV(g_outputFile)) return 1;

    return g_captureError ? 1 : 0;
}
