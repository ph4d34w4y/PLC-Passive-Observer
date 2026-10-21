/*
 * plc_passive_observer.cpp
 *
 * Passive ICS / PLC asset fingerprinter
 * -------------------------------------
 * Builds an inventory of industrial devices by ONLY observing traffic that is
 * already on the wire (or replaying a capture file). It never transmits.
 *
 * What it reports, per host:
 *   - IP / MAC (with ARP-vs-routed MAC handling and address-change notes)
 *   - OUI vendor (built-in industrial table, or a full IEEE/Wireshark file)
 *   - Each ICS protocol seen, the host's ROLE in it (server / client) and the
 *     EVIDENCE level (port-only vs. structurally validated payload)
 *   - Identity the device reported about itself, where visible in cleartext:
 *       EtherNet/IP ListIdentity (vendor ID, CIP device type, product code,
 *         revision, serial, product name)
 *       PROFINET DCP Identify response (station name, type, vendor/device ID)
 *       LLDP (system name / description - often includes the order number)
 *       Modbus 43/14 Read Device Identification responses
 *       S7comm SZL 0x0011 / 0x001C responses (order number / station name)
 *       Beckhoff ADS ReadDeviceInfo responses, Omron FINS 05 01 responses
 *       BACnet I-Am (device instance, vendor ID)
 *   - Hostnames from mDNS / LLMNR / NetBIOS (only when the record's address
 *     matches the sender)
 *   - A classification that never claims more than the evidence supports
 *
 * Known limitations (also printed at the end of every run):
 *   - TCP streams are NOT reassembled. Messages are parsed per segment
 *     (multiple messages in one segment are handled; a message split across
 *     segments is missed). Results are best-effort.
 *   - IPv6 is counted but not analysed. Non-initial IPv4 fragments are skipped.
 *   - Visibility depends on the capture point: use a SPAN/mirror port or tap.
 *
 * Build:
 *   g++ -std=c++17 -O2 -Wall -Wextra -o plc_passive_observer plc_passive_observer.cpp -lpcap
 *
 * Usage:
 *   sudo ./plc_passive_observer -i <iface> [-t <sec>] [-o out.csv] [options]
 *        ./plc_passive_observer -r capture.pcap [-o out.csv] [options]
 *
 * LEGAL NOTICE: Only use on networks you own or have explicit written
 * authorization to monitor.
 */

#include <pcap/pcap.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <poll.h>

// ════════════════════════════════════════════════════════════════════════════
//  Bounds-checked byte span. Every wire read goes through has() first.
// ════════════════════════════════════════════════════════════════════════════
struct Span {
    const uint8_t *p = nullptr;
    size_t n = 0;
    Span() = default;
    Span(const uint8_t *d, size_t len) : p(d), n(len) {}
    bool has(size_t off, size_t len) const { return off <= n && len <= n - off; }
    uint8_t  u8(size_t o)   const { return p[o]; }
    uint16_t be16(size_t o) const { return uint16_t((p[o] << 8) | p[o + 1]); }
    uint16_t le16(size_t o) const { return uint16_t(p[o] | (p[o + 1] << 8)); }
    uint32_t be32(size_t o) const {
        return (uint32_t(p[o]) << 24) | (uint32_t(p[o + 1]) << 16) |
               (uint32_t(p[o + 2]) << 8) | uint32_t(p[o + 3]);
    }
    uint32_t le32(size_t o) const {
        return uint32_t(p[o]) | (uint32_t(p[o + 1]) << 8) |
               (uint32_t(p[o + 2]) << 16) | (uint32_t(p[o + 3]) << 24);
    }
    Span sub(size_t off, size_t len) const { return Span(p + off, len); } // caller checked has()
    Span from(size_t off) const { return off <= n ? Span(p + off, n - off) : Span(); }
};

// Keep only printable ASCII; collapse to a sane length. Device-supplied strings
// end up on the console and in CSV, so never pass raw bytes through.
static std::string cleanStr(const uint8_t *s, size_t len, size_t maxLen = 64) {
    std::string out;
    for (size_t i = 0; i < len && out.size() < maxLen; i++) {
        uint8_t c = s[i];
        if (c == 0) break;
        out += (c >= 0x20 && c < 0x7F) ? char(c) : '?';
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    size_t st = out.find_first_not_of(' ');
    return st == std::string::npos ? std::string() : out.substr(st);
}
static bool mostlyPrintable(const uint8_t *s, size_t len) {
    if (len == 0) return false;
    size_t good = 0;
    for (size_t i = 0; i < len; i++)
        if ((s[i] >= 0x20 && s[i] < 0x7F) || s[i] == 0) good++;
    return good == len;
}

// ════════════════════════════════════════════════════════════════════════════
//  Address helpers
// ════════════════════════════════════════════════════════════════════════════
using MacKey = uint64_t;
static MacKey macKey(const uint8_t *m) {
    MacKey k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | m[i];
    return k;
}
static std::string fmtMac(MacKey k) {
    char b[18];
    snprintf(b, sizeof b, "%02X:%02X:%02X:%02X:%02X:%02X",
             unsigned((k >> 40) & 0xFF), unsigned((k >> 32) & 0xFF), unsigned((k >> 24) & 0xFF),
             unsigned((k >> 16) & 0xFF), unsigned((k >> 8) & 0xFF), unsigned(k & 0xFF));
    return b;
}
static std::string fmtIp(uint32_t ip) {
    char b[16];
    snprintf(b, sizeof b, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return b;
}
static bool isUnicastIp(uint32_t ip) {
    if (ip == 0 || ip == 0xFFFFFFFFu) return false;
    if ((ip >> 28) == 0xE) return false;          // 224.0.0.0/4 multicast
    if ((ip >> 24) == 127) return false;          // loopback
    return true;
}
static bool isUnicastMac(MacKey k) { return ((k >> 40) & 0x01) == 0 && k != 0; }

// ════════════════════════════════════════════════════════════════════════════
//  OUI → vendor
//  Built-in table: industrial-automation prefixes verified against the
//  Wireshark manufacturer database (IEEE MA-L). Use --oui-file for the full
//  registry. A vendor match identifies the NIC maker, not a PLC.
// ════════════════════════════════════════════════════════════════════════════
struct OuiEntry { uint32_t oui; const char *vendor; };
static const OuiEntry OUI_TABLE[] = {
    // Siemens (industrial automation / drives)
    {0x0001E3, "Siemens AG"}, {0x000BA3, "Siemens AG"}, {0x000E8C, "Siemens AG"},
    {0x001B1B, "Siemens AG"}, {0x001C06, "Siemens Numerical Control"},
    {0x001FF8, "Siemens AG (Drive Technologies)"}, {0x080006, "Siemens AG"},
    {0x10DFFC, "Siemens AG"}, {0x208756, "Siemens AG"}, {0x20A8B9, "Siemens AG"},
    {0x286336, "Siemens AG"}, {0x301389, "Siemens AG (Automation & Drives)"},
    {0x302F1E, "Siemens AG"}, {0x30B851, "Siemens AG"}, {0x384B24, "Siemens AG"},
    {0x40ECF8, "Siemens AG"}, {0x4CE705, "Siemens Industrial Automation Products"},
    {0x681FD8, "Siemens Industry"}, {0x683E02, "Siemens AG (Digital Factory)"},
    {0x789F87, "Siemens AG"}, {0x883F99, "Siemens AG"},
    {0x8CF319, "Siemens Industrial Automation Products"}, {0xAC6417, "Siemens AG"},
    {0xD4F527, "Siemens AG"}, {0xE0DCA0, "Siemens Industrial Automation Products"},
    {0xE8EF22, "Siemens Numerical Control"}, {0xEC1C5D, "Siemens AG"},
    // Rockwell Automation / Allen-Bradley
    {0x0000BC, "Rockwell Automation"}, {0x001D9C, "Rockwell Automation"},
    {0x086195, "Rockwell Automation"}, {0x184C08, "Rockwell Automation"},
    {0x34C0F9, "Rockwell Automation"}, {0x404101, "Rockwell Automation"},
    {0x5C2167, "Rockwell Automation"}, {0x5C8816, "Rockwell Automation"},
    {0x68C8EB, "Rockwell Automation"}, {0xBCF499, "Rockwell Automation"},
    {0xE48EBB, "Rockwell Automation"}, {0xE49069, "Rockwell Automation"},
    {0xF45433, "Rockwell Automation"},
    // Schneider Electric / Telemecanique (Modicon)
    {0x000054, "Schneider Electric"}, {0x000123, "Schneider Electric Japan"},
    {0x000C81, "Schneider Electric (Australia)"}, {0x001100, "Schneider Electric"},
    {0x0080F4, "Telemecanique (Schneider Electric)"}, {0x20443A, "Schneider Electric"},
    {0x942E17, "Schneider Electric Canada"},
    // ABB
    {0x000023, "ABB Industrial Systems"}, {0x00032C, "ABB Switzerland"},
    {0x000C02, "ABB Oy"}, {0x000CDE, "ABB Stotz-Kontakt"}, {0x001B45, "ABB (Automation Products)"},
    {0x001C01, "ABB Oy Drives"}, {0x002459, "ABB Automation Products"},
    {0x54F876, "ABB AG"}, {0x60391F, "ABB Ltd"}, {0xE002A5, "ABB Robotics"},
    // Mitsubishi Electric
    {0x002692, "Mitsubishi Electric"}, {0x104B46, "Mitsubishi Electric"},
    {0x28E98E, "Mitsubishi Electric"}, {0x30BE3B, "Mitsubishi Electric"},
    {0x38E08E, "Mitsubishi Electric"}, {0x58528A, "Mitsubishi Electric"},
    {0x588D39, "Mitsubishi Electric Automation (China)"}, {0x94A4B5, "Mitsubishi Electric"},
    {0x986DC8, "Toshiba Mitsubishi-Electric Industrial Systems"},
    // Omron
    {0x00000A, "Omron"}, {0x3CF7D1, "Omron"},
    // GE / Fanuc / Emerson
    {0x00E0E4, "FANUC Robotics"}, {0x0022E5, "Fisher-Rosemount (Emerson)"},
    {0x004003, "Emerson Process Management"},
    // Honeywell
    {0x00226A, "Honeywell"}, {0x0030AF, "Honeywell GmbH"}, {0x004084, "Honeywell"},
    {0x0080A7, "Honeywell"}, {0xC4EFDA, "Honeywell"},
    // Others
    {0x000105, "Beckhoff Automation"},
    {0x006065, "B&R Industrial Automation"},
    {0x00A045, "Phoenix Contact"}, {0xA8741D, "Phoenix Contact"}, {0xCCCCEA, "Phoenix Contact"},
    {0x000248, "Pilz"},
    {0x0090E8, "Moxa"},
    {0x0030DE, "WAGO Kontakttechnik"},
    {0x000B0F, "Bosch Rexroth"},
    {0x000768, "Danfoss"}, {0x001B08, "Danfoss Drives"},
    {0x0020B5, "Yaskawa Electric"},
    {0x000A86, "Lenze"},
    {0x0005E4, "Red Lion Controls"}, {0x0007AF, "Red Lion Controls"},
    {0x001347, "Red Lion Controls"}, {0x0060DA, "Red Lion Controls"}, {0x00A01D, "Red Lion Controls"},
    {0x0002A2, "Hilscher"},
    {0x000327, "HMS Industrial Networks"}, {0x000594, "HMS Industrial Networks"},
    {0x003011, "HMS Industrial Networks"}, {0x003056, "HMS Industrial Networks"},
    {0x9CB206, "HMS Industrial Networks"},
    {0x000D8D, "ProSoft Technology"},
    {0x000746, "Turck"},
    {0x0001FC, "Keyence"}, {0x7495A7, "Keyence"},
    {0x00066E, "Delta Electronics"}, {0x001823, "Delta Electronics"}, {0x20F85E, "Delta Electronics"},
    {0x000201, "ifm electronic"}, {0x74731D, "ifm electronic"},
    {0x000D22, "Unitronics"},
    {0x0020D5, "VIPA"},
    {0x7C160D, "Saia-Burgess Controls"},
    {0x00037B, "IDEC"},
    {0x00401A, "Fuji Electric"},
    {0x005040, "Panasonic Electric Works"}, {0x00C08F, "Panasonic Electric Works"},
    {0x000064, "Yokogawa"}, {0x006041, "Yokogawa"}, {0xD00AAB, "Yokogawa"},
    {0x000EF0, "Festo"},
    {0x000677, "SICK"},
    {0x000705, "Endress+Hauser"},
    {0x00141D, "KEBA"}, {0x0060B5, "KEBA"},
    {0x00157E, "Weidmueller"},
    {0x008063, "Hirschmann"}, {0x646038, "Hirschmann"}, {0x740BB0, "Hirschmann"},
    {0xA0B086, "Hirschmann"}, {0xEC74BA, "Hirschmann"},
    {0x00077C, "Westermo"}, {0x0011B4, "Westermo"},
    {0x000671, "Softing"},
    {0x00054B, "Eaton Automation"},
    {0xA497BB, "Hitachi Industrial Equipment Systems"},
    {0x000D46, "Parker SSD Drives"},
    {0x0010DA, "Kollmorgen"},
};

static std::unordered_map<uint32_t, std::string> g_ouiFile;   // from --oui-file
static std::string g_ouiSource = "built-in industrial table";

static std::string lookupOui(MacKey mac) {
    if (mac & (MacKey(0x02) << 40)) return "locally administered MAC";
    uint32_t oui = uint32_t(mac >> 24);
    auto it = g_ouiFile.find(oui);
    if (it != g_ouiFile.end()) return it->second;
    for (const auto &e : OUI_TABLE)
        if (e.oui == oui) return e.vendor;
    return "";
}

// Accepts IEEE oui.txt ("00-00-0A   (hex)\t\tOmron ...") and Wireshark manuf
// ("00:00:0A<TAB>Omron<TAB>Omron Tateisi ...") formats. Only 24-bit entries.
static bool loadOuiFile(const std::string &path) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    size_t n = 0;
    while (std::getline(f, line)) {
        if (line.size() < 9 || line[0] == '#') continue;
        auto hex = [](char c) { return std::isxdigit((unsigned char)c) != 0; };
        if (!(hex(line[0]) && hex(line[1]) && (line[2] == '-' || line[2] == ':') &&
              hex(line[3]) && hex(line[4]) && line[5] == line[2] && hex(line[6]) && hex(line[7])))
            continue;
        if (line.size() > 8 && line[8] == '/') continue;          // MA-M / MA-S range
        uint32_t oui = uint32_t(std::strtoul((line.substr(0, 2) + line.substr(3, 2) + line.substr(6, 2)).c_str(), nullptr, 16));
        std::string rest = line.substr(8);
        auto hp = rest.find("(hex)");
        if (hp != std::string::npos) rest = rest.substr(hp + 5);
        // Wireshark: short<TAB>long - prefer the long name
        std::vector<std::string> cols;
        size_t s = 0;
        while (s <= rest.size()) {
            size_t t = rest.find('\t', s);
            std::string c = rest.substr(s, t == std::string::npos ? std::string::npos : t - s);
            size_t a = c.find_first_not_of(" \t\r"), b = c.find_last_not_of(" \t\r");
            if (a != std::string::npos) cols.push_back(c.substr(a, b - a + 1));
            if (t == std::string::npos) break;
            s = t + 1;
        }
        if (cols.empty()) continue;
        g_ouiFile[oui] = cleanStr(reinterpret_cast<const uint8_t *>(cols.back().data()), cols.back().size(), 80);
        n++;
    }
    if (n == 0) return false;
    g_ouiSource = path + " (" + std::to_string(n) + " entries)";
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  Protocols, evidence and roles
// ════════════════════════════════════════════════════════════════════════════
enum class Proto : uint8_t {
    MODBUS, ENIP, PROFINET, S7, DNP3, BACNET, FINS, MELSEC, IEC104, CRIMSON, ADS
};
static const char *protoName(Proto p) {
    switch (p) {
        case Proto::MODBUS:   return "Modbus/TCP";
        case Proto::ENIP:     return "EtherNet/IP";
        case Proto::PROFINET: return "PROFINET";
        case Proto::S7:       return "S7comm";
        case Proto::DNP3:     return "DNP3";
        case Proto::BACNET:   return "BACnet/IP";
        case Proto::FINS:     return "Omron FINS";
        case Proto::MELSEC:   return "MELSEC MC/SLMP";
        case Proto::IEC104:   return "IEC 60870-5-104";
        case Proto::CRIMSON:  return "Red Lion Crimson";
        case Proto::ADS:      return "Beckhoff ADS";
    }
    return "?";
}

// PORT      = traffic used the protocol's usual port, payload not confirmed
// VALIDATED = at least one message passed structural validation
enum class Evidence : uint8_t { NONE = 0, PORT = 1, VALIDATED = 2 };
enum : uint8_t { ROLE_SERVER = 1, ROLE_CLIENT = 2 };
enum class Dir { UNKNOWN, SRC_IS_SERVER, SRC_IS_CLIENT };

struct ProtoObs {
    Evidence portEv = Evidence::NONE;   // strongest evidence seen
    uint8_t  roles = 0;                 // ROLE_* bits (any evidence level)
    uint8_t  validatedRoles = 0;        // ROLE_* bits backed by a validated message
    bool     validatedNoRole = false;   // validated, role not determinable (e.g. peer-to-peer)
    uint64_t validMsgs = 0;
    std::set<uint16_t> serverPorts;
};

struct Identity {
    std::set<std::string> sources;
    std::string vendor, product, model, deviceType, productCode, revision, serial,
                orderNumber, description;
    int cipDeviceType = -1;
};

struct Device {
    bool     isMacOnly = false;
    uint32_t ip = 0;
    MacKey   macKeyOnly = 0;                 // for MAC-only (L2) records
    std::map<MacKey, uint8_t> macs;          // flags: MAC_*
    std::map<Proto, ProtoObs> protos;
    std::set<uint32_t> peers;
    std::string hostname, hostnameSrc;
    Identity id;
    std::vector<std::string> notes;
    time_t   firstSeen = 0, lastSeen = 0;
    uint64_t pktsSent = 0, pktsRecv = 0;
};
enum : uint8_t { MAC_ARP = 1, MAC_IPSRC = 2, MAC_L2DISC = 4 };

// ════════════════════════════════════════════════════════════════════════════
//  Global state
// ════════════════════════════════════════════════════════════════════════════
static std::map<uint32_t, Device> g_ipDev;
static std::map<MacKey, Device>   g_macDev;
static std::map<MacKey, std::set<uint32_t>> g_macToIps;     // MACs used as IP source
static std::map<MacKey, std::set<uint32_t>> g_arpMacToIps;  // IPs each MAC claimed via ARP
static volatile std::sig_atomic_t g_running = 1;
static pcap_t *g_handle = nullptr;

struct Stats {
    uint64_t frames = 0, vlanTagged = 0, arp = 0, ipv4 = 0, ipv6 = 0, fragments = 0,
             truncated = 0, malformed = 0, profinet = 0, lldp = 0, otherEther = 0,
             arpMismatch = 0;
} g_st;

static void sigHandler(int) {
    g_running = 0;
    if (g_handle) pcap_breakloop(g_handle);   // documented as safe from a signal handler
}

static void touch(Device &d, time_t ts) {
    if (d.firstSeen == 0 || ts < d.firstSeen) d.firstSeen = ts;
    if (ts > d.lastSeen) d.lastSeen = ts;
}
static Device &ipDevice(uint32_t ip, time_t ts) {
    Device &d = g_ipDev[ip];
    d.ip = ip;
    touch(d, ts);
    return d;
}
static Device &macDevice(MacKey m, time_t ts) {
    Device &d = g_macDev[m];
    d.isMacOnly = true;
    d.macKeyOnly = m;
    d.macs[m] |= MAC_L2DISC;
    touch(d, ts);
    return d;
}
static void addNote(Device &d, const std::string &n) {
    if (std::find(d.notes.begin(), d.notes.end(), n) == d.notes.end() && d.notes.size() < 8)
        d.notes.push_back(n);
}
static void setIf(std::string &field, const std::string &v) { if (field.empty() && !v.empty()) field = v; }
static void setHostname(Device &d, const std::string &name, const char *src) {
    if (name.empty() || !d.hostname.empty()) return;
    d.hostname = name;
    d.hostnameSrc = src;
}

// Record one observation of `proto` between src and (optional) dst.
static void observe(Proto proto, Device *src, Device *dst, Dir dir, Evidence ev,
                    uint16_t sport, uint16_t dport) {
    uint8_t srcRole = dir == Dir::SRC_IS_SERVER ? ROLE_SERVER : dir == Dir::SRC_IS_CLIENT ? ROLE_CLIENT : 0;
    uint8_t dstRole = dir == Dir::SRC_IS_SERVER ? ROLE_CLIENT : dir == Dir::SRC_IS_CLIENT ? ROLE_SERVER : 0;
    auto apply = [&](Device *d, uint8_t role, uint16_t ownPort) {
        if (!d) return;
        ProtoObs &o = d->protos[proto];
        if (ev > o.portEv) o.portEv = ev;
        o.roles |= role;
        if (ev == Evidence::VALIDATED) {
            o.validMsgs++;
            if (role) o.validatedRoles |= role; else o.validatedNoRole = true;
        }
        if (role == ROLE_SERVER && ownPort) o.serverPorts.insert(ownPort);
    };
    apply(src, srcRole, sport);
    apply(dst, dstRole, dport);
    if (src && dst) {
        if (src->peers.size() < 256) src->peers.insert(dst->ip);
        if (dst->peers.size() < 256) dst->peers.insert(src->ip);
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Protocol validators.  Each returns true only for a structurally valid
//  message; it may refine the direction and attach identity to the sender.
//  `src` is the device that sent this message.
// ════════════════════════════════════════════════════════════════════════════
struct Ctx {
    Device *src = nullptr;
    Device *dst = nullptr;
    Dir dir = Dir::UNKNOWN;
};

// ── Modbus/TCP ──────────────────────────────────────────────────────────────
// MBAP: txid(2) proto=0(2) len(2) unit(1) | PDU: fc(1) data...
// len counts unit+PDU, 2..254. Iterates over every complete ADU in the segment.
static bool modbusFcValid(uint8_t fc) {
    uint8_t f = fc & 0x7F;
    switch (f) {
        case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 11: case 12:
        case 15: case 16: case 17: case 20: case 21: case 22: case 23: case 24: case 43:
            return true;
        default:
            return f >= 65 && f <= 72;   // user-defined range
    }
}
static void modbusDeviceId(Span pdu, Ctx &c) {
    // Response: fc=0x2B MEI=0x0E code conformity more next nobj {id len value}...
    if (!pdu.has(0, 7) || pdu.u8(0) != 0x2B || pdu.u8(1) != 0x0E) return;
    if (c.dir != Dir::SRC_IS_SERVER) return;          // only trust what the server says about itself
    uint8_t nobj = pdu.u8(6);
    size_t off = 7;
    for (uint8_t i = 0; i < nobj; i++) {
        if (!pdu.has(off, 2)) return;
        uint8_t id = pdu.u8(off), len = pdu.u8(off + 1);
        if (!pdu.has(off + 2, len)) return;
        std::string v = cleanStr(pdu.p + off + 2, len);
        Identity &I = c.src->id;
        switch (id) {
            case 0: setIf(I.vendor, v); break;
            case 1: setIf(I.productCode, v); break;
            case 2: setIf(I.revision, v); break;
            case 4: setIf(I.product, v); break;
            case 5: setIf(I.model, v); break;
            default: break;
        }
        I.sources.insert("Modbus 43/14 Device ID");
        off += 2u + len;
    }
}
static bool validateModbus(Span d, Ctx &c) {
    size_t off = 0;
    int good = 0;
    while (d.has(off, 8)) {
        uint16_t proto = d.be16(off + 2), len = d.be16(off + 4);
        if (proto != 0 || len < 2 || len > 254 || !d.has(off + 6, len)) break;
        if (!modbusFcValid(d.u8(off + 7))) break;
        modbusDeviceId(d.sub(off + 7, len - 1u), c);
        good++;
        off += 6u + len;
    }
    return good > 0;
}

// ── EtherNet/IP encapsulation (little-endian!) ─────────────────────────────
// cmd(2) len(2) session(4) status(4) context(8) options(4) | data[len]
static bool enipCmdValid(uint16_t cmd) {
    switch (cmd) {
        case 0x0000: /* NOP */            case 0x0004: /* ListServices */
        case 0x0063: /* ListIdentity */   case 0x0064: /* ListInterfaces */
        case 0x0065: /* RegisterSession */case 0x0066: /* UnRegisterSession */
        case 0x006F: /* SendRRData */     case 0x0070: /* SendUnitData */
        case 0x0072: /* IndicateStatus */ case 0x0073: /* Cancel */
            return true;
        default: return false;
    }
}
static const char *cipDeviceTypeName(uint16_t t) {
    switch (t) {
        case 0x00: return "Generic Device";
        case 0x02: return "AC Drive";
        case 0x03: return "Motor Overload";
        case 0x04: return "Limit Switch";
        case 0x05: return "Inductive Proximity Switch";
        case 0x06: return "Photoelectric Sensor";
        case 0x07: return "General Purpose Discrete I/O";
        case 0x09: return "Resolver";
        case 0x0C: return "Communications Adapter";
        case 0x0E: return "Programmable Logic Controller";
        case 0x10: return "Position Controller";
        case 0x13: return "DC Drive";
        case 0x15: return "Contactor";
        case 0x16: return "Motor Starter";
        case 0x17: return "Soft Start";
        case 0x18: return "Human-Machine Interface";
        case 0x22: return "Encoder";
        case 0x23: return "Safety Discrete I/O";
        case 0x25: return "CIP Motion Drive";
        case 0x2B: return "Generic Device (keyable)";
        default:   return nullptr;
    }
}
// ListIdentity reply CPF item 0x000C. Fields are little-endian except the
// embedded sockaddr (big-endian, BSD layout). Every read is bounded by the
// item's own length, not just the packet.
static void enipListIdentity(Span data, Ctx &c) {
    if (!data.has(0, 2) || data.le16(0) < 1) return;
    size_t off = 2;
    if (!data.has(off, 4)) return;
    uint16_t type = data.le16(off), ilen = data.le16(off + 2);
    off += 4;
    if (type != 0x000C || !data.has(off, ilen)) return;
    Span it = data.sub(off, ilen);
    // ver(2) sockaddr(16) vendor(2) dtype(2) pcode(2) rev(2) status(2) serial(4) namelen(1)
    const size_t fixed = 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 + 1;
    if (!it.has(0, fixed)) return;
    if (it.be16(2) != 2) return;                  // sin_family = AF_INET
    uint16_t vendor = it.le16(18), dtype = it.le16(20), pcode = it.le16(22);
    uint8_t revMaj = it.u8(24), revMin = it.u8(25);
    uint32_t serial = it.le32(28);
    uint8_t nameLen = it.u8(32);
    if (!it.has(33, nameLen) || nameLen > 64) return;

    Identity &I = c.src->id;
    I.sources.insert("EtherNet/IP ListIdentity");
    char buf[64];
    snprintf(buf, sizeof buf, "%u%s", vendor, vendor == 1 ? " (Rockwell Automation/Allen-Bradley)" : "");
    setIf(I.vendor, std::string("CIP vendor ID ") + buf);
    const char *dn = cipDeviceTypeName(dtype);
    snprintf(buf, sizeof buf, "%s (0x%02X)", dn ? dn : "CIP device type", dtype);
    setIf(I.deviceType, buf);
    if (I.cipDeviceType < 0) I.cipDeviceType = dtype;
    setIf(I.productCode, std::to_string(pcode));
    snprintf(buf, sizeof buf, "%u.%03u", revMaj, revMin);
    setIf(I.revision, buf);
    snprintf(buf, sizeof buf, "0x%08X", serial);
    setIf(I.serial, buf);
    setIf(I.product, cleanStr(it.p + 33, nameLen));
}
static bool validateEnipEncap(Span d, Ctx &c, bool isUdp) {
    size_t off = 0;
    int good = 0;
    while (d.has(off, 24)) {
        uint16_t cmd = d.le16(off), len = d.le16(off + 2);
        uint32_t options = d.le32(off + 20);
        if (!enipCmdValid(cmd) || options != 0 || !d.has(off + 24, len)) break;
        if (isUdp && off + 24u + len != d.n) break;   // one encapsulation per datagram
        Span body = d.sub(off + 24, len);
        if (cmd == 0x0063) {
            // Request has no body; reply has a CPF item list. The replier is the device.
            if (len == 0) { if (c.dir == Dir::UNKNOWN) c.dir = Dir::SRC_IS_CLIENT; }
            else { c.dir = Dir::SRC_IS_SERVER; enipListIdentity(body, c); }
        }
        good++;
        off += 24u + len;
    }
    return good > 0;
}
// Class 0/1 implicit I/O on UDP 2222: CPF without an encapsulation header.
// count(2) {type 0x8002 seq-addr len 8} {type 0x00B1 connected data len n}
static bool validateEnipIo(Span d) {
    if (!d.has(0, 2)) return false;
    uint16_t count = d.le16(0);
    if (count < 2 || count > 4) return false;
    size_t off = 2;
    for (uint16_t i = 0; i < count; i++) {
        if (!d.has(off, 4)) return false;
        uint16_t type = d.le16(off), len = d.le16(off + 2);
        if (i == 0 && !(type == 0x8002 && len == 8)) return false;
        if (i == 1 && type != 0x00B1) return false;
        if (!d.has(off + 4, len)) return false;
        off += 4u + len;
    }
    return off == d.n;
}

// ── S7comm over ISO-on-TCP (TPKT/COTP) ──────────────────────────────────────
// A TPKT/COTP frame alone is NOT S7 (IEC 61850 MMS uses the same transport),
// so only a 0x32 (S7comm) or 0x72 (S7comm-plus) PDU counts as validated.
static void s7Szl(Span s7, size_t hdrLen, uint16_t plen, uint16_t dlen, Ctx &c) {
    // Userdata response: param = 00 01 12 len method type|group subfn seq ...
    if (!s7.has(hdrLen, plen) || plen < 8) return;
    Span par = s7.sub(hdrLen, plen);
    if (par.u8(0) != 0x00 || par.u8(1) != 0x01 || par.u8(2) != 0x12) return;
    uint8_t tg = par.u8(5), subfn = par.u8(6);
    if ((tg >> 4) != 0x8 || (tg & 0x0F) != 0x4 || subfn != 0x01) return;   // response, CPU fn, read SZL
    if (!s7.has(hdrLen + plen, dlen) || dlen < 12) return;
    Span dat = s7.sub(hdrLen + plen, dlen);
    if (dat.u8(0) != 0xFF) return;                                         // return code success
    uint16_t szlId = dat.be16(4), entLen = dat.be16(8), count = dat.be16(10);
    size_t off = 12;
    c.dir = Dir::SRC_IS_SERVER;
    Identity &I = c.src->id;
    for (uint16_t i = 0; i < count && entLen >= 4 && dat.has(off, entLen); i++, off += entLen) {
        uint16_t index = dat.be16(off);
        if ((szlId & 0x00FF) == 0x11 && index == 0x0001 && entLen >= 22) {
            setIf(I.orderNumber, cleanStr(dat.p + off + 2, 20));
            I.sources.insert("S7 SZL 0x0011");
        } else if ((szlId & 0x00FF) == 0x1C && entLen >= 26) {
            std::string v = cleanStr(dat.p + off + 2, std::min<size_t>(entLen - 2u, 32));
            if (index == 0x0001) setIf(I.description, "AS name: " + v);
            else if (index == 0x0002) setIf(I.model, v);
            else if (index == 0x0007) setIf(I.product, v);
            I.sources.insert("S7 SZL 0x001C");
        }
    }
}
static bool validateS7(Span d, Ctx &c, bool &cotpOnly) {
    size_t off = 0;
    int good = 0;
    cotpOnly = false;
    while (d.has(off, 7)) {
        if (d.u8(off) != 0x03 || d.u8(off + 1) != 0x00) break;
        uint16_t tlen = d.be16(off + 2);
        if (tlen < 7 || !d.has(off, tlen)) break;
        Span t = d.sub(off, tlen);
        uint8_t li = t.u8(4), pdu = t.u8(5) & 0xF0;
        if (size_t(li) + 5 > tlen || li < 2) break;
        if (pdu == 0xE0 || pdu == 0xD0) cotpOnly = true;               // CR / CC
        if (pdu == 0xF0) {
            Span s7 = t.from(5u + li);
            if (s7.has(0, 1) && s7.u8(0) == 0x32 && s7.has(0, 10)) {
                uint8_t rosctr = s7.u8(1);
                size_t hdr = (rosctr == 2 || rosctr == 3) ? 12 : 10;
                if (rosctr >= 1 && rosctr <= 7 && s7.has(0, hdr)) {
                    uint16_t plen = s7.be16(6), dlen = s7.be16(8);
                    if (s7.has(hdr, size_t(plen) + dlen)) {
                        if (rosctr == 1) c.dir = Dir::SRC_IS_CLIENT;
                        if (rosctr == 3) c.dir = Dir::SRC_IS_SERVER;
                        if (rosctr == 7) s7Szl(s7, hdr, plen, dlen, c);
                        good++;
                    }
                }
            } else if (s7.has(0, 4) && s7.u8(0) == 0x72 &&
                       (s7.u8(1) == 0x01 || s7.u8(1) == 0x02 || s7.u8(1) == 0x03 || s7.u8(1) == 0xFE)) {
                good++;   // S7comm-plus (S7-1200/1500); payload is integrity-protected, no identity
            }
        }
        off += tlen;
    }
    if (good) cotpOnly = false;
    return good > 0;
}

// ── DNP3 link layer ─────────────────────────────────────────────────────────
// 05 64 len ctrl dst(2,LE) src(2,LE) crc(2,LE). Header CRC is verified.
static uint16_t crcDnp(const uint8_t *p, size_t n) {
    uint16_t crc = 0;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) crc = (crc & 1) ? uint16_t((crc >> 1) ^ 0xA6BC) : uint16_t(crc >> 1);
    }
    return uint16_t(~crc);
}
static bool validateDnp3(Span d, Ctx &c) {
    if (!d.has(0, 10) || d.u8(0) != 0x05 || d.u8(1) != 0x64 || d.u8(2) < 5) return false;
    if (crcDnp(d.p, 8) != d.le16(8)) return false;
    uint8_t ctrl = d.u8(3);
    c.dir = (ctrl & 0x80) ? Dir::SRC_IS_CLIENT : Dir::SRC_IS_SERVER;   // DIR=1: from master
    if (c.dir == Dir::SRC_IS_SERVER) {
        Identity &I = c.src->id;
        if (I.description.empty())
            I.description = "DNP3 outstation address " + std::to_string(d.le16(6));
    }
    return true;
}

// ── IEC 60870-5-104 ─────────────────────────────────────────────────────────
static bool validateIec104(Span d) {
    size_t off = 0;
    int good = 0;
    while (d.has(off, 6)) {
        if (d.u8(off) != 0x68) break;
        uint8_t len = d.u8(off + 1);
        if (len < 4 || !d.has(off + 2, len)) break;
        uint8_t c1 = d.u8(off + 2);
        if ((c1 & 0x01) == 0) {                       // I-format
            if (len < 4 + 6) break;                   // must carry an ASDU header
        } else if ((c1 & 0x03) == 0x01) {             // S-format
            if (len != 4 || c1 != 0x01 || d.u8(off + 3) != 0) break;
        } else {                                      // U-format: exactly one function bit
            if (len != 4) break;
            uint8_t f = c1 & 0xFC;
            if (!(f == 0x04 || f == 0x08 || f == 0x10 || f == 0x20 || f == 0x40 || f == 0x80)) break;
        }
        good++;
        off += 2u + len;
    }
    return good > 0;
}

// ── BACnet/IP ───────────────────────────────────────────────────────────────
// BVLC: 0x81 fn len(2, == datagram length). I-Am yields device instance + vendor.
static void bacnetIAm(Span npdu, Ctx &c) {
    if (!npdu.has(0, 2) || npdu.u8(0) != 0x01) return;
    uint8_t ctl = npdu.u8(1);
    if (ctl & 0x80) return;                           // network-layer message
    size_t off = 2;
    if (ctl & 0x20) {                                 // DNET/DLEN/DADR
        if (!npdu.has(off, 3)) return;
        off += 3u + npdu.u8(off + 2);
    }
    if (ctl & 0x08) {                                 // SNET/SLEN/SADR
        if (!npdu.has(off, 3)) return;
        off += 3u + npdu.u8(off + 2);
    }
    if (ctl & 0x20) off += 1;                         // hop count
    Span a = npdu.from(off);
    if (!a.has(0, 7) || a.u8(0) != 0x10 || a.u8(1) != 0x00) return;   // Unconfirmed I-Am
    if (a.u8(2) != 0xC4) return;                      // object identifier tag
    uint32_t oid = a.be32(3);
    if ((oid >> 22) != 8) return;                     // object type 8 = device
    size_t p = 7;
    auto readUnsigned = [&](uint32_t &v) -> bool {    // context tag class=application unsigned (0x2X)
        if (!a.has(p, 1)) return false;
        uint8_t tag = a.u8(p);
        uint8_t l = tag & 0x07;
        if ((tag & 0xF8) != 0x20 || l < 1 || l > 4 || !a.has(p + 1, l)) return false;
        v = 0;
        for (uint8_t i = 0; i < l; i++) v = (v << 8) | a.u8(p + 1 + i);
        p += 1u + l;
        return true;
    };
    uint32_t maxApdu = 0, vendor = 0;
    if (!readUnsigned(maxApdu)) return;
    if (!a.has(p, 2) || a.u8(p) != 0x91) return;      // segmentation (enumerated)
    p += 2;
    if (!readUnsigned(vendor)) return;
    c.dir = Dir::SRC_IS_SERVER;
    Identity &I = c.src->id;
    I.sources.insert("BACnet I-Am");
    setIf(I.description, "BACnet device instance " + std::to_string(oid & 0x3FFFFF));
    setIf(I.vendor, "BACnet vendor ID " + std::to_string(vendor));
}
static bool validateBacnet(Span d, Ctx &c) {
    if (!d.has(0, 4) || d.u8(0) != 0x81 || d.u8(1) > 0x0C || d.be16(2) != d.n) return false;
    uint8_t fn = d.u8(1);
    if (fn == 0x0A || fn == 0x0B) bacnetIAm(d.from(4), c);          // Original-Unicast/Broadcast
    else if (fn == 0x04) bacnetIAm(d.from(10), c);                  // Forwarded-NPDU
    return true;
}

// ── Omron FINS (UDP/TCP 9600) ───────────────────────────────────────────────
// UDP: ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID MRC SRC [...]
// TCP: "FINS" magic header (16 bytes) before the same frame.
static bool validateFinsFrame(Span d, Ctx &c) {
    if (!d.has(0, 12)) return false;
    uint8_t icf = d.u8(0);
    if ((icf & 0x80) == 0 || (icf & 0x3E) != 0 || d.u8(1) != 0x00 || d.u8(2) > 0x07) return false;
    bool resp = (icf & 0x40) != 0;
    c.dir = resp ? Dir::SRC_IS_SERVER : Dir::SRC_IS_CLIENT;
    // 05 01 Controller Data Read response: MRES SRES model[20] version[20]
    if (resp && d.u8(10) == 0x05 && d.u8(11) == 0x01 && d.has(12, 2 + 20 + 20) &&
        d.u8(12) == 0x00 && (d.u8(13) & 0x3F) == 0x00 && mostlyPrintable(d.p + 14, 20)) {
        Identity &I = c.src->id;
        I.sources.insert("FINS 05 01 Controller Data");
        setIf(I.model, cleanStr(d.p + 14, 20));
        setIf(I.revision, cleanStr(d.p + 34, 20));
        setIf(I.vendor, "Omron");
    }
    return true;
}
static bool validateFins(Span d, Ctx &c, bool tcp) {
    if (!tcp) return validateFinsFrame(d, c);
    // FINS/TCP: 'FINS' len(4) cmd(4) err(4) then frame (cmd 2 = frame send)
    if (!d.has(0, 16) || memcmp(d.p, "FINS", 4) != 0) return false;
    uint32_t len = d.be32(4), cmd = d.be32(8);
    if (len < 8 || !d.has(8, len)) return false;
    if (cmd == 2) validateFinsFrame(d.sub(16, len - 8), c);
    return cmd <= 3;
}

// ── MELSEC MC protocol / SLMP, 3E binary frame ──────────────────────────────
static bool validateMelsec(Span d, Ctx &c) {
    if (!d.has(0, 11)) return false;
    uint16_t sub = d.be16(0);
    if (sub != 0x5000 && sub != 0xD000) return false;
    if (d.le16(4) != 0x03FF && d.le16(4) != 0x03E0 && d.le16(4) != 0x03D0) return false; // request dest module I/O
    uint16_t dlen = d.le16(7);
    if (size_t(dlen) + 9 != d.n) return false;
    c.dir = sub == 0xD000 ? Dir::SRC_IS_SERVER : Dir::SRC_IS_CLIENT;
    return true;
}

// ── Beckhoff ADS / AMS over TCP 48898 ───────────────────────────────────────
// AMS/TCP: reserved(2)=0 len(4,LE) | AMS hdr 32 bytes | data
static bool validateAds(Span d, Ctx &c) {
    size_t off = 0;
    int good = 0;
    while (d.has(off, 6 + 32)) {
        if (d.le16(off) != 0) break;
        uint32_t len = d.le32(off + 2);
        if (len < 32 || !d.has(off + 6, len)) break;
        Span a = d.sub(off + 6, len);
        uint16_t cmd = a.le16(16), state = a.le16(18);
        uint32_t dlen = a.le32(20);
        if (cmd == 0 || cmd > 9 || size_t(dlen) + 32 != len) break;
        bool resp = (state & 0x0001) != 0;
        c.dir = resp ? Dir::SRC_IS_SERVER : Dir::SRC_IS_CLIENT;
        // ReadDeviceInfo response: result(4) major minor build(2) name[16]
        if (resp && cmd == 1 && dlen >= 24 && a.le32(32) == 0) {
            Identity &I = c.src->id;
            I.sources.insert("ADS ReadDeviceInfo");
            char v[32];
            snprintf(v, sizeof v, "%u.%u.%u", a.u8(36), a.u8(37), a.le16(38));
            setIf(I.revision, v);
            setIf(I.product, cleanStr(a.p + 40, 16));
            setIf(I.vendor, "Beckhoff");
        }
        good++;
        off += 6u + len;
    }
    return good > 0;
}

// ── PROFINET context manager (DCE/RPC v4 over UDP 34964) ────────────────────
static bool validatePnioCm(Span d, Ctx &c) {
    if (!d.has(0, 80) || d.u8(0) != 4) return false;   // RPC version 4, 80-byte header
    uint8_t ptype = d.u8(1);
    if (ptype > 10) return false;
    if (ptype == 0) c.dir = Dir::SRC_IS_CLIENT;          // request
    if (ptype == 2) c.dir = Dir::SRC_IS_SERVER;          // response
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  DNS-format parsing for mDNS / LLMNR / NetBIOS-NS (all share the layout)
// ════════════════════════════════════════════════════════════════════════════
static bool dnsName(Span m, size_t &off, std::string &out) {
    out.clear();
    size_t pos = off;
    bool jumped = false;
    int hops = 0;
    while (true) {
        if (!m.has(pos, 1)) return false;
        uint8_t l = m.u8(pos);
        if ((l & 0xC0) == 0xC0) {                         // compression pointer
            if (!m.has(pos, 2) || ++hops > 16) return false;
            size_t target = size_t(((l & 0x3F) << 8) | m.u8(pos + 1));
            if (!jumped) off = pos + 2;
            jumped = true;
            if (target >= m.n) return false;
            pos = target;
            continue;
        }
        if (l & 0xC0) return false;                       // reserved label types
        if (l == 0) { if (!jumped) off = pos + 1; return true; }
        if (!m.has(pos + 1, l) || out.size() + l + 1 > 255) return false;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char *>(m.p + pos + 1), l);
        pos += 1u + l;
    }
}
static std::string decodeNetbios(const std::string &enc, uint8_t &suffix) {
    if (enc.size() < 32) return "";
    std::string raw;
    for (size_t i = 0; i < 32; i += 2) {
        char a = enc[i], b = enc[i + 1];
        if (a < 'A' || a > 'P' || b < 'A' || b > 'P') return "";
        raw += char(((a - 'A') << 4) | (b - 'A'));
    }
    suffix = uint8_t(raw[15]);
    return cleanStr(reinterpret_cast<const uint8_t *>(raw.data()), 15, 15);
}
static std::string sanitizeHost(const std::string &n) {
    std::string s = n;
    if (s.size() > 6 && s.compare(s.size() - 6, 6, ".local") == 0) s.resize(s.size() - 6);
    if (!s.empty() && s.back() == '.') s.pop_back();
    for (char ch : s)
        if (!(std::isalnum((unsigned char)ch) || ch == '-' || ch == '_' || ch == '.')) return "";
    return s.size() <= 63 ? s : "";
}
enum class NameProto { MDNS, LLMNR, NBNS };
// Returns a name only if a resource record binds it to the sender's address.
static std::string nameFromDns(Span m, uint32_t srcIp, NameProto kind) {
    if (!m.has(0, 12)) return "";
    uint16_t flags = m.be16(2);
    bool isResp = (flags & 0x8000) != 0;
    uint8_t opcode = uint8_t((flags >> 11) & 0x0F);
    if (kind != NameProto::NBNS && !isResp) return "";
    if (kind == NameProto::NBNS && !isResp && !(opcode == 5 || opcode == 8 || opcode == 9)) return "";
    uint32_t qd = m.be16(4), rr = uint32_t(m.be16(6)) + m.be16(8) + m.be16(10);
    if (qd > 32 || rr > 64) return "";
    size_t off = 12;
    std::string nm;
    for (uint32_t i = 0; i < qd; i++) {
        if (!dnsName(m, off, nm) || !m.has(off, 4)) return "";
        off += 4;
    }
    for (uint32_t i = 0; i < rr; i++) {
        if (!dnsName(m, off, nm) || !m.has(off, 10)) return "";
        uint16_t type = m.be16(off);
        uint16_t rdlen = m.be16(off + 8);
        off += 10;
        if (!m.has(off, rdlen)) return "";
        Span rd = m.sub(off, rdlen);
        off += rdlen;
        if (kind != NameProto::NBNS && type == 1 && rdlen == 4 && rd.be32(0) == srcIp)
            return sanitizeHost(nm);
        if (kind == NameProto::NBNS && type == 0x0020) {
            for (size_t e = 0; e + 6 <= rd.n; e += 6) {
                if (rd.be16(e) & 0x8000) continue;               // group name (workgroup)
                if (rd.be32(e + 2) != srcIp) continue;
                uint8_t sfx = 0;
                std::string h = decodeNetbios(nm.substr(0, nm.find('.')), sfx);
                if (sfx == 0x00 || sfx == 0x20) return sanitizeHost(h);
            }
        }
    }
    return "";
}

// ════════════════════════════════════════════════════════════════════════════
//  Layer-2 discovery: PROFINET (0x8892) and LLDP (0x88CC)
// ════════════════════════════════════════════════════════════════════════════
static void handleProfinet(Span f, MacKey srcMac, time_t ts) {
    g_st.profinet++;
    if (!f.has(0, 2)) { g_st.malformed++; return; }
    uint16_t frameId = f.be16(0);

    // DCP Identify response: ServiceID 5, ServiceType 1 (response, success)
    if (frameId == 0xFEFF && f.has(2, 10) && f.u8(2) == 0x05 && (f.u8(3) & 0x87) == 0x01) {
        uint16_t dataLen = f.be16(10);
        if (!f.has(12, dataLen)) { g_st.malformed++; return; }
        Span blk = f.sub(12, dataLen);
        std::string station, typeName, vendDev;
        uint32_t ip = 0;
        size_t off = 0;
        while (blk.has(off, 4)) {
            uint8_t opt = blk.u8(off), sub = blk.u8(off + 1);
            uint16_t blen = blk.be16(off + 2);
            if (!blk.has(off + 4, blen)) break;
            Span v = blk.sub(off + 4, blen);      // response blocks start with BlockInfo(2)
            if (opt == 2 && sub == 2 && v.n > 2) station = cleanStr(v.p + 2, v.n - 2, 240);
            if (opt == 2 && sub == 1 && v.n > 2) typeName = cleanStr(v.p + 2, v.n - 2);
            if (opt == 2 && sub == 3 && v.n >= 6) {
                char b[48];
                snprintf(b, sizeof b, "PN vendor 0x%04X / device 0x%04X", v.be16(2), v.be16(4));
                vendDev = b;
            }
            if (opt == 1 && sub == 2 && v.n >= 14) ip = v.be32(2);
            off += 4u + blen + (blen & 1u);       // blocks are padded to even length
        }
        Device &d = (ip && isUnicastIp(ip)) ? ipDevice(ip, ts) : macDevice(srcMac, ts);
        d.macs[srcMac] |= MAC_L2DISC;
        d.pktsSent++;
        Identity &I = d.id;
        I.sources.insert("PROFINET DCP Identify");
        setIf(I.product, typeName);
        setIf(I.productCode, vendDev);
        setHostname(d, sanitizeHost(station), "PROFINET station name");
        ProtoObs &o = d.protos[Proto::PROFINET];
        o.portEv = Evidence::VALIDATED;
        o.roles |= ROLE_SERVER;
        o.validatedRoles |= ROLE_SERVER;
        o.validMsgs++;
        return;
    }
    // DCP Identify request / Get / Set issued by a controller or engineering tool
    if (frameId == 0xFEFE || frameId == 0xFEFD) {
        Device &d = macDevice(srcMac, ts);
        d.pktsSent++;
        ProtoObs &o = d.protos[Proto::PROFINET];
        o.portEv = Evidence::VALIDATED;
        o.roles |= ROLE_CLIENT;
        o.validatedRoles |= ROLE_CLIENT;
        o.validMsgs++;
        return;
    }
    // Cyclic real-time I/O data (RT class 1/UDP range) - a live I/O participant
    if (frameId >= 0x8000 && frameId <= 0xFBFF) {
        Device &d = macDevice(srcMac, ts);
        d.pktsSent++;
        ProtoObs &o = d.protos[Proto::PROFINET];
        o.portEv = Evidence::VALIDATED;
        o.validatedNoRole = true;
        o.validMsgs++;
        addNote(d, "sends PROFINET cyclic I/O frames");
    }
}

static void handleLldp(Span f, MacKey srcMac, time_t ts) {
    g_st.lldp++;
    std::string sysName, sysDesc;
    uint32_t mgmtIp = 0;
    size_t off = 0;
    while (f.has(off, 2)) {
        uint16_t h = f.be16(off);
        uint8_t type = uint8_t(h >> 9);
        uint16_t len = h & 0x01FF;
        if (!f.has(off + 2, len)) { g_st.malformed++; return; }
        Span v = f.sub(off + 2, len);
        if (type == 0) break;
        if (type == 5) sysName = cleanStr(v.p, v.n, 64);
        if (type == 6) sysDesc = cleanStr(v.p, v.n, 160);
        if (type == 8 && v.n >= 6 && v.u8(0) == 5 && v.u8(1) == 1) mgmtIp = v.be32(2);  // IPv4
        off += 2u + len;
    }
    if (sysName.empty() && sysDesc.empty()) return;
    Device &d = (mgmtIp && isUnicastIp(mgmtIp)) ? ipDevice(mgmtIp, ts) : macDevice(srcMac, ts);
    d.macs[srcMac] |= MAC_L2DISC;
    d.pktsSent++;
    setHostname(d, sanitizeHost(sysName), "LLDP system name");
    if (!sysDesc.empty()) {
        d.id.sources.insert("LLDP");
        setIf(d.id.description, sysDesc);
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Transport dispatch
// ════════════════════════════════════════════════════════════════════════════
struct PortProto { uint16_t port; Proto proto; };
static const PortProto TCP_PORTS[] = {
    {502, Proto::MODBUS}, {44818, Proto::ENIP}, {102, Proto::S7}, {20000, Proto::DNP3},
    {2404, Proto::IEC104}, {789, Proto::CRIMSON}, {48898, Proto::ADS}, {5007, Proto::MELSEC},
    {9600, Proto::FINS},
};
static const PortProto UDP_PORTS[] = {
    {44818, Proto::ENIP}, {2222, Proto::ENIP}, {34964, Proto::PROFINET}, {47808, Proto::BACNET},
    {9600, Proto::FINS}, {20000, Proto::DNP3}, {5007, Proto::MELSEC},
};
template <size_t N>
static bool portProto(const PortProto (&tbl)[N], uint16_t port, Proto &out) {
    for (const auto &e : tbl) if (e.port == port) { out = e.proto; return true; }
    return false;
}

static bool runValidator(Proto proto, Span d, Ctx &c, bool tcp, uint16_t sport, uint16_t dport,
                         bool &cotpOnly) {
    cotpOnly = false;
    switch (proto) {
        case Proto::MODBUS:   return validateModbus(d, c);
        case Proto::ENIP:
            if (!tcp && (sport == 2222 || dport == 2222)) return validateEnipIo(d);
            return validateEnipEncap(d, c, !tcp);
        case Proto::S7:       return validateS7(d, c, cotpOnly);
        case Proto::DNP3:     return validateDnp3(d, c);
        case Proto::IEC104:   return validateIec104(d);
        case Proto::BACNET:   return validateBacnet(d, c);
        case Proto::FINS:     return validateFins(d, c, tcp);
        case Proto::MELSEC:   return validateMelsec(d, c);
        case Proto::ADS:      return validateAds(d, c);
        case Proto::PROFINET: return validatePnioCm(d, c);
        case Proto::CRIMSON:  return false;   // no public spec: port evidence only
    }
    return false;
}

static void handleTransport(bool tcp, Device &src, Device *dst, uint16_t sport, uint16_t dport,
                            uint8_t tcpFlags, Span payload) {
    Proto ps{}, pd{};
    bool hasS = tcp ? portProto(TCP_PORTS, sport, ps) : portProto(UDP_PORTS, sport, ps);
    bool hasD = tcp ? portProto(TCP_PORTS, dport, pd) : portProto(UDP_PORTS, dport, pd);
    if (!hasS && !hasD) return;
    Proto proto = hasD ? pd : ps;
    if (hasS && hasD && ps != pd) proto = (sport < dport) ? ps : pd;   // pick the lower, more specific port

    // Default direction from port placement; refined below by SYN flags and payload.
    Dir dir = Dir::UNKNOWN;
    if (hasS && !hasD) dir = Dir::SRC_IS_SERVER;
    else if (hasD && !hasS) dir = Dir::SRC_IS_CLIENT;
    else if (tcp && (tcpFlags & 0x12) == 0x02) dir = Dir::SRC_IS_CLIENT;   // SYN
    else if (tcp && (tcpFlags & 0x12) == 0x12) dir = Dir::SRC_IS_SERVER;   // SYN-ACK
    uint16_t srvPortS = (dir == Dir::SRC_IS_SERVER) ? sport : 0;
    uint16_t srvPortD = (dir == Dir::SRC_IS_CLIENT) ? dport : 0;

    observe(proto, &src, dst, dir, Evidence::PORT, srvPortS, srvPortD);
    if (payload.n == 0) return;

    Ctx c;
    c.src = &src;
    c.dst = dst;
    c.dir = dir;
    bool cotpOnly = false;
    if (runValidator(proto, payload, c, tcp, sport, dport, cotpOnly)) {
        uint16_t sp = (c.dir == Dir::SRC_IS_SERVER) ? sport : 0;
        uint16_t dp = (c.dir == Dir::SRC_IS_CLIENT) ? dport : 0;
        observe(proto, &src, dst, c.dir, Evidence::VALIDATED, sp, dp);
    } else if (cotpOnly) {
        addNote(src, "ISO-TSAP/COTP on 102 without S7 payload (could be S7 setup or IEC 61850 MMS)");
    }
}

static void handleUdpNames(Device &src, uint32_t srcIp, uint16_t sport, uint16_t dport, Span payload) {
    std::string n;
    if (sport == 5353 || dport == 5353) {
        n = nameFromDns(payload, srcIp, NameProto::MDNS);
        setHostname(src, n, "mDNS");
    } else if (sport == 5355 || dport == 5355) {
        n = nameFromDns(payload, srcIp, NameProto::LLMNR);
        setHostname(src, n, "LLMNR");
    } else if (sport == 137 || dport == 137) {
        n = nameFromDns(payload, srcIp, NameProto::NBNS);
        setHostname(src, n, "NetBIOS-NS");
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Frame processing
// ════════════════════════════════════════════════════════════════════════════
static void processPacket(const struct pcap_pkthdr *hdr, const uint8_t *pkt) {
    g_st.frames++;
    if (hdr->caplen < hdr->len) g_st.truncated++;
    Span fr(pkt, hdr->caplen);
    if (!fr.has(0, 14)) { g_st.malformed++; return; }
    time_t ts = time_t(hdr->ts.tv_sec);
    MacKey dstMac = macKey(pkt), srcMac = macKey(pkt + 6);
    uint16_t etype = fr.be16(12);
    size_t off = 14;

    // Up to 4 stacked 802.1Q / 802.1ad / legacy Q-in-Q tags
    int tags = 0;
    while ((etype == 0x8100 || etype == 0x88A8 || etype == 0x9100) && tags < 4) {
        if (!fr.has(off, 4)) { g_st.malformed++; return; }
        etype = fr.be16(off + 2);
        off += 4;
        tags++;
    }
    if (tags) g_st.vlanTagged++;
    Span l3 = fr.from(off);

    switch (etype) {
        case 0x8892: handleProfinet(l3, srcMac, ts); return;
        case 0x88CC: handleLldp(l3, srcMac, ts); return;
        case 0x86DD: g_st.ipv6++; return;
        case 0x0806: break;
        case 0x0800: break;
        default:     g_st.otherEther++; return;
    }

    // ── ARP ────────────────────────────────────────────────────────────────
    if (etype == 0x0806) {
        g_st.arp++;
        if (!l3.has(0, 28) || l3.be16(0) != 1 || l3.be16(2) != 0x0800 || l3.u8(4) != 6 || l3.u8(5) != 4) {
            g_st.malformed++;
            return;
        }
        uint16_t op = l3.be16(6);
        if (op != 1 && op != 2) { g_st.malformed++; return; }
        MacKey sha = macKey(l3.p + 8);
        uint32_t spa = l3.be32(14);
        if (!isUnicastIp(spa) || !isUnicastMac(sha)) return;     // ARP probes use 0.0.0.0
        // Only trust an ARP mapping when the sender hardware address matches the
        // Ethernet source; a mismatch is relayed, forged or proxied.
        if (sha != srcMac) { g_st.arpMismatch++; return; }
        Device &d = ipDevice(spa, ts);
        d.macs[sha] |= MAC_ARP;
        auto &claimed = g_arpMacToIps[sha];
        if (claimed.size() < 64) claimed.insert(spa);
        d.pktsSent++;
        return;
    }

    // ── IPv4 ───────────────────────────────────────────────────────────────
    g_st.ipv4++;
    if (!l3.has(0, 20)) { g_st.malformed++; return; }
    uint8_t ver = l3.u8(0) >> 4;
    size_t ihl = size_t(l3.u8(0) & 0x0F) * 4;
    if (ver != 4 || ihl < 20 || !l3.has(0, ihl)) { g_st.malformed++; return; }
    size_t totLen = l3.be16(2);
    if (totLen < ihl) { g_st.malformed++; return; }
    bool truncated = false;
    if (totLen > l3.n) {
        if (hdr->caplen >= hdr->len) { g_st.malformed++; return; }   // claims more than the wire carried
        truncated = true;                                            // snaplen cut it: parse what we have
        totLen = l3.n;
    }
    Span ip = l3.sub(0, totLen);                                     // drops Ethernet padding
    uint8_t proto = ip.u8(9);
    uint32_t srcIp = ip.be32(12), dstIp = ip.be32(16);
    uint16_t frag = ip.be16(6);
    if (!isUnicastIp(srcIp)) return;

    Device &src = ipDevice(srcIp, ts);
    src.pktsSent++;
    if (isUnicastMac(srcMac)) {
        src.macs[srcMac] |= MAC_IPSRC;
        auto &ips = g_macToIps[srcMac];
        if (ips.size() < 64) ips.insert(srcIp);
    }

    if ((frag & 0x1FFF) != 0 || (frag & 0x2000) != 0) { g_st.fragments++; return; }

    // Only create a record for the destination if it is a plausible host.
    Device *dst = nullptr;
    bool dstBroadcastLike = !isUnicastIp(dstIp) || !isUnicastMac(dstMac) ||
                            (proto == 17 && (dstIp & 0xFF) == 0xFF);
    if (!dstBroadcastLike) {
        dst = &ipDevice(dstIp, ts);
        dst->pktsRecv++;
    }

    Span l4 = ip.from(ihl);

    if (proto == 6) {
        if (!l4.has(0, 20)) { if (!truncated) g_st.malformed++; return; }
        size_t doff = size_t(l4.u8(12) >> 4) * 4;
        if (doff < 20 || !l4.has(0, doff)) { if (!truncated) g_st.malformed++; return; }
        uint16_t sport = l4.be16(0), dport = l4.be16(2);
        uint8_t flags = l4.u8(13);
        handleTransport(true, src, dst, sport, dport, flags, l4.from(doff));
    } else if (proto == 17) {
        if (!l4.has(0, 8)) { if (!truncated) g_st.malformed++; return; }
        uint16_t sport = l4.be16(0), dport = l4.be16(2);
        size_t ulen = l4.be16(4);
        if (ulen < 8) { g_st.malformed++; return; }
        if (ulen > l4.n) {
            if (!truncated) { g_st.malformed++; return; }
            ulen = l4.n;
        }
        Span payload = l4.sub(8, ulen - 8);
        handleTransport(false, src, dst, sport, dport, 0, payload);
        handleUdpNames(src, srcIp, sport, dport, payload);
    }
}

static void pcapCallback(uint8_t *, const struct pcap_pkthdr *hdr, const uint8_t *pkt) {
    processPacket(hdr, pkt);
}

// ════════════════════════════════════════════════════════════════════════════
//  Post-processing: MAC selection, L2-record merging, classification
// ════════════════════════════════════════════════════════════════════════════
// Where the reported MAC came from, strongest first. An Ethernet source MAC on
// an IP packet is only the last hop, so it is used reluctantly and labelled.
enum class MacSrc { NONE, ARP, L2_DISCOVERY, IP_TRAFFIC };
static const char *macSrcName(MacSrc s) {
    switch (s) {
        case MacSrc::ARP:          return "ARP";
        case MacSrc::L2_DISCOVERY: return "PROFINET/LLDP";
        case MacSrc::IP_TRAFFIC:   return "IP traffic only, unconfirmed";
        default:                   return "";
    }
}
struct MacView { MacKey primary = 0; MacSrc src = MacSrc::NONE; bool viaRouter = false; };
static MacView chooseMac(const Device &d) {
    MacView v;
    if (d.isMacOnly) { v.primary = d.macKeyOnly; v.src = MacSrc::L2_DISCOVERY; return v; }
    std::vector<MacKey> arp, l2, ipsrc;
    for (const auto &[m, f] : d.macs) {
        if (f & MAC_ARP) arp.push_back(m);
        if (f & MAC_L2DISC) l2.push_back(m);
        if (f & MAC_IPSRC) ipsrc.push_back(m);
    }
    // Prefer an ARP-claimed MAC that also sources this IP's traffic; with an IP
    // conflict that is the one actually talking, not just announcing.
    for (MacKey m : arp)
        if (d.macs.at(m) & MAC_IPSRC) { v.primary = m; v.src = MacSrc::ARP; return v; }
    if (!arp.empty()) { v.primary = arp.front(); v.src = MacSrc::ARP; return v; }
    if (!l2.empty())  { v.primary = l2.front(); v.src = MacSrc::L2_DISCOVERY; return v; }
    // Without ARP, accept the frame source MAC only if it never sourced any other
    // IP and never ARP-claimed a different IP (a gateway does both).
    for (MacKey m : ipsrc) {
        auto it = g_macToIps.find(m);
        if (it == g_macToIps.end() || it->second.size() != 1) continue;
        auto ac = g_arpMacToIps.find(m);
        if (ac != g_arpMacToIps.end() && !(ac->second.size() == 1 && *ac->second.begin() == d.ip)) continue;
        v.primary = m;
        v.src = MacSrc::IP_TRAFFIC;
        return v;
    }
    v.viaRouter = !ipsrc.empty();
    return v;
}

static void mergeDevice(Device &into, Device &from) {
    for (auto &[m, f] : from.macs) into.macs[m] |= f;
    for (auto &[p, o] : from.protos) {
        ProtoObs &t = into.protos[p];
        t.portEv = std::max(t.portEv, o.portEv);
        t.roles |= o.roles;
        t.validatedRoles |= o.validatedRoles;
        t.validatedNoRole |= o.validatedNoRole;
        t.validMsgs += o.validMsgs;
        t.serverPorts.insert(o.serverPorts.begin(), o.serverPorts.end());
    }
    if (into.hostname.empty()) { into.hostname = from.hostname; into.hostnameSrc = from.hostnameSrc; }
    Identity &a = into.id, &b = from.id;
    a.sources.insert(b.sources.begin(), b.sources.end());
    setIf(a.vendor, b.vendor); setIf(a.product, b.product); setIf(a.model, b.model);
    setIf(a.deviceType, b.deviceType); setIf(a.productCode, b.productCode);
    setIf(a.revision, b.revision); setIf(a.serial, b.serial);
    setIf(a.orderNumber, b.orderNumber); setIf(a.description, b.description);
    if (a.cipDeviceType < 0) a.cipDeviceType = b.cipDeviceType;
    for (auto &n : from.notes) addNote(into, n);
    if (from.firstSeen && (!into.firstSeen || from.firstSeen < into.firstSeen)) into.firstSeen = from.firstSeen;
    into.lastSeen = std::max(into.lastSeen, from.lastSeen);
    into.pktsSent += from.pktsSent;
    into.pktsRecv += from.pktsRecv;
}

// Fold MAC-only L2 records into the IP record that owns that MAC, when unique.
static void reconcile() {
    std::map<MacKey, std::vector<uint32_t>> owner;
    for (auto &[ip, d] : g_ipDev) {
        MacView v = chooseMac(d);
        if (v.primary) owner[v.primary].push_back(ip);
    }
    for (auto it = g_macDev.begin(); it != g_macDev.end();) {
        auto o = owner.find(it->first);
        if (o != owner.end() && o->second.size() == 1) {
            mergeDevice(g_ipDev[o->second[0]], it->second);
            it = g_macDev.erase(it);
        } else {
            ++it;
        }
    }
    for (auto &[ip, d] : g_ipDev) {
        int arpMacs = 0;
        for (auto &[m, f] : d.macs) if (f & MAC_ARP) arpMacs++;
        if (arpMacs > 1) addNote(d, "multiple MACs claimed this IP via ARP (IP conflict, failover or reassignment)");
        MacView v = chooseMac(d);
        if (v.viaRouter) addNote(d, "no ARP and its frames arrive via a shared/gateway MAC - host may be off-subnet; OUI unknown");
    }
}

static bool hasIcsEvidence(const Device &d) {
    return !d.protos.empty() || !d.id.sources.empty();
}

static std::string classify(const Device &d) {
    bool valServer = false, valClient = false, valAny = false, portOnly = false;
    for (const auto &[p, o] : d.protos) {
        if (o.validatedRoles & ROLE_SERVER) valServer = true;
        if (o.validatedRoles & ROLE_CLIENT) valClient = true;
        if (o.portEv == Evidence::VALIDATED) valAny = true;
        if (o.portEv == Evidence::PORT) portOnly = true;
    }
    bool selfId = false;
    for (const auto &s : d.id.sources)
        if (s != "LLDP") selfId = true;     // LLDP is sent by switches and PCs too
    if (d.id.cipDeviceType == 0x0E) return "PLC (self-reported CIP device type)";
    if (selfId && valServer)        return "ICS device - identity reported by device";
    if (valServer)                  return "ICS server (PLC/RTU/gateway candidate)";
    if (valClient && !valServer)    return "ICS client (HMI/EWS/SCADA candidate)";
    if (valAny)                     return "ICS protocol participant (role undetermined)";
    if (!d.id.sources.empty())      return "Device with discovery info (LLDP), no ICS traffic";
    if (portOnly)                   return "Unconfirmed - ICS port only";
    return "Network host (no ICS evidence)";
}

static std::string protoSummary(const Device &d, bool verbose) {
    std::string out;
    for (const auto &[p, o] : d.protos) {
        if (!out.empty()) out += verbose ? "\n" : "|";
        out += protoName(p);
        std::string role;
        uint8_t r = o.validatedRoles ? o.validatedRoles : o.roles;
        if ((r & ROLE_SERVER) && (r & ROLE_CLIENT)) role = "server+client";
        else if (r & ROLE_SERVER) role = "server";
        else if (r & ROLE_CLIENT) role = "client";
        else role = "peer/unknown";
        out += verbose ? "  " : ":";
        out += role;
        out += verbose ? ", " : ":";
        if (o.portEv == Evidence::VALIDATED)
            out += verbose ? ("validated (" + std::to_string(o.validMsgs) + " msgs)") : "validated";
        else
            out += verbose ? "port only - payload not confirmed" : "port-only";
        if (verbose && !o.serverPorts.empty()) {
            out += ", listens on";
            for (auto port : o.serverPorts) out += " " + std::to_string(port);
        }
    }
    return out;
}

static std::string fmtTime(time_t t, const char *fmt) {
    if (t == 0) return "";
    struct tm tmv{};
    if (!localtime_r(&t, &tmv)) return "?";
    char b[40];
    if (strftime(b, sizeof b, fmt, &tmv) == 0) return "?";
    return b;
}

// ════════════════════════════════════════════════════════════════════════════
//  Output
// ════════════════════════════════════════════════════════════════════════════
struct Row { std::string key; const Device *d; };
static std::vector<Row> allRows() {
    std::vector<Row> rows;
    for (auto &[ip, d] : g_ipDev) rows.push_back({fmtIp(ip), &d});
    for (auto &[m, d] : g_macDev) rows.push_back({"(L2 only) " + fmtMac(m), &d});
    return rows;
}

static void printDevice(const Row &r, int idx) {
    const Device &d = *r.d;
    MacView mv = chooseMac(d);
    printf("  [%d] %s\n", idx, r.key.c_str());
    printf("      Class:     %s\n", classify(d).c_str());
    if (mv.primary) {
        std::string v = lookupOui(mv.primary);
        printf("      MAC:       %s  (%s)  [source: %s]\n", fmtMac(mv.primary).c_str(),
               v.empty() ? "OUI not in table" : v.c_str(), macSrcName(mv.src));
    } else if (mv.viaRouter) {
        printf("      MAC:       unknown (routed)\n");
    }
    if (!d.hostname.empty())
        printf("      Hostname:  %s  [%s]\n", d.hostname.c_str(), d.hostnameSrc.c_str());
    const Identity &I = d.id;
    if (!I.sources.empty()) {
        std::string src;
        for (auto &s : I.sources) src += (src.empty() ? "" : ", ") + s;
        printf("      Identity reported by device [%s]:\n", src.c_str());
        auto line = [](const char *k, const std::string &v) { if (!v.empty()) printf("        %-13s %s\n", k, v.c_str()); };
        line("Vendor:", I.vendor);
        line("Product:", I.product);
        line("Model:", I.model);
        line("Order number:", I.orderNumber);
        line("Device type:", I.deviceType);
        line("Product code:", I.productCode);
        line("Revision:", I.revision);
        line("Serial:", I.serial);
        line("Description:", I.description);
    }
    if (!d.protos.empty()) {
        std::string s = protoSummary(d, true), indent = "\n                 ";
        for (size_t p = 0; (p = s.find('\n', p)) != std::string::npos; p += indent.size())
            s.replace(p, 1, indent);
        printf("      Protocols: %s\n", s.c_str());
    }
    if (!d.peers.empty()) {
        printf("      Peers:     %zu", d.peers.size());
        int n = 0;
        for (uint32_t p : d.peers) { if (n++ == 4) { printf(" ..."); break; } printf(" %s", fmtIp(p).c_str()); }
        printf("\n");
    }
    for (const auto &n : d.notes) printf("      Note:      %s\n", n.c_str());
    printf("      Seen:      %s - %s  |  packets sent %llu, received %llu\n\n",
           fmtTime(d.firstSeen, "%H:%M:%S").c_str(), fmtTime(d.lastSeen, "%H:%M:%S").c_str(),
           (unsigned long long)d.pktsSent, (unsigned long long)d.pktsRecv);
}

static void printResults(bool showAll) {
    auto rows = allRows();
    std::stable_sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        return hasIcsEvidence(*a.d) > hasIcsEvidence(*b.d);
    });
    printf("\n  ── Passive ICS inventory ─────────────────────────────────────────────\n\n");
    int idx = 1, hidden = 0;
    for (const auto &r : rows) {
        if (!showAll && !hasIcsEvidence(*r.d)) { hidden++; continue; }
        printDevice(r, idx++);
    }
    if (idx == 1) printf("  No hosts with ICS evidence observed.\n\n");
    if (hidden) printf("  (%d other hosts with no ICS evidence not shown; use -a to list them, all are in the CSV)\n\n", hidden);

    printf("  ── Capture statistics ────────────────────────────────────────────────\n");
    printf("  frames %llu | IPv4 %llu | ARP %llu | VLAN-tagged %llu | PROFINET %llu | LLDP %llu\n",
           (unsigned long long)g_st.frames, (unsigned long long)g_st.ipv4, (unsigned long long)g_st.arp,
           (unsigned long long)g_st.vlanTagged, (unsigned long long)g_st.profinet, (unsigned long long)g_st.lldp);
    printf("  not analysed: IPv6 %llu, IPv4 fragments %llu, other EtherTypes %llu\n",
           (unsigned long long)g_st.ipv6, (unsigned long long)g_st.fragments, (unsigned long long)g_st.otherEther);
    printf("  malformed frames rejected %llu | frames truncated by snaplen %llu | ARP sender != Ethernet source %llu\n",
           (unsigned long long)g_st.malformed, (unsigned long long)g_st.truncated,
           (unsigned long long)g_st.arpMismatch);
    printf("  OUI source: %s\n\n", g_ouiSource.c_str());
    printf("  Limitations: TCP streams are not reassembled (messages split across\n"
           "  segments are missed); results reflect only traffic visible at this\n"
           "  capture point. 'Identity' fields are what devices reported, not verified.\n\n");
}

// RFC 4180 quoting plus spreadsheet formula neutralisation.
static std::string csv(const std::string &v) {
    std::string s = v;
    if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r'))
        s.insert(s.begin(), '\'');
    bool quote = s.find_first_of(",\"\r\n") != std::string::npos;
    std::string out;
    if (quote) out += '"';
    for (char c : s) { if (c == '"') out += '"'; out += c; }
    if (quote) out += '"';
    return out;
}

static bool saveCsv(const std::string &path) {
    std::ofstream f(path);
    if (!f) { fprintf(stderr, "  Cannot open %s for writing\n", path.c_str()); return false; }
    f << "Key,IP,Primary_MAC,MAC_Source,All_MACs,OUI_Vendor,Classification,Hostname,Hostname_Source,"
         "Identity_Sources,Reported_Vendor,Reported_Product,Reported_Model,Order_Number,Device_Type,"
         "Product_Code,Revision,Serial,Description,Protocols(proto:role:evidence),Peer_Count,"
         "First_Seen,Last_Seen,Packets_Sent,Packets_Received,Notes\n";
    for (const auto &r : allRows()) {
        const Device &d = *r.d;
        MacView mv = chooseMac(d);
        std::string macs, srcs, notes;
        for (auto &[m, fl] : d.macs) {
            (void)fl;
            macs += (macs.empty() ? "" : "|") + fmtMac(m);
        }
        for (auto &s : d.id.sources) srcs += (srcs.empty() ? "" : "|") + s;
        for (auto &n : d.notes) notes += (notes.empty() ? "" : "; ") + n;
        const Identity &I = d.id;
        f << csv(r.key) << ',' << csv(d.isMacOnly ? "" : fmtIp(d.ip)) << ','
          << csv(mv.primary ? fmtMac(mv.primary) : "") << ',' << csv(macSrcName(mv.src)) << ','
          << csv(macs) << ','
          << csv(mv.primary ? lookupOui(mv.primary) : "") << ',' << csv(classify(d)) << ','
          << csv(d.hostname) << ',' << csv(d.hostnameSrc) << ',' << csv(srcs) << ','
          << csv(I.vendor) << ',' << csv(I.product) << ',' << csv(I.model) << ',' << csv(I.orderNumber) << ','
          << csv(I.deviceType) << ',' << csv(I.productCode) << ',' << csv(I.revision) << ','
          << csv(I.serial) << ',' << csv(I.description) << ',' << csv(protoSummary(d, false)) << ','
          << d.peers.size() << ',' << csv(fmtTime(d.firstSeen, "%Y-%m-%d %H:%M:%S")) << ','
          << csv(fmtTime(d.lastSeen, "%Y-%m-%d %H:%M:%S")) << ',' << d.pktsSent << ','
          << d.pktsRecv << ',' << csv(notes) << '\n';
    }
    f.close();
    if (!f) { fprintf(stderr, "  Write to %s failed\n", path.c_str()); return false; }
    printf("  Results saved to: %s\n", path.c_str());
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  main
// ════════════════════════════════════════════════════════════════════════════
static void usage(const char *prog) {
    printf("Usage: %s (-i <iface> | -r <file.pcap>) [options]\n"
           "  -i <iface>          Live capture interface (requires root/CAP_NET_RAW)\n"
           "  -r <file>           Read a pcap/pcapng file instead of capturing\n"
           "  -t <seconds>        Live capture duration (0 = until Ctrl-C, default)\n"
           "  -o <file.csv>       Write the full inventory to CSV\n"
           "  -m <oui file>       IEEE oui.txt or Wireshark 'manuf' file for vendor lookup\n"
           "  -a                  Also list hosts with no ICS evidence on the console\n"
           "  --no-promisc        Do not request promiscuous mode\n"
           "  --allow-unfiltered  Continue if the BPF filter cannot be installed\n\n"
           "Example: sudo %s -i eth1 -t 600 -o inventory.csv\n", prog, prog);
}

static bool parseSeconds(const char *s, int &out) {
    errno = 0;
    char *end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < 0 || v > INT_MAX) return false;
    out = int(v);
    return true;
}

int main(int argc, char *argv[]) {
    std::string iface, readFile, csvOut, ouiFile;
    int duration = 0;
    bool showAll = false, promisc = true, allowUnfiltered = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto need = [&](std::string &dst) { if (i + 1 >= argc) return false; dst = argv[++i]; return true; };
        if (a == "-i") { if (!need(iface)) { usage(argv[0]); return 1; } }
        else if (a == "-r") { if (!need(readFile)) { usage(argv[0]); return 1; } }
        else if (a == "-o") { if (!need(csvOut)) { usage(argv[0]); return 1; } }
        else if (a == "-m") { if (!need(ouiFile)) { usage(argv[0]); return 1; } }
        else if (a == "-t") {
            if (i + 1 >= argc || !parseSeconds(argv[++i], duration)) {
                fprintf(stderr, "Invalid duration (expected a non-negative integer number of seconds)\n");
                return 1;
            }
        }
        else if (a == "-a") showAll = true;
        else if (a == "--no-promisc") promisc = false;
        else if (a == "--allow-unfiltered") allowUnfiltered = true;
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown option: %s\n\n", a.c_str()); usage(argv[0]); return 1; }
    }
    if (iface.empty() == readFile.empty()) { usage(argv[0]); return 1; }
    if (!ouiFile.empty() && !loadOuiFile(ouiFile)) {
        fprintf(stderr, "Could not load OUI entries from %s\n", ouiFile.c_str());
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t *handle = readFile.empty()
        ? pcap_open_live(iface.c_str(), 65535, promisc ? 1 : 0, 100, errbuf)
        : pcap_open_offline(readFile.c_str(), errbuf);
    if (!handle) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        if (readFile.empty()) fprintf(stderr, "  (Are you root / CAP_NET_RAW? Does the interface exist?)\n");
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Link type is not Ethernet (DLT_EN10MB required)\n");
        pcap_close(handle);
        return 1;
    }

    // "vlan" must come last: in BPF it shifts offsets for the terms after it.
    const char *filterExpr = "arp or ip or ip6 or ether proto 0x8892 or ether proto 0x88cc or vlan";
    bool filtered = false;
    struct bpf_program fp{};
    if (pcap_compile(handle, &fp, filterExpr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "BPF compile failed: %s\n", pcap_geterr(handle));
    } else {
        if (pcap_setfilter(handle, &fp) == -1) fprintf(stderr, "BPF install failed: %s\n", pcap_geterr(handle));
        else filtered = true;
        pcap_freecode(&fp);
    }
    if (!filtered && !allowUnfiltered) {
        fprintf(stderr, "Refusing to run without the capture filter (use --allow-unfiltered to override).\n");
        pcap_close(handle);
        return 1;
    }

    g_handle = handle;
    struct sigaction sa{};
    sa.sa_handler = sigHandler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    printf("\n  PLC Passive Observer (no packets are transmitted)\n");
    if (readFile.empty()) {
        printf("  Interface : %s%s\n", iface.c_str(), promisc ? " (promiscuous)" : "");
        printf("  Duration  : %s\n", duration > 0 ? (std::to_string(duration) + " s").c_str() : "until Ctrl-C");
    } else {
        printf("  Reading   : %s\n", readFile.c_str());
    }
    printf("  Filter    : %s\n", filtered ? filterExpr : "NONE (unfiltered)");
    if (!csvOut.empty()) printf("  Output    : %s\n", csvOut.c_str());
    printf("\n");

    auto start = std::chrono::steady_clock::now();
    std::string stopReason = "interrupted by signal";
    bool captureError = false;
    // Live capture: libpcap's read timeout does not fire on Linux when no packets
    // arrive, so a blocking pcap_dispatch() would ignore -t and Ctrl-C on a quiet
    // segment. Read non-blocking and wait with poll() instead.
    int selFd = -1;
    if (readFile.empty()) {
        if (pcap_setnonblock(handle, 1, errbuf) == -1) {
            fprintf(stderr, "Cannot set non-blocking mode: %s\n", errbuf);
            pcap_close(handle);
            return 1;
        }
        selFd = pcap_get_selectable_fd(handle);
    }
    while (g_running) {
        if (readFile.empty()) {
            if (selFd >= 0) {
                struct pollfd pfd{selFd, POLLIN, 0};
                int pr = poll(&pfd, 1, 200);
                if (pr < 0 && errno != EINTR) {
                    stopReason = std::string("poll error: ") + strerror(errno);
                    captureError = true;
                    break;
                }
            } else {
                struct timespec nap{0, 50 * 1000 * 1000};   // no selectable fd: short sleep
                nanosleep(&nap, nullptr);
            }
            if (!g_running) break;
        }
        int rc = pcap_dispatch(handle, 256, pcapCallback, nullptr);
        if (rc == PCAP_ERROR) {
            stopReason = std::string("capture error: ") + pcap_geterr(handle);
            captureError = true;
            break;
        }
        if (rc == PCAP_ERROR_BREAK) break;                       // breakloop from signal handler
        if (!readFile.empty() && rc == 0) { stopReason = "end of capture file"; break; }
        if (duration > 0 && readFile.empty()) {
            auto el = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
            if (el >= duration) { stopReason = "capture duration reached"; break; }
        }
    }
    if (readFile.empty()) {
        struct pcap_stat ps{};
        if (pcap_stats(handle, &ps) == 0 && (ps.ps_drop || ps.ps_ifdrop))
            printf("  WARNING: kernel dropped %u packets, interface dropped %u - inventory may be incomplete\n",
                   ps.ps_drop, ps.ps_ifdrop);
    }
    g_handle = nullptr;
    pcap_close(handle);

    printf("  Stopped: %s\n", stopReason.c_str());
    reconcile();
    printResults(showAll);
    bool csvOk = csvOut.empty() || saveCsv(csvOut);
    return (captureError || !csvOk) ? 2 : 0;
}
