#define main scanner_main
#include "plc_passive_observer.cpp"
#undef main
#include <cassert>
#include <array>

// Link-only libpcap stand-ins: these tests exercise packet parsing without capture.
extern "C" {
pcap_t *pcap_open_live(const char *,int,int,int,char *) { return nullptr; }
pcap_t *pcap_open_offline(const char *,char *) { return nullptr; }
int pcap_datalink(pcap_t *) { return 1; }
int pcap_compile(pcap_t *,bpf_program *,const char *,int,unsigned int) { return -1; }
int pcap_setfilter(pcap_t *,bpf_program *) { return -1; }
void pcap_freecode(bpf_program *) {}
const char *pcap_geterr(pcap_t *) { return ""; }
int pcap_dispatch(pcap_t *,int,void (*)(unsigned char *,const pcap_pkthdr *,const unsigned char *),unsigned char *) { return 0; }
void pcap_close(pcap_t *) {}
}
int main() {
    std::array<uint8_t, 62> frame{};
    frame[6]=0x02; frame[7]=0xaa; frame[8]=0xbb; frame[9]=0xcc; frame[10]=0xdd; frame[11]=0xee;
    frame[12]=0x08; frame[13]=0x00;
    frame[14]=0x45; frame[16]=0; frame[17]=40; frame[23]=6;
    frame[26]=10; frame[27]=0; frame[28]=0; frame[29]=1;
    frame[30]=10; frame[31]=0; frame[32]=0; frame[33]=2;
    frame[34]=0xc0; frame[35]=0x00; frame[36]=0x01; frame[37]=0xf6; // client -> 502
    frame[46]=0x50;
    pcap_pkthdr h{}; h.caplen=54; h.ts.tv_sec=1;
    processPacket(&h,frame.data());
    auto &client=g_devices.at("10.0.0.1");
    assert(client.protocols.empty() && client.ports.empty());
    assert(client.clientProtocols.count(ICSProto::MODBUS_TCP)==1);
    assert(client.ouiVendor.empty()); // gateway Ethernet MAC cannot identify IP owner
    frame[46]=0xf0; // invalid TCP data offset: should be ignored
    h.ts.tv_sec=2;
    processPacket(&h,frame.data());
    assert(client.packetCount==2 && client.protocols.empty());
    frame[46]=0x50; frame[34]=0x01; frame[35]=0xf6; frame[36]=0xc0; frame[37]=0x00;
    h.ts.tv_sec=3;
    processPacket(&h,frame.data());
    assert(client.protocols.count(ICSProto::MODBUS_TCP)==1);
    assert(client.ports.count(502)==1);
    frame[20]=0x20; // non-initial IPv4 fragment
    h.ts.tv_sec=4;
    processPacket(&h,frame.data());
    assert(client.packetCount==3);
    uint8_t enip[24]{}; enip[0]=0x63;
    assert(isENIP(enip,24));
    enip[2]=1; assert(!isENIP(enip,24));
    assert(csvField("=x,\"y") == "\"'=x,\"\"y\"");
}
