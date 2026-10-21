# PLC Passive Observer

A passive Ethernet traffic observer that builds an inventory of industrial devices. It can capture from an interface or analyze an existing PCAP. It never transmits packets.

## Requirements

- Linux or another platform with libpcap development headers, a C++17 compiler, and Make
- Live capture privileges appropriate to your system (often root or packet-capture capabilities); offline PCAP reading needs no capture privileges
- An Ethernet capture (`DLT_EN10MB`)

On Debian or Ubuntu, install the dependencies with `sudo apt-get install g++ make libpcap-dev`.

## Build and run

```bash
make
sudo ./plc_passive_observer -i eth0 -t 300 -o results.csv
./plc_passive_observer -r capture.pcap -o results.csv
make test        # unit tests
make asan-test   # same tests under AddressSanitizer + UBSan
```

Use `-t 0` or omit `-t` to capture until Ctrl-C. Use only one of `-i` or `-r`. The `-t` option applies to live capture, not PCAP timestamps. Other options:

| Option | Meaning |
|---|---|
| `-m <file>` | Full IEEE `oui.txt` or Wireshark `manuf` file for vendor lookup (the built-in table covers only industrial vendors) |
| `-a` | Also list hosts with no industrial evidence on the console (the CSV always has every host) |
| `--no-promisc` | Do not request promiscuous mode |
| `--allow-unfiltered` | Continue if the BPF capture filter cannot be installed (by default this is fatal) |

## What it detects

| Protocol | Validation | Identity extracted when visible |
|---|---|---|
| Modbus/TCP | MBAP header, length, function code; several ADUs per segment | 43/14 Read Device Identification (vendor, product code, revision, model) |
| EtherNet/IP | Little-endian encapsulation header, length, options; class 0/1 I/O on UDP 2222 | ListIdentity reply over UDP or TCP (vendor ID, CIP device type, product code, revision, serial, product name) |
| PROFINET | DCP frames, cyclic RT frames, DCE/RPC on UDP 34964 | DCP Identify reply (station name, type, vendor/device ID, IP) |
| S7comm / S7comm-plus | TPKT + COTP + 0x32/0x72 PDU (COTP alone is not counted, since IEC 61850 MMS shares port 102) | SZL 0x0011 order number, SZL 0x001C names |
| DNP3 | Link header with CRC check; DIR bit gives master/outstation | Outstation address |
| IEC 60870-5-104 | APCI framing, I/S/U format rules | |
| BACnet/IP | BVLC type, function and length | I-Am (device instance, vendor ID) |
| Omron FINS | UDP and FINS/TCP framing, ICF rules | 05 01 Controller Data Read (model, version) |
| MELSEC MC/SLMP | 3E binary frame, declared length | |
| Beckhoff ADS | AMS/TCP + AMS header, command, length | ReadDeviceInfo (name, version) |
| Red Lion Crimson | Port 789 only (no public specification) | |
| LLDP | TLV parsing | System name, system description (often includes the order number) |
| mDNS, LLMNR, NetBIOS-NS | DNS-format parser with compression limits | Hostname, only when the record's address equals the sender's IP |

## Reading results

Each host shows a **classification**, and each protocol shows the host's **role** (server or client) and the **evidence level**:

- **port only** — traffic used the protocol's usual port, but no message passed validation. This is not proof that the service runs.
- **validated** — at least one structurally valid message was seen.

Classifications never claim more than the evidence supports. "PLC" is used only when the device itself reports CIP device type 0x0E. Hosts that serve an industrial protocol are "ICS server (PLC/RTU/gateway candidate)", and hosts that only initiate connections are "ICS client (HMI/EWS/SCADA candidate)". Identity fields are what the device reported about itself; they are not verified.

**MAC addresses** carry their source:

- `ARP` — an ARP packet whose sender address matches the Ethernet source. ARP packets where these differ are ignored and counted.
- `PROFINET/LLDP` — a layer-2 discovery frame sent by the device.
- `IP traffic only, unconfirmed` — the Ethernet source of the host's IP packets. It is used only if that MAC never sent traffic for any other IP and never claimed another IP via ARP; a gateway MAC fails these tests and is never assigned to the hosts behind it.

Hosts seen only behind a gateway show `MAC: unknown (routed)`. PROFINET devices without an IP appear as `(L2 only)` records and are merged into the matching IP record when one is found. Two MACs claiming the same IP through ARP are flagged in the notes.

The CSV contains every host with these fields plus first/last seen times and packet counts. Text from the network is restricted to printable characters, and fields that start with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets do not run them as formulas.

## Limitations

Payload parsing is best effort. It does not reassemble TCP streams (a message split across segments is missed) or IPv4 fragments, decrypt traffic, or analyze IPv6 (IPv6 frames are counted). Results reflect only traffic visible at the capture point; use a SPAN/mirror port or a tap for wider visibility. The program warns if the kernel or interface dropped packets during a live capture. These limitations are also printed at the end of every run.

## Safety and scope

Only monitor networks where you have authorization. Passive packet capture can still include sensitive information. Review CSV data before sharing it. The program opens live capture in promiscuous mode (unless `--no-promisc` is given) but does not transmit packets itself.
