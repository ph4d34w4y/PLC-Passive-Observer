# PLC Passive Observer

A passive Ethernet traffic observer that records industrial protocol hints and potential PLC devices. It can capture from an interface or analyze an existing PCAP. It does not send discovery packets.

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
make test
```

Use `-t 0` or omit `-t` to capture until Ctrl-C. Use only one of `-i` or `-r`. The `-t` option applies to live capture, not PCAP timestamps.

## Reading results

Results list observed source IPs, verified ARP MAC mappings when available, industrial protocol hints, source service ports, and separate client traffic. An IP seen contacting an industrial service is not automatically a PLC. Source-port hints are not proof that a service is running, and the small built-in OUI table is incomplete. An Ethernet source MAC seen across a router is deliberately not assigned to the IP host. PROFINET frames without an IP appear under a MAC-based key and may also have a separate IP record.

The CSV contains observed service ports, client protocols, and limited evidence labels. Payload parsing is best effort: it does not reassemble TCP streams or IPv4 fragments, decrypt traffic, or support IPv6 and every industrial protocol variant. DNS question names are not attributed as hostnames. PCAP analysis uses the same BPF filter as live capture.

## Safety and scope

Only monitor networks where you have authorization. Passive packet capture can still include sensitive information. Review CSV data before sharing it. The program opens live capture in promiscuous mode but does not transmit packets itself.
