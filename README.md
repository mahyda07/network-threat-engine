# Network Threat Detection Engine

A real-time network packet analyzer and threat detection engine built in C++17.

**Internship:** Tynovate Studio 2026 — Track A  
**Author:** Mahida (25F-0795), FAST NUCES CFD Campus

---

## What it does

- Captures network packets from a pcap file
- Parses Ethernet, IP, TCP, and UDP headers
- Tracks all TCP/UDP connections in a flow table
- Displays per-flow stats: packet count, bytes, TCP state

---

## Build Instructions

### Requirements
- Linux or WSL2
- g++ with C++17 support
- libpcap-dev
- CMake 3.16+

### Install dependencies
```bash
sudo apt install -y build-essential cmake libpcap-dev
```

### Build
```bash
mkdir build && cd build
cmake ..
make
```

### Run
```bash
./threat_engine <path-to-file.pcap>
```

### Generate a test pcap (WSL2)
```bash
sudo tcpdump -i lo -w samples/sample.pcap -c 100
# in another terminal:
curl http://127.0.0.1:8080
```

---

## Project Structure
network-threat-engine/

├── src/

│   ├── main.cpp

│   ├── protocol/

│   │   ├── ProtocolParser.hpp

│   │   └── ProtocolParser.cpp

│   └── flow/

│       ├── FlowKey.hpp

│       ├── FlowTable.hpp

│       └── FlowTable.cpp

├── docs/

│   └── architecture.md

├── samples/

└── CMakeLists.txt

---

## Sample Output
=== Network Threat Engine ===

[TCP] 127.0.0.1:54244 → 127.0.0.1:8080 | 74 bytes

[TCP] 127.0.0.1:8080 → 127.0.0.1:54244 | 74 bytes

...

=== Flow Table (6 flows) ===

127.0.0.1:8080 → 127.0.0.1:54244 | TCP | 6 pkts | 1001 bytes | CLOSED

...
