# Network Threat Detection Engine — Architecture Document

**Author:** Mahida (25F-0795)  
**Track:** A — Real-Time Network Packet Analyzer  
**Institution:** FAST NUCES CFD Campus  
**Internship:** Tynovate Studio 2026  

---

## 1. System Overview

The Network Threat Detection Engine is a C++17 system that captures network 
traffic, parses packets at the protocol level, tracks TCP/UDP connections in 
a flow table, and will detect threats such as port scans and SYN floods in 
later stages.

The system is built in four layers:
- **Capture Layer** — reads packets from a network interface or pcap file
- **Protocol Layer** — parses Ethernet, IP, TCP, and UDP headers
- **Flow Layer** — groups packets into conversations and tracks state
- **Detection Layer** — (Week 3) identifies threats from flow patterns





---

## 2. Pipeline

```
Raw Packets (pcap file / live interface)
         │
         ▼
┌─────────────────┐
│  Capture Layer  │  libpcap reads packets one by one
│  (libpcap)      │  
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Protocol Layer  │  Peels Ethernet → IP → TCP/UDP headers
│ ProtocolParser  │  Extracts IPs, ports, flags
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Flow Layer    │  Groups packets into conversations
│   FlowTable     │  Tracks packet count, bytes, TCP state
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Detection Layer │  (Week 3) Port scan, SYN flood detection
│ ThreatDetector  │  Logs alerts to SQLite
└─────────────────┘
```




---

## 3. Components

### 3.1 Capture Layer
- Uses **libpcap** to read packets from a `.pcap` file
- In production would use `pcap_open_live()` for live capture
- WSL2 limitation: live capture not supported, pcap files used instead
- Each packet is passed to a callback function `onPacket()`

### 3.2 Protocol Parser (ProtocolParser.hpp / .cpp)
- Reads raw bytes and casts them to structs using `reinterpret_cast`
- Parses three layers per packet:
  - **Ethernet** (14 bytes): source/destination MAC, EtherType
  - **IP** (20 bytes): source/destination IP, protocol type
  - **TCP/UDP**: source/destination ports, TCP flags (SYN/ACK/FIN)
- Handles network byte order using `ntohs()` and `ntohl()`
- Returns a `ParsedPacket` struct with all extracted fields

### 3.3 Flow Table (FlowTable.hpp / .cpp)
- Uses `std::unordered_map` with a custom hash for O(1) lookup
- Identifies flows by 5-tuple: srcIP, dstIP, srcPort, dstPort, protocol
- Tracks per-flow: packet count, byte count, first/last seen timestamp
- Implements TCP state machine: SYN_SENT → ESTABLISHED → CLOSING → CLOSED
- Thread-safe using `std::mutex` with `std::lock_guard`





---

## 4. Technology Choices

| Technology | Why |
|---|---|
| C++17 | Required by internship, supports modern features like structured bindings |
| libpcap | Industry standard for packet capture, works with pcap files in WSL2 |
| std::unordered_map | O(1) average lookup for flow tracking at high packet rates |
| std::mutex | Simple thread safety for the flow table |
| CMake | Standard C++ build system, easy dependency management |

---

## 5. Known Constraints

- **WSL2 limitation:** WSL2 does not support raw socket access to the host 
  Windows network interface. Live capture is not possible in this environment.
  Mitigation: pcap files generated with `tcpdump` on the loopback interface 
  are used for all testing and demonstration.

- **Single threaded:** Current implementation processes packets sequentially.
  Week 3 will introduce a multi-threaded pipeline separating capture, parsing,
  and detection into concurrent threads.

---

## 6. Week 3 Plan

- Add `ThreatDetector` class with port scan and SYN flood detection
- Log alerts to SQLite database
- Add EWMA statistical profiling per IP
- Introduce producer-consumer threading model





