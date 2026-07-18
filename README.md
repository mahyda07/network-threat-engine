# Network Threat Detection Engine

A real-time network packet analyzer and threat detection system built 
in C++17 as part of the Tynovate Studio 2026 Internship — Track A.

**Author:** Mahida (25F-0795) — FAST NUCES CFD Campus  
**Internship:** Tynovate Studio 2026  
**Track:** A — C++ Systems Engineering  

---

## What This Project Does

This engine captures network traffic, breaks down every packet layer 
by layer, groups packets into conversations (flows), detects suspicious 
patterns, and logs alerts to a database — all in real time with a live 
terminal dashboard.

In simple terms: it watches your network and raises an alarm when 
something looks like an attack.

---

## The Five-Layer Pipeline
Raw Packets (pcap file / live interface)
│
▼
┌─────────────────────┐
│   Capture Layer     │  libpcap reads packets one by one
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Protocol Layer    │  Peels Ethernet → IP → TCP/UDP
│   ProtocolParser    │  Extracts IPs, ports, TCP flags
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Flow Layer        │  Groups packets into conversations
│   FlowTable         │  Tracks state, bytes, packet count
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Detection Layer   │  Port scan + SYN flood detection
│   ThreatDetector    │  Fires alerts when thresholds hit
└────────┬────────────┘
│
▼
┌─────────────────────┐
│   Delivery Layer    │  SQLite logging + JSON export
│   + Dashboard       │  Live ncurses terminal UI
└─────────────────────┘

---

## Features

### Week 1 — Capture Layer
- libpcap reads packets from pcap files
- Prints raw packet info (timestamp, length, hex)
- CMake build system with documented dependencies

### Week 2 — Protocol Parsing + Flow Tracking
- Parses Ethernet, IP, TCP, UDP headers from raw bytes
- Extracts source/destination IPs and ports
- Reads TCP flags: SYN, ACK, FIN
- Flow Table groups packets by 5-tuple into conversations
- TCP state machine: SYN_SENT → ESTABLISHED → CLOSING → CLOSED

### Week 3 — Threat Detection + SQLite Logging
- **Port Scan Detection** — alerts when one IP contacts 15+ unique ports
- **SYN Flood Detection** — alerts when 20+ SYNs sent with no handshake
- All alerts saved permanently to SQLite database (`alerts.db`)
- Alerts queryable via `sqlite3` CLI

### Week 4 — Dashboard + JSON Export
- Live ncurses terminal dashboard showing:
  - Packet count and flow count in real time
  - Progress bar
  - Recent packets feed
  - Active flows
  - Alert feed in red
- JSON export of all alerts to `alerts.json`
- Dashboard stays open until keypress

---

## Sample Output

### Terminal Dashboard
+==================================================+
|   Network Threat Engine - Live View              |
+==================================================+
|  Packets : 52       Flows : 52                   |
+--------------------------------------------------+
|  [====================] 52%                      |
+==================================================+
| RECENT PACKETS                                   |
+--------------------------------------------------+
|  TCP 127.0.0.1:59928 -> 127.0.0.1:83            |
|  TCP 127.0.0.1:83 -> 127.0.0.1:59928            |
+==================================================+
| ALERTS                                           |
+--------------------------------------------------+
|  [13:31:52] PORT SCAN from 127.0.0.1             |
|  [13:31:52] SYN FLOOD from 127.0.0.1             |
+==================================================+
|  Press any key to exit                           |
+==================================================+

### SQLite Alert Log
1|PORT SCAN|127.0.0.1|contacted 15 unique ports|2026-07-13 23:04:51
2|SYN FLOOD|127.0.0.1|20 SYNs with 0 completed handshakes|2026-07-13 23:04:51

### JSON Export
```json
{
  "alerts": [
    {
      "id": 1,
      "type": "PORT SCAN",
      "ip": "127.0.0.1",
      "detail": "contacted 15 unique ports",
      "timestamp": "2026-07-13 23:04:51"
    }
  ]
}
```

---

## Project Structure
network-threat-engine/
├── src/
│   ├── main.cpp                      ← entry point, ties everything together
│   ├── protocol/
│   │   ├── ProtocolParser.hpp        ← packet header structs
│   │   └── ProtocolParser.cpp        ← parsing logic (Ethernet/IP/TCP/UDP)
│   ├── flow/
│   │   ├── FlowKey.hpp               ← 5-tuple definition + hash
│   │   ├── FlowTable.hpp             ← flow record + table class
│   │   └── FlowTable.cpp             ← update() and printSummary()
│   ├── detection/
│   │   ├── ThreatDetector.hpp        ← detector class definition
│   │   └── ThreatDetector.cpp        ← port scan + SYN flood logic
│   ├── storage/
│   │   ├── AlertLogger.hpp/cpp       ← SQLite alert persistence
│   │   └── JsonExporter.hpp/cpp      ← JSON file export
│   └── ui/
│       ├── Dashboard.hpp             ← dashboard class definition
│       └── Dashboard.cpp             ← ncurses rendering logic
├── docs/
│   └── architecture.md              ← system architecture document
├── samples/
│   └── portscan.pcap                ← test traffic capture
├── CMakeLists.txt                   ← build configuration
└── README.md                        ← this file

---

## Tech Stack

| Technology | Purpose |
|---|---|
| C++17 | Core language |
| libpcap | Packet capture from pcap files |
| std::unordered_map | O(1) flow table lookup |
| std::mutex | Thread-safe flow table access |
| SQLite3 | Persistent alert storage |
| ncurses | Live terminal dashboard |
| CMake | Build system |
| Git + GitHub | Version control |

---

## Build Instructions

### Requirements
- Linux or WSL2
- g++ with C++17 support (g++ 11+)
- CMake 3.16+

### Install Dependencies
```bash
sudo apt install -y build-essential cmake libpcap-dev \
                    libsqlite3-dev libncurses-dev
```

### Build
```bash
mkdir build && cd build
cmake ..
make
```

### Generate Test Traffic (WSL2)
```bash
# Terminal 1 — capture traffic
sudo tcpdump -i lo -w samples/portscan.pcap -c 200

# Terminal 2 — simulate port scan
for port in 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95; do
    curl -s --connect-timeout 1 http://127.0.0.1:$port &
done
wait
```

### Run
```bash
./threat_engine ../samples/portscan.pcap
```

### Query Alerts from Database
```bash
sqlite3 alerts.db "SELECT * FROM alerts;"
```

---

## Known Constraints

**WSL2 Live Capture:** WSL2 does not support raw socket access to the 
host Windows network interface. Live capture via `pcap_open_live()` is 
not possible in this environment. All testing uses pcap files generated 
with `tcpdump` on the loopback interface — the code is identical for 
both modes, only the open call changes.

---

## What I Learned

- How network packets are structured in layers (Ethernet → IP → TCP)
- How to parse raw bytes into meaningful data using C++ structs
- How TCP handshakes work (SYN → SYN/ACK → ACK)
- How to detect attack patterns from traffic statistics
- How to use SQLite from C++ with prepared statements
- How to build terminal UIs with ncurses
- How real security tools like Wireshark and Snort work under the hood
