# 🛡️ SentinelNet — Network Intrusion Detection System & Packet Sniffer

[![Language](https://img.shields.io/badge/Language-C11-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-orange.svg)](https://ubuntu.com/)
[![Library](https://img.shields.io/badge/Dependency-libpcap-green.svg)](https://www.tcpdump.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**SentinelNet** is a high-performance, real-time Network Intrusion Detection System (NIDS) and packet analyzer written in pure C using `libpcap`. Inspired by tools like **Wireshark**, **Snort**, and **Suricata**, SentinelNet inspects live network interfaces or offline `.pcap` dumps, parses multi-layer protocols (Ethernet, IPv4, TCP, UDP, ICMP), correlates traffic patterns to detect cyber threats, and streams metrics to both an ANSI-colored console and an interactive web dashboard.

---

## 🏗️ Architecture

```
                                      ┌────────────────────────────────────────┐
                                      │           Network Interface            │
                                      │       (Live Promiscuous / PCAP)        │
                                      └───────────────────┬────────────────────┘
                                                          │
                                                          ▼
                                      ┌────────────────────────────────────────┐
                                      │          Module 1: Capture             │
                                      │     libpcap + Berkeley Packet Filter   │
                                      └───────────────────┬────────────────────┘
                                                          │
                                                          ▼
                                      ┌────────────────────────────────────────┐
                                      │          Module 2: Dissector           │
                                      │     Ethernet ➔ IPv4 ➔ TCP/UDP/ICMP     │
                                      └───────┬────────────────────────┬───────┘
                                              │                        │
                       ┌──────────────────────┴───────┐                │
                       ▼                              ▼                ▼
        ┌────────────────────────────┐  ┌───────────────────────────┐  │
        │    Module 3: Detector      │  │     Module 4: Stats       │  │
        │ • Port scan heuristics     │  │ • Per-protocol counters   │  │
        │ • Brute-force thresholds   │  │ • Unique IP hash-set      │  │
        │ • Payload signatures       │  │                           │  │
        └──────────────┬─────────────┘  └─────────────┬─────────────┘  │
                       │                              │                │
                       └──────────────────────┬───────┘                │
                                              │                        │
                                              ▼                        ▼
                                ┌──────────────────────────────────────────────┐
                                │              Module 5: Logger                │
                                │ • ANSI Colored CLI output                    │
                                │ • logs/alerts.log & logs/stats.log           │
                                │ • /var/sentinelnet/*.json live state sinks   │
                                └──────────────────────┬───────────────────────┘
                                                       │
                                                       ▼
                                ┌──────────────────────────────────────────────┐
                                │             SentinelNet Web UI               │
                                │    PHP + Chart.js Real-time Dashboard        │
                                └──────────────────────────────────────────────┘
```

---

## ✨ Features

- **Multi-Source Packet Capture**:
  - Live promiscuous sniffing on any network interface (`eth0`, `wlan0`, etc.).
  - Offline `.pcap` trace replay for incident investigation and testing.
  - Native **Berkeley Packet Filter (BPF)** support (e.g. `"tcp port 80 or port 443"`).
- **Protocol Dissection (L2 - L4)**:
  - **Layer 2**: Ethernet framing and type validation.
  - **Layer 3**: IPv4 header parsing, IP options handling, network-byte-order conversion.
  - **Layer 4**: TCP (ports, flags, header lengths), UDP (ports, datagram lengths), ICMP.
  - Payload extraction and bounds-checked slice indexing.
- **Rule-Based Threat Detection**:
  - **Port Scan Detection**: Sliding-window tracking of unique destination ports targeted by a single IP.
  - **Brute Force Detection**: High-frequency connection flood identification per host.
  - **Signature Matching**: Inspects packet payloads for attack strings (`/etc/passwd`, `/etc/shadow`, `cmd.exe`, `nmap`, `../`, `SELECT `, `<script`).
- **Telemetry & Metrics**:
  - Open-addressing hash table tracking distinct hosts across the network.
  - Real-time packet distribution (TCP, UDP, ICMP, other).
- **Unified Multi-Sink Logging**:
  - ANSI terminal output for active monitoring.
  - Rotated log files (`logs/alerts.log`, `logs/stats.log`) with size-limit management.
  - Atomic JSON state feeds for external integrations and dashboards.
- **Web Dashboard**:
  - Built-in lightweight PHP/Chart.js dashboard displaying live network bandwidth, protocol breakdowns, and security alerts.

---

## 🔬 Detection Engine Rules

| Threat Type | Mechanism | Default Window & Threshold |
| :--- | :--- | :--- |
| **Port Scanning** | Tracks distinct destination ports hit by a single source IP | **> 15 unique ports** within **5 seconds** |
| **Connection Flood / Brute Force** | Tracks total TCP/UDP connection attempts per source IP | **> 100 connections** within **10 seconds** |
| **Payload Signature Hit** | Substring pattern matching on Layer 4 payload bytes | Triggers immediately upon matching pattern |

### Default Signature Patterns
- **System File Access**: `/etc/passwd`, `/etc/shadow`
- **Reconnaissance & Tools**: `nmap`
- **Web Exploits**: `../` (Path Traversal), `<script` (XSS), `SELECT ` (SQL Injection)
- **Windows Command Execution**: `cmd.exe`

---

## 📦 Project Layout

```
sentinelnet/
├── include/
│   ├── sentinelnet.h        # Shared types, structs, and configurable tunables
│   ├── capture.h            # Module 1: Packet capture abstraction (libpcap)
│   ├── parser.h             # Module 2: Protocol dissector headers
│   ├── detector.h           # Module 3: Threat detection engine interfaces
│   ├── stats.h              # Module 4: Traffic metrics & hash table sets
│   └── logger.h             # Module 5: Multi-sink logging system
├── src/
│   ├── main.c               # Application entry point, CLI args & lifecycle
│   ├── capture.c            # libpcap wrapper, BPF compiler, device enumerator
│   ├── parser.c             # Ethernet, IPv4, TCP, UDP, ICMP dissectors
│   ├── detector.c           # Port scan, brute-force & payload inspection
│   ├── stats.c              # Protocol counters & open-addressing IP set
│   └── logger.c             # Terminal output, file rotation, and JSON sinks
├── web/                     # Full-stack Web Monitoring Dashboard
│   ├── api/                 # Backend JSON REST endpoints
│   │   ├── alerts.php       # Streams real-time alerts to frontend
│   │   ├── stats.php        # Streams traffic statistics
│   │   └── traffic.php      # Streams per-second throughput data
│   ├── assets/              # Dashboard styling and Chart.js integration
│   │   ├── dashboard.js     # Live polling and reactive charts
│   │   └── style.css        # Dark-mode dashboard theme
│   ├── auth.php             # Session security guard
│   ├── index.php            # Main dashboard view
│   ├── login.php            # Authentication page
│   └── logout.php           # Session termination
├── logs/                    # Runtime alerts and statistics directory
│   └── .gitkeep
├── Makefile                 # Optimized C build configuration
├── .gitignore
└── README.md
```

---

## ⚡ Quick Start

### 1. Install Dependencies

On Ubuntu / Debian / WSL:

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev gcc make
```

*(Optional) If using the web dashboard:*
```bash
sudo apt install -y php php-cli
```

### 2. Build

```bash
make
```

To clean previous builds:
```bash
make clean
```

---

## 🚀 Usage

### List Available Interfaces
```bash
./sentinelnet --list
```

### Live Capture on Interface
```bash
# Capture all traffic on eth0 (requires root or CAP_NET_RAW)
sudo ./sentinelnet eth0
```

### Live Capture with Berkeley Packet Filter (BPF)
```bash
# Only capture HTTP and HTTPS traffic
sudo ./sentinelnet eth0 "tcp port 80 or tcp port 443"

# Capture traffic to a specific target host
sudo ./sentinelnet eth0 "host 192.168.1.100"
```

### Replay Saved PCAP Trace
```bash
# Analyze a previously captured trace file (no root required)
./sentinelnet --file sample.pcap
```

---

## 🌐 Web Dashboard Setup

SentinelNet exports real-time JSON metrics directly to `/var/sentinelnet/`. The included web dashboard visualizes this telemetry with live-updating charts.

1. **Prepare the JSON directory**:
   ```bash
   sudo mkdir -p /var/sentinelnet
   sudo chmod 777 /var/sentinelnet
   ```

2. **Start SentinelNet**:
   ```bash
   sudo ./sentinelnet eth0
   ```

3. **Start the Web Dashboard**:
   ```bash
   cd web
   php -S 0.0.0.0:8000
   ```

4. **Access the Dashboard**:
   - Open your browser at `http://localhost:8000`
   - Default credentials (configured in `web/login.php`):
     - **Username**: `admin`
     - **Password**: `sentinel2026`

---

## ⚙️ Configuration & Tuning

Thresholds and buffer sizes can be adjusted directly in `include/sentinelnet.h`:

```c
/* Capture settings */
#define SN_SNAPLEN               65535   /* Full packet capture snapshot */
#define SN_PROMISC                   1   /* Enable promiscuous mode */
#define SN_TIMEOUT_MS             1000   /* Read timeout */

/* Port scan detector thresholds */
#define SN_PORTSCAN_THRESHOLD       15   /* Unique ports required to trigger */
#define SN_PORTSCAN_WINDOW_SEC       5   /* Evaluation window in seconds */

/* Brute force detector thresholds */
#define SN_BRUTEFORCE_THRESHOLD    100   /* Connections required to trigger */
#define SN_BRUTEFORCE_WINDOW_SEC    10   /* Evaluation window in seconds */

/* Log rotation */
#define SN_LOG_MAX_BYTES     (10 * 1024 * 1024)  /* 10 MB maximum log size */
```

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
