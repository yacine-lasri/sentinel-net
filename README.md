# 🛡️ SentinelNet — Network Intrusion Detection System & Packet Sniffer

[![Language](https://img.shields.io/badge/Language-C11-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-orange.svg)](https://ubuntu.com/)
[![Library](https://img.shields.io/badge/Dependency-libpcap-green.svg)](https://www.tcpdump.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**SentinelNet** is a lightweight, educational Network Intrusion Detection System (NIDS) and packet analyzer written in pure C using `libpcap`. Inspired by foundational security tools like **Wireshark** and **Snort**, SentinelNet inspects live network interfaces or offline `.pcap` trace dumps, parses multi-layer protocols (Ethernet, IPv4, TCP, UDP, ICMP), correlates traffic patterns to detect network threats, and streams metrics to both an ANSI-colored console and an interactive web dashboard.

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
        │ • Connection flood checks  │  │ • Unique IP hash-set      │  │
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
  - **Connection Flood Detection**: High-frequency packet/connection volume tracking per host.
  - **Signature Matching**: Inspects packet payloads for known attack strings (`/etc/passwd`, `/etc/shadow`, `cmd.exe`, `nmap`, `../`, `SELECT `, `<script`).
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
| **Connection Flood** | Tracks total TCP/UDP packet/connection attempts per source IP | **> 100 connections** within **10 seconds** |
| **Payload Signature Hit** | Substring pattern matching on Layer 4 payload bytes | Triggers immediately upon matching pattern |

> [!NOTE]
> **Clarification on "Connection Flood" vs. "Brute Force"**: The detector increments a per-IP counter on every incoming TCP/UDP packet within a 10-second window. It measures raw connection frequency rather than application-layer authentication failures (e.g., repeated HTTP 401s, failed SSH handshakes, or SMTP rejections). It is therefore an L4 connection-flood detector rather than a service-level credential brute-force analyzer.

### Default Signature Patterns
- **System File Access**: `/etc/passwd`, `/etc/shadow`
- **Reconnaissance & Tools**: `nmap`
- **Web Exploits**: `../` (Path Traversal), `<script` (XSS), `SELECT ` (SQL Injection)
- **Windows Command Execution**: `cmd.exe`

> [!WARNING]
> **False-Positive Noise with Bare `SELECT `**: The default signature `"SELECT "` is an unanchored ASCII substring match across raw payload bytes. Because it lacks protocol dissection or SQL context awareness, it fires on any packet containing that sequence of characters — including legitimate database queries, web forms, documentation, source code, or email bodies.

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
│   ├── detector.c           # Port scan, connection flood & payload inspection
│   ├── stats.c              # Protocol counters & open-addressing IP set
│   └── logger.c             # Terminal output, file rotation, and JSON sinks
├── web/                     # Web Monitoring Dashboard
│   ├── api/                 # Backend JSON REST endpoints
│   │   ├── alerts.php       # Streams real-time alerts to frontend
│   │   ├── stats.php        # Streams traffic statistics
│   │   └── traffic.php      # Streams per-second throughput data
│   ├── assets/              # Dashboard styling and Chart.js integration
│   │   ├── dashboard.js     # Live polling and reactive charts
│   │   └── style.css        # Dark-mode dashboard theme
│   ├── auth.php             # Session security guard
│   ├── index.php            # Main dashboard view
│   ├── login.php            # Secure authentication page
│   └── logout.php           # Session termination
├── logs/                    # Runtime alerts and statistics directory
│   └── .gitkeep
├── Makefile                 # C build configuration
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

SentinelNet exports real-time JSON metrics to `/var/sentinelnet/`. The included web dashboard visualizes this telemetry.

### 1. Prepare Directory & Group Permissions

Avoid permissive `chmod 777`. Create a dedicated system group for SentinelNet and grant read/write access only to authorized service accounts:

```bash
# Create dedicated group and add your user
sudo groupadd -f sentinelnet
sudo usermod -aG sentinelnet $USER

# If running behind an external web server like Nginx/Apache, also add its user:
sudo usermod -aG sentinelnet www-data 2>/dev/null || true

# Create directory with restricted group permissions (750)
sudo mkdir -p /var/sentinelnet
sudo chown root:sentinelnet /var/sentinelnet
sudo chmod 750 /var/sentinelnet
```

### 2. Start SentinelNet Engine

```bash
sudo ./sentinelnet eth0
```

### 3. Start the Web Dashboard Securely

Never hardcode credentials or expose the PHP development server to the public network (`0.0.0.0`). Set the password via environment variables and bind strictly to loopback (`127.0.0.1`):

```bash
cd web

# Set your credentials via environment variables
export SENTINEL_ADMIN_USER="admin"
export SENTINEL_ADMIN_PASS="choose_a_strong_password"

# Launch PHP server bound exclusively to localhost
php -S 127.0.0.1:8000
```

### 4. Access the Dashboard
- Open your browser at `http://127.0.0.1:8000`
- Log in with the credentials defined in your `SENTINEL_ADMIN_USER` and `SENTINEL_ADMIN_PASS` variables.
- *Note:* If `SENTINEL_ADMIN_PASS` is not set, login is locked out by default to prevent unauthorized access.

---

## ⚙️ Configuration & Tuning

Thresholds and buffer sizes can be adjusted in `include/sentinelnet.h`:

```c
/* Capture settings */
#define SN_SNAPLEN               65535   /* Full packet capture snapshot */
#define SN_PROMISC                   1   /* Enable promiscuous mode */
#define SN_TIMEOUT_MS             1000   /* Read timeout */

/* Port scan detector thresholds */
#define SN_PORTSCAN_THRESHOLD       15   /* Unique ports required to trigger */
#define SN_PORTSCAN_WINDOW_SEC       5   /* Evaluation window in seconds */

/* Connection flood detector thresholds */
#define SN_BRUTEFORCE_THRESHOLD    100   /* Connections required to trigger */
#define SN_BRUTEFORCE_WINDOW_SEC    10   /* Evaluation window in seconds */

/* Log rotation */
#define SN_LOG_MAX_BYTES     (10 * 1024 * 1024)  /* 10 MB maximum log size */
```

---

## 🧠 Known Architectural Limitations (Engineering Deep Dive)

Understanding the design boundaries of an intrusion detection system is critical for technical evaluation and systems interviews:

### 1. Lack of TCP Stream Reassembly
- **Limitation**: Packets are inspected individually (`parser_parse` processes one datagram at a time). The engine lacks a stateful TCP reassembly stack (such as Snort's stream5 or Suricata's stream engine).
- **Security Impact**: An attacker can evade all payload signatures by fragmenting the payload across multiple TCP segments (e.g. transmitting `"SEL"` in packet 1 and `"ECT "` in packet 2, or sending one character per packet). Because SentinelNet does not reconstruct the stream before pattern matching, split payloads bypass detection entirely.

### 2. IPv4 Only (No IPv6 Support)
- **Limitation**: The protocol dissector in `src/parser.c` explicitly tests for `ether_type == htons(ETHERTYPE_IP)`. 
- **Security Impact**: Any traffic transmitted over IPv6 (`ETHERTYPE_IPV6`) is ignored and dropped by the parser, leaving an entire protocol family unmonitored.

### 3. Naive Substring Matching vs. Deep Content Inspection
- **Limitation**: Signature matching in `src/detector.c` executes a linear `memcmp` against raw payload bytes. It does not perform:
  - Case normalization (`select` vs `SELECT`).
  - Decoding (URL percent-decoding, base64, hex, unicode).
  - Regular expressions or multi-pattern matching algorithms (e.g. Aho-Corasick or Hyperscan).
- **Security Impact**: Attackers can easily bypass signatures via casing (`sElEcT`), URL encoding (`%53%45%4c%45%43%54`), or whitespace variation (`SELECT/**/`). Furthermore, linear byte-by-byte scanning on every packet scales poorly as pattern counts grow.

### 4. Untuned Static Detection Thresholds
- **Limitation**: The port scan (15 ports / 5 seconds) and connection flood (100 packets / 10 seconds) thresholds are hardcoded heuristic guesses.
- **Trade-off**: In high-throughput production environments, legitimate parallel applications (e.g., web crawlers, BitTorrent, or microservices) easily exceed 100 packets in 10 seconds, generating high volumes of false alerts. Conversely, slow and stealthy reconnaissance (`nmap -T1` or scanning one port per minute) remains invisible to the sliding window.

### 5. Web Dashboard Security (Unencrypted Transport & Shared Auth)
- **Limitation**: The dashboard relies on PHP's built-in development server over plaintext HTTP without TLS/HTTPS.
- **Security Impact**: Telemetry, sensitive network indicators, and session cookies are transmitted unencrypted on the local wire. Furthermore, the dashboard utilizes a single shared administrator session rather than multi-user role-based access control (RBAC), multi-factor authentication (MFA), or salted hash database storage (e.g., bcrypt/Argon2).

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
