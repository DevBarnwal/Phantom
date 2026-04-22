<div align="center">

# 👻 Phantom

**Network Intelligence & Threat Monitor**

[![Download](https://img.shields.io/github/v/release/DevBarnwal/phantom?label=Download&style=for-the-badge&color=6e40c9)](https://github.com/DevBarnwal/phantom/releases/latest)
[![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=for-the-badge)](https://github.com/DevBarnwal/phantom/releases)
[![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)](LICENSE)

*Silently watching your network — real-time packet capture, GeoIP intelligence, and threat detection.*

---

[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Security](#security-detection) · [Export](#export--reports) · [Download](#download)

</div>

---

## Overview

Phantom is a professional network analysis tool built with Python and Scapy. It captures live network traffic, identifies protocols, geolocates IP addresses, detects security threats, and generates full HTML dashboard reports — all from a clean dark-themed desktop GUI.

---

## Features

### 📡 Live Packet Capture
- Real-time capture from any network interface
- Protocol detection — TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP
- BPF filter support for focused capture sessions
- Multi-threaded — GUI stays responsive under heavy traffic

### 🎨 Visual Interface
- Color-coded rows per protocol
- Live pie + bar charts updating every second
- Search bar — filter by IP, protocol, keyword, or country in real time
- Column sorting — click any header
- Double-click any packet for full layer-by-layer breakdown with hex dump

### 🌍 GeoIP Intelligence
- Flag + country + city column next to every IP
- Hover tooltip showing country, city, region, ISP/org, ASN, coordinates
- In-memory cache — each IP looked up only once
- Powered by MaxMind GeoLite2 (local database, no internet required)

### 🛡️ Threat Detection
- **Port scan detector** — alerts when one IP hits 15+ ports in 10 seconds
- **ARP spoof detector** — alerts when an IP changes its MAC address
- Dedicated Alerts tab with severity color coding
- Flashing tab + sound notification on detection
- Export all alerts to CSV

### 📊 Export & Reports
- **PCAP** — open in Wireshark or tcpdump
- **CSV** — with full GeoIP columns (country, city, ISP, ASN, lat/lon)
- **JSON** — structured with metadata and export timestamp
- **HTML Dashboard Report** — self-contained file with interactive charts, stats cards, alerts table, and searchable packet table

---

## Project Structure

```
phantom/
├── main.py               # Entry point
├── gui.py                # GUI — all visual components
├── packet_sniffer.py     # Capture engine (Scapy + threading)
├── packet_analyzer.py    # Protocol identification
├── threat_detector.py    # Port scan + ARP spoof detection
├── geo_lookup.py         # GeoIP lookup with caching
├── exporter.py           # PCAP, CSV, JSON export
├── report_generator.py   # HTML dashboard report
├── config.py             # App-wide constants
├── phantom.spec          # PyInstaller build config
├── requirements.txt      # Dependencies
└── README.md
```

---

## Installation

### Requirements
- Python 3.10 or higher
- Root / Administrator privileges (required for packet capture)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/DevBarnwal/phantom.git
cd phantom

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download GeoIP database (free)
# → https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# → Download GeoLite2-City (.mmdb format)
# → Place GeoLite2-City.mmdb in the project root
```

---

## Usage

```bash
# macOS / Linux
sudo .venv/bin/python main.py

# Windows (run terminal as Administrator)
python main.py
```

### Workflow
1. Select a **network interface** from the dropdown
2. Optionally set a **protocol filter**
3. Click **Start Capture**
4. Monitor live traffic in the packet table
5. Switch to the **🛡️ Alerts** tab to watch for threats
6. Click **Export ▾** to save data or generate an HTML report

### Packet Table Columns

| Column | Description |
|--------|-------------|
| TIME | Capture timestamp |
| SRC | Source IP address |
| DST | Destination IP address |
| GEO | Flag + country + city of source IP |
| PROTO | Protocol (color-coded) |
| LEN | Packet size in bytes |
| INFO | Protocol-specific detail |

---

## Security Detection

### Port Scan
Fires when a single source IP connects to **15+ distinct ports within 10 seconds**.

```python
# Tunable in threat_detector.py
PORT_SCAN_THRESHOLD  = 15    # distinct ports
PORT_SCAN_WINDOW_SEC = 10    # seconds
```

**Test it:**
```bash
sudo nmap -sS -p 1-200 <router-ip>
```

### ARP Spoofing
Fires when an IP address is seen using a **different MAC address** than previously recorded — a classic sign of ARP poisoning / MITM attacks.

**Test it:**
```bash
sudo python3 -c "
from scapy.all import *
send(ARP(op=2, psrc='192.168.1.1', hwsrc='aa:bb:cc:dd:ee:ff'))
send(ARP(op=2, psrc='192.168.1.1', hwsrc='11:22:33:44:55:66'))
"
```

---

## Export & Reports

| Format | Contents |
|--------|----------|
| PCAP | Raw packets for Wireshark |
| CSV | All fields + 14 GeoIP columns per row |
| JSON | Structured data with export metadata |
| HTML | Full dashboard — charts, stats, alerts, packet table |

The HTML report is a **single self-contained file** that works offline in any browser.

---

## Download

| Platform | Download | Requirements |
|----------|----------|--------------|
| 🍎 macOS | [Phantom-macOS.zip](https://github.com/DevBarnwal/phantom/releases/latest) | Run with `sudo` |
| 🪟 Windows | [Phantom-Windows.zip](https://github.com/DevBarnwal/phantom/releases/latest) | Install [Npcap](https://npcap.com) · Run as Administrator |
| 🐧 Linux | [Phantom-Linux.tar.gz](https://github.com/DevBarnwal/phantom/releases/latest) | `sudo apt install libpcap-dev` · Run with `sudo` |

### macOS
```bash
unzip Phantom-macOS.zip
sudo ./Phantom.app/Contents/MacOS/Phantom
```

### Windows
```
1. Extract Phantom-Windows.zip
2. Install Npcap from https://npcap.com
3. Right-click Phantom.exe → Run as Administrator
```

### Linux
```bash
tar -xzf Phantom-Linux.tar.gz
sudo ./Phantom/Phantom
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `scapy` | Packet capture and analysis |
| `matplotlib` | Live charts embedded in GUI |
| `geoip2` | GeoIP country / city / ISP lookup |

---

## Roadmap

- [ ] Bandwidth graph — live packets/sec over time
- [ ] Top talkers leaderboard
- [ ] DNS tunneling detection
- [ ] Multi-interface capture
- [ ] REST API for external tool integration

---

## Legal

Phantom is provided for **educational and authorized security analysis only**.
Only monitor networks you own or have explicit permission to analyze.
Unauthorized network monitoring may be illegal in your jurisdiction.

---

<div align="center">
Built with 👻 Python · Scapy · Tkinter · matplotlib
</div>