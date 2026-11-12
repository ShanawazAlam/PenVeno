# PenVeno: Beginner-Friendly Penetration Testing Suite (v2.0)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](https://isocpp.org/)
[![GTK](https://img.shields.io/badge/GUI-GTKmm%203.0-brightgreen.svg)](https://www.gtkmm.org/)

**PenVeno** is a modern, fast, and beginner-friendly penetration testing toolkit designed for cybersecurity students, ethical hackers, and security researchers. Developed in **C++17** with a responsive **GTKmm 3.0** interface and dark cyber theme, PenVeno brings core penetration testing tools into a unified, non-blocking desktop suite.

---

## 🚀 Key Features

* **🎯 Host & OS Fingerprinting**:
  * Fast Ping Sweep (`-sn`), OS Detection & Service Fingerprinting (`-O -sV`), Aggressive Scan (`-A`), and Hop Discovery (`--traceroute`).
  * Option to treat hosts as online (`-Pn`) and verbose output mode.
* **🔍 Port Scanner & Service Auditor**:
  * Multiple scan scopes: Top 100 fast ports (`-F`), Top 1000 standard ports, Full port range 1–65535 (`-p-`), Core Web & Admin services, or custom port ranges.
  * Configurable service versioning (`-sV`), default NSE scripts (`-sC`), and aggressive timing (`-T4`).
* **🌐 DNS & Web Reconnaissance**:
  * Subdomain brute-force mapping via `dnsmap` (with optional custom wordlist).
  * Comprehensive DNS record queries (`dig ANY`), WHOIS registrar/domain information, and reverse host lookups.
* **💣 Metasploit Payload Generator (`msfvenom`)**:
  * Cross-platform payload presets: **Windows** (x86/x64), **Linux** (x86/x64), **macOS** (x64/ARM64 Apple Silicon), **Android** (APK), **iOS**, **PHP**, **Python**, and **Bash**.
  * **Network Interface Auto-Discovery**: Automatically enumerates local network interfaces (`eth0`, `wlan0`, `tun0` VPN) to set `LHOST` without manual IP lookups.
  * Built-in encoding options (`x86/shikata_ga_nai`, `cmd/powershell_base64`, `x64/zutto_dekiru`) with custom iteration count and native file-save picker.
* **🔤 Custom Wordlist Generator (`crunch`)**:
  * Minimum/maximum word length configuration with built-in presets (Numeric, Lowercase, Uppercase, Alphanumeric, Special characters, or Custom charset).
  * Output file selector with integrated path handling.
* **🛡️ Hash Analyzer & Cryptographic Tools**:
  * Instant **Hash Identifier**: Identifies hashes (MD5, SHA-1, SHA-256, SHA-512, NTLM, Bcrypt, Linux shadow hashes) with corresponding **Hashcat** mode and **John the Ripper** format references.
  * Real-time **Cryptographic Generator**: Instant MD5, SHA-1, SHA-256, and SHA-512 calculation for any plain text.
* **💻 Integrated Real-Time Console**:
  * Live asynchronous output streaming directly inside the GUI — **no terminal freezing or blocking popups**.
  * Active process management: **Stop / Abort** button to kill running scans, animated progress spinner, Copy to Clipboard, and **Export Scan Report** (.txt).
* **🔒 Hardened Security Architecture**:
  * Safe argument-vector execution (`execvp`) — **eliminates shell injection / command injection vulnerabilities**.
  * Strict input sanitization and boundary validation on all fields.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/ShanawazAlam/PenVeno.git
cd PenVeno
```

### 2. Install Dependencies (Ubuntu / Debian / Kali Linux)
```bash
sudo apt-get update
sudo apt-get install -y build-essential libgtkmm-3.0-dev libssl-dev nmap metasploit-framework crunch dnsmap whois dnsutils
```

### 3. Compile the Program
You can easily build PenVeno using the provided `Makefile`:
```bash
make
```
Or manually using `g++`:
```bash
g++ -std=c++17 -Wall -Wextra -O2 -o PenVeno PenVeno.c++ `pkg-config gtkmm-3.0 openssl --cflags --libs`
```

### 4. Run PenVeno
```bash
./PenVeno
```
Or via make:
```bash
make run
```

---

## 🖥️ User Interface Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ PenVeno 2.0 | Penetration Testing Suite      [ IDLE ]  [ ⏹ Stop Process ] │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ 🧭 NAVIGATION   │ Target Host / IP: [ 192.168.1.100       ]                 │
│                 ├───────────────────────────────────────────────────────────┤
│ 🎯 Host & OS    │ Discovery Profile:                                        │
│ 🔍 Port Scanner │ [ 2. OS Detection & Version (-O -sV) ▾ ]                  │
│ 🌐 DNS Recon    │ [x] Verbose Output (-v)    [x] Treat host as online (-Pn) │
│ 💣 MSF Payload  │                                                           │
│ 🔤 Wordlist     │ [  ▶  Launch Host Discovery  ]                            │
│ 🛡️ Hash Tools   ├───────────────────────────────────────────────────────────┤
│                 │ Live Output Terminal & Logs:                              │
│                 │ ┌───────────────────────────────────────────────────────┐ │
│                 │ │ [▶] Starting task: Host & OS Discovery                │ │
│                 │ │ Starting Nmap 7.94 ( https://nmap.org )               │ │
│                 │ │ Nmap scan report for target (192.168.1.100)           │ │
│                 │ │ PORT   STATE SERVICE VERSION                          │ │
│                 │ │ 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu             │ │
│                 │ │ 80/tcp open  http    Apache httpd 2.4.52              │ │
│                 │ │ [✓] Task finished: Host & OS Discovery                │ │
│                 │ └───────────────────────────────────────────────────────┘ │
│                 │ [ Clear ] [ Copy All ] [ Export Report ] [x] Auto-Scroll  │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

---

## ⚠️ Disclaimer & Ethical Use

PenVeno is developed strictly for **authorized educational, penetration testing, and security auditing purposes**. Only use this tool against systems and networks that you own or have explicit written permission to test. Unauthorized access or scanning against targets without authorization is illegal.

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewFeature`)
3. Commit your Changes (`git commit -m "Add NewFeature"`)
4. Push to the Branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## 👤 Author
* **Shanawaz Alam** — [GitHub Profile](https://github.com/ShanawazAlam)
