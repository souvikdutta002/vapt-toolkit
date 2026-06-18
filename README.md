# 🛡️ VAPT Toolkit

> **Vulnerability Assessment and Penetration Testing Framework**  
> Built with Python | Internship Project — Codec Technologies × AICTE National Internship Portal

---

## 📌 Overview

**VAPT Toolkit** is a modular, command-line penetration testing framework built entirely in Python. It automates common vulnerability assessment tasks performed during ethical hacking engagements — from port scanning and banner grabbing to web application testing and structured report generation.

This project was developed as part of a cybersecurity internship to demonstrate real-world VAPT skills including reconnaissance, vulnerability mapping, exploitation testing, and documentation — all within authorized, simulated environments.

---

## ⚙️ Features

| Module | Description |
|---|---|
| 🔍 **Port Scanner** | Multi-threaded TCP port scanning with service detection |
| 🏷️ **Banner Grabber** | Grabs service banners for OS/software fingerprinting |
| 🧨 **Vulnerability Checker** | Maps open ports to known CVEs and CVSS scores |
| 🌐 **Web App Tester** | Tests for OWASP Top 10: SQLi, XSS, path traversal, open redirect, missing headers |
| 📄 **Report Generator** | Outputs structured reports in TXT and JSON format |

---

## 🛠️ Tools & Technologies

- **Language:** Python 3.8+
- **Libraries:** `socket`, `threading`, `urllib`, `json`, `ssl` *(Standard Library only)*
- **Concepts:** OWASP Top 10, CVE/CVSS, TCP/IP, HTTP security headers, ethical hacking methodology
- **Comparable tools:** Nmap, Nessus, Burp Suite, Metasploit *(this toolkit implements similar concepts at a foundational level)*

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- A terminal (Linux/macOS recommended; works on Windows too)

### Installation

```bash
git clone https://github.com/souvikdutta002/vapt-toolkit.git
cd vapt-toolkit
```

No external dependencies required. All modules use Python's standard library.


This runs a simulated VAPT assessment and generates sample reports in `reports/`.

---

## 📖 Usage

```bash
python vapt_toolkit.py [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `--target` / `-t` | Target IP or hostname |
| `--url` / `-u` | Target URL for web app testing |
| `--ports` / `-p` | Port range (default: `1-1024`) |
| `--scan` | Run port scan |
| `--banner` | Grab service banners |
| `--vuln` | Run vulnerability check |
| `--web` | Run web application tests |
| `--full` | Run complete assessment |
| `--report` / `-r` | Output path for report file |
| `--output-format` | `txt` or `json` (default: `txt`) |

### Examples

```bash
# Port scan only
python vapt_toolkit.py --target 192.168.1.10 --scan

# Full assessment against a lab VM
python vapt_toolkit.py --target 192.168.1.10 --url http://192.168.1.10 --full

# Web-only test with JSON report
python vapt_toolkit.py --url http://testphp.vulnweb.com --web --output-format json

# Custom port range + banner grab
python vapt_toolkit.py --target 10.0.0.5 --ports 1-65535 --scan --banner
```

---

## 📂 Project Structure

```
vapt-toolkit/
│
├── vapt_toolkit.py         # Main entry point
├── requirements.txt
│
├── modules/
│   ├── scanner.py          # Multi-threaded port scanner
│   ├── banner_grabber.py   # Service banner fingerprinting
│   ├── vuln_checker.py     # CVE-mapped vulnerability assessment
│   ├── web_tester.py       # OWASP web app vulnerability tests
│   ├── reporter.py         # TXT/JSON report generation
│   └── utils.py            # Shared utilities and logging
│
├── reports/                # Generated reports (auto-created)
└── logs/                   # Assessment logs (auto-created)
```

---

## 📋 Sample Report Output

```
======================================================================
       VAPT TOOLKIT - ASSESSMENT REPORT
======================================================================
  Target   : 192.168.1.100 (Lab VM)
  Date     : 2026-06-17 10:45:00
======================================================================

[ PORT SCAN RESULTS ]
  [OPEN] Port 21   - ftp
  [OPEN] Port 22   - ssh
  [OPEN] Port 80   - http
  [OPEN] Port 445  - microsoft-ds

[ VULNERABILITY ASSESSMENT ]
  [CRITICAL] Port 445 (SMB) - SMB EternalBlue Risk
    CVE    : CVE-2017-0144
    CVSS   : 9.3
    Details: SMB port exposed. EternalBlue targets this (WannaCry).
    Fix    : Apply MS17-010 patch. Disable SMBv1.

  [HIGH] Port 21 (FTP) - Anonymous FTP Login
    CVE    : CVE-1999-0497 | CVSS: 7.5
    Fix    : Disable anonymous FTP access.
```

---

## ⚠️ Disclaimer

> This tool is developed **strictly for educational and authorized testing purposes**.  
> Only run this toolkit against systems you **own** or have **explicit written permission** to test.  
> Unauthorized use against real systems is illegal and unethical.  
> The author and contributors hold no liability for misuse.

---

## 🧠 Skills Demonstrated

- **Vulnerability Scanning** — Port enumeration, service detection, CVE mapping
- **Penetration Testing Concepts** — OWASP Top 10, exploitation techniques (conceptual & simulated)
- **Python Development** — Multi-threaded sockets, HTTP clients, modular architecture
- **Ethical Hacking** — Responsible disclosure mindset, authorized testing only
- **Security Documentation** — Structured reporting with severity scoring (CVSS)

---

## 👤 Author [Souvik Dutta]

<h2 align="center">✨ Thank You for Visiting My Profile ✨</h2>

<p align="center">
I truly appreciate you taking the time to explore my GitHub profile.<br>
I'm constantly learning and building projects in <b>Cybersecurity, Ethical Hacking, and Software Development</b>.
</p>

<p align="center">
⭐ Consider giving a <b>Star</b> to the repositories you like <br>
🍴 Feel free to <b>Fork</b> and explore the code <br>
🤝 Let's connect and collaborate
</p>

<p align="center">
<img src="https://img.shields.io/badge/Focus-Cybersecurity-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Learning-Ethical%20Hacking-green?style=for-the-badge">
<img src="https://img.shields.io/badge/Goal-Penetration_Testing-red?style=for-the-badge">
</p>

<p align="center">
<i>*Built for cybersecurity education. Always hack ethically.* 🛡️
</i>
</p>

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
