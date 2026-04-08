<div align="center">

# 🐾 Gravehound
### Automated OSINT Recon Tool | Digging Up Buried Secrets

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](#)

A powerful, modular OSINT reconnaissance tool designed specifically for bug bounty hunters, and security researchers.  
Powered by **real free APIs**: AlienVault OTX, URLScan.io, Internet Archive, ThreatFox, Shodan, SecurityTrails and more. 🔍

---
```text
   ██████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
  ██╔════╝ ██╔══██╗██╔══██╗██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
  ██║  ███╗██████╔╝███████║██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
  ██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
  ╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
```
---

</div>

## Table of Contents
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Optional API Keys (Turbocharge your scans)](#-optional-api-keys--environmental-variables)
- [Output Formats](#-output-formats)
- [Project Architecture](#%EF%B8%8F-project-architecture)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## Features

Gravehound runs 16 parallel modules to extract every drop of public intelligence on a target.

| Module | Description | Data Sources / Libraries |
|--------|------------|-------------------------|
|  **DNS Lookup** | A, AAAA, MX, NS, TXT, CNAME, SOA records. | `dnspython` |
|  **WHOIS** | Domain registration, registrar, dates, nameservers, status. | `python-whois` |
|  **Subdomains** | Discovers hidden subdomains via active brute-forcing and passive certificate transparency logs. | `dnspython`, `crt.sh`, SecurityTrails API |
|  **Port Scanner** | Lightning fast TCP connect scanner for the Top 100 most common vulnerable ports. | `socket` (stdlib) |
|  **HTTP Headers** | Security header analysis with severity ratings (HSTS, CSP, Clickjacking, MIME-sniffing). | `httpx` |
|  **SSL/TLS** | Certificate details, issuer, SANs, expiry dates, cipher suites, and protocol versions. | `ssl`, `socket` |
|  **Tech Detection** | Fingerprints frameworks, CMS, CDNs, and analytics via HTTP response headers. | `httpx` |
|  **Geolocation** | Finds the physical location, ISP, and ASN for the target IP address. | `ip-api.com` |
|  **Email Harvest** | Discovers employee and corporate emails via web scraping and public databases. | Custom scraper, Hunter.io API |
|  **Wayback Machine** | Searches the Internet Archive for historical snapshots and hidden paths. | `archive.org` CDX API |
|  **Wayback Secrets** | Scans historical `.env`, `.json`, and `.sql` file archives for leaked API keys (AWS, Google, Stripe). | `archive.org` CDX API |
|  **DOM Fingerprint** | Bypasses WAFs via Headless Chromium to detect hidden JavaScript frontend frameworks. | `playwright` |
|  **Dependency Analyzer**| Parses client-side scripts to identify outdated libraries with known CVEs (e.g. ancient jQuery). | `httpx`, regex |
|  **Threat Intel** | Cross-references the domain against global threat intelligence feeds. | AlienVault OTX, URLScan.io, ThreatFox, HackerTarget |
|  **Shodan / VT** | Queries the biggest cybersecurity databases for vulnerabilities and malware reputation. | Shodan, VirusTotal, AbuseIPDB |
|  **Ghost Assets** | Detects dangling DNS records and subdomain takeover vulnerabilities across 31 providers. | `httpx`, DNS resolution |

---

## Quick Start

### 1. Requirements
- **Python 3.10+**
- Works on **Windows**, **macOS**, and **Linux**

### 2. Installation
The fastest way to get started is to clone the repository and set up a virtual environment.

```bash
# Clone the repository
git clone https://github.com/WIzbisy/gravehound.git
cd gravehound

# Create a virtual environment (Recommended)
python -m venv venv

# Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install the required dependencies
pip install -r requirements.txt
```

---

## Usage Examples

Gravehound is built on top of `click` for a clean, intuitive command-line interface.

### Running a Full Scan
Run all 16 modules against a target domain.
```bash
python -m gravehound scan example.com
```

### Targeted Scans
Only care about subdomains and open ports? Use the `--modules` (or `-m`) flag.
```bash
python -m gravehound scan example.com -m subdomains,ports,dns
```

### Generating Beautiful Reports
Gravehound generates interactive HTML reports that are perfect for delivering to clients or bug bounty programs.
```bash
# Output results to an HTML file
python -m gravehound scan example.com --output report.html

# Output results to machine-readable JSON (useful for CI/CD or jq parsing)
python -m gravehound scan example.com --output results.json
```

### Help Menu
View all available commands and modules.
```bash
python -m gravehound --help
python -m gravehound modules
```

---

## Optional API Keys / Environmental Variables

Gravehound performs highly effective reconnaissance **out-of-the-box with zero configuration.**
However, you can turbocharge the modules by providing API keys for premium (but free-tier) services. 

Gravehound uses `python-dotenv` to automatically load keys. Create a `.env` file in the root directory like this:

```env
# ─── Threat Intelligence ──────────────────────────────────────────
# Enhances the port scanner and checks for known CVEs
SHODAN_API_KEY=your_shodan_key_here

# Checks the target against 70+ antivirus engines
VIRUSTOTAL_API_KEY=your_vt_key_here

# Checks if the target IP has been reported for malicious activity
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# ─── Recon Enhancements ─────────────────────────────────────────
# Pulls from Hunter's massive database of corporate emails
HUNTER_API_KEY=your_hunter_key_here

# Pulls thousands of historical subdomains from DNS history
SECURITYTRAILS_API_KEY=your_securitytrails_key_here
```

**Where to get free keys:**
- [Shodan](https://account.shodan.io/register) (Free 100 queries/month)
- [VirusTotal](https://www.virustotal.com/gui/join-us) (Free 500 queries/day)
- [AbuseIPDB](https://www.abuseipdb.com/register) (Free 1000 queries/day)
- [Hunter.io](https://hunter.io) (Free 50 searches/month)
- [SecurityTrails](https://securitytrails.com/app/signup) (Free 50 queries/month)

---

## Output Formats

1. **Terminal (Rich)**: Beautiful, color-coded tables, progress bars, and panels rendered natively in your terminal using the `rich` library.
2. **HTML Report**: A stunning, self-contained, dark-themed HTML report. It parses the data into clean tables with security score widgets.
3. **JSON**: A complete data dump for building automation pipelines.

---

## Project Architecture

If you want to contribute or build your own modules, here is the architecture:

```text
gravehound/                      ← repo root
├── gravehound/
│   ├── cli.py               # CLI entry point (Click)
│   ├── scanner.py           # Orchestrator that runs the modules
│   ├── config.py            # Global configuration & constants
│   ├── modules/
│   │   ├── dns_lookup.py    # DNS records module
│   │   ├── whois_lookup.py  # WHOIS data module
│   │   ├── subdomains.py    # Subdomain discovery (crt.sh & SecurityTrails)
│   │   ├── port_scanner.py  # Top 100 ports scanner
│   │   ├── http_headers.py  # Security headers analyzer
│   │   ├── ssl_info.py      # SSL/TLS cert evaluator
│   │   ├── tech_detect.py   # Tech fingerprinting
│   │   ├── geo_lookup.py    # IP geolocation
│   │   ├── email_harvest.py # Email discovery (Scraping & Hunter.io)
│   │   ├── wayback.py       # Wayback Machine API
│   │   ├── wayback_secrets.py # Historical API Key detection
│   │   ├── dom_fingerprint.py # Headless browser framework detection
│   │   ├── dependency_chain.py# Frontend vulnerable libs check
│   │   ├── threat_intel.py  # AlienVault OTX, URLScan, ThreatFox
│   │   ├── shodan_vt.py     # Shodan, VirusTotal, AbuseIPDB
│   │   └── ghost_assets.py  # Subdomain takeover scanner
│   └── reporting/
│       ├── console.py       # Terminal rendering logic (Rich)
│       ├── json_report.py   # JSON export logic
│       └── html_report.py   # HTML template and rendering
├── requirements.txt         # Project dependencies
├── .env                     # (You create this) API Keys
├── .gitignore               # Ignored files for git
├── setup.py                 # Package setup and installation
├── CONTRIBUTING.md          # Guide for contributors
├── LICENSE                  # MIT License
└── README.md                # Project documentation
```

## 🤝 Contributing
We welcome contributions! Please see the `CONTRIBUTING.md` file for guidelines on how to add new modules, fix bugs, or improve documentation.

## ⚖️ Disclaimer

> **⚠️ Gravehound is intended for authorized security testing and educational purposes only.**
>
> You must only scan targets that you own or have explicit written permission to test (e.g., Bug Bounty programs). Unauthorized scanning of infrastructure may be illegal in your jurisdiction. The authors and maintainers are not responsible for any misuse of this tool.

## 📄 License
This project is licensed under the [MIT License](LICENSE).
