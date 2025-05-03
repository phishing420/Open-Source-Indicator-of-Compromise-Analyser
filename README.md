# Open Source IoC Analyser 🔍🛡️

**A unified threat intelligence platform for analyzing Indicators of Compromise (IoCs)**  
*Analyze Hashes, Domains, IPs, URLs & Files with 15+ threat intelligence feeds and YARA rules*

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open Source](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

## Features ✨

- **Multi-IoC Analysis**  
  Supports hashes (MD5/SHA1/SHA256), domains, IP addresses, URLs, and file uploads
- **Integrated Threat Intelligence**  
  - VirusTotal | AbuseIPDB | URLScan.io | ThreatFox (abuse.ch)  
  - Malware Bazaar (abuse.ch) | Hybrid Analysis (via VirusTotal)
- **YARA Rule Scanning**  
  30+ pre-configured rules for detecting malware patterns
- **Interactive CLI**  
  Typewriter effect and color-coded risk assessments
- **Caching System**  
  Local cache for repeated domain lookups

## Installation 🛠️

    # Clone repository
    git clone https://github.com/yourusername/open-source-ioc-analyzer.git
    cd open-source-ioc-analyzer         
    # Install dependencies
    pip install -r requirements.txt
    # Create YARA rules directory
    mkdir yara_rules

**Configuration 🔑**
Obtain API keys:

**VirusTotal** --> https://www.virustotal.com/gui/my-apikey
**AbuseIPDB** --> https://www.abuseipdb.com/account/api
**URLScan.io** --> https://urlscan.io/user/profile/
**Abuse.ch** --> https://urlhaus.abuse.ch/api/

**Usage 🚀**

    python index.py
    
**Main Menu Options:**

    1. Hash Analysis          # Analyze malware hashes
    2. Domain Analysis        # Full domain reputation check
    3. IP Address Analysis    # GeoIP + threat scoring
    4. File Upload            # YARA + VirusTotal scan
    5. URL Analysis           # Phishing/suspicious URL check
    6. Exit

**YARA Rules 🕵️♂️**
Our pre-configured rules detect:

Common malware families (AgentTesla, RemcosRAT, Formbook)

Obfuscation techniques (Base64, XOR loops, PowerShell encoding)

Suspicious behaviors (process hollowing, AMSI bypass)

**To update rules:**

Add new .yar files to /yara_rules

Re-run file analysis (Option 4)
