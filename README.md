# Open Source IoC Analyzer 🔍🛡️

**A unified threat intelligence platform for analyzing Indicators of Compromise (IoCs)**  
*Analyze Hashes, Domains, IPs, URLs & Files with 15+ threat intelligence feeds and YARA rules*

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open Source](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

![Demo Banner](https://via.placeholder.com/800x200.png?text=Open+Source+IoC+Analyzer+Demo+GIF+Here)

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
