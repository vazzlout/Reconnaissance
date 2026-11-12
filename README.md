# Recon Tool

A modular reconnaissance toolkit for information gathering during security assessments.

## Features

- **Subdomain Enumeration** - Discover subdomains using 15+ sources (crt.sh, DNSDumpster, SecurityTrails, Shodan, Censys, VirusTotal, etc.)
- **Port Scanning** - Identify open ports and services (nmap SYN/Connect/UDP + socket fallback)
- **DNS Enumeration** - Gather DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, zone transfer)
- **HTTP Reconnaissance** - Headers analysis, technology fingerprinting, security headers audit, HTTP methods testing, CDN/WAF detection
- **SSL/TLS Analysis** - Certificate chain validation, CT log monitoring, protocol/cipher enumeration, vulnerability checks (Heartbleed, POODLE, FREAK, Logjam, etc.)
- **Directory/File Enumeration** - Async brute force with smart wordlists, recursive scanning, soft 404 detection, tech-specific wordlists
- **Technology Fingerprinting** - Wappalyzer-style detection (80+ technologies), version detection, confidence scoring, implication resolution
- **Stealth/Evasion** - Token bucket rate limiting, random delays, jitter, user-agent rotation, initial random delay
- **Modular Design** - Run individual modules or all at once
- **Multiple Output Formats** - JSON, CSV, TXT, Rich Table, Rich Tree

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run all modules
python main.py example.com

# Run specific modules
python main.py example.com --subdomain
python main.py example.com --portscan
python main.py example.com --dns
python main.py example.com --http
python main.py example.com --ssl
python main.py example.com --dir
python main.py example.com --tech

# Save output to file
python main.py example.com -o results.json
python main.py example.com -f csv -o results.csv

# Output formats
python main.py example.com -f table
python main.py example.com -f tree

# Custom config
python main.py example.com -c config.yaml

# Stealth mode overrides
python main.py example.com --stealth-rate 5 --stealth-delay-min 2 --stealth-delay-max 10
python main.py example.com --no-stealth
```

## Modules Overview

### Subdomain Enumeration (`--subdomain`)

15+ sources supported:

| Source | API Key | Description |
|--------|---------|-------------|
| **crt.sh** | No | Certificate Transparency logs |
| **DNSDumpster** | No | DNS reconnaissance via web scraping |
| **SecurityTrails** | Yes | SecurityTrails API |
| **Shodan** | Yes | Shodan DNS API |
| **Censys** | Yes | Censys Search API |
| **HackerTarget** | No | HackerTarget API (rate limited) |
| **RapidDNS** | No | RapidDNS.io web scraping |
| **AlienVault OTX** | No | AlienVault Open Threat Exchange |
| **VirusTotal** | Yes | VirusTotal API v3 |
| **Wayback Machine** | No | Internet Archive CDX API |
| **BufferOver** | No | DNS.BufferOver.run |
| **ThreatCrowd** | No | ThreatCrowd API |
| **AnubisDB** | No | AnubisDB (jldc.me) |
| **Riddler** | No | Riddler.io CSV export |
| **Brute Force** | No | Wordlist-based DNS brute force |

**Recursive Enumeration**: Discover subdomains of discovered subdomains
```yaml
subdomain_enum:
  recursive: true
  max_depth: 2
```

### Port Scanning (`--portscan`)

- Nmap SYN/Connect/UDP scans with `-T4` timing
- Socket-based fallback when nmap unavailable
- Configurable port ranges and scan types

### DNS Enumeration (`--dns`)

- Record types: A, AAAA, MX, TXT, NS, CNAME, SOA
- Multiple resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
- Zone transfer (AXFR) attempts

### HTTP Reconnaissance (`--http`)

- **Headers Analysis**: Server, X-Powered-By, Via, X-Cache, CF-Ray, interesting headers
- **Technology Fingerprinting**: 35+ technologies (Web servers, CMS, Frameworks, JS libs, Analytics, WAF/CDN)
- **Security Headers Audit**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP - scoring 0-100
- **HTTP Methods Testing**: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT
- **CDN/WAF Detection**: Cloudflare, Akamai, Fastly, AWS CloudFront, Azure, Incapsula, Sucuri, Imperva, F5, Barracuda, Fortinet
- **Redirect Chain Tracking**

### SSL/TLS Analysis (`--ssl`)

- **Certificate Chain**: Full chain parsing, SANs, OCSP, CRL, key usage, expiry
- **Certificate Transparency**: Query crt.sh, track certs in CT logs
- **Protocol Support**: SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
- **Cipher Suite Enumeration**: All supported ciphers with strength analysis
- **Vulnerability Checks**: Heartbleed, POODLE, FREAK, Logjam, DROWN, ROBOT, SWEET32, CCS Injection
- **Security Features**: OCSP Stapling, Session Tickets, Secure Renegotiation, Compression (CRIME)
- **Scoring & Grading**: Score 0-100, Grade A+/A/B/C/D/F with detailed findings

### Directory/File Enumeration (`--dir`)

- **Async Brute Force**: Configurable concurrency (default 20 threads)
- **Smart Wordlists**: 200+ default paths + tech-specific wordlists (WordPress, Drupal, Laravel, Django, Node.js, Spring, PHP, Python, Ruby, Go, Java, .NET)
- **Extension Fuzzing**: 25+ extensions (.php, .html, .js, .json, .bak, .zip, .sql, etc.)
- **Recursive Scanning**: Configurable depth (default 3)
- **Soft 404 Detection**: Response clustering to filter false positives
- **Tech Detection**: Auto-detect technology from main page for targeted wordlists

### Technology Fingerprinting (`--tech`)

- **Wappalyzer-style Detection**: 80+ built-in fingerprints
- **Multi-vector Analysis**: Headers, Cookies, HTML body, Script sources, Meta tags
- **Version Detection**: Regex patterns for version extraction
- **Confidence Scoring**: 0-100% per technology
- **Implication Resolution**: Auto-detect implied tech (WordPress → PHP + MySQL)
- **Exclusion Resolution**: Handle mutually exclusive technologies
- **Categories**: Web Servers, CDN/WAF, CMS, Frameworks, JS Libraries, Analytics, Languages, Databases, Security

## Stealth/Evasion Features

All modules integrate with the stealth scheduler:

- **Token Bucket Rate Limiting**: Configurable requests/second with burst allowance
- **Random Delays**: Min/max delay between requests with configurable jitter (±30%)
- **Initial Random Delay**: 5-30 seconds before starting
- **User-Agent Rotation**: Per-request UA rotation
- **Request Order Randomization**: Shuffle wordlists and target lists

```bash
# Disable stealth for faster scans
python main.py example.com --no-stealth

# Custom stealth parameters
python main.py example.com --stealth-rate 5 --stealth-delay-min 2 --stealth-delay-max 10 --stealth-initial-min 10 --stealth-initial-max 60
```

## Project Structure

```
recon_tool/
├── main.py                 # Entry point
├── requirements.txt        # Dependencies
├── config.yaml             # Configuration
├── ROADMAP.md              # Development roadmap
├── README.md               # This file
├── modules/
│   ├── __init__.py
│   ├── subdomain_enum.py   # Subdomain enumeration (15+ sources)
│   ├── port_scanner.py     # Port scanning (nmap + socket)
│   ├── dns_enum.py         # DNS enumeration
│   ├── http_recon.py       # HTTP reconnaissance
│   ├── ssl_analyzer.py     # SSL/TLS analysis
│   ├── dir_enum.py         # Directory/file enumeration
│   └── tech_fingerprint.py # Technology fingerprinting
├── utils/
│   ├── __init__.py
│   ├── output.py           # Output formatting (JSON, CSV, TXT, Table, Tree)
│   └── helpers.py          # Helpers + Stealth scheduler
└── wordlists/
    └── subdomains.txt      # ~400 subdomain wordlist
```

## Configuration

Create a `config.yaml` file for custom settings (see `config.yaml` for full example):

```yaml
# Subdomain Enumeration
subdomain_enum:
  sources:
    - crtsh
    - dnsdumpster
    - hackertarget
    - rapiddns
    - alienvault
    - wayback
    - bufferover
    - threatcrowd
    - anubis
    - riddler
    - bruteforce
  api_keys:
    securitytrails: ""
    shodan: ""
    censys_id: ""
    censys_secret: ""
    virustotal: ""
  wordlist: "wordlists/subdomains.txt"
  threads: 50
  timeout: 10
  recursive: false
  max_depth: 2

# Stealth/Evasion
stealth:
  enabled: true
  initial_delay_min: 5.0
  initial_delay_max: 30.0
  request_delay_min: 1.0
  request_delay_max: 5.0
  jitter_factor: 0.3
  rate_limit: 10.0
  burst_allowance: 5
  randomize_order: true
  rotate_user_agent: true

# HTTP Reconnaissance
http_recon:
  timeout: 10
  follow_redirects: true
  test_methods: true
  max_redirects: 10

# SSL/TLS Analyzer
ssl_analyzer:
  port: 443
  timeout: 10
  check_ct_logs: true
  check_vulnerabilities: true
  deep_scan: false

# Directory/File Enumeration
dir_enum:
  timeout: 10
  threads: 20
  recursive: false
  max_depth: 3
  extensions: ['', '.php', '.html', '.js', '.json', '.xml', '.txt', '.bak', '.backup', '.old', '.orig', '.swp', '.tmp', '.temp', '.log', '.sql', '.zip', '.tar.gz', '.tgz', '.rar', '.7z', '.gz', '.bz2', '.xz']
  detect_tech: true
  follow_redirects: true
  status_codes: [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
  exclude_status: [404]

# Technology Fingerprinting
tech_fingerprint:
  timeout: 10
  custom_fingerprints: null

# Port Scanning
port_scan:
  ports: "1-1000,3306,5432,8080,8443"
  scan_type: "syn"
  timeout: 5
  use_nmap: true

# DNS Enumeration
dns_enum:
  record_types: [A, AAAA, MX, TXT, NS, CNAME, SOA]
  resolvers: [8.8.8.8, 1.1.1.1, 9.9.9.9]
  try_zone_transfer: true

# Output
output:
  format: "json"
  file: null

# General
general:
  user_agent: "ReconTool/1.0"
  rate_limit: 100
  proxy: null
```

## API Keys

For sources requiring API keys, set them in `config.yaml` or via environment variables:

```bash
export SECURITYTRAILS_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export VIRUSTOTAL_API_KEY="your_key"
```

## Requirements

```
# Core dependencies
requests>=2.31.0
dnspython>=2.4.0
python-nmap>=0.7.1

# Async support
aiohttp>=3.9.0
asyncio-throttle>=1.0.0

# Utilities
click>=8.1.0
rich>=13.0.0
pyyaml>=6.0.0

# SSL Analysis
pyopenssl>=23.0.0
cryptography>=42.0.0

# Data processing
pandas>=2.1.0
```

## TODO

### Phase 1: Core Web Reconnaissance ✅ COMPLETE
- [x] HTTP Headers Analysis + Tech Fingerprinting
- [x] SSL/TLS Certificate Analysis + CT Monitoring
- [x] Directory/File Brute Force + Smart Wordlists
- [x] Technology Fingerprinting (Wappalyzer-style)
- [x] Stealth/Evasion Framework

### Phase 2: OSINT & Intelligence Gathering 🔄 NEXT
- [ ] Email Harvester (Hunter.io, Clearbit, LinkedIn, GitHub, WHOIS)
- [ ] Employee Enumeration (LinkedIn, company pages, GitHub org members)
- [ ] Document Discovery & Metadata Extraction (PDF, Office docs)
- [ ] GitHub/GitLab Recon (public repos, secrets, contributors)
- [ ] Breach Data Integration (HaveIBeenPwned, DeHashed)
- [ ] Threat Intelligence (URLhaus, PhishTank, AlienVault OTX)

### Phase 3: Vulnerability Reconnaissance
- [ ] CVE Matcher (map service versions to known CVEs)
- [ ] Misconfiguration Detection (S3, Docker, K8s, databases)
- [ ] Nuclei Template Integration
- [ ] Default Credentials Testing

### Phase 4: Cloud & Infrastructure
- [ ] AWS/Azure/GCP Asset Discovery
- [ ] Subdomain Takeover Detection
- [ ] ASN/Netblock Discovery

### Phase 5: Advanced Features
- [ ] HTML/PDF Reports
- [ ] CI/CD Integration
- [ ] Proxy/Tor Support
- [ ] Distributed Scanning
- [ ] Scheduled Scans

### Quality & Packaging
- [ ] Unit Tests (pytest, 80% coverage)
- [ ] Type Hints (mypy compliance)
- [ ] PyPI Package
- [ ] Docker Image
- [ ] Documentation (Sphinx)