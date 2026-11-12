# Recon Tool

A modular reconnaissance toolkit for information gathering during security assessments.

## Features

- **Subdomain Enumeration** - Discover subdomains using 15+ sources
- **Port Scanning** - Identify open ports and services
- **DNS Enumeration** - Gather DNS records (A, AAAA, MX, TXT, NS, CNAME, etc.)
- **Modular Design** - Run individual modules or all at once
- **Multiple Output Formats** - JSON, CSV, TXT, Table, Tree

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

# Save output to file
python main.py example.com -o results.json
python main.py example.com -f csv -o results.csv

# Output formats
python main.py example.com -f table
python main.py example.com -f tree

# Custom config
python main.py example.com -c config.yaml
```

## Subdomain Enumeration Sources

The tool supports 15+ subdomain enumeration sources:

| Source | API Key Required | Description |
|--------|------------------|-------------|
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

### Recursive Enumeration

Enable recursive enumeration to discover subdomains of discovered subdomains:

```yaml
subdomain_enum:
  recursive: true
  max_depth: 2
```

## Project Structure

```
recon_tool/
├── main.py              # Entry point
├── requirements.txt     # Dependencies
├── config.yaml          # Configuration (optional)
├── modules/
│   ├── __init__.py
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   └── dns_enum.py
├── utils/
│   ├── __init__.py
│   ├── output.py
│   └── helpers.py
└── wordlists/
    └── subdomains.txt
```

## Configuration

Create a `config.yaml` file for custom settings:

```yaml
subdomain_enum:
  # Available sources: crtsh, dnsdumpster, securitytrails, shodan, censys, 
  # hackertarget, rapiddns, alienvault, virustotal, wayback, bufferover, 
  # threatcrowd, anubis, riddler, bruteforce
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
  # API keys for sources that require them
  api_keys:
    securitytrails: ""  # SecurityTrails API key
    shodan: ""          # Shodan API key
    censys_id: ""       # Censys API ID
    censys_secret: ""   # Censys API Secret
    virustotal: ""      # VirusTotal API key
  wordlist: "wordlists/subdomains.txt"
  threads: 50
  timeout: 10
  recursive: false      # Enable recursive subdomain enumeration
  max_depth: 2          # Max depth for recursive enumeration

port_scan:
  ports: "1-1000,3306,5432,8080,8443"
  scan_type: "syn"  # syn, connect, udp
  timeout: 5
  use_nmap: true

dns_enum:
  record_types:
    - A
    - AAAA
    - MX
    - TXT
    - NS
    - CNAME
    - SOA
  resolvers:
    - 8.8.8.8
    - 1.1.1.1
    - 9.9.9.9
  try_zone_transfer: true

output:
  format: "json"  # json, csv, txt, table, tree
  file: null

general:
  user_agent: "ReconTool/1.0"
  rate_limit: 100  # requests per second
  proxy: null
```

## API Keys

For sources requiring API keys, you can set them in `config.yaml` or via environment variables:

```bash
export SECURITYTRAILS_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export VIRUSTOTAL_API_KEY="your_key"
```

## TODO

- [x] Implement subdomain enumeration module (15+ sources)
- [x] Implement port scanner module
- [x] Implement DNS enumeration module
- [x] Add configuration file support
- [ ] Add rate limiting
- [ ] Add proxy support
- [ ] Add logging
- [ ] Add HTTP/HTTPS service detection
- [ ] Add technology fingerprinting
- [ ] Add SSL certificate analysis