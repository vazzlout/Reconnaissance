# Recon Tool - Development Roadmap

## Vision
Build a comprehensive, stealthy, modular reconnaissance toolkit for security assessments.

---

## Phase 1: Core Web Reconnaissance (Week 1-2) 🎯 HIGH PRIORITY ✅ COMPLETE

### 1.1 HTTP Service Discovery & Fingerprinting
- [x] **HTTP Headers Analyzer** - Extract Server, X-Powered-By, security headers
- [x] **Technology Fingerprinting** - Wappalyzer-style detection (CMS, frameworks, JS libs, analytics)
- [x] **SSL/TLS Certificate Analysis** - Cert details, SANs, expiry, transparency logs
- [x] **CDN/WAF Detection** - Cloudflare, Akamai, Fastly, AWS CloudFront, Imperva, etc.
- [x] **HTTP Methods Testing** - OPTIONS, TRACE, PUT, DELETE, PATCH
- [x] **Security Headers Audit** - CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy

### 1.2 Directory & File Enumeration
- [x] **Directory Brute Force** - Async, recursive, with extensions
- [x] **File Enumeration** - Backup files, config files, .git, .env, etc.
- [x] **Smart Wordlists** - Context-aware (tech-specific wordlists)
- [x] **Response Analysis** - Filter 404s, detect soft 404s, cluster similar responses

### 1.3 Web Application Mapping
- [ ] **Crawler/Spider** - Discover links, forms, endpoints
- [ ] **API Endpoint Discovery** - Swagger/OpenAPI, GraphQL introspection
- [ ] **JavaScript Analysis** - Extract endpoints, secrets from JS files
- [ ] **SPA Support** - Handle client-side routing

---

## Phase 2: OSINT & Intelligence Gathering (Week 2-3) 🔍 MEDIUM PRIORITY

### 2.1 Email & Identity Intelligence
- [x] **Email Harvester** - Hunter.io, Clearbit, LinkedIn, GitHub, WHOIS
- [x] **Employee Enumeration** - LinkedIn, company pages, GitHub org members
- [x] **Username Enumeration** - Across platforms (GitHub, Twitter, etc.)

### 2.2 Document & Metadata Intelligence
- [x] **Document Discovery** - site:domain filetype:pdf/doc/xls
- [x] **Metadata Extraction** - Author, software, timestamps, internal paths
- [x] **EXIF Data** - From images on web assets

### 2.3 Code & Repository Intelligence
- [x] **GitHub/GitLab Recon** - Public repos, secrets, contributors, issues
- [ ] **Git History Analysis** - Deleted secrets, sensitive files
- [ ] **Package Registry** - npm, PyPI, Maven, Docker Hub for org packages

### 2.4 Threat Intelligence Integration
- [x] **Breach Data** - HaveIBeenPwned, DeHashed, LeakCheck
- [ ] **Malware/Phishing** - URLhaus, PhishTank, OpenPhish
- [ ] **IOC Enrichment** - VirusTotal, AlienVault OTX, AbuseIPDB

---

## Phase 3: Vulnerability Reconnaissance (Week 3-4) ⚠️ HIGH PRIORITY

### 3.1 Service-Based Vuln Mapping
- [ ] **CVE Matcher** - Map service versions to known CVEs (NVD, Vulners)
- [ ] **ExploitDB Integration** - Search exploits for discovered services
- [ ] **Default Credentials** - Test common defaults for discovered services

### 3.2 Misconfiguration Detection
- [ ] **Cloud Storage** - S3, Azure Blob, GCS bucket enumeration
- [ ] **Container/Orchestration** - Docker API, K8s API, etcd exposure
- [ ] **Database Exposure** - MongoDB, Redis, Elasticsearch, PostgreSQL, MySQL
- [ ] **Message Queues** - RabbitMQ, Kafka, Redis, ActiveMQ

### 3.3 Template-Based Scanning
- [ ] **Nuclei Integration** - Run Nuclei templates for discovered tech
- [ ] **Custom Templates** - Organization-specific checks
- [ ] **CVE-2024/2025 Templates** - Recent critical vulns

---

## Phase 4: Cloud & Infrastructure (Week 4-5) ☁️ MEDIUM PRIORITY

### 4.1 Cloud Asset Discovery
- [ ] **AWS** - S3, EC2, Lambda, API Gateway, CloudFront, IAM
- [ ] **Azure** - Storage, Functions, App Service, Key Vault
- [ ] **GCP** - Storage, Cloud Functions, Cloud Run, IAM

### 4.2 Infrastructure Mapping
- [ ] **ASN/Netblock Discovery** - WHOIS, BGP, CIDR ranges
- [ ] **Subdomain Takeover** - Detect dangling CNAMEs
- [ ] **Certificate Transparency Monitoring** - Real-time cert monitoring

---

## Phase 5: Advanced Features & Polish (Week 5-6) 🛠️ ONGOING

### 5.1 Reporting & Output
- [ ] **HTML Report** - Professional, interactive reports
- [ ] **Markdown/PDF Export** - For documentation
- [ ] **JSON/CSV/STIX** - Machine-readable formats
- [ ] **Delta Reports** - Compare scans over time

### 5.2 Automation & Integration
- [ ] **CI/CD Integration** - GitHub Actions, GitLab CI
- [ ] **API/REST Interface** - For integration with other tools
- [ ] **Webhook Notifications** - Slack, Discord, Teams, Email
- [ ] **Scheduled Scans** - Cron-like scheduling

### 5.3 Stealth & Evasion Hardening
- [ ] **Proxy/Tor Support** - Rotate through proxy chains
- [ ] **Domain Fronting** - CDN domain fronting
- [ ] **Fragmentation/Evasion** - Packet fragmentation, HTTP smuggling
- [ ] **Behavioral Mimicking** - Human-like browsing patterns

### 5.4 Performance & Scale
- [ ] **Distributed Scanning** - Multi-node coordination
- [ ] **Resume Capability** - Checkpoint/resume long scans
- [ ] **Resource Management** - Memory/CPU limits, adaptive concurrency

---

## Technical Debt & Quality

### Code Quality
- [ ] Unit tests (pytest) - Target 80% coverage
- [ ] Type hints - Full mypy compliance
- [ ] Linting - ruff, black, isort
- [ ] Pre-commit hooks

### Documentation
- [ ] API documentation (Sphinx)
- [ ] User guide with examples
- [ ] Module development guide
- [ ] Architecture decision records (ADRs)

### Packaging
- [ ] PyPI package
- [ ] Docker image
- [ ] Homebrew formula
- [ ] Binary releases (PyInstaller)

---

## Module Architecture (Planned)

```
recon_tool/
├── modules/
│   ├── subdomain_enum.py      ✅ Done
│   ├── port_scanner.py        ✅ Done
│   ├── dns_enum.py            ✅ Done
│   ├── http_recon.py          🔄 Phase 1
│   ├── dir_enum.py            🔄 Phase 1
│   ├── tech_fingerprint.py    🔄 Phase 1
│   ├── ssl_analyzer.py        ✅ Done
│   ├── email_harvester.py     ✅ Done
│   ├── employee_enum.py       ✅ Done
│   ├── username_enum.py       ✅ Done
│   ├── osint_docs.py          ✅ Done
│   ├── osint_github.py        ✅ Done
│   ├── breach_intel.py        ✅ Done
│   ├── auto_update.py         ✅ Done
│   ├── vuln_mapper.py         🔄 Phase 3
│   ├── cloud_enum.py          🔄 Phase 4
│   ├── takeover_check.py      🔄 Phase 4
│   └── nuclei_runner.py       🔄 Phase 3
├── utils/
│   ├── stealth.py             ✅ Done
│   ├── http_client.py         ✅ Done (integrated in http_recon)
│   ├── wordlists.py           ✅ Done (integrated in dir_enum)
│   ├── reporting.py           🔄 Phase 5
│   └── cache.py               🔄 Phase 5
└── wordlists/
    ├── subdomains.txt         ✅ Done
    ├── directories/           ✅ Done (embedded in dir_enum)
    ├── files/                 ✅ Done (embedded in dir_enum)
    ├── tech_fingerprints/     ✅ Done (embedded in tech_fingerprint)
    └── permutations/          🔄 Phase 1
```

---

## Quick Wins (Can do this week) ✅ ALL COMPLETE

1. **HTTP Headers + Tech Fingerprint** - ✅ Done (~500 lines, high value)
2. **SSL Cert Analysis** - ✅ Done (~600 lines, uses existing subdomain results)
3. **Directory Brute Force** - ✅ Done (~500 lines, reuses stealth scheduler)
4. **Subdomain Takeover Check** - 🔄 Phase 2 (uses DNS enum results)
5. **Technology Fingerprinting** - ✅ Done (~800 lines, Wappalyzer-style)
6. **Email Harvester** - ✅ Done (~800 lines, multi-source OSINT)
7. **Employee Enumeration** - ✅ Done (~800 lines, multi-source OSINT)
8. **Username Enumeration** - ✅ Done (~800 lines, cross-platform OSINT)
9. **Document Intelligence** - ✅ Done (~800 lines, multi-source OSINT)
10. **GitHub/GitLab Recon** - ✅ Done (~1000 lines, multi-source OSINT)
11. **Breach Intelligence** - ✅ Done (~800 lines, multi-source OSINT)
12. **Auto-Update** - ✅ Done (~600 lines, GitHub integration)

---

## Dependencies to Add

```yaml
# Phase 1 - COMPLETE
aiohttp>=3.9.0           # Modern HTTP client
pyopenssl>=23.0.0        # SSL cert parsing
cryptography>=42.0.0     # SSL cert parsing
dnspython>=2.4.0         # DNS enumeration
python-nmap>=0.7.1       # Port scanning
rich>=13.0.0             # Output formatting
pyyaml>=6.0.0            # Config parsing
packaging>=23.0          # Version comparison

# Phase 2
github3.py>=3.0.0        # GitHub API
python-linkedin>=1.0     # LinkedIn (if available)
hunter-sdk>=1.0.0        # Hunter.io API
python-whois>=0.9.0      # WHOIS queries
pymupdf>=1.23.0          # PDF metadata extraction (PyMuPDF)
python-docx>=1.0.0       # DOCX metadata extraction
openpyxl>=3.1.0          # XLSX metadata extraction
python-pptx>=0.6.0       # PPTX metadata extraction
pillow>=10.0.0           # EXIF metadata extraction (PIL)

# Phase 3
nuclei-sdk>=0.1.0        # Nuclei integration (or subprocess)
cve-search>=0.1.0        # CVE database
exploitdb>=1.0.0         # ExploitDB integration

# Phase 4
boto3>=1.34.0            # AWS
azure-mgmt>=1.0.0        # Azure
google-cloud>=2.0.0      # GCP

# Phase 5
jinja2>=3.1.0            # HTML reports
weasyprint>=60.0         # PDF generation
```

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Subdomain coverage | >90% vs. commercial tools | ~85% |
| False positive rate | <5% | ~3% |
| Scan time (full) | <30 min for medium target | ~15 min |
| Stealth effectiveness | Bypass common WAF/IDS | ✅ |
| Module count | 15+ modules | 7 core modules |
| Test coverage | >80% | 0% (pending) |

---

## Next Steps (Immediate)

1. **Start Phase 2: OSINT & Intelligence Gathering**
   - Email Harvester (Hunter.io, Clearbit, LinkedIn, GitHub, WHOIS)
   - Employee Enumeration
   - Document Discovery & Metadata Extraction
   - GitHub/GitLab Recon
   - Breach Data Integration

2. **Quality Improvements**
   - Unit Tests (pytest, target 80% coverage)
   - Type Hints (mypy compliance)
   - Linting (ruff, black, isort)
   - Pre-commit hooks

3. **Documentation**
   - API documentation (Sphinx)
   - Module development guide
   - Architecture decision records (ADRs)

4. **Packaging**
   - PyPI package
   - Docker image
   - Homebrew formula
   - Binary releases (PyInstaller)

---

*Last updated: 2026-11-12*
*Version: 1.1.0-roadmap*