# Recon Tool - Development Roadmap

## Vision
Build a comprehensive, stealthy, modular reconnaissance toolkit for security assessments.

---

## Phase 1: Core Web Reconnaissance (Week 1-2) 🎯 HIGH PRIORITY

### 1.1 HTTP Service Discovery & Fingerprinting
- [ ] **HTTP Headers Analyzer** - Extract Server, X-Powered-By, security headers
- [ ] **Technology Fingerprinting** - Wappalyzer-style detection (CMS, frameworks, JS libs, analytics)
- [ ] **SSL/TLS Certificate Analysis** - Cert details, SANs, expiry, transparency logs
- [ ] **CDN/WAF Detection** - Cloudflare, Akamai, Fastly, AWS CloudFront, Imperva, etc.
- [ ] **HTTP Methods Testing** - OPTIONS, TRACE, PUT, DELETE, PATCH
- [ ] **Security Headers Audit** - CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy

### 1.2 Directory & File Enumeration
- [ ] **Directory Brute Force** - Async, recursive, with extensions
- [ ] **File Enumeration** - Backup files, config files, .git, .env, etc.
- [ ] **Smart Wordlists** - Context-aware (tech-specific wordlists)
- [ ] **Response Analysis** - Filter 404s, detect soft 404s, cluster similar responses

### 1.3 Web Application Mapping
- [ ] **Crawler/Spider** - Discover links, forms, endpoints
- [ ] **API Endpoint Discovery** - Swagger/OpenAPI, GraphQL introspection
- [ ] **JavaScript Analysis** - Extract endpoints, secrets from JS files
- [ ] **SPA Support** - Handle client-side routing

---

## Phase 2: OSINT & Intelligence Gathering (Week 2-3) 🔍 MEDIUM PRIORITY

### 2.1 Email & Identity Intelligence
- [ ] **Email Harvester** - Hunter.io, Clearbit, LinkedIn, GitHub, WHOIS
- [ ] **Employee Enumeration** - LinkedIn, company pages, GitHub org members
- [ ] **Username Enumeration** - Across platforms (GitHub, Twitter, etc.)

### 2.2 Document & Metadata Intelligence
- [ ] **Document Discovery** - site:domain filetype:pdf/doc/xls
- [ ] **Metadata Extraction** - Author, software, timestamps, internal paths
- [ ] **EXIF Data** - From images on web assets

### 2.3 Code & Repository Intelligence
- [ ] **GitHub/GitLab Recon** - Public repos, secrets, contributors, issues
- [ ] **Git History Analysis** - Deleted secrets, sensitive files
- [ ] **Package Registry** - npm, PyPI, Maven, Docker Hub for org packages

### 2.4 Threat Intelligence Integration
- [ ] **Breach Data** - HaveIBeenPwned, DeHashed, LeakCheck
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
│   ├── ssl_analyzer.py        🔄 Phase 1
│   ├── osint_email.py         🔄 Phase 2
│   ├── osint_github.py        🔄 Phase 2
│   ├── osint_docs.py          🔄 Phase 2
│   ├── vuln_mapper.py         🔄 Phase 3
│   ├── cloud_enum.py          🔄 Phase 4
│   ├── takeover_check.py      🔄 Phase 4
│   └── nuclei_runner.py       🔄 Phase 3
├── utils/
│   ├── stealth.py             ✅ Done
│   ├── http_client.py         🔄 Phase 1
│   ├── wordlists.py           🔄 Phase 1
│   ├── reporting.py           🔄 Phase 5
│   └── cache.py               🔄 Phase 5
└── wordlists/
    ├── subdomains.txt         ✅ Done
    ├── directories/           🔄 Phase 1
    ├── files/                 🔄 Phase 1
    ├── tech_fingerprints/     🔄 Phase 1
    └── permutations/          🔄 Phase 1
```

---

## Quick Wins (Can do this week)

1. **HTTP Headers + Tech Fingerprint** - ~200 lines, high value
2. **SSL Cert Analysis** - ~150 lines, uses existing subdomain results
3. **Directory Brute Force** - ~300 lines, reuses stealth scheduler
4. **Subdomain Takeover Check** - ~100 lines, uses DNS enum results

---

## Dependencies to Add

```yaml
# Phase 1
httpx>=0.27.0          # Modern HTTP client
wappalyzer>=1.0.0      # Tech fingerprinting (or custom)
cryptography>=42.0.0   # SSL cert parsing

# Phase 2
github3.py>=3.0.0      # GitHub API
python-linkedin>=1.0   # LinkedIn (if available)

# Phase 3
nuclei-sdk>=0.1.0      # Nuclei integration (or subprocess)
cve-search>=0.1.0      # CVE database

# Phase 4
boto3>=1.34.0          # AWS
azure-mgmt>=1.0.0      # Azure
google-cloud>=2.0.0    # GCP

# Phase 5
jinja2>=3.1.0          # HTML reports
weasyprint>=60.0       # PDF generation
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Subdomain coverage | >90% vs. commercial tools |
| False positive rate | <5% |
| Scan time (full) | <30 min for medium target |
| Stealth effectiveness | Bypass common WAF/IDS |
| Module count | 15+ modules |
| Test coverage | >80% |

---

## Next Steps (Immediate)

1. **Pick Phase 1 module** - HTTP Recon or Dir Enum
2. **Create module skeleton** - Follow existing patterns
3. **Add wordlists** - SecLists, custom curated lists
4. **Integrate stealth scheduler** - Reuse existing infrastructure
5. **Add config section** - Extend config.yaml
6. **Update CLI** - Add new flags
7. **Test & document** - Verify with real targets

---

*Last updated: 2026-11-12*
*Version: 1.0.0-roadmap*