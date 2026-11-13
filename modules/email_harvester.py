"""
Email Harvester Module - OSINT Phase 2
- Multi-source email enumeration
- Hunter.io, Clearbit, GitHub, WHOIS, LinkedIn
- Search engines (Google, Bing, DuckDuckGo)
- Pattern-based extraction from web pages
- Stealth integration
"""

import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, quote_plus
from collections import defaultdict

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class EmailResult:
    """Email finding result"""
    email: str
    source: str
    confidence: int  # 0-100
    context: str = ""  # Where it was found
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    position: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    twitter: Optional[str] = None
    verified: bool = False
    verification_date: Optional[str] = None


@dataclass
class EmailHarvestConfig:
    """Configuration for email harvesting"""
    # API Keys
    hunter_api_key: Optional[str] = None
    clearbit_api_key: Optional[str] = None
    github_token: Optional[str] = None
    linkedin_cookie: Optional[str] = None
    
    # Search settings
    max_results_per_source: int = 100
    max_pages_per_engine: int = 10
    request_delay: float = 2.0
    
    # Sources to use
    use_hunter: bool = True
    use_clearbit: bool = True
    use_github: bool = True
    use_whois: bool = True
    use_search_engines: bool = True
    use_web_crawl: bool = True
    
    # Patterns
    custom_patterns: List[str] = field(default_factory=list)
    
    # Verification
    verify_emails: bool = False
    smtp_check: bool = False


class EmailHarvester:
    """Multi-source email harvester"""
    
    # Email regex pattern
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # Common email patterns for permutation
    EMAIL_FORMATS = [
        '{first}.{last}',
        '{first}{last}',
        '{first}_{last}',
        '{first}-{last}',
        '{f}{last}',
        '{first}{l}',
        '{f}.{last}',
        '{first}',
        '{last}.{first}',
        '{last}{first}',
        '{l}{first}',
        '{last}.{f}',
    ]
    
    def __init__(self, domain: str, config: EmailHarvestConfig,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.domain = domain.lower()
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        self.found_emails: Dict[str, EmailResult] = {}
        self.stats = {
            'total_found': 0,
            'by_source': defaultdict(int),
            'verified': 0,
            'errors': 0
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 EmailHarvester)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def _add_email(self, email: str, source: str, confidence: int = 50,
                   context: str = "", **kwargs):
        """Add email to results with deduplication"""
        email = email.lower().strip()
        
        # Validate email format
        if not self.EMAIL_PATTERN.match(email):
            return
        
        # Must belong to target domain
        if not email.endswith(f'@{self.domain}'):
            return
        
        # Skip common false positives
        skip_prefixes = ['noreply', 'no-reply', 'donotreply', 'do-not-reply',
                        'admin', 'administrator', 'root', 'postmaster',
                        'webmaster', 'hostmaster', 'abuse', 'security',
                        'support', 'help', 'info', 'sales', 'marketing',
                        'billing', 'accounts', 'hr', 'jobs', 'careers',
                        'privacy', 'legal', 'compliance', 'dpo',
                        'newsletter', 'marketing', 'promo', 'offers',
                        'test', 'testing', 'dev', 'staging', 'demo',
                        'example', 'sample', 'placeholder', 'dummy',
                        'fake', 'null', 'void', 'empty', 'temp', 'tmp']
        
        local_part = email.split('@')[0]
        if any(local_part.startswith(p) for p in skip_prefixes):
            return
        
        if email in self.found_emails:
            # Update if higher confidence
            if confidence > self.found_emails[email].confidence:
                self.found_emails[email].confidence = confidence
                self.found_emails[email].source += f", {source}"
            return
        
        result = EmailResult(
            email=email,
            source=source,
            confidence=confidence,
            context=context,
            **kwargs
        )
        self.found_emails[email] = result
        self.stats['total_found'] += 1
        self.stats['by_source'][source] += 1
    
    async def _stealth_get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=30, method='GET', **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=30, **kwargs)
            except Exception:
                return None
    
    async def _stealth_post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a POST request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=30, method='POST', **kwargs
            )
        else:
            try:
                return await session.post(url, timeout=30, **kwargs)
            except Exception:
                return None
    
    def _extract_emails_from_text(self, text: str, source: str, confidence: int = 50) -> List[str]:
        """Extract emails from text"""
        emails = []
        for match in self.EMAIL_PATTERN.finditer(text):
            email = match.group(0).lower()
            if email.endswith(f'@{self.domain}'):
                self._add_email(email, source, confidence, context=match.group(0)[:200])
                emails.append(email)
        return emails
    
    # ==================== Source: Hunter.io ====================
    
    async def harvest_hunter(self) -> List[EmailResult]:
        """Harvest emails from Hunter.io API"""
        if not self.config.use_hunter or not self.config.hunter_api_key:
            return []
        
        print(f"[+] Harvesting from Hunter.io for {self.domain}")
        emails = []
        
        url = "https://api.hunter.io/v2/domain-search"
        params = {
            'domain': self.domain,
            'api_key': self.config.hunter_api_key,
            'limit': self.config.max_results_per_source,
            'offset': 0
        }
        
        try:
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    params=params, method='GET'
                )
            else:
                resp = await session.get(url, params=params, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                for email_data in data.get('data', {}).get('emails', []):
                    email = email_data.get('value', '').lower()
                    if email.endswith(f'@{self.domain}'):
                        self._add_email(
                            email, 'hunter.io',
                            confidence=90,
                            context=f"Hunter.io: {email_data.get('type', 'unknown')}",
                            first_name=email_data.get('first_name'),
                            last_name=email_data.get('last_name'),
                            position=email_data.get('position'),
                            department=email_data.get('department'),
                            phone=email_data.get('phone'),
                            linkedin=email_data.get('linkedin'),
                            twitter=email_data.get('twitter'),
                            verified=email_data.get('verification', {}).get('status') == 'valid',
                            verification_date=email_data.get('verification', {}).get('date')
                        )
                        emails.append(self.found_emails[email])
            
            elif resp and resp.status == 401:
                print("[!] Hunter.io: Invalid API key")
            elif resp:
                print(f"[!] Hunter.io error: HTTP {resp.status}")
                
        except Exception as e:
            print(f"[!] Hunter.io error: {e}")
            self.stats['errors'] += 1
        
        return emails
    
    # ==================== Source: Clearbit ====================
    
    async def harvest_clearbit(self) -> List[EmailResult]:
        """Harvest emails from Clearbit API"""
        if not self.config.use_clearbit or not self.config.clearbit_api_key:
            return []
        
        print(f"[+] Harvesting from Clearbit for {self.domain}")
        emails = []
        
        url = f"https://company.clearbit.com/v2/companies/find"
        params = {'domain': self.domain}
        headers = {'Authorization': f'Bearer {self.config.clearbit_api_key}'}
        
        try:
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    params=params, headers=headers, method='GET'
                )
            else:
                resp = await session.get(url, params=params, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                # Clearbit returns company info, not directly emails
                # But we can use the domain to search for people
                company_domain = data.get('domain', self.domain)
                
                # Use Clearbit's person search (requires different endpoint)
                # For now, we note the company info
                pass
            
            elif resp and resp.status == 401:
                print("[!] Clearbit: Invalid API key")
                
        except Exception as e:
            print(f"[!] Clearbit error: {e}")
            self.stats['errors'] += 1
        
        return emails
    
    # ==================== Source: GitHub ====================
    
    async def harvest_github(self) -> List[EmailResult]:
        """Harvest emails from GitHub (commits, profiles, repos)"""
        if not self.config.use_github:
            return []
        
        print(f"[+] Harvesting from GitHub for {self.domain}")
        emails = []
        
        headers = {}
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        
        # Search for users with email in domain
        search_queries = [
            f'email:{self.domain}',
            f'{self.domain} in:email',
            f'org:{self.domain.replace(".", "")} email:{self.domain}'
        ]
        
        for query in search_queries:
            try:
                url = "https://api.github.com/search/users"
                params = {'q': query, 'per_page': 100}
                
                session = await self._get_session()
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    data = await resp.json()
                    for user in data.get('items', []):
                        # Get user details for email
                        user_url = user.get('url')
                        if user_url:
                            await self._get_github_user_email(user_url, headers)
                
                elif resp and resp.status == 403:
                    print("[!] GitHub: Rate limited or invalid token")
                    break
                    
            except Exception as e:
                print(f"[!] GitHub search error: {e}")
                self.stats['errors'] += 1
        
        # Also search commits
        await self._harvest_github_commits(headers)
        
        return emails
    
    async def _get_github_user_email(self, user_url: str, headers: Dict):
        """Get email from GitHub user profile"""
        try:
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, user_url, self.stealth_scheduler,
                    headers=headers, method='GET'
                )
            else:
                resp = await session.get(user_url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                email = data.get('email')
                if email and email.endswith(f'@{self.domain}'):
                    self._add_email(
                        email, 'github',
                        confidence=85,
                        context=f"GitHub profile: {data.get('login')}",
                        first_name=data.get('name', '').split()[0] if data.get('name') else None,
                        last_name=' '.join(data.get('name', '').split()[1:]) if data.get('name') and len(data.get('name', '').split()) > 1 else None,
                        linkedin=data.get('blog') if 'linkedin' in (data.get('blog') or '') else None
                    )
        except Exception:
            pass
    
    async def _harvest_github_commits(self, headers: Dict):
        """Harvest emails from GitHub commits"""
        try:
            # Search for commits with emails from domain
            url = "https://api.github.com/search/commits"
            params = {
                'q': f'author-email:{self.domain}',
                'per_page': 100
            }
            headers['Accept'] = 'application/vnd.github.cloak-preview+json'
            
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    params=params, headers=headers, method='GET'
                )
            else:
                resp = await session.get(url, params=params, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                for item in data.get('items', []):
                    commit = item.get('commit', {})
                    author = commit.get('author', {})
                    email = author.get('email', '').lower()
                    if email.endswith(f'@{self.domain}'):
                        self._add_email(
                            email, 'github-commits',
                            confidence=95,
                            context=f"GitHub commit: {commit.get('message', '')[:100]}",
                            first_name=author.get('name', '').split()[0] if author.get('name') else None
                        )
                        
        except Exception as e:
            print(f"[!] GitHub commits error: {e}")
    
    # ==================== Source: WHOIS ====================
    
    async def harvest_whois(self) -> List[EmailResult]:
        """Harvest emails from WHOIS records"""
        if not self.config.use_whois:
            return []
        
        print(f"[+] Harvesting from WHOIS for {self.domain}")
        emails = []
        
        try:
            import whois
            w = whois.whois(self.domain)
            
            # Extract emails from WHOIS fields
            whois_text = str(w)
            self._extract_emails_from_text(whois_text, 'whois', confidence=80)
            
            # Also check specific fields
            for field in ['emails', 'email', 'registrant_email', 'admin_email', 'tech_email']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        for email in value:
                            self._add_email(email.lower(), 'whois', confidence=80, context=f"WHOIS {field}")
                    else:
                        self._add_email(value.lower(), 'whois', confidence=80, context=f"WHOIS {field}")
                        
        except ImportError:
            print("[!] python-whois not installed, skipping WHOIS")
        except Exception as e:
            print(f"[!] WHOIS error: {e}")
            self.stats['errors'] += 1
        
        return emails
    
    # ==================== Source: Search Engines ====================
    
    async def harvest_search_engines(self) -> List[EmailResult]:
        """Harvest emails from search engines (Google, Bing, DuckDuckGo)"""
        if not self.config.use_search_engines:
            return []
        
        print(f"[+] Harvesting from search engines for {self.domain}")
        emails = []
        
        # Search queries for email discovery
        queries = [
            f'site:{self.domain} "@{self.domain}"',
            f'site:{self.domain} "email" "@{self.domain}"',
            f'site:{self.domain} "contact" "@{self.domain}"',
            f'site:{self.domain} "mailto:" "@{self.domain}"',
            f'"@{self.domain}" "email"',
            f'"@{self.domain}" "contact"',
            f'"@{self.domain}" "mailto"',
            f'intext:"@{self.domain}" filetype:pdf',
            f'intext:"@{self.domain}" filetype:doc',
            f'intext:"@{self.domain}" filetype:xls',
        ]
        
        engines = [
            ('duckduckgo', 'https://html.duckduckgo.com/html/', {'q': '{query}'}),
            ('bing', 'https://www.bing.com/search', {'q': '{query}'}),
        ]
        
        for engine_name, base_url, params_template in engines:
            for query in queries[:5]:  # Limit queries per engine
                try:
                    params = {k: v.format(query=query) for k, v in params_template.items()}
                    
                    session = await self._get_session()
                    if self.stealth_scheduler:
                        resp = await fetch_with_stealth(
                            session, base_url, self.stealth_scheduler,
                            params=params, method='GET'
                        )
                    else:
                        resp = await session.get(base_url, params=params, timeout=30)
                    
                    if resp and resp.status == 200:
                        html = await resp.text()
                        self._extract_emails_from_text(html, f'{engine_name}-search', confidence=60)
                    
                    # Rate limiting between queries
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                        
                except Exception as e:
                    print(f"[!] {engine_name} search error: {e}")
                    self.stats['errors'] += 1
        
        return emails
    
    # ==================== Source: Web Crawling ====================
    
    async def harvest_web_crawl(self, max_pages: int = 50) -> List[EmailResult]:
        """Crawl website and extract emails from pages"""
        if not self.config.use_web_crawl:
            return []
        
        print(f"[+] Crawling website for emails: {self.domain}")
        emails = []
        
        base_url = f"https://{self.domain}"
        visited = set()
        to_visit = [base_url]
        page_count = 0
        
        while to_visit and page_count < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                session = await self._get_session()
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        method='GET'
                    )
                else:
                    resp = await session.get(url, timeout=30)
                
                if resp and resp.status == 200:
                    html = await resp.text()
                    page_count += 1
                    
                    # Extract emails
                    self._extract_emails_from_text(html, 'web-crawl', confidence=70)
                    
                    # Find links to crawl
                    if page_count < max_pages:
                        links = re.findall(r'href=["\']([^"\']+)["\']', html)
                        for link in links:
                            # Normalize link
                            if link.startswith('/'):
                                link = urljoin(base_url, link)
                            elif not link.startswith('http'):
                                link = urljoin(url, link)
                            
                            # Only follow same domain
                            parsed = urlparse(link)
                            if parsed.netloc.endswith(self.domain) or parsed.netloc == self.domain:
                                if link not in visited and link not in to_visit:
                                    to_visit.append(link)
                
                # Rate limiting
                if self.stealth_scheduler:
                    await self.stealth_scheduler.wait_before_request()
                    
            except Exception as e:
                print(f"[!] Crawl error for {url}: {e}")
                self.stats['errors'] += 1
        
        return emails
    
    # ==================== Source: LinkedIn (limited) ====================
    
    async def harvest_linkedin(self) -> List[EmailResult]:
        """Harvest emails from LinkedIn (limited - requires auth)"""
        if not self.config.linkedin_cookie:
            return []
        
        print(f"[+] Harvesting from LinkedIn for {self.domain}")
        emails = []
        
        # LinkedIn scraping is complex and requires authentication
        # This is a placeholder for future implementation
        # Would need to use LinkedIn's search API or scrape with proper auth
        
        return emails
    
    # ==================== Pattern-based Generation ====================
    
    def generate_email_permutations(self, first_name: str, last_name: str) -> List[str]:
        """Generate email permutations based on common patterns"""
        emails = []
        first = first_name.lower().strip()
        last = last_name.lower().strip()
        f = first[0] if first else ''
        l = last[0] if last else ''
        
        for pattern in self.EMAIL_FORMATS:
            try:
                email = pattern.format(
                    first=first, last=last, f=f, l=l
                ) + f'@{self.domain}'
                emails.append(email)
            except KeyError:
                continue
        
        return emails
    
    async def verify_email_smtp(self, email: str) -> bool:
        """Verify email via SMTP (optional)"""
        if not self.config.smtp_check:
            return False
        
        try:
            import smtplib
            import dns.resolver
            
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange).rstrip('.')
            
            with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                smtp.helo()
                smtp.mail('verify@recontool.local')
                code, _ = smtp.rcpt(email)
                return code == 250
        except Exception:
            return False
    
    # ==================== Main Run Method ====================
    
    async def run(self) -> Dict[str, Any]:
        """Run all email harvesting sources"""
        print(f"[+] Starting email harvesting for {self.domain}")
        
        # Run all sources concurrently where possible
        tasks = []
        
        if self.config.use_hunter and self.config.hunter_api_key:
            tasks.append(self.harvest_hunter())
        
        if self.config.use_github:
            tasks.append(self.harvest_github())
        
        if self.config.use_whois:
            tasks.append(self.harvest_whois())
        
        if self.config.use_search_engines:
            tasks.append(self.harvest_search_engines())
        
        if self.config.use_web_crawl:
            tasks.append(self.harvest_web_crawl())
        
        # Run concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Optional SMTP verification
        if self.config.verify_emails and self.config.smtp_check:
            print(f"[+] Verifying {len(self.found_emails)} emails via SMTP...")
            for email, result in self.found_emails.items():
                if await self.verify_email_smtp(email):
                    result.verified = True
                    self.stats['verified'] += 1
        
        # Prepare results
        results = {
            'domain': self.domain,
            'stats': self.stats,
            'emails': [
                {
                    'email': r.email,
                    'source': r.source,
                    'confidence': r.confidence,
                    'context': r.context,
                    'first_name': r.first_name,
                    'last_name': r.last_name,
                    'position': r.position,
                    'department': r.department,
                    'phone': r.phone,
                    'linkedin': r.linkedin,
                    'twitter': r.twitter,
                    'verified': r.verified,
                    'verification_date': r.verification_date
                }
                for r in sorted(self.found_emails.values(), key=lambda x: -x.confidence)
            ]
        }
        
        print(f"[+] Harvested {self.stats['total_found']} unique emails")
        print(f"[+] By source: {dict(self.stats['by_source'])}")
        if self.stats['verified']:
            print(f"[+] Verified: {self.stats['verified']}")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python email_harvester.py <domain> [--hunter-key KEY] [--github-token TOKEN]")
        return
    
    domain = sys.argv[1]
    
    # Parse optional args
    hunter_key = None
    github_token = None
    for i, arg in enumerate(sys.argv):
        if arg == '--hunter-key' and i + 1 < len(sys.argv):
            hunter_key = sys.argv[i + 1]
        elif arg == '--github-token' and i + 1 < len(sys.argv):
            github_token = sys.argv[i + 1]
    
    config = EmailHarvestConfig(
        hunter_api_key=hunter_key,
        github_token=github_token
    )
    
    harvester = EmailHarvester(domain, config)
    results = await harvester.run()
    await harvester.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())