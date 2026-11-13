"""
Employee Enumeration Module - OSINT Phase 2
- LinkedIn employee search
- GitHub organization members
- Company page scraping
- People search engines
- Social media profiles
- Stealth integration
"""

import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, quote_plus, urlparse
from collections import defaultdict

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class Employee:
    """Employee/Person result"""
    name: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    department: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    twitter: Optional[str] = None
    github: Optional[str] = None
    source: str = ""
    confidence: int = 50
    profile_url: Optional[str] = None
    summary: Optional[str] = None
    skills: List[str] = field(default_factory=list)
    education: List[str] = field(default_factory=list)
    experience: List[Dict] = field(default_factory=list)


@dataclass
class EmployeeEnumConfig:
    """Configuration for employee enumeration"""
    # API Keys
    linkedin_cookie: Optional[str] = None  # li_at cookie
    github_token: Optional[str] = None
    hunter_api_key: Optional[str] = None
    clearbit_api_key: Optional[str] = None
    
    # Search settings
    max_results_per_source: int = 100
    max_pages: int = 10
    request_delay: float = 2.0
    
    # Sources to use
    use_linkedin: bool = True
    use_github: bool = True
    use_company_pages: bool = True
    use_search_engines: bool = True
    use_hunter: bool = True
    
    # Filters
    keywords: List[str] = field(default_factory=list)  # e.g., ['engineer', 'developer', 'admin']
    exclude_keywords: List[str] = field(default_factory=list)  # e.g., ['intern', 'student']
    locations: List[str] = field(default_factory=list)
    
    # Verification
    verify_emails: bool = False


class EmployeeEnumerator:
    """Multi-source employee enumerator"""
    
    def __init__(self, domain: str, company_name: Optional[str] = None,
                 config: EmployeeEnumConfig = None,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.domain = domain.lower()
        self.company_name = company_name or domain.split('.')[0].capitalize()
        self.config = config or EmployeeEnumConfig()
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        self.found_employees: Dict[str, Employee] = {}  # key: name+company
        self.stats = {
            'total_found': 0,
            'by_source': defaultdict(int),
            'with_email': 0,
            'with_linkedin': 0,
            'with_github': 0,
            'errors': 0
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 EmployeeEnumerator)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def _add_employee(self, employee: Employee):
        """Add employee to results with deduplication"""
        # Create unique key
        key = f"{employee.first_name or ''} {employee.last_name or ''} {employee.company or ''}".lower().strip()
        key = re.sub(r'\s+', ' ', key)
        
        if key in self.found_employees:
            # Merge information, keep higher confidence
            existing = self.found_employees[key]
            if employee.confidence > existing.confidence:
                # Merge new info into existing
                for field_name in ['email', 'phone', 'linkedin', 'twitter', 'github', 'title', 'department', 'location', 'summary', 'skills', 'education', 'experience']:
                    new_val = getattr(employee, field_name)
                    if new_val and not getattr(existing, field_name):
                        setattr(existing, field_name, new_val)
                existing.confidence = max(existing.confidence, employee.confidence)
                existing.source += f", {employee.source}"
            return
        
        self.found_employees[key] = employee
        self.stats['total_found'] += 1
        self.stats['by_source'][employee.source] += 1
        if employee.email:
            self.stats['with_email'] += 1
        if employee.linkedin:
            self.stats['with_linkedin'] += 1
        if employee.github:
            self.stats['with_github'] += 1
    
    def _matches_filters(self, employee: Employee) -> bool:
        """Check if employee matches filter criteria"""
        # Check keywords
        if self.config.keywords:
            text = f"{employee.title or ''} {employee.department or ''} {employee.summary or ''} {' '.join(employee.skills)}".lower()
            if not any(kw.lower() in text for kw in self.config.keywords):
                return False
        
        # Check exclude keywords
        if self.config.exclude_keywords:
            text = f"{employee.title or ''} {employee.department or ''} {employee.summary or ''}".lower()
            if any(kw.lower() in text for kw in self.config.exclude_keywords):
                return False
        
        # Check locations
        if self.config.locations and employee.location:
            if not any(loc.lower() in employee.location.lower() for loc in self.config.locations):
                return False
        
        return True
    
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
    
    # ==================== Source: LinkedIn ====================
    
    async def enumerate_linkedin(self) -> List[Employee]:
        """Enumerate employees from LinkedIn"""
        if not self.config.use_linkedin or not self.config.linkedin_cookie:
            return []
        
        print(f"[+] Enumerating LinkedIn employees for {self.company_name}")
        employees = []
        
        # LinkedIn search requires authentication and is complex
        # This is a placeholder for the actual implementation
        # Would need to use LinkedIn's search API or scrape with proper auth
        
        # Example approach (requires valid li_at cookie):
        # 1. Search for people at company
        # 2. Parse results
        # 3. Get profile details
        
        return employees
    
    async def _linkedin_search_people(self, keywords: str = "", page: int = 1) -> List[Dict]:
        """Search LinkedIn for people at company"""
        # Placeholder - requires LinkedIn API or scraping
        return []
    
    async def _linkedin_get_profile(self, profile_url: str) -> Optional[Dict]:
        """Get LinkedIn profile details"""
        # Placeholder - requires LinkedIn API or scraping
        return None
    
    # ==================== Source: GitHub Organization ====================
    
    async def enumerate_github_org(self) -> List[Employee]:
        """Enumerate employees from GitHub organization"""
        if not self.config.use_github:
            return []
        
        print(f"[+] Enumerating GitHub organization members for {self.domain}")
        employees = []
        
        headers = {}
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        
        # Try to find GitHub org from domain
        org_names = [
            self.domain.split('.')[0],
            self.company_name.lower().replace(' ', ''),
            self.company_name.lower().replace(' ', '-'),
        ]
        
        for org_name in org_names:
            try:
                org_employees = await self._get_github_org_members(org_name, headers)
                employees.extend(org_employees)
            except Exception as e:
                print(f"[!] GitHub org {org_name} error: {e}")
                self.stats['errors'] += 1
        
        return employees
    
    async def _get_github_org_members(self, org_name: str, headers: Dict) -> List[Employee]:
        """Get members of a GitHub organization"""
        employees = []
        
        try:
            session = await self._get_session()
            
            # Get organization members
            url = f"https://api.github.com/orgs/{org_name}/members"
            params = {'per_page': 100}
            
            page = 1
            while page <= self.config.max_pages:
                params['page'] = page
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    members = await resp.json()
                    if not members:
                        break
                    
                    for member in members:
                        # Get detailed user info
                        user_employee = await self._get_github_user_details(member.get('url'), headers)
                        if user_employee:
                            user_employee.source = f"github-org:{org_name}"
                            if self._matches_filters(user_employee):
                                self._add_employee(user_employee)
                                employees.append(user_employee)
                    
                    page += 1
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                        
                elif resp and resp.status == 404:
                    break  # Org not found
                elif resp and resp.status == 403:
                    print(f"[!] GitHub: Rate limited or invalid token for org {org_name}")
                    break
                else:
                    break
                    
        except Exception as e:
            print(f"[!] GitHub org {org_name} error: {e}")
            self.stats['errors'] += 1
        
        return employees
    
    async def _get_github_user_details(self, user_url: str, headers: Dict) -> Optional[Employee]:
        """Get detailed GitHub user information"""
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
                
                # Parse name
                name = data.get('name') or data.get('login')
                name_parts = name.split() if name else [data.get('login', '')]
                first_name = name_parts[0] if name_parts else None
                last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else None
                
                # Extract email if public
                email = data.get('email')
                
                employee = Employee(
                    name=name,
                    first_name=first_name,
                    last_name=last_name,
                    title=data.get('bio', '').split('\n')[0] if data.get('bio') else None,
                    company=data.get('company'),
                    location=data.get('location'),
                    email=email,
                    linkedin=data.get('blog') if data.get('blog') and 'linkedin' in data.get('blog', '') else None,
                    twitter=data.get('twitter_username'),
                    github=data.get('html_url'),
                    source='github',
                    confidence=85 if email else 70,
                    profile_url=data.get('html_url'),
                    summary=data.get('bio'),
                    skills=[]  # Would need to parse from repos
                )
                
                return employee
                
        except Exception as e:
            print(f"[!] GitHub user details error: {e}")
        
        return None
    
    # ==================== Source: GitHub Search (by domain) ====================
    
    async def enumerate_github_search(self) -> List[Employee]:
        """Search GitHub for users with email in domain"""
        if not self.config.use_github:
            return []
        
        print(f"[+] Searching GitHub for users with domain {self.domain}")
        employees = []
        
        headers = {}
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        
        # Search queries
        queries = [
            f'email:{self.domain}',
            f'{self.domain} in:email',
        ]
        
        for query in queries:
            try:
                url = "https://api.github.com/search/users"
                params = {'q': query, 'per_page': 100}
                
                session = await self._get_session()
                
                page = 1
                while page <= self.config.max_pages:
                    params['page'] = page
                    
                    if self.stealth_scheduler:
                        resp = await fetch_with_stealth(
                            session, url, self.stealth_scheduler,
                            params=params, headers=headers, method='GET'
                        )
                    else:
                        resp = await session.get(url, params=params, headers=headers, timeout=30)
                    
                    if resp and resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        if not items:
                            break
                        
                        for user in items:
                            user_employee = await self._get_github_user_details(user.get('url'), headers)
                            if user_employee:
                                user_employee.source = 'github-search'
                                if self._matches_filters(user_employee):
                                    self._add_employee(user_employee)
                                    employees.append(user_employee)
                        
                        page += 1
                        
                        if self.stealth_scheduler:
                            await self.stealth_scheduler.wait_before_request()
                            
                    elif resp and resp.status == 403:
                        print("[!] GitHub: Rate limited or invalid token")
                        break
                    else:
                        break
                        
            except Exception as e:
                print(f"[!] GitHub search error: {e}")
                self.stats['errors'] += 1
        
        return employees
    
    # ==================== Source: Company Pages ====================
    
    async def enumerate_company_pages(self) -> List[Employee]:
        """Extract employees from company website pages"""
        if not self.config.use_company_pages:
            return []
        
        print(f"[+] Extracting employees from company pages for {self.domain}")
        employees = []
        
        # Common pages that list employees
        pages_to_check = [
            f"https://{self.domain}/team",
            f"https://{self.domain}/about",
            f"https://{self.domain}/about-us",
            f"https://{self.domain}/our-team",
            f"https://{self.domain}/people",
            f"https://{self.domain}/staff",
            f"https://{self.domain}/leadership",
            f"https://{self.domain}/management",
            f"https://{self.domain}/careers",
            f"https://{self.domain}/jobs",
            f"https://{self.domain}/company",
            f"https://{self.domain}/who-we-are",
        ]
        
        for url in pages_to_check:
            try:
                page_employees = await self._extract_employees_from_page(url)
                employees.extend(page_employees)
                
                if self.stealth_scheduler:
                    await self.stealth_scheduler.wait_before_request()
                    
            except Exception as e:
                print(f"[!] Company page {url} error: {e}")
                self.stats['errors'] += 1
        
        return employees
    
    async def _extract_employees_from_page(self, url: str) -> List[Employee]:
        """Extract employee information from a web page"""
        employees = []
        
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
                
                # Try to find employee cards/profiles
                # This is a simplified extraction - real implementation would be more sophisticated
                
                # Look for common patterns
                patterns = [
                    # Name + Title patterns
                    r'<h[2-4][^>]*>([^<]+)</h[2-4]>.*?<p[^>]*>([^<]+)</p>',
                    r'class="[^"]*(?:team|staff|member|employee|person)[^"]*"[^>]*>.*?<h[2-4][^>]*>([^<]+)</h[2-4]>.*?<p[^>]*>([^<]+)</p>',
                    # LinkedIn-style cards
                    r'data-test-id="[^"]*"[^>]*>.*?<span[^>]*>([^<]+)</span>.*?<span[^>]*>([^<]+)</span>',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        if isinstance(match, tuple) and len(match) >= 2:
                            name = match[0].strip()
                            title = match[1].strip()
                            
                            if len(name) > 2 and len(name) < 100:
                                name_parts = name.split()
                                if len(name_parts) >= 2:
                                    employee = Employee(
                                        name=name,
                                        first_name=name_parts[0],
                                        last_name=' '.join(name_parts[1:]),
                                        title=title[:200],
                                        company=self.company_name,
                                        source='company-page',
                                        confidence=60,
                                        profile_url=url
                                    )
                                    if self._matches_filters(employee):
                                        self._add_employee(employee)
                                        employees.append(employee)
                
        except Exception as e:
            print(f"[!] Extract employees from {url} error: {e}")
        
        return employees
    
    # ==================== Source: Search Engines ====================
    
    async def enumerate_search_engines(self) -> List[Employee]:
        """Search for employees via search engines"""
        if not self.config.use_search_engines:
            return []
        
        print(f"[+] Searching for employees via search engines for {self.company_name}")
        employees = []
        
        # Search queries for employee discovery
        queries = [
            f'site:linkedin.com "{self.company_name}" "employee" OR "staff" OR "team"',
            f'site:linkedin.com "{self.company_name}" "software engineer" OR "developer" OR "engineer"',
            f'"{self.company_name}" "team" OR "staff" OR "employees"',
            f'"{self.company_name}" "software engineer" OR "developer"',
            f'site:github.com "{self.company_name}"',
            f'"{self.company_name}" "CTO" OR "VP Engineering" OR "Director"',
        ]
        
        engines = [
            ('duckduckgo', 'https://html.duckduckgo.com/html/', {'q': '{query}'}),
            ('bing', 'https://www.bing.com/search', {'q': '{query}'}),
        ]
        
        for engine_name, base_url, params_template in engines:
            for query in queries[:4]:  # Limit queries per engine
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
                        
                        # Extract LinkedIn profile URLs
                        linkedin_urls = re.findall(
                            r'linkedin\.com/in/([a-zA-Z0-9\-_]+)', html
                        )
                        
                        for li_id in linkedin_urls[:20]:  # Limit per query
                            # Would need to fetch profile for details
                            pass
                        
                        # Extract names from snippets
                        snippets = re.findall(
                            r'<a[^>]*class="[^"]*result[^"]*"[^>]*>([^<]+)</a>', html
                        )
                        
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                        
                except Exception as e:
                    print(f"[!] {engine_name} search error: {e}")
                    self.stats['errors'] += 1
        
        return employees
    
    # ==================== Source: Hunter.io ====================
    
    async def enumerate_hunter(self) -> List[Employee]:
        """Get employees from Hunter.io"""
        if not self.config.use_hunter or not self.config.hunter_api_key:
            return []
        
        print(f"[+] Getting employees from Hunter.io for {self.domain}")
        employees = []
        
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
                    employee = Employee(
                        name=f"{email_data.get('first_name', '')} {email_data.get('last_name', '')}".strip(),
                        first_name=email_data.get('first_name'),
                        last_name=email_data.get('last_name'),
                        title=email_data.get('position'),
                        department=email_data.get('department'),
                        company=self.company_name,
                        email=email_data.get('value'),
                        phone=email_data.get('phone'),
                        linkedin=email_data.get('linkedin'),
                        twitter=email_data.get('twitter'),
                        source='hunter.io',
                        confidence=90,
                        verified=email_data.get('verification', {}).get('status') == 'valid',
                        verification_date=email_data.get('verification', {}).get('date')
                    )
                    if self._matches_filters(employee):
                        self._add_employee(employee)
                        employees.append(employee)
            
            elif resp and resp.status == 401:
                print("[!] Hunter.io: Invalid API key")
                
        except Exception as e:
            print(f"[!] Hunter.io error: {e}")
            self.stats['errors'] += 1
        
        return employees
    
    # ==================== Main Run Method ====================
    
    async def run(self) -> Dict[str, Any]:
        """Run all employee enumeration sources"""
        print(f"[+] Starting employee enumeration for {self.company_name} ({self.domain})")
        
        # Run all sources concurrently where possible
        tasks = []
        
        if self.config.use_github:
            tasks.append(self.enumerate_github_org())
            tasks.append(self.enumerate_github_search())
        
        if self.config.use_company_pages:
            tasks.append(self.enumerate_company_pages())
        
        if self.config.use_search_engines:
            tasks.append(self.enumerate_search_engines())
        
        if self.config.use_hunter and self.config.hunter_api_key:
            tasks.append(self.enumerate_hunter())
        
        if self.config.use_linkedin and self.config.linkedin_cookie:
            tasks.append(self.enumerate_linkedin())
        
        # Run concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter results
        filtered_employees = [e for e in self.found_employees.values() if self._matches_filters(e)]
        
        # Prepare results
        results = {
            'domain': self.domain,
            'company_name': self.company_name,
            'stats': self.stats,
            'employees': [
                {
                    'name': e.name,
                    'first_name': e.first_name,
                    'last_name': e.last_name,
                    'title': e.title,
                    'department': e.department,
                    'company': e.company,
                    'location': e.location,
                    'email': e.email,
                    'phone': e.phone,
                    'linkedin': e.linkedin,
                    'twitter': e.twitter,
                    'github': e.github,
                    'source': e.source,
                    'confidence': e.confidence,
                    'profile_url': e.profile_url,
                    'summary': e.summary,
                    'skills': e.skills,
                    'education': e.education,
                    'experience': e.experience
                }
                for e in sorted(filtered_employees, key=lambda x: -x.confidence)
            ]
        }
        
        print(f"[+] Found {len(filtered_employees)} employees")
        print(f"[+] By source: {dict(self.stats['by_source'])}")
        print(f"[+] With email: {self.stats['with_email']}, LinkedIn: {self.stats['with_linkedin']}, GitHub: {self.stats['with_github']}")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python employee_enum.py <domain> [company_name] [--github-token TOKEN] [--hunter-key KEY]")
        return
    
    domain = sys.argv[1]
    company_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Parse optional args
    github_token = None
    hunter_key = None
    for i, arg in enumerate(sys.argv):
        if arg == '--github-token' and i + 1 < len(sys.argv):
            github_token = sys.argv[i + 1]
        elif arg == '--hunter-key' and i + 1 < len(sys.argv):
            hunter_key = sys.argv[i + 1]
    
    config = EmployeeEnumConfig(
        github_token=github_token,
        hunter_api_key=hunter_key
    )
    
    enumerator = EmployeeEnumerator(domain, company_name, config)
    results = await enumerator.run()
    await enumerator.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())