"""
Breach Intelligence Module - OSINT Phase 2
- HaveIBeenPwned integration
- DeHashed integration
- LeakCheck integration
- Email/domain breach checking
- Credential stuffing detection
- Stealth integration
"""

import asyncio
import aiohttp
import hashlib
import json
import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, quote_plus
from collections import defaultdict
from datetime import datetime

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class BreachRecord:
    """Breach record"""
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    modified_date: str
    pwn_count: int
    description: str
    logo_path: str
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool
    is_subscription_free: bool


@dataclass
class PasteRecord:
    """Paste record (from HIBP)"""
    id: str
    source: str
    title: str
    date: str
    email_count: int
    emails: List[str]


@dataclass
class BreachResult:
    """Breach check result for an email/domain"""
    email: str
    domain: str
    breaches: List[BreachRecord] = field(default_factory=list)
    pastes: List[PasteRecord] = field(default_factory=list)
    total_breaches: int = 0
    total_pastes: int = 0
    first_breach: Optional[str] = None
    last_breach: Optional[str] = None
    total_accounts: int = 0
    data_classes_exposed: Set[str] = field(default_factory=set)


@dataclass
class BreachIntelConfig:
    """Configuration for breach intelligence"""
    # API Keys
    hibp_api_key: Optional[str] = None
    dehashed_email: Optional[str] = None
    dehashed_key: Optional[str] = None
    leakcheck_key: Optional[str] = None
    
    # Sources to use
    use_hibp: bool = True
    use_dehashed: bool = True
    use_leakcheck: bool = True
    
    # Settings
    request_delay: float = 1.5
    timeout: int = 30
    max_retries: int = 3
    
    # Domain breach check
    check_domain_breaches: bool = True
    
    # Paste search
    search_pastes: bool = True
    
    # Filters
    min_breach_size: int = 0
    exclude_spam_lists: bool = True
    exclude_malware: bool = True
    
    # Domain to check (for domain-wide breach check)
    target_domain: str = ""


class BreachIntelligence:
    """Breach intelligence gatherer"""
    
    def __init__(self, target: str, config: BreachIntelConfig,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.target = target.lower()
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Results
        self.results: Dict[str, BreachResult] = {}
        self.all_breaches: List[BreachRecord] = []
        self.all_pastes: List[PasteRecord] = []
        
        self.stats = {
            'emails_checked': 0,
            'breaches_found': 0,
            'pastes_found': 0,
            'total_accounts_exposed': 0,
            'errors': 0
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 BreachIntelligence)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _stealth_get(self, url: str, headers: Dict = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=self.config.timeout, method='GET', headers=headers, **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=self.config.timeout, headers=headers, **kwargs)
            except Exception:
                return None
    
    def _get_hibp_headers(self) -> Dict[str, str]:
        """Get HIBP API headers"""
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'ReconTool/1.0 BreachIntelligence'
        }
        if self.config.hibp_api_key:
            headers['hibp-api-key'] = self.config.hibp_api_key
        return headers
    
    def _get_dehashed_headers(self) -> Dict[str, str]:
        """Get DeHashed API headers"""
        if not self.config.dehashed_email or not self.config.dehashed_key:
            return {}
        
        auth = base64.b64encode(
            f"{self.config.dehashed_email}:{self.config.dehashed_key}".encode()
        ).decode()
        
        return {
            'Accept': 'application/json',
            'Authorization': f'Basic {auth}',
            'User-Agent': 'ReconTool/1.0 BreachIntelligence'
        }
    
    def _get_leakcheck_headers(self) -> Dict[str, str]:
        """Get LeakCheck API headers"""
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'ReconTool/1.0 BreachIntelligence'
        }
        if self.config.leakcheck_key:
            headers['X-API-Key'] = self.config.leakcheck_key
        return headers
    
    # ==================== HaveIBeenPwned Methods ====================
    
    async def check_email_hibp(self, email: str) -> BreachResult:
        """Check email against HaveIBeenPwned"""
        result = BreachResult(email=email, domain=email.split('@')[1] if '@' in email else '')
        
        if not self.config.use_hibp:
            return result
        
        # Check breaches
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}"
        params = {'truncateResponse': 'false', 'includeUnverified': 'true'}
        
        try:
            headers = self._get_hibp_headers()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session=await self._get_session(),
                    url=url,
                    scheduler=self.stealth_scheduler,
                    params=params,
                    headers=self._get_hibp_headers(),
                    method='GET'
                )
            else:
                session = await self._get_session()
                resp = await session.get(url, params=params, headers=self._get_hibp_headers(), timeout=self.config.timeout)
            
            if resp and resp.status == 200:
                breaches_data = await resp.json()
                for breach_data in breaches_data:
                    breach = BreachRecord(
                        name=breach_data.get('Name', ''),
                        title=breach_data.get('Title', ''),
                        domain=breach_data.get('Domain', ''),
                        breach_date=breach_data.get('BreachDate', ''),
                        added_date=breach_data.get('AddedDate', ''),
                        modified_date=breach_data.get('ModifiedDate', ''),
                        pwn_count=breach_data.get('PwnCount', 0),
                        description=breach_data.get('Description', ''),
                        logo_path=breach_data.get('LogoPath', ''),
                        data_classes=breach_data.get('DataClasses', []),
                        is_verified=breach_data.get('IsVerified', False),
                        is_fabricated=breach_data.get('IsFabricated', False),
                        is_sensitive=breach_data.get('IsSensitive', False),
                        is_retired=breach_data.get('IsRetired', False),
                        is_spam_list=breach_data.get('IsSpamList', False),
                        is_malware=breach_data.get('IsMalware', False),
                        is_subscription_free=breach_data.get('IsSubscriptionFree', False)
                    )
                    
                    # Apply filters
                    if self.config.exclude_spam_lists and breach.is_spam_list:
                        continue
                    if self.config.exclude_malware and breach.is_malware:
                        continue
                    if breach.pwn_count < self.config.min_breach_size:
                        continue
                    
                    result.breaches.append(breach)
                    self.all_breaches.append(breach)
                    result.data_classes_exposed.update(breach.data_classes)
                
                result.total_breaches = len(result.breaches)
                if result.breaches:
                    result.first_breach = min(b.breach_date for b in result.breaches)
                    result.last_breach = max(b.breach_date for b in result.breaches)
                    result.total_accounts = sum(b.pwn_count for b in result.breaches)
            
            elif resp and resp.status == 404:
                # No breaches found
                pass
            elif resp and resp.status == 429:
                print("[!] HIBP: Rate limited")
                self.stats['errors'] += 1
            
            # Check pastes
            if self.config.search_pastes:
                await self._check_pastes_hibp(email, result)
            
        except Exception as e:
            print(f"[!] HIBP check error for {email}: {e}")
            self.stats['errors'] += 1
        
        return result
    
    async def _check_pastes_hibp(self, email: str, result: BreachResult):
        """Check pastes for email on HIBP"""
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote_plus(email)}"
        
        try:
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session=await self._get_session(),
                    url=url,
                    scheduler=self.stealth_scheduler,
                    headers=self._get_hibp_headers(),
                    method='GET'
                )
            else:
                session = await self._get_session()
                resp = await session.get(url, headers=self._get_hibp_headers(), timeout=self.config.timeout)
            
            if resp and resp.status == 200:
                pastes_data = await resp.json()
                for paste_data in pastes_data:
                    paste = PasteRecord(
                        id=paste_data.get('Id', ''),
                        source=paste_data.get('Source', ''),
                        title=paste_data.get('Title', ''),
                        date=paste_data.get('Date', ''),
                        email_count=paste_data.get('EmailCount', 0),
                        emails=paste_data.get('Emails', [])
                    )
                    result.pastes.append(paste)
                    self.all_pastes.append(paste)
                
                result.total_pastes = len(result.pastes)
            
        except Exception as e:
            print(f"[!] HIBP pastes error for {email}: {e}")
    
    async def check_domain_hibp(self, domain: str) -> List[BreachRecord]:
        """Check domain breaches on HIBP"""
        if not self.config.use_hibp or not self.config.check_domain_breaches:
            return []
        
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        params = {'domain': domain}
        
        try:
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session=await self._get_session(),
                    url=url,
                    scheduler=self.stealth_scheduler,
                    params=params,
                    headers=self._get_hibp_headers(),
                    method='GET'
                )
            else:
                session = await self._get_session()
                resp = await session.get(url, params=params, headers=self._get_hibp_headers(), timeout=self.config.timeout)
            
            if resp and resp.status == 200:
                breaches_data = await resp.json()
                breaches = []
                for breach_data in breaches_data:
                    breach = BreachRecord(
                        name=breach_data.get('Name', ''),
                        title=breach_data.get('Title', ''),
                        domain=breach_data.get('Domain', ''),
                        breach_date=breach_data.get('BreachDate', ''),
                        added_date=breach_data.get('AddedDate', ''),
                        modified_date=breach_data.get('ModifiedDate', ''),
                        pwn_count=breach_data.get('PwnCount', 0),
                        description=breach_data.get('Description', ''),
                        logo_path=breach_data.get('LogoPath', ''),
                        data_classes=breach_data.get('DataClasses', []),
                        is_verified=breach_data.get('IsVerified', False),
                        is_fabricated=breach_data.get('IsFabricated', False),
                        is_sensitive=breach_data.get('IsSensitive', False),
                        is_retired=breach_data.get('IsRetired', False),
                        is_spam_list=breach_data.get('IsSpamList', False),
                        is_malware=breach_data.get('IsMalware', False),
                        is_subscription_free=breach_data.get('IsSubscriptionFree', False)
                    )
                    
                    if self.config.exclude_spam_lists and breach.is_spam_list:
                        continue
                    if self.config.exclude_malware and breach.is_malware:
                        continue
                    if breach.pwn_count < self.config.min_breach_size:
                        continue
                    
                    breaches.append(breach)
                
                return breaches
            
        except Exception as e:
            print(f"[!] HIBP domain check error for {domain}: {e}")
            self.stats['errors'] += 1
        
        return []
    
    # ==================== DeHashed Methods ====================
    
    async def check_email_dehashed(self, email: str) -> BreachResult:
        """Check email against DeHashed"""
        result = BreachResult(email=email, domain=email.split('@')[1] if '@' in email else '')
        
        if not self.config.use_dehashed or not self.config.dehashed_email or not self.config.dehashed_key:
            return result
        
        url = "https://api.dehashed.com/search"
        params = {'query': email, 'size': 100}
        
        try:
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session=await self._get_session(),
                    url="https://api.dehashed.com/search",
                    scheduler=self.stealth_scheduler,
                    params=params,
                    headers=self._get_dehashed_headers(),
                    method='GET'
                )
            else:
                session = await self._get_session()
                resp = await session.get("https://api.dehashed.com/search", params=params, headers=self._get_dehashed_headers(), timeout=self.config.timeout)
            
            if resp and resp.status == 200:
                data = await resp.json()
                entries = data.get('entries', [])
                
                for entry in entries:
                    # DeHashed returns individual records
                    breach = BreachRecord(
                        name=entry.get('database_name', 'DeHashed'),
                        title=entry.get('database_name', 'DeHashed'),
                        domain=entry.get('domain', ''),
                        breach_date=entry.get('last_seen', ''),
                        added_date='',
                        modified_date='',
                        pwn_count=1,
                        description=f"DeHashed entry: {entry.get('email', '')}",
                        logo_path='',
                        data_classes=[entry.get('type', 'unknown')],
                        is_verified=True,
                        is_fabricated=False,
                        is_sensitive=False,
                        is_retired=False,
                        is_spam_list=False,
                        is_malware=False,
                        is_subscription_free=False
                    )
                    result.breaches.append(breach)
                    self.all_breaches.append(breach)
                    result.data_classes_exposed.add(entry.get('type', 'unknown'))
                
                result.total_breaches = len(result.breaches)
                result.total_accounts = len(result.breaches)
            
        except Exception as e:
            print(f"[!] DeHashed check error for {email}: {e}")
            self.stats['errors'] += 1
        
        return result
    
    # ==================== LeakCheck Methods ====================
    
    async def check_email_leakcheck(self, email: str) -> BreachResult:
        """Check email against LeakCheck"""
        result = BreachResult(email=email, domain=email.split('@')[1] if '@' in email else '')
        
        if not self.config.use_leakcheck or not self.config.leakcheck_key:
            return result
        
        url = f"https://leakcheck.net/api/public"
        params = {'key': self.config.leakcheck_key, 'check': email}
        
        try:
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session=await self._get_session(),
                    url=url,
                    scheduler=self.stealth_scheduler,
                    params=params,
                    headers=self._get_leakcheck_headers(),
                    method='GET'
                )
            else:
                session = await self._get_session()
                resp = await session.get(url, params=params, headers=self._get_leakcheck_headers(), timeout=self.config.timeout)
            
            if resp and resp.status == 200:
                data = await resp.json()
                
                if data.get('success') and data.get('found'):
                    for leak in data.get('result', []):
                        breach = BreachRecord(
                            name=leak.get('source', 'LeakCheck'),
                            title=leak.get('source', 'LeakCheck'),
                            domain=leak.get('domain', ''),
                            breach_date=leak.get('date', ''),
                            added_date='',
                            modified_date='',
                            pwn_count=1,
                            description=f"LeakCheck: {leak.get('line', '')[:200]}",
                            logo_path='',
                            data_classes=[leak.get('type', 'unknown')],
                            is_verified=True,
                            is_fabricated=False,
                            is_sensitive=False,
                            is_retired=False,
                            is_spam_list=False,
                            is_malware=False,
                            is_subscription_free=False
                        )
                        result.breaches.append(breach)
                        self.all_breaches.append(breach)
                        result.data_classes_exposed.add(leak.get('type', 'unknown'))
                    
                    result.total_breaches = len(result.breaches)
                    result.total_accounts = len(result.breaches)
            
        except Exception as e:
            print(f"[!] LeakCheck error for {email}: {e}")
            self.stats['errors'] += 1
        
        return result
    
    # ==================== Main Methods ====================
    
    async def check_email(self, email: str) -> BreachResult:
        """Check email against all sources"""
        email = email.lower().strip()
        
        # Check if already processed
        if email in self.results:
            return self.results[email]
        
        print(f"[+] Checking breaches for: {email}")
        self.stats['emails_checked'] += 1
        
        # Combine results from all sources
        combined_result = BreachResult(email=email, domain=email.split('@')[1] if '@' in email else '')
        
        # HIBP
        if self.config.use_hibp:
            hibp_result = await self.check_email_hibp(email)
            combined_result.breaches.extend(hibp_result.breaches)
            combined_result.pastes.extend(hibp_result.pastes)
        
        # DeHashed
        if self.config.use_dehashed:
            dehashed_result = await self.check_email_dehashed(email)
            combined_result.breaches.extend(dehashed_result.breaches)
        
        # LeakCheck
        if self.config.use_leakcheck:
            leakcheck_result = await self.check_email_leakcheck(email)
            combined_result.breaches.extend(leakcheck_result.breaches)
        
        # Deduplicate breaches by name
        seen = set()
        unique_breaches = []
        for breach in combined_result.breaches:
            if breach.name not in seen:
                seen.add(breach.name)
                unique_breaches.append(breach)
        
        combined_result.breaches = unique_breaches
        combined_result.total_breaches = len(combined_result.breaches)
        combined_result.total_pastes = len(combined_result.pastes)
        
        if combined_result.breaches:
            combined_result.first_breach = min(b.breach_date for b in combined_result.breaches if b.breach_date)
            combined_result.last_breach = max(b.breach_date for b in combined_result.breaches if b.breach_date)
            combined_result.total_accounts = sum(b.pwn_count for b in combined_result.breaches)
            for breach in combined_result.breaches:
                combined_result.data_classes_exposed.update(breach.data_classes)
        
        self.results[email] = combined_result
        self.stats['breaches_found'] += combined_result.total_breaches
        self.stats['pastes_found'] += combined_result.total_pastes
        self.stats['total_accounts_exposed'] += combined_result.total_accounts
        
        return combined_result
    
    async def check_emails(self, emails: List[str]) -> Dict[str, BreachResult]:
        """Check multiple emails"""
        results = {}
        
        for email in emails:
            result = await self.check_email(email)
            results[email] = result
            
            # Rate limiting
            if self.stealth_scheduler:
                await self.stealth_scheduler.wait_before_request()
        
        return results
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain for breaches"""
        print(f"[+] Checking domain breaches for: {domain}")
        
        results = {
            'domain': domain,
            'domain_breaches': [],
            'email_breaches': {}
        }
        
        # Check domain breaches on HIBP
        if self.config.use_hibp and self.config.check_domain_breaches:
            domain_breaches = await self.check_domain_hibp(domain)
            results['domain_breaches'] = [
                {
                    'name': b.name,
                    'title': b.title,
                    'domain': b.domain,
                    'breach_date': b.breach_date,
                    'pwn_count': b.pwn_count,
                    'data_classes': b.data_classes,
                    'is_verified': b.is_verified,
                    'is_sensitive': b.is_sensitive
                }
                for b in domain_breaches
            ]
        
        # Get emails from other modules (email_harvester, employee_enum)
        # This would be populated from other module results
        
        return results
    
    async def run(self, emails: List[str] = None) -> Dict[str, Any]:
        """Run breach intelligence"""
        print(f"[+] Starting breach intelligence for {self.target}")
        
        all_emails = emails or []
        
        # If no emails provided, try to get from target domain
        if not all_emails:
            # Try common patterns
            common_prefixes = ['admin', 'info', 'support', 'contact', 'sales', 'hr', 'security', 'it', 'dev', 'test']
            all_emails = [f"{prefix}@{self.target}" for prefix in common_prefixes]
        
        # Check all emails
        email_results = await self.check_emails(all_emails)
        
        # Check domain breaches
        domain_results = await self.check_domain(self.target)
        
        # Prepare results
        results = {
            'target': self.target,
            'stats': self.stats,
            'email_results': {
                email: {
                    'email': r.email,
                    'domain': r.domain,
                    'total_breaches': r.total_breaches,
                    'total_pastes': r.total_pastes,
                    'first_breach': r.first_breach,
                    'last_breach': r.last_breach,
                    'total_accounts': r.total_accounts,
                    'data_classes_exposed': list(r.data_classes_exposed),
                    'breaches': [
                        {
                            'name': b.name,
                            'title': b.title,
                            'domain': b.domain,
                            'breach_date': b.breach_date,
                            'pwn_count': b.pwn_count,
                            'data_classes': b.data_classes,
                            'is_verified': b.is_verified,
                            'is_fabricated': b.is_fabricated,
                            'is_sensitive': b.is_sensitive,
                            'is_retired': b.is_retired,
                            'is_spam_list': b.is_spam_list,
                            'is_malware': b.is_malware
                        }
                        for b in r.breaches
                    ],
                    'pastes': [
                        {
                            'id': p.id,
                            'source': p.source,
                            'title': p.title,
                            'date': p.date,
                            'email_count': p.email_count
                        }
                        for p in r.pastes
                    ]
                }
                for email, r in email_results.items()
            },
            'domain_results': domain_results,
            'summary': {
                'total_emails_checked': self.stats['emails_checked'],
                'total_breaches_found': self.stats['breaches_found'],
                'total_pastes_found': self.stats['pastes_found'],
                'total_accounts_exposed': self.stats['total_accounts_exposed'],
                'unique_data_classes': list(set().union(*[set(r.data_classes_exposed) for r in email_results.values()]))
            }
        }
        
        print(f"[+] Checked {self.stats['emails_checked']} emails")
        print(f"[+] Found {self.stats['breaches_found']} breaches, {self.stats['pastes_found']} pastes")
        print(f"[+] Total accounts exposed: {self.stats['total_accounts_exposed']}")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python breach_intel.py <domain> [--hibp-key KEY] [--dehashed-email EMAIL --dehashed-key KEY] [--leakcheck-key KEY]")
        return
    
    domain = sys.argv[1]
    
    # Parse optional args
    hibp_key = None
    dehashed_email = None
    dehashed_key = None
    leakcheck_key = None
    
    for i, arg in enumerate(sys.argv):
        if arg == '--hibp-key' and i + 1 < len(sys.argv):
            hibp_key = sys.argv[i + 1]
        elif arg == '--dehashed-email' and i + 1 < len(sys.argv):
            dehashed_email = sys.argv[i + 1]
        elif arg == '--dehashed-key' and i + 1 < len(sys.argv):
            dehashed_key = sys.argv[i + 1]
        elif arg == '--leakcheck-key' and i + 1 < len(sys.argv):
            leakcheck_key = sys.argv[i + 1]
    
    config = BreachIntelConfig(
        hibp_api_key=hibp_key,
        dehashed_email=dehashed_email,
        dehashed_key=dehashed_key,
        leakcheck_key=leakcheck_key
    )
    
    intel = BreachIntelligence(domain, config)
    results = await intel.run()
    await intel.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())