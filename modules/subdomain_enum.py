"""
Subdomain Enumeration Module
"""

import asyncio
import aiohttp
import re
import json
from typing import List, Set, Dict, Optional
import dns.resolver
from utils import StealthScheduler


class SubdomainEnumerator:
    """Subdomain enumeration using multiple sources"""
    
    def __init__(self, domain: str, wordlist_path: str = None, threads: int = 50, 
                 api_keys: Dict[str, str] = None, recursive: bool = False, max_depth: int = 2,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.api_keys = api_keys or {}
        self.recursive = recursive
        self.max_depth = max_depth
        self.stealth_scheduler = stealth_scheduler
        self.found_subdomains: Set[str] = set()
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _stealth_get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            from utils import fetch_with_stealth
            return await fetch_with_stealth(session, url, self.stealth_scheduler, **kwargs)
        else:
            try:
                return await session.get(url, **kwargs)
            except Exception:
                return None
    
    async def _stealth_post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a POST request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            from utils import fetch_with_stealth
            return await fetch_with_stealth(session, url, self.stealth_scheduler, method='POST', **kwargs)
        else:
            try:
                return await session.post(url, **kwargs)
            except Exception:
                return None
    
    def _filter_subdomains(self, subdomains: List[str]) -> List[str]:
        """Filter subdomains to only include valid ones for target domain"""
        filtered = []
        for sub in subdomains:
            sub = sub.strip().lower().rstrip('.')
            if sub.endswith(f'.{self.domain}') or sub == self.domain:
                # Remove wildcard entries
                if not sub.startswith('*.'):
                    filtered.append(sub)
        return list(set(filtered))
    
    async def enumerate_crtsh(self) -> List[str]:
        """Enumerate subdomains from crt.sh"""
        subdomains = []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            subdomains.append(subdomain)
        except Exception as e:
            print(f"[!] crt.sh error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_dnsdumpster(self) -> List[str]:
        """Enumerate subdomains from DNSDumpster"""
        subdomains = []
        url = "https://dnsdumpster.com/"
        
        try:
            # First get the page to get CSRF token
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                html = await resp.text()
                # Extract CSRF token
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
                if not csrf_match:
                    print("[!] DNSDumpster: Could not find CSRF token")
                    return []
                
                csrf_token = csrf_match.group(1)
                
                # Submit the form
                headers = {
                    'Referer': url,
                    'Origin': 'https://dnsdumpster.com',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': self.domain,
                    'user': 'free',
                }
                
                resp = await self._stealth_post(url, headers=headers, data=data)
                if resp and resp.status == 200:
                    result_html = await resp.text()
                    # Parse subdomains from results table
                    subdomain_pattern = r'<td class="col-md-4">([^<]+)</td>'
                    matches = re.findall(subdomain_pattern, result_html)
                    for match in matches:
                        match = match.strip()
                        if match.endswith(f'.{self.domain}') or match == self.domain:
                            subdomains.append(match)
        except Exception as e:
            print(f"[!] DNSDumpster error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_securitytrails(self) -> List[str]:
        """Enumerate subdomains from SecurityTrails (requires API key)"""
        subdomains = []
        api_key = self.api_keys.get('securitytrails')
        if not api_key:
            return []
        
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {'APIKEY': api_key}
        
        try:
            resp = await self._stealth_get(url, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json()
                for sub in data.get('subdomains', []):
                    subdomains.append(f"{sub}.{self.domain}")
            elif resp and resp.status == 403:
                print("[!] SecurityTrails: Invalid API key or quota exceeded")
            elif resp:
                print(f"[!] SecurityTrails error: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] SecurityTrails error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_shodan(self) -> List[str]:
        """Enumerate subdomains from Shodan (requires API key)"""
        subdomains = []
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return []
        
        url = f"https://api.shodan.io/dns/domain/{self.domain}?key={api_key}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                for record in data.get('data', []):
                    subdomain = record.get('subdomain', '')
                    if subdomain:
                        subdomains.append(f"{subdomain}.{self.domain}")
            elif resp and resp.status == 401:
                print("[!] Shodan: Invalid API key")
            elif resp:
                print(f"[!] Shodan error: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] Shodan error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_censys(self) -> List[str]:
        """Enumerate subdomains from Censys (requires API key)"""
        subdomains = []
        api_id = self.api_keys.get('censys_id')
        api_secret = self.api_keys.get('censys_secret')
        if not api_id or not api_secret:
            return []
        
        import base64
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        url = f"https://search.censys.io/api/v2/hosts/search?q={self.domain}&per_page=100"
        headers = {'Authorization': f'Basic {auth}'}
        
        try:
            resp = await self._stealth_get(url, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json()
                for hit in data.get('result', {}).get('hits', []):
                    names = hit.get('names', [])
                    for name in names:
                        if name.endswith(f'.{self.domain}') or name == self.domain:
                            subdomains.append(name)
            elif resp and resp.status == 401:
                print("[!] Censys: Invalid API credentials")
            elif resp:
                print(f"[!] Censys error: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] Censys error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_hackertarget(self) -> List[str]:
        """Enumerate subdomains from HackerTarget"""
        subdomains = []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                if "error" not in text.lower() and "api count exceeded" not in text.lower():
                    for line in text.strip().split('\n'):
                        if line:
                            parts = line.split(',')
                            if parts:
                                subdomains.append(parts[0].strip())
                else:
                    print("[!] HackerTarget: API limit exceeded or error")
        except Exception as e:
            print(f"[!] HackerTarget error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_rapiddns(self) -> List[str]:
        """Enumerate subdomains from RapidDNS"""
        subdomains = []
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0)'}
            resp = await self._stealth_get(url, headers=headers)
            if resp and resp.status == 200:
                html = await resp.text()
                # Parse table rows
                pattern = r'<td>([^<]+\.' + re.escape(self.domain) + r')</td>'
                matches = re.findall(pattern, html)
                subdomains.extend(matches)
        except Exception as e:
            print(f"[!] RapidDNS error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_alienvault_otx(self) -> List[str]:
        """Enumerate subdomains from AlienVault OTX"""
        subdomains = []
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '')
                    if hostname:
                        subdomains.append(hostname.rstrip('.'))
            elif resp and resp.status == 404:
                pass  # No data
            elif resp:
                print(f"[!] AlienVault OTX error: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] AlienVault OTX error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_virustotal(self) -> List[str]:
        """Enumerate subdomains from VirusTotal (requires API key)"""
        subdomains = []
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return []
        
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=40"
        headers = {'x-apikey': api_key}
        
        try:
            resp = await self._stealth_get(url, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain:
                        subdomains.append(subdomain)
            elif resp and resp.status == 401:
                print("[!] VirusTotal: Invalid API key")
            elif resp:
                print(f"[!] VirusTotal error: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] VirusTotal error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_wayback(self) -> List[str]:
        """Enumerate subdomains from Wayback Machine (CDX API)"""
        subdomains = []
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                if len(data) > 1:  # First row is header
                    for row in data[1:]:
                        if row:
                            url_str = row[0]
                            # Extract subdomain from URL
                            match = re.search(r'https?://([^/]+)', url_str)
                            if match:
                                host = match.group(1)
                                if host.endswith(f'.{self.domain}') or host == self.domain:
                                    subdomains.append(host)
        except Exception as e:
            print(f"[!] Wayback error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_bufferover(self) -> List[str]:
        """Enumerate subdomains from BufferOver (dns.bufferover.run)"""
        subdomains = []
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                for entry in data.get('FDNS_A', []):
                    parts = entry.split(',')
                    if len(parts) > 1:
                        subdomain = parts[1].strip()
                        if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                            subdomains.append(subdomain)
        except Exception as e:
            print(f"[!] BufferOver error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_threatcrowd(self) -> List[str]:
        """Enumerate subdomains from ThreatCrowd"""
        subdomains = []
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                for sub in data.get('subdomains', []):
                    subdomains.append(sub)
        except Exception as e:
            print(f"[!] ThreatCrowd error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_anubis(self) -> List[str]:
        """Enumerate subdomains from AnubisDB"""
        subdomains = []
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                data = await resp.json()
                subdomains.extend(data)
        except Exception as e:
            print(f"[!] Anubis error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def enumerate_riddler(self) -> List[str]:
        """Enumerate subdomains from Riddler.io"""
        subdomains = []
        url = f"https://riddler.io/search/exportcsv?q=pld:{self.domain}"
        
        try:
            resp = await self._stealth_get(url)
            if resp and resp.status == 200:
                text = await resp.text()
                for line in text.strip().split('\n')[1:]:  # Skip header
                    if line:
                        parts = line.split(',')
                        if parts:
                            subdomain = parts[0].strip().strip('"')
                            if subdomain.endswith(f'.{self.domain}') or subdomain == self.domain:
                                subdomains.append(subdomain)
        except Exception as e:
            print(f"[!] Riddler error: {e}")
        
        return self._filter_subdomains(subdomains)
    
    async def brute_force(self, wordlist: List[str]) -> List[str]:
        """Brute force subdomains using wordlist with stealth timing"""
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async def check_subdomain(subdomain: str):
            async with semaphore:
                # Apply stealth delay before each DNS query
                if self.stealth_scheduler:
                    await self.stealth_scheduler.wait_before_request()
                try:
                    full_domain = f"{subdomain}.{self.domain}"
                    answers = resolver.resolve(full_domain, 'A')
                    if answers:
                        found.append(full_domain)
                except:
                    pass
        
        tasks = [check_subdomain(word) for word in wordlist]
        await asyncio.gather(*tasks)
        
        return found
    
    async def recursive_enum(self, subdomains: List[str], depth: int = 1) -> List[str]:
        """Recursively enumerate subdomains of discovered subdomains"""
        if depth >= self.max_depth or not self.recursive:
            return []
        
        all_new = []
        # Use a smaller wordlist for recursive enumeration
        recursive_wordlist = ['dev', 'test', 'staging', 'prod', 'api', 'admin', 'mail', 'web', 'app', 'vpn', 'git', 'ci', 'cdn', 'static', 'assets', 'img', 'images', 'js', 'css', 'api', 'v1', 'v2', 'beta', 'alpha', 'demo', 'sandbox', 'internal', 'private', 'secure', 'ssh', 'ftp', 'db', 'database', 'sql', 'redis', 'mongo', 'mq', 'queue', 'worker', 'job', 'cron', 'backup', 'bak', 'old', 'new', 'tmp', 'temp', 'logs', 'log', 'monitor', 'metrics', 'grafana', 'kibana', 'prometheus', 'alertmanager', 'jaeger', 'zipkin', 'consul', 'vault', 'nomad', 'k8s', 'kubernetes', 'rancher', 'argocd', 'flux', 'tekton', 'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'wiki', 'docs', 'readme', 'changelog', 'release', 'version', 'build', 'deploy', 'pipeline', 'artifact', 'package', 'registry', 'docker', 'helm', 'chart', 'operator', 'controller', 'crd', 'crds', 'csi', 'cni', 'ingress', 'egress', 'gateway', 'mesh', 'istio', 'linkerd', 'envoy', 'sidecar', 'init', 'pre', 'post', 'hook', 'webhook', 'event', 'trigger', 'action', 'workflow', 'job', 'cronjob', 'daemonset', 'statefulset', 'deployment', 'replicaset', 'pod', 'container', 'volume', 'pvc', 'pv', 'secret', 'configmap', 'service', 'endpoint', 'ingress', 'networkpolicy', 'rbac', 'role', 'rolebinding', 'clusterrole', 'clusterrolebinding', 'sa', 'serviceaccount', 'ns', 'namespace', 'quota', 'limit', 'range', 'priority', 'class', 'scheduler', 'node', 'taint', 'toleration', 'affinity', 'antiaffinity', 'topology', 'spread', 'constraint', 'label', 'annotation', 'selector', 'field', 'match', 'expressions', 'operator', 'in', 'notin', 'exists', 'doesnotexist', 'gt', 'lt']
        
        for subdomain in subdomains[:50]:  # Limit to first 50 to avoid explosion
            # Extract the subdomain part (remove main domain)
            if subdomain.endswith(f'.{self.domain}'):
                sub_part = subdomain[:-len(f'.{self.domain}')]
                # Try common prefixes for this subdomain
                for prefix in recursive_wordlist:
                    # Apply stealth delay before each DNS query
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                    new_sub = f"{prefix}.{sub_part}.{self.domain}"
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        answers = resolver.resolve(new_sub, 'A')
                        if answers:
                            all_new.append(new_sub)
                    except:
                        pass
        
        # Recursively enumerate deeper
        if all_new and depth < self.max_depth:
            deeper = await self.recursive_enum(all_new, depth + 1)
            all_new.extend(deeper)
        
        return all_new
    
    async def run(self, wordlist: List[str] = None, sources: List[str] = None) -> List[str]:
        """Run all enumeration methods"""
        all_subdomains = set()
        
        # Default sources to use
        available_sources = {
            'crtsh': self.enumerate_crtsh,
            'dnsdumpster': self.enumerate_dnsdumpster,
            'securitytrails': self.enumerate_securitytrails,
            'shodan': self.enumerate_shodan,
            'censys': self.enumerate_censys,
            'hackertarget': self.enumerate_hackertarget,
            'rapiddns': self.enumerate_rapiddns,
            'alienvault': self.enumerate_alienvault_otx,
            'virustotal': self.enumerate_virustotal,
            'wayback': self.enumerate_wayback,
            'bufferover': self.enumerate_bufferover,
            'threatcrowd': self.enumerate_threatcrowd,
            'anubis': self.enumerate_anubis,
            'riddler': self.enumerate_riddler,
        }
        
        # Filter sources if specified
        if sources:
            sources_to_run = {k: v for k, v in available_sources.items() if k in sources}
        else:
            sources_to_run = available_sources
        
        # Run all sources concurrently
        print(f"[+] Running {len(sources_to_run)} subdomain enumeration sources...")
        tasks = [func() for func in sources_to_run.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, (source_name, result) in enumerate(zip(sources_to_run.keys(), results)):
            if isinstance(result, Exception):
                print(f"[!] {source_name} error: {result}")
            elif result:
                all_subdomains.update(result)
                print(f"[+] {source_name} found {len(result)} subdomains")
        
        # Brute force
        if wordlist:
            bf_results = await self.brute_force(wordlist)
            all_subdomains.update(bf_results)
            print(f"[+] Brute force found {len(bf_results)} subdomains")
        
        # Recursive enumeration
        if self.recursive and all_subdomains:
            print(f"[+] Starting recursive enumeration (depth={self.max_depth})...")
            recursive_results = await self.recursive_enum(list(all_subdomains))
            all_subdomains.update(recursive_results)
            print(f"[+] Recursive enumeration found {len(recursive_results)} additional subdomains")
        
        return sorted(list(all_subdomains))


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python subdomain_enum.py <domain>")
        return
    
    domain = sys.argv[1]
    enum = SubdomainEnumerator(domain)
    results = await enum.run()
    
    for sub in results:
        print(sub)


if __name__ == "__main__":
    asyncio.run(main())