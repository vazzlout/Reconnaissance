"""
HTTP Reconnaissance Module
- HTTP headers analysis
- Technology fingerprinting
- SSL/TLS certificate analysis
- CDN/WAF detection
- HTTP methods testing
- Security headers audit
"""

import asyncio
import aiohttp
import ssl
import socket
import re
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import certifi

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class HTTPResponse:
    """HTTP response data"""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float
    ssl_info: Optional[Dict] = None
    redirect_chain: List[str] = field(default_factory=list)


@dataclass
class Technology:
    """Detected technology"""
    name: str
    version: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    confidence: int = 100  # 0-100
    evidence: Dict[str, str] = field(default_factory=dict)


@dataclass
class SecurityHeaders:
    """Security headers analysis"""
    csp: Optional[str] = None
    hsts: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    x_xss_protection: Optional[str] = None
    cross_origin_embedder_policy: Optional[str] = None
    cross_origin_opener_policy: Optional[str] = None
    cross_origin_resource_policy: Optional[str] = None
    
    # Analysis
    missing: List[str] = field(default_factory=list)
    weak: List[str] = field(default_factory=list)
    score: int = 0  # 0-100


@dataclass
class CDNWAFDetection:
    """CDN/WAF detection result"""
    detected: bool = False
    cdn: Optional[str] = None
    waf: Optional[str] = None
    evidence: Dict[str, str] = field(default_factory=dict)
    confidence: int = 0


class HTTPRecon:
    """HTTP Reconnaissance"""
    
    # Technology fingerprints (simplified - in production use Wappalyzer database)
    TECH_FINGERPRINTS = {
        # Web Servers
        'nginx': {
            'headers': {'server': r'nginx'},
            'categories': ['Web Server']
        },
        'apache': {
            'headers': {'server': r'apache'},
            'categories': ['Web Server']
        },
        'iis': {
            'headers': {'server': r'iis|microsoft-iis'},
            'categories': ['Web Server']
        },
        'cloudflare': {
            'headers': {'server': r'cloudflare', 'cf-ray': r'.+'},
            'categories': ['CDN', 'WAF']
        },
        'openresty': {
            'headers': {'server': r'openresty'},
            'categories': ['Web Server']
        },
        'caddy': {
            'headers': {'server': r'caddy'},
            'categories': ['Web Server']
        },
        'litespeed': {
            'headers': {'server': r'litespeed'},
            'categories': ['Web Server']
        },
        
        # CMS
        'wordpress': {
            'headers': {'x-powered-by': r'wordpress', 'link': r'wp-json'},
            'body': [r'wp-content', r'wp-includes', r'wordpress'],
            'categories': ['CMS']
        },
        'drupal': {
            'headers': {'x-generator': r'drupal', 'x-drupal-cache': r'.+'},
            'body': [r'drupal', r'sites/default/files'],
            'categories': ['CMS']
        },
        'joomla': {
            'headers': {'x-content-encoded-by': r'joomla'},
            'body': [r'joomla', r'com_content', r'/media/jui/'],
            'categories': ['CMS']
        },
        'magento': {
            'headers': {'x-magento': r'.+'},
            'body': [r'mage/', r'magento', r'Mage_Core'],
            'categories': ['CMS', 'E-commerce']
        },
        'shopify': {
            'headers': {'x-shopify-stage': r'.+', 'x-shopify-shop': r'.+'},
            'body': [r'shopify', r'cdn.shopify.com'],
            'categories': ['CMS', 'E-commerce']
        },
        
        # Frameworks
        'django': {
            'headers': {'x-frame-options': r'deny', 'server': r'gunicorn|uwsgi'},
            'body': [r'csrftoken', r'django'],
            'categories': ['Framework']
        },
        'rails': {
            'headers': {'x-powered-by': r'rails', 'x-runtime': r'.+'},
            'body': [r'rails', r'authenticity_token'],
            'categories': ['Framework']
        },
        'laravel': {
            'headers': {'x-powered-by': r'laravel'},
            'body': [r'laravel_session', r'laravel_token'],
            'categories': ['Framework']
        },
        'express': {
            'headers': {'x-powered-by': r'express'},
            'categories': ['Framework']
        },
        'spring': {
            'headers': {'x-powered-by': r'spring'},
            'body': [r'jsessionid', r'spring'],
            'categories': ['Framework']
        },
        'asp.net': {
            'headers': {'x-powered-by': r'asp\.net', 'x-aspnet-version': r'.+'},
            'categories': ['Framework']
        },
        'nextjs': {
            'headers': {'x-powered-by': r'next\.js'},
            'body': [r'_next/static', r'__NEXT_DATA__'],
            'categories': ['Framework']
        },
        'nuxt': {
            'headers': {},
            'body': [r'_nuxt/', r'nuxt'],
            'categories': ['Framework']
        },
        
        # JavaScript Libraries
        'react': {
            'body': [r'react', r'react-dom', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
            'categories': ['JavaScript Library']
        },
        'vue': {
            'body': [r'vue\.js', r'vuejs', r'__VUE__'],
            'categories': ['JavaScript Library']
        },
        'angular': {
            'body': [r'angular', r'ng-app', r'ng-controller'],
            'categories': ['JavaScript Library']
        },
        'jquery': {
            'body': [r'jquery', r'jQuery'],
            'categories': ['JavaScript Library']
        },
        
        # Analytics/Tracking
        'google-analytics': {
            'body': [r'google-analytics', r'gtag\(', r'ga\('],
            'categories': ['Analytics']
        },
        'google-tag-manager': {
            'body': [r'googletagmanager', r'gtm\.js'],
            'categories': ['Analytics']
        },
        'facebook-pixel': {
            'body': [r'fbevents\.js', r'fbq\('],
            'categories': ['Analytics']
        },
        'hotjar': {
            'body': [r'hotjar', r'hj\('],
            'categories': ['Analytics']
        },
        
        # Security
        'mod_security': {
            'headers': {'server': r'mod_security'},
            'categories': ['WAF']
        },
        'sucuri': {
            'headers': {'server': r'sucuri', 'x-sucuri-id': r'.+'},
            'categories': ['WAF', 'CDN']
        },
        'incapsula': {
            'headers': {'x-cdn': r'incapsula', 'x-iinfo': r'.+'},
            'categories': ['WAF', 'CDN']
        },
        'akamai': {
            'headers': {'server': r'akamai', 'x-akamai': r'.+'},
            'categories': ['CDN']
        },
        'fastly': {
            'headers': {'server': r'fastly', 'x-served-by': r'.+', 'via': r'fastly'},
            'categories': ['CDN']
        },
        'aws-cloudfront': {
            'headers': {'via': r'cloudfront', 'x-amz-cf-id': r'.+'},
            'categories': ['CDN']
        },
        'azure-front-door': {
            'headers': {'x-azure-ref': r'.+'},
            'categories': ['CDN']
        },
    }
    
    # CDN/WAF signatures
    CDN_WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare'],
            'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
            'body': ['cloudflare', 'attention required! | cloudflare']
        },
        'akamai': {
            'headers': ['x-akamai-transformed', 'x-akamai-edgescape', 'akamai-origin-hop', 'server: akamai'],
            'cookies': ['akamai'],
            'body': ['akamai', 'reference #']
        },
        'fastly': {
            'headers': ['fastly', 'x-served-by', 'x-cache', 'x-cache-hits', 'via: fastly'],
            'cookies': [],
            'body': ['fastly', 'varnish']
        },
        'aws-cloudfront': {
            'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'via: cloudfront'],
            'cookies': ['cloudfront'],
            'body': ['cloudfront', 'generated by cloudfront']
        },
        'azure-front-door': {
            'headers': ['x-azure-ref', 'x-azure-fdid', 'x-azure-socketip'],
            'cookies': [],
            'body': []
        },
        'incapsula': {
            'headers': ['x-cdn: incapsula', 'x-iinfo', 'incap_ses', 'visid_incap'],
            'cookies': ['incap_ses', 'visid_incap', 'nlbi_'],
            'body': ['incapsula', 'incap_']
        },
        'sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache', 'server: sucuri'],
            'cookies': ['sucuri_cloudproxy_uuid'],
            'body': ['sucuri', 'cloudproxy']
        },
        'imperva': {
            'headers': ['x-iinfo', 'x-cdn: imperva', 'incap_ses'],
            'cookies': ['incap_ses', 'visid_incap', 'nlbi_'],
            'body': ['imperva', 'incapsula']
        },
        'f5-bigip': {
            'headers': ['x-wa-info', 'server: bigip', 'x-f5'],
            'cookies': ['bigipserver', 'ts', 'mr'],
            'body': ['f5', 'bigip']
        },
        'barracuda': {
            'headers': ['barracuda', 'x-barracuda'],
            'cookies': ['barracuda'],
            'body': ['barracuda', 'barra']
        },
        'fortinet': {
            'headers': ['fortiwaf', 'x-fortiwaf'],
            'cookies': ['fortiwafsid'],
            'body': ['fortinet', 'fortiwaf']
        },
    }
    
    def __init__(self, target: str, stealth_scheduler: Optional[StealthScheduler] = None,
                 timeout: int = 10, follow_redirects: bool = True, max_redirects: int = 10):
        self.target = target
        self.stealth_scheduler = stealth_scheduler
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Normalize target to URL
        if not target.startswith(('http://', 'https://')):
            self.base_url = f"https://{target}"
        else:
            self.base_url = target
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(
                ssl=ssl.create_default_context(cafile=certifi.where()),
                limit=10,
                limit_per_host=5
            )
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def fetch(self, url: str, method: str = 'GET', **kwargs) -> Optional[HTTPResponse]:
        """Fetch URL with stealth timing"""
        import time
        start_time = time.time()
        
        session = await self._get_session()
        
        try:
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=self.timeout, method=method, **kwargs
                )
            else:
                if method == 'GET':
                    resp = await session.get(url, timeout=self.timeout, **kwargs)
                elif method == 'HEAD':
                    resp = await session.head(url, timeout=self.timeout, **kwargs)
                elif method == 'OPTIONS':
                    resp = await session.options(url, timeout=self.timeout, **kwargs)
                else:
                    resp = await session.request(method, url, timeout=self.timeout, **kwargs)
            
            if resp is None:
                return None
            
            response_time = time.time() - start_time
            
            # Read body
            body = await resp.text()
            
            # Build redirect chain
            redirect_chain = []
            if resp.history:
                for r in resp.history:
                    redirect_chain.append(str(r.url))
            redirect_chain.append(str(resp.url))
            
            # Get SSL info if HTTPS
            ssl_info = None
            if str(resp.url).startswith('https://'):
                ssl_info = await self._get_ssl_info(urlparse(str(resp.url)).hostname)
            
            return HTTPResponse(
                url=str(resp.url),
                status_code=resp.status,
                headers=dict(resp.headers),
                body=body,
                response_time=response_time,
                ssl_info=ssl_info,
                redirect_chain=redirect_chain
            )
            
        except asyncio.TimeoutError:
            print(f"[!] Timeout fetching {url}")
        except aiohttp.ClientError as e:
            print(f"[!] Client error fetching {url}: {e}")
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
        
        return None
    
    async def _get_ssl_info(self, hostname: str) -> Optional[Dict]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Parse certificate
                    san = []
                    if cert:
                        for ext in cert.get('subjectAltName', []):
                            san.append(ext[1])
                    
                    return {
                        'version': version,
                        'cipher': cipher[0] if cipher else None,
                        'cipher_version': cipher[1] if cipher else None,
                        'cipher_bits': cipher[2] if cipher else None,
                        'subject': dict(x[0] for x in cert.get('subject', [])) if cert else {},
                        'issuer': dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                        'san': san,
                        'not_before': cert.get('notBefore') if cert else None,
                        'not_after': cert.get('notAfter') if cert else None,
                        'serial_number': cert.get('serialNumber') if cert else None,
                    }
        except Exception as e:
            print(f"[!] SSL info error for {hostname}: {e}")
        
        return None
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers for information disclosure"""
        findings = {
            'server': headers.get('server', ''),
            'x_powered_by': headers.get('x-powered-by', ''),
            'x_aspnet_version': headers.get('x-aspnet-version', ''),
            'x_runtime': headers.get('x-runtime', ''),
            'x_version': headers.get('x-version', ''),
            'x_generator': headers.get('x-generator', ''),
            'via': headers.get('via', ''),
            'x_cache': headers.get('x-cache', ''),
            'x_cache_hits': headers.get('x-cache-hits', ''),
            'cf_ray': headers.get('cf-ray', ''),
            'x_amz_cf_id': headers.get('x-amz-cf-id', ''),
            'x_azure_ref': headers.get('x-azure-ref', ''),
            'interesting': []
        }
        
        # Check for interesting headers
        interesting_headers = [
            'x-debug-token', 'x-debug-token-link', 'x-drupal-cache',
            'x-varnish', 'age', 'x-drupal-dynamic-cache', 'x-content-digest',
            'x-request-id', 'x-correlation-id', 'x-trace-id', 'x-span-id',
            'x-github-request-id', 'x-envoy-upstream-service-time'
        ]
        
        for h in interesting_headers:
            if h in headers:
                findings['interesting'].append({h: headers[h]})
        
        return findings
    
    def detect_technologies(self, response: HTTPResponse) -> List[Technology]:
        """Detect technologies from response"""
        technologies = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        body_lower = response.body.lower()
        
        for tech_name, signatures in self.TECH_FINGERPRINTS.items():
            confidence = 0
            evidence = {}
            matched = False
            
            # Check headers
            for header_name, pattern in signatures.get('headers', {}).items():
                header_value = headers_lower.get(header_name.lower(), '')
                if re.search(pattern, header_value, re.IGNORECASE):
                    confidence += 30
                    evidence[f'header:{header_name}'] = header_value
                    matched = True
            
            # Check body
            for pattern in signatures.get('body', []):
                if re.search(pattern, body_lower, re.IGNORECASE):
                    confidence += 20
                    evidence[f'body:{pattern}'] = 'matched'
                    matched = True
            
            # Check cookies
            for cookie_name, pattern in signatures.get('cookies', {}).items():
                cookie_header = headers_lower.get('set-cookie', '')
                if re.search(pattern, cookie_header, re.IGNORECASE):
                    confidence += 25
                    evidence[f'cookie:{cookie_name}'] = 'matched'
                    matched = True
            
            if matched:
                technologies.append(Technology(
                    name=tech_name,
                    categories=signatures.get('categories', []),
                    confidence=min(confidence, 100),
                    evidence=evidence
                ))
        
        # Sort by confidence
        technologies.sort(key=lambda t: t.confidence, reverse=True)
        return technologies
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> SecurityHeaders:
        """Analyze security headers"""
        sh = SecurityHeaders()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Extract headers
        sh.csp = headers_lower.get('content-security-policy')
        sh.hsts = headers_lower.get('strict-transport-security')
        sh.x_frame_options = headers_lower.get('x-frame-options')
        sh.x_content_type_options = headers_lower.get('x-content-type-options')
        sh.referrer_policy = headers_lower.get('referrer-policy')
        sh.permissions_policy = headers_lower.get('permissions-policy')
        sh.x_xss_protection = headers_lower.get('x-xss-protection')
        sh.cross_origin_embedder_policy = headers_lower.get('cross-origin-embedder-policy')
        sh.cross_origin_opener_policy = headers_lower.get('cross-origin-opener-policy')
        sh.cross_origin_resource_policy = headers_lower.get('cross-origin-resource-policy')
        
        # Analyze
        score = 100
        
        # CSP
        if not sh.csp:
            sh.missing.append('Content-Security-Policy')
            score -= 20
        elif 'unsafe-inline' in sh.csp or 'unsafe-eval' in sh.csp:
            sh.weak.append('CSP allows unsafe-inline/eval')
            score -= 10
        
        # HSTS
        if not sh.hsts:
            sh.missing.append('Strict-Transport-Security')
            score -= 15
        elif 'max-age=' in sh.hsts:
            try:
                max_age = int(re.search(r'max-age=(\d+)', sh.hsts).group(1))
                if max_age < 31536000:  # Less than 1 year
                    sh.weak.append('HSTS max-age less than 1 year')
                    score -= 5
            except:
                pass
        
        # X-Frame-Options
        if not sh.x_frame_options:
            sh.missing.append('X-Frame-Options')
            score -= 10
        elif sh.x_frame_options.upper() not in ['DENY', 'SAMEORIGIN']:
            sh.weak.append('X-Frame-Options not DENY or SAMEORIGIN')
            score -= 5
        
        # X-Content-Type-Options
        if not sh.x_content_type_options:
            sh.missing.append('X-Content-Type-Options')
            score -= 5
        elif sh.x_content_type_options.lower() != 'nosniff':
            sh.weak.append('X-Content-Type-Options not nosniff')
            score -= 3
        
        # Referrer-Policy
        if not sh.referrer_policy:
            sh.missing.append('Referrer-Policy')
            score -= 5
        
        # Permissions-Policy
        if not sh.permissions_policy:
            sh.missing.append('Permissions-Policy')
            score -= 5
        
        # X-XSS-Protection (deprecated but still checked)
        if not sh.x_xss_protection:
            sh.missing.append('X-XSS-Protection')
            score -= 3
        
        sh.score = max(score, 0)
        return sh
    
    def detect_cdn_waf(self, response: HTTPResponse) -> CDNWAFDetection:
        """Detect CDN/WAF"""
        result = CDNWAFDetection()
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        body_lower = response.body.lower()
        cookies = headers_lower.get('set-cookie', '').lower()
        
        best_match = None
        best_score = 0
        
        for name, signatures in self.CDN_WAF_SIGNATURES.items():
            score = 0
            evidence = {}
            
            # Check headers
            for pattern in signatures.get('headers', []):
                if ':' in pattern:
                    header_name, header_value = pattern.split(':', 1)
                    header_name = header_name.strip().lower()
                    header_value = header_value.strip()
                    actual_value = headers_lower.get(header_name, '')
                    if re.search(header_value, actual_value, re.IGNORECASE):
                        score += 10
                        evidence[f'header:{header_name}'] = actual_value
                else:
                    # Check any header contains pattern
                    for h, v in headers_lower.items():
                        if re.search(pattern, v, re.IGNORECASE):
                            score += 5
                            evidence[f'header:{h}'] = v
                            break
            
            # Check cookies
            for cookie_pattern in signatures.get('cookies', []):
                if re.search(cookie_pattern, cookies, re.IGNORECASE):
                    score += 8
                    evidence[f'cookie:{cookie_pattern}'] = 'matched'
            
            # Check body
            for body_pattern in signatures.get('body', []):
                if re.search(body_pattern, body_lower, re.IGNORECASE):
                    score += 5
                    evidence[f'body:{body_pattern}'] = 'matched'
            
            if score > best_score:
                best_score = score
                best_match = name
                result.evidence = evidence
        
        if best_match and best_score >= 10:
            result.detected = True
            result.confidence = min(best_score, 100)
            
            # Categorize as CDN or WAF
            cdn_list = ['cloudflare', 'akamai', 'fastly', 'aws-cloudfront', 'azure-front-door']
            waf_list = ['incapsula', 'sucuri', 'imperva', 'f5-bigip', 'barracuda', 'fortinet']
            
            if best_match in cdn_list:
                result.cdn = best_match
            elif best_match in waf_list:
                result.waf = best_match
            else:
                # Cloudflare is both
                if best_match == 'cloudflare':
                    result.cdn = 'cloudflare'
                    result.waf = 'cloudflare'
        
        return result
    
    async def test_http_methods(self, url: str) -> Dict[str, Any]:
        """Test HTTP methods"""
        methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT']
        results = {}
        
        for method in methods:
            try:
                resp = await self.fetch(url, method=method)
                if resp:
                    results[method] = {
                        'status': resp.status_code,
                        'allowed': resp.status_code not in [405, 501, 403],
                        'headers': dict(resp.headers)
                    }
                else:
                    results[method] = {'status': 0, 'allowed': False, 'error': 'No response'}
            except Exception as e:
                results[method] = {'status': 0, 'allowed': False, 'error': str(e)}
            
            # Small delay between methods
            if self.stealth_scheduler:
                await self.stealth_scheduler.wait_before_request()
        
        return results
    
    async def run(self) -> Dict[str, Any]:
        """Run full HTTP reconnaissance"""
        print(f"[+] Starting HTTP reconnaissance for {self.target}")
        
        # Fetch main page
        response = await self.fetch(self.base_url)
        if not response:
            return {'error': 'Failed to fetch target'}
        
        print(f"[+] Fetched {response.url} - Status: {response.status_code}")
        
        # Analyze
        results = {
            'target': self.target,
            'url': response.url,
            'status_code': response.status_code,
            'response_time': response.response_time,
            'redirect_chain': response.redirect_chain,
            'headers_analysis': self.analyze_headers(response.headers),
            'technologies': [t.__dict__ for t in self.detect_technologies(response)],
            'security_headers': self.analyze_security_headers(response.headers).__dict__,
            'cdn_waf': self.detect_cdn_waf(response).__dict__,
            'ssl_info': response.ssl_info,
            'http_methods': await self.test_http_methods(response.url)
        }
        
        # Summary
        tech_names = [t['name'] for t in results['technologies']]
        print(f"[+] Technologies detected: {', '.join(tech_names) if tech_names else 'None'}")
        
        if results['cdn_waf']['detected']:
            cdn = results['cdn_waf'].get('cdn')
            waf = results['cdn_waf'].get('waf')
            print(f"[+] CDN: {cdn or 'None'}, WAF: {waf or 'None'}")
        
        sh_score = results['security_headers']['score']
        print(f"[+] Security Headers Score: {sh_score}/100")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python http_recon.py <target>")
        return
    
    target = sys.argv[1]
    recon = HTTPRecon(target)
    results = await recon.run()
    await recon.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())