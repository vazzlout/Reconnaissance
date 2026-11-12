"""
Enhanced Technology Fingerprinting Module
- Wappalyzer-style fingerprinting
- Custom fingerprint database
- Version detection
- Confidence scoring
- Category classification
"""

import asyncio
import aiohttp
import re
import json
import hashlib
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from collections import defaultdict

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class Fingerprint:
    """Technology fingerprint"""
    name: str
    categories: List[str]
    website: str = ""
    description: str = ""
    # Detection patterns
    headers: Dict[str, str] = field(default_factory=dict)  # header_name: regex_pattern
    cookies: Dict[str, str] = field(default_factory=dict)  # cookie_name: regex_pattern
    html: List[str] = field(default_factory=list)  # regex patterns in HTML
    scripts: List[str] = field(default_factory=list)  # regex patterns in script src
    meta: Dict[str, str] = field(default_factory=dict)  # meta tag name: regex_pattern
    dns: Dict[str, str] = field(default_factory=dict)  # DNS record type: regex_pattern
    # Version detection
    version_patterns: List[str] = field(default_factory=list)
    # Implications
    implies: List[str] = field(default_factory=list)  # Other technologies this implies
    excludes: List[str] = field(default_factory=list)  # Technologies this excludes
    # Confidence
    confidence: int = 100  # Base confidence 0-100


@dataclass
class DetectedTechnology:
    """Detected technology with version and confidence"""
    name: str
    version: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    confidence: int = 0
    evidence: Dict[str, str] = field(default_factory=dict)
    fingerprint: Optional[Fingerprint] = None


class TechFingerprinter:
    """Enhanced Technology Fingerprinter with Wappalyzer-style detection"""
    
    def __init__(self, stealth_scheduler: Optional[StealthScheduler] = None,
                 timeout: int = 10, custom_fingerprints: Dict = None):
        self.stealth_scheduler = stealth_scheduler
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.fingerprints: Dict[str, Fingerprint] = {}
        self._load_fingerprints(custom_fingerprints)
    
    def _load_fingerprints(self, custom_fingerprints: Dict = None):
        """Load fingerprint database"""
        # Built-in fingerprints (subset of Wappalyzer)
        builtin = self._get_builtin_fingerprints()
        
        for fp_data in builtin:
            fp = Fingerprint(**fp_data)
            self.fingerprints[fp.name.lower()] = fp
        
        # Load custom fingerprints if provided
        if custom_fingerprints:
            for fp_data in custom_fingerprints:
                fp = Fingerprint(**fp_data)
                self.fingerprints[fp.name.lower()] = fp
    
    def _get_builtin_fingerprints(self) -> List[Dict]:
        """Get built-in fingerprint database"""
        return [
            # Web Servers
            {
                "name": "Nginx",
                "categories": ["Web Server"],
                "website": "https://nginx.org",
                "headers": {"server": r"nginx[^/]*/?([\d.]+)?"},
                "confidence": 100
            },
            {
                "name": "Apache",
                "categories": ["Web Server"],
                "website": "https://httpd.apache.org",
                "headers": {"server": r"apache[^/]*/?([\d.]+)?"},
                "confidence": 100
            },
            {
                "name": "IIS",
                "categories": ["Web Server"],
                "website": "https://www.iis.net",
                "headers": {"server": r"microsoft-iis/([\d.]+)"},
                "confidence": 100
            },
            {
                "name": "OpenResty",
                "categories": ["Web Server"],
                "website": "https://openresty.org",
                "headers": {"server": r"openresty/([\d.]+)"},
                "confidence": 100
            },
            {
                "name": "Caddy",
                "categories": ["Web Server"],
                "website": "https://caddyserver.com",
                "headers": {"server": r"caddy/([\d.]+)"},
                "confidence": 100
            },
            {
                "name": "LiteSpeed",
                "categories": ["Web Server"],
                "website": "https://www.litespeedtech.com",
                "headers": {"server": r"litespeed/([\d.]+)"},
                "confidence": 100
            },
            {
                "name": "Apache Tomcat",
                "categories": ["Web Server", "Application Server"],
                "website": "https://tomcat.apache.org",
                "headers": {"server": r"apache-tomcat/([\d.]+)"},
                "html": [r"apache tomcat"],
                "confidence": 100
            },
            {
                "name": "Jetty",
                "categories": ["Web Server", "Application Server"],
                "website": "https://www.eclipse.org/jetty/",
                "headers": {"server": r"jetty/([\d.]+)"},
                "confidence": 100
            },
            
            # CDN/WAF
            {
                "name": "Cloudflare",
                "categories": ["CDN", "WAF", "Security"],
                "website": "https://cloudflare.com",
                "headers": {
                    "server": r"cloudflare",
                    "cf-ray": r".+",
                    "cf-cache-status": r".+"
                },
                "cookies": {"__cfduid": r".+", "__cf_bm": r".+", "cf_clearance": r".+"},
                "html": [r"cloudflare", r"attention required! \| cloudflare"],
                "confidence": 100
            },
            {
                "name": "Akamai",
                "categories": ["CDN", "Security"],
                "website": "https://akamai.com",
                "headers": {
                    "server": r"akamai",
                    "x-akamai-transformed": r".+",
                    "akamai-origin-hop": r".+"
                },
                "html": [r"akamai", r"reference #\d+"],
                "confidence": 100
            },
            {
                "name": "Fastly",
                "categories": ["CDN"],
                "website": "https://fastly.com",
                "headers": {
                    "fastly": r".+",
                    "x-served-by": r".+",
                    "via": r"fastly"
                },
                "html": [r"fastly", r"varnish"],
                "confidence": 100
            },
            {
                "name": "AWS CloudFront",
                "categories": ["CDN"],
                "website": "https://aws.amazon.com/cloudfront/",
                "headers": {
                    "via": r"cloudfront",
                    "x-amz-cf-id": r".+",
                    "x-amz-cf-pop": r".+"
                },
                "html": [r"cloudfront", r"generated by cloudfront"],
                "confidence": 100
            },
            {
                "name": "Azure Front Door",
                "categories": ["CDN"],
                "website": "https://azure.microsoft.com/services/frontdoor/",
                "headers": {
                    "x-azure-ref": r".+",
                    "x-azure-fdid": r".+",
                    "x-azure-socketip": r".+"
                },
                "confidence": 100
            },
            {
                "name": "Incapsula",
                "categories": ["CDN", "WAF", "Security"],
                "website": "https://www.incapsula.com",
                "headers": {
                    "x-cdn": r"incapsula",
                    "x-iinfo": r".+"
                },
                "cookies": {"incap_ses": r".+", "visid_incap": r".+", "nlbi_": r".+"},
                "html": [r"incapsula", r"incap_"],
                "confidence": 100
            },
            {
                "name": "Sucuri",
                "categories": ["WAF", "Security", "CDN"],
                "website": "https://sucuri.net",
                "headers": {
                    "x-sucuri-id": r".+",
                    "x-sucuri-cache": r".+",
                    "server": r"sucuri"
                },
                "cookies": {"sucuri_cloudproxy_uuid": r".+"},
                "html": [r"sucuri", r"cloudproxy"],
                "confidence": 100
            },
            {
                "name": "Imperva",
                "categories": ["WAF", "Security", "CDN"],
                "website": "https://www.imperva.com",
                "headers": {
                    "x-iinfo": r".+",
                    "x-cdn": r"imperva"
                },
                "cookies": {"incap_ses": r".+", "visid_incap": r".+", "nlbi_": r".+"},
                "html": [r"imperva", r"incapsula"],
                "confidence": 100
            },
            {
                "name": "F5 BIG-IP",
                "categories": ["Load Balancer", "WAF"],
                "website": "https://www.f5.com",
                "headers": {
                    "x-wa-info": r".+",
                    "server": r"bigip",
                    "x-f5": r".+"
                },
                "cookies": {"bigipserver": r".+", "ts": r".+", "mr": r".+"},
                "html": [r"f5", r"bigip"],
                "confidence": 100
            },
            
            # CMS
            {
                "name": "WordPress",
                "categories": ["CMS", "Blog"],
                "website": "https://wordpress.org",
                "headers": {
                    "x-powered-by": r"wordpress",
                    "link": r"wp-json"
                },
                "html": [
                    r"wp-content",
                    r"wp-includes",
                    r"wordpress",
                    r"wp-json",
                    r"/wp-admin/",
                    r"/wp-login\.php"
                ],
                "scripts": [r"wp-includes/js", r"wp-content/plugins"],
                "meta": {"generator": r"wordpress\s*([\d.]+)?"},
                "version_patterns": [
                    r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)",
                    r"wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)",
                    r"generator.*wordpress\s*([\d.]+)"
                ],
                "implies": ["PHP", "MySQL"],
                "confidence": 100
            },
            {
                "name": "Drupal",
                "categories": ["CMS"],
                "website": "https://drupal.org",
                "headers": {
                    "x-generator": r"drupal\s*([\d.]+)?",
                    "x-drupal-cache": r".+",
                    "x-drupal-dynamic-cache": r".+"
                },
                "html": [
                    r"drupal",
                    r"sites/default/files",
                    r"drupal\.js",
                    r"drupal\.css"
                ],
                "meta": {"generator": r"drupal\s*([\d.]+)?"},
                "version_patterns": [
                    r"drupal\s*([\d.]+)",
                    r"core/assets/vendor/drupal/([\d.]+)"
                ],
                "implies": ["PHP", "MySQL"],
                "confidence": 100
            },
            {
                "name": "Joomla",
                "categories": ["CMS"],
                "website": "https://joomla.org",
                "headers": {
                    "x-content-encoded-by": r"joomla"
                },
                "html": [
                    r"joomla",
                    r"com_content",
                    r"/media/jui/",
                    r"joomla\.js"
                ],
                "meta": {"generator": r"joomla\s*([\d.]+)?"},
                "version_patterns": [
                    r"joomla\s*([\d.]+)",
                    r"media/jui/js/jquery-migrate\.min\.js\?v=([\d.]+)"
                ],
                "implies": ["PHP", "MySQL"],
                "confidence": 100
            },
            {
                "name": "Magento",
                "categories": ["CMS", "E-commerce"],
                "website": "https://magento.com",
                "headers": {
                    "x-magento": r".+"
                },
                "html": [
                    r"mage/",
                    r"magento",
                    r"mage_cookies",
                    r"mage-cache-storage"
                ],
                "cookies": {"mage-cache-storage": r".+", "mage-cache-sessid": r".+"},
                "meta": {"generator": r"magento\s*([\d.]+)?"},
                "version_patterns": [
                    r"magento/([\d.]+)",
                    r"mage/version/([\d.]+)"
                ],
                "implies": ["PHP", "MySQL"],
                "confidence": 100
            },
            {
                "name": "Shopify",
                "categories": ["CMS", "E-commerce", "SaaS"],
                "website": "https://shopify.com",
                "headers": {
                    "x-shopify-stage": r".+",
                    "x-shopify-shop": r".+",
                    "x-shopify-request-id": r".+"
                },
                "html": [
                    r"shopify",
                    r"cdn\.shopify\.com",
                    r"shopify\.theme",
                    r"shopify\.analytics"
                ],
                "scripts": [r"cdn\.shopify\.com"],
                "confidence": 100
            },
            {
                "name": "Wix",
                "categories": ["CMS", "Website Builder", "SaaS"],
                "website": "https://wix.com",
                "headers": {
                    "x-wix-request-id": r".+"
                },
                "html": [
                    r"wix\.com",
                    r"wixstatic\.com",
                    r"_wix_",
                    r"wixapps"
                ],
                "confidence": 100
            },
            {
                "name": "Squarespace",
                "categories": ["CMS", "Website Builder", "SaaS"],
                "website": "https://squarespace.com",
                "html": [
                    r"squarespace",
                    r"static\.squarespace\.com",
                    r"squarespace\.com"
                ],
                "confidence": 100
            },
            
            # Frameworks
            {
                "name": "Django",
                "categories": ["Framework", "Python"],
                "website": "https://djangoproject.com",
                "headers": {
                    "x-frame-options": r"deny|sameorigin",
                    "server": r"gunicorn|uwsgi"
                },
                "html": [
                    r"csrftoken",
                    r"django",
                    r"django\.csrf"
                ],
                "cookies": {"csrftoken": r".+", "sessionid": r".+"},
                "meta": {"generator": r"django\s*([\d.]+)?"},
                "version_patterns": [
                    r"django\s*([\d.]+)",
                    r"django\.version\s*=\s*['\"]([\d.]+)['\"]"
                ],
                "implies": ["Python"],
                "confidence": 100
            },
            {
                "name": "Ruby on Rails",
                "categories": ["Framework", "Ruby"],
                "website": "https://rubyonrails.org",
                "headers": {
                    "x-powered-by": r"rails",
                    "x-runtime": r"[\d.]+",
                    "x-request-id": r".+"
                },
                "html": [
                    r"rails",
                    r"authenticity_token",
                    r"csrf-param",
                    r"csrf-token"
                ],
                "meta": {"csrf-param": r"authenticity_token", "csrf-token": r".+"},
                "version_patterns": [
                    r"rails\s*([\d.]+)",
                    r"rails-assets-[\w-]+-([\d.]+)"
                ],
                "implies": ["Ruby"],
                "confidence": 100
            },
            {
                "name": "Laravel",
                "categories": ["Framework", "PHP"],
                "website": "https://laravel.com",
                "headers": {
                    "x-powered-by": r"laravel"
                },
                "html": [
                    r"laravel_session",
                    r"laravel_token",
                    r"laravel",
                    r"_token"
                ],
                "cookies": {"laravel_session": r".+", "XSRF-TOKEN": r".+"},
                "meta": {"generator": r"laravel\s*([\d.]+)?"},
                "version_patterns": [
                    r"laravel\s*([\d.]+)",
                    r"laravel/framework\s*v?([\d.]+)"
                ],
                "implies": ["PHP"],
                "confidence": 100
            },
            {
                "name": "Express",
                "categories": ["Framework", "Node.js"],
                "website": "https://expressjs.com",
                "headers": {
                    "x-powered-by": r"express"
                },
                "confidence": 100
            },
            {
                "name": "Next.js",
                "categories": ["Framework", "Node.js", "React"],
                "website": "https://nextjs.org",
                "headers": {
                    "x-powered-by": r"next\.js"
                },
                "html": [
                    r"_next/static",
                    r"__NEXT_DATA__",
                    r"next\.js",
                    r"next/router"
                ],
                "scripts": [r"_next/static", r"__NEXT_DATA__"],
                "version_patterns": [
                    r"next\.js\s*([\d.]+)",
                    r"_next/static/([\w-]+)/"
                ],
                "implies": ["Node.js", "React"],
                "confidence": 100
            },
            {
                "name": "Nuxt.js",
                "categories": ["Framework", "Node.js", "Vue.js"],
                "website": "https://nuxtjs.org",
                "html": [
                    r"_nuxt/",
                    r"nuxt",
                    r"__NUXT__"
                ],
                "scripts": [r"_nuxt/"],
                "version_patterns": [
                    r"nuxt\s*([\d.]+)",
                    r"_nuxt/([\w-]+)/"
                ],
                "implies": ["Node.js", "Vue.js"],
                "confidence": 100
            },
            {
                "name": "Spring",
                "categories": ["Framework", "Java"],
                "website": "https://spring.io",
                "headers": {
                    "x-powered-by": r"spring"
                },
                "html": [
                    r"spring",
                    r"jsessionid",
                    r"_csrf"
                ],
                "cookies": {"jsessionid": r".+", "spring_security_remember_me": r".+"},
                "version_patterns": [
                    r"spring\s*([\d.]+)",
                    r"spring-boot\s*([\d.]+)"
                ],
                "implies": ["Java"],
                "confidence": 100
            },
            {
                "name": "ASP.NET",
                "categories": ["Framework", "Microsoft"],
                "website": "https://dotnet.microsoft.com/apps/aspnet",
                "headers": {
                    "x-powered-by": r"asp\.net",
                    "x-aspnet-version": r"([\d.]+)",
                    "x-aspnetmvc-version": r"([\d.]+)"
                },
                "html": [
                    r"asp\.net",
                    r"__viewstate",
                    r"__eventvalidation",
                    r"aspnet"
                ],
                "version_patterns": [
                    r"asp\.net\s*([\d.]+)",
                    r"mvc\s*([\d.]+)"
                ],
                "implies": ["IIS", "Windows"],
                "confidence": 100
            },
            {
                "name": "Flask",
                "categories": ["Framework", "Python"],
                "website": "https://flask.palletsprojects.com",
                "headers": {
                    "server": r"werkzeug/([\d.]+)"
                },
                "html": [
                    r"flask",
                    r"werkzeug"
                ],
                "cookies": {"session": r".+"},
                "version_patterns": [
                    r"flask\s*([\d.]+)",
                    r"werkzeug/([\d.]+)"
                ],
                "implies": ["Python"],
                "confidence": 100
            },
            {
                "name": "FastAPI",
                "categories": ["Framework", "Python"],
                "website": "https://fastapi.tiangolo.com",
                "headers": {
                    "server": r"uvicorn"
                },
                "html": [
                    r"fastapi",
                    r"openapi\.json",
                    r"docs",
                    r"redoc"
                ],
                "version_patterns": [
                    r"fastapi\s*([\d.]+)",
                    r"uvicorn\s*([\d.]+)"
                ],
                "implies": ["Python", "Starlette"],
                "confidence": 100
            },
            
            # JavaScript Libraries
            {
                "name": "React",
                "categories": ["JavaScript Library", "Frontend"],
                "website": "https://reactjs.org",
                "html": [
                    r"react",
                    r"react-dom",
                    r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
                    r"data-reactroot",
                    r"data-reactid"
                ],
                "scripts": [r"react", r"react-dom"],
                "version_patterns": [
                    r"react@([\d.]+)",
                    r"react\.production\.min\.js\?v=([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "Vue.js",
                "categories": ["JavaScript Library", "Frontend"],
                "website": "https://vuejs.org",
                "html": [
                    r"vue\.js",
                    r"vuejs",
                    r"__VUE__",
                    r"v-",
                    r"data-v-"
                ],
                "scripts": [r"vue", r"vue\.runtime"],
                "version_patterns": [
                    r"vue@([\d.]+)",
                    r"vue\.runtime\.min\.js\?v=([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "Angular",
                "categories": ["JavaScript Library", "Frontend"],
                "website": "https://angular.io",
                "html": [
                    r"angular",
                    r"ng-app",
                    r"ng-controller",
                    r"ng-version",
                    r"angular\.js"
                ],
                "scripts": [r"angular", r"@angular"],
                "version_patterns": [
                    r"angular\s*([\d.]+)",
                    r"@angular/core\s*([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "jQuery",
                "categories": ["JavaScript Library"],
                "website": "https://jquery.com",
                "html": [
                    r"jquery",
                    r"jQuery"
                ],
                "scripts": [r"jquery"],
                "version_patterns": [
                    r"jquery[/-]([\d.]+)",
                    r"jquery\.min\.js\?v=([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "Bootstrap",
                "categories": ["CSS Framework", "Frontend"],
                "website": "https://getbootstrap.com",
                "html": [
                    r"bootstrap",
                    r"btn-",
                    r"col-",
                    r"row",
                    r"container-fluid"
                ],
                "scripts": [r"bootstrap"],
                "version_patterns": [
                    r"bootstrap[/-]([\d.]+)",
                    r"bootstrap\.min\.css\?v=([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "Tailwind CSS",
                "categories": ["CSS Framework", "Frontend"],
                "website": "https://tailwindcss.com",
                "html": [
                    r"tailwind",
                    r"tw-",
                    r"@tailwind"
                ],
                "scripts": [r"tailwind"],
                "version_patterns": [
                    r"tailwindcss\s*([\d.]+)",
                    r"tailwind\s*([\d.]+)"
                ],
                "confidence": 100
            },
            
            # Analytics/Tracking
            {
                "name": "Google Analytics",
                "categories": ["Analytics", "Tracking"],
                "website": "https://analytics.google.com",
                "html": [
                    r"google-analytics",
                    r"gtag\(",
                    r"ga\(",
                    r"analytics\.js",
                    r"gtag\.js"
                ],
                "scripts": [r"google-analytics", r"gtag", r"ga"],
                "version_patterns": [
                    r"gtag\(['\"]config['\"],\s*['\"]G-[\w]+['\"]"
                ],
                "confidence": 100
            },
            {
                "name": "Google Tag Manager",
                "categories": ["Analytics", "Tag Management"],
                "website": "https://tagmanager.google.com",
                "html": [
                    r"googletagmanager",
                    r"gtm\.js",
                    r"gtm-"
                ],
                "scripts": [r"googletagmanager", r"gtm"],
                "confidence": 100
            },
            {
                "name": "Facebook Pixel",
                "categories": ["Analytics", "Advertising"],
                "website": "https://facebook.com/business/pixel",
                "html": [
                    r"fbevents\.js",
                    r"fbq\(",
                    r"facebook\.net/tr"
                ],
                "scripts": [r"fbevents", r"fbq"],
                "confidence": 100
            },
            {
                "name": "Hotjar",
                "categories": ["Analytics", "Heatmap"],
                "website": "https://hotjar.com",
                "html": [
                    r"hotjar",
                    r"hj\(",
                    r"static\.hotjar\.com"
                ],
                "scripts": [r"hotjar", r"hj"],
                "confidence": 100
            },
            {
                "name": "Matomo",
                "categories": ["Analytics", "Privacy"],
                "website": "https://matomo.org",
                "html": [
                    r"matomo",
                    r"piwik",
                    r"matomo\.js",
                    r"piwik\.js"
                ],
                "scripts": [r"matomo", r"piwik"],
                "confidence": 100
            },
            
            # Programming Languages
            {
                "name": "PHP",
                "categories": ["Programming Language"],
                "website": "https://php.net",
                "headers": {
                    "x-powered-by": r"php/([\d.]+)"
                },
                "html": [
                    r"\.php",
                    r"phpsessid"
                ],
                "cookies": {"phpsessid": r".+"},
                "version_patterns": [
                    r"php/([\d.]+)",
                    r"x-powered-by: php/([\d.]+)"
                ],
                "confidence": 100
            },
            {
                "name": "Python",
                "categories": ["Programming Language"],
                "website": "https://python.org",
                "headers": {
                    "server": r"gunicorn|uwsgi|werkzeug|uvicorn|daphne"
                },
                "html": [
                    r"python",
                    r"django",
                    r"flask",
                    r"fastapi"
                ],
                "confidence": 100
            },
            {
                "name": "Node.js",
                "categories": ["Programming Language", "Runtime"],
                "website": "https://nodejs.org",
                "headers": {
                    "x-powered-by": r"express|next\.js|nuxt"
                },
                "html": [
                    r"node\.js",
                    r"express",
                    r"next\.js",
                    r"nuxt"
                ],
                "confidence": 100
            },
            {
                "name": "Ruby",
                "categories": ["Programming Language"],
                "website": "https://ruby-lang.org",
                "headers": {
                    "x-powered-by": r"rails|rack|puma|passenger"
                },
                "html": [
                    r"ruby",
                    r"rails",
                    r"rack"
                ],
                "confidence": 100
            },
            {
                "name": "Java",
                "categories": ["Programming Language"],
                "website": "https://java.com",
                "headers": {
                    "server": r"tomcat|jetty|jboss|wildfly|glassfish|weblogic|websphere"
                },
                "html": [
                    r"java",
                    r"jsessionid",
                    r"spring"
                ],
                "confidence": 100
            },
            {
                "name": "Go",
                "categories": ["Programming Language"],
                "website": "https://golang.org",
                "headers": {
                    "server": r"go|gin|echo|fiber|chi|httprouter"
                },
                "html": [
                    r"go",
                    r"golang"
                ],
                "confidence": 100
            },
            {
                "name": ".NET",
                "categories": ["Programming Language", "Framework"],
                "website": "https://dotnet.microsoft.com",
                "headers": {
                    "x-powered-by": r"asp\.net",
                    "x-aspnet-version": r"([\d.]+)"
                },
                "html": [
                    r"\.net",
                    r"asp\.net",
                    r"__viewstate"
                ],
                "confidence": 100
            },
            
            # Databases (detected via error pages, headers)
            {
                "name": "MySQL",
                "categories": ["Database"],
                "website": "https://mysql.com",
                "html": [
                    r"mysql",
                    r"mysqli",
                    r"mysql_error",
                    r"you have an error in your sql syntax"
                ],
                "confidence": 80
            },
            {
                "name": "PostgreSQL",
                "categories": ["Database"],
                "website": "https://postgresql.org",
                "html": [
                    r"postgresql",
                    r"pgsql",
                    r"pg_",
                    r"syntax error at or near"
                ],
                "confidence": 80
            },
            {
                "name": "MongoDB",
                "categories": ["Database", "NoSQL"],
                "website": "https://mongodb.com",
                "html": [
                    r"mongodb",
                    r"mongo",
                    r"objectid"
                ],
                "confidence": 80
            },
            {
                "name": "Redis",
                "categories": ["Database", "Cache", "NoSQL"],
                "website": "https://redis.io",
                "html": [
                    r"redis",
                    r"redis-cli"
                ],
                "confidence": 80
            },
            
            # Security
            {
                "name": "ModSecurity",
                "categories": ["WAF", "Security"],
                "website": "https://modsecurity.org",
                "headers": {
                    "server": r"mod_security"
                },
                "html": [
                    r"mod_security",
                    r"modsecurity"
                ],
                "confidence": 100
            },
            {
                "name": "reCAPTCHA",
                "categories": ["Security", "Bot Protection"],
                "website": "https://google.com/recaptcha",
                "html": [
                    r"recaptcha",
                    r"g-recaptcha",
                    r"google\.com/recaptcha"
                ],
                "scripts": [r"recaptcha", r"www\.google\.com/recaptcha"],
                "confidence": 100
            },
            {
                "name": "hCaptcha",
                "categories": ["Security", "Bot Protection"],
                "website": "https://hcaptcha.com",
                "html": [
                    r"hcaptcha",
                    r"h-captcha",
                    r"hcaptcha\.com"
                ],
                "scripts": [r"hcaptcha", r"hcaptcha\.com"],
                "confidence": 100
            },
        ]
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def fetch_page(self, url: str) -> Optional[Tuple[Dict, str, List]]:
        """Fetch page and return headers, body, and scripts"""
        try:
            session = await self._get_session()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=self.timeout, method='GET'
                )
            else:
                resp = await session.get(url, timeout=self.timeout)
            
            if resp is None or resp.status != 200:
                return None
            
            body = await resp.text()
            headers = dict(resp.headers)
            
            # Extract script sources
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
            
            return headers, body, scripts
            
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return None
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[Tuple[str, int, Dict]]:
        """Analyze headers for technology fingerprints"""
        matches = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for name, fp in self.fingerprints.items():
            confidence = 0
            evidence = {}
            
            for header_name, pattern in fp.headers.items():
                header_value = headers_lower.get(header_name.lower(), '')
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    confidence += 30
                    evidence[f'header:{header_name}'] = header_value
                    # Extract version if pattern has capture group
                    if match.groups():
                        version = match.group(1)
                        if version and re.match(r'^[\d.]+$', version):
                            evidence['version'] = version
            
            if confidence > 0:
                matches.append((name, min(confidence, fp.confidence), evidence))
        
        return matches
    
    def analyze_cookies(self, headers: Dict[str, str]) -> List[Tuple[str, int, Dict]]:
        """Analyze cookies for technology fingerprints"""
        matches = []
        cookies = headers.get('set-cookie', '').lower()
        
        for name, fp in self.fingerprints.items():
            confidence = 0
            evidence = {}
            
            for cookie_name, pattern in fp.cookies.items():
                if re.search(pattern, cookies, re.IGNORECASE):
                    confidence += 25
                    evidence[f'cookie:{cookie_name}'] = 'matched'
            
            if confidence > 0:
                matches.append((name, min(confidence, fp.confidence), evidence))
        
        return matches
    
    def analyze_html(self, body: str) -> List[Tuple[str, int, Dict]]:
        """Analyze HTML body for technology fingerprints"""
        matches = []
        body_lower = body.lower()
        
        for name, fp in self.fingerprints.items():
            confidence = 0
            evidence = {}
            
            # Check HTML patterns
            for pattern in fp.html:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    confidence += 20
                    evidence[f'html:{pattern}'] = 'matched'
            
            # Check meta tags
            for meta_name, pattern in fp.meta.items():
                meta_pattern = rf'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']([^"\']*)["\']'
                match = re.search(meta_pattern, body, re.IGNORECASE)
                if match:
                    content = match.group(1)
                    if re.search(pattern, content, re.IGNORECASE):
                        confidence += 25
                        evidence[f'meta:{meta_name}'] = content
                        # Extract version
                        version_match = re.search(r'([\d.]+)', content)
                        if version_match:
                            evidence['version'] = version_match.group(1)
            
            if confidence > 0:
                matches.append((name, min(confidence, fp.confidence), evidence))
        
        return matches
    
    def analyze_scripts(self, scripts: List[str]) -> List[Tuple[str, int, Dict]]:
        """Analyze script sources for technology fingerprints"""
        matches = []
        scripts_str = ' '.join(scripts).lower()
        
        for name, fp in self.fingerprints.items():
            confidence = 0
            evidence = {}
            
            for pattern in fp.scripts:
                if re.search(pattern, scripts_str, re.IGNORECASE):
                    confidence += 15
                    evidence[f'script:{pattern}'] = 'matched'
            
            if confidence > 0:
                matches.append((name, min(confidence, fp.confidence), evidence))
        
        return matches
    
    def detect_version(self, name: str, body: str, headers: Dict, scripts: List[str]) -> Optional[str]:
        """Detect version for a specific technology"""
        fp = self.fingerprints.get(name.lower())
        if not fp or not fp.version_patterns:
            return None
        
        all_content = body + ' ' + str(headers) + ' ' + ' '.join(scripts)
        
        for pattern in fp.version_patterns:
            match = re.search(pattern, all_content, re.IGNORECASE)
            if match and match.groups():
                version = match.group(1)
                if re.match(r'^[\d.]+$', version):
                    return version
        
        return None
    
    def resolve_implications(self, detected: Set[str]) -> Set[str]:
        """Resolve technology implications"""
        expanded = set(detected)
        changed = True
        
        while changed:
            changed = False
            for tech in list(expanded):
                fp = self.fingerprints.get(tech.lower())
                if fp and fp.implies:
                    for implied in fp.implies:
                        if implied.lower() not in expanded:
                            expanded.add(implied.lower())
                            changed = True
        
        return expanded
    
    def resolve_exclusions(self, detected: Set[str]) -> Set[str]:
        """Resolve technology exclusions"""
        to_remove = set()
        
        for tech in detected:
            fp = self.fingerprints.get(tech.lower())
            if fp and fp.excludes:
                for excluded in fp.excludes:
                    if excluded.lower() in detected:
                        # Lower confidence one gets removed
                        tech_fp = self.fingerprints.get(tech.lower())
                        excl_fp = self.fingerprints.get(excluded.lower())
                        if tech_fp and excl_fp:
                            if tech_fp.confidence < excl_fp.confidence:
                                to_remove.add(tech)
                            else:
                                to_remove.add(excluded)
        
        return detected - to_remove
    
    async def fingerprint(self, url: str) -> List[DetectedTechnology]:
        """Run full technology fingerprinting on a URL"""
        print(f"[+] Fingerprinting {url}")
        
        # Fetch page
        result = await self.fetch_page(url)
        if not result:
            return []
        
        headers, body, scripts = result
        
        # Run all detection methods
        all_matches = []
        
        # Headers
        all_matches.extend(self.analyze_headers(headers))
        
        # Cookies
        all_matches.extend(self.analyze_cookies(headers))
        
        # HTML
        all_matches.extend(self.analyze_html(body))
        
        # Scripts
        all_matches.extend(self.analyze_scripts(scripts))
        
        # Aggregate matches by technology
        tech_scores = defaultdict(lambda: {'confidence': 0, 'evidence': {}})
        
        for name, confidence, evidence in all_matches:
            if confidence > tech_scores[name]['confidence']:
                tech_scores[name]['confidence'] = confidence
            tech_scores[name]['evidence'].update(evidence)
        
        # Filter by minimum confidence
        detected = {name for name, data in tech_scores.items() if data['confidence'] >= 30}
        
        # Resolve implications and exclusions
        detected = self.resolve_implications(detected)
        detected = self.resolve_exclusions(detected)
        
        # Build results with version detection
        results = []
        for name in detected:
            fp = self.fingerprints.get(name.lower())
            if not fp:
                continue
            
            data = tech_scores.get(name, {'confidence': 0, 'evidence': {}})
            version = self.detect_version(name, body, headers, scripts)
            
            results.append(DetectedTechnology(
                name=name,
                version=version,
                categories=fp.categories,
                confidence=data['confidence'],
                evidence=data['evidence'],
                fingerprint=fp
            ))
        
        # Sort by confidence
        results.sort(key=lambda t: t.confidence, reverse=True)
        
        print(f"[+] Detected {len(results)} technologies")
        for tech in results:
            ver = f" v{tech.version}" if tech.version else ""
            print(f"    - {tech.name}{ver} (confidence: {tech.confidence}%, categories: {', '.join(tech.categories)})")
        
        return results
    
    async def fingerprint_multiple(self, urls: List[str]) -> Dict[str, List[DetectedTechnology]]:
        """Fingerprint multiple URLs"""
        results = {}
        
        for url in urls:
            try:
                techs = await self.fingerprint(url)
                results[url] = techs
            except Exception as e:
                print(f"[!] Error fingerprinting {url}: {e}")
                results[url] = []
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python tech_fingerprint.py <url>")
        return
    
    url = sys.argv[1]
    fingerprinter = TechFingerprinter()
    results = await fingerprinter.fingerprint(url)
    await fingerprinter.close()
    
    import json
    print(json.dumps([t.__dict__ for t in results], indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())