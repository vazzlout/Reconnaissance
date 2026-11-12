"""
Directory & File Enumeration Module
- Async directory brute force
- Recursive scanning
- Smart wordlists (tech-specific)
- Response analysis & clustering
- Soft 404 detection
- Extension fuzzing
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import hashlib

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class DirEntry:
    """Directory/File entry result"""
    url: str
    path: str
    status_code: int
    content_length: int
    content_type: str
    response_time: float
    redirect_url: Optional[str] = None
    is_directory: bool = False
    hash: str = ""
    similarity_cluster: Optional[int] = None


@dataclass
class ScanStats:
    """Scan statistics"""
    total_requests: int = 0
    found: int = 0
    errors: int = 0
    directories: int = 0
    files: int = 0
    redirects: int = 0
    start_time: float = 0
    end_time: float = 0


# Default wordlists
DEFAULT_DIRECTORIES = [
    'admin', 'administrator', 'login', 'wp-admin', 'wp-login', 'phpmyadmin',
    'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs',
    'test', 'testing', 'dev', 'development', 'staging', 'stage', 'prod', 'production',
    'backup', 'backups', 'bak', 'old', 'tmp', 'temp', 'logs', 'log',
    'config', 'configuration', 'conf', 'settings', 'setup', 'install',
    'assets', 'static', 'media', 'uploads', 'files', 'images', 'img', 'css', 'js',
    'vendor', 'node_modules', 'bower_components', 'packages', 'lib', 'libs',
    'src', 'source', 'app', 'application', 'core', 'includes', 'inc',
    'bin', 'scripts', 'tools', 'utils', 'helpers', 'services',
    'database', 'db', 'sql', 'migrations', 'seeds', 'fixtures',
    'docker', 'kubernetes', 'k8s', 'helm', 'terraform', 'ansible',
    'jenkins', 'gitlab', 'github', 'bitbucket', 'ci', 'cd', 'pipeline',
    'monitoring', 'metrics', 'prometheus', 'grafana', 'kibana', 'elasticsearch',
    'debug', 'console', 'shell', 'terminal', 'webhook', 'callback',
    'oauth', 'auth', 'sso', 'ldap', 'saml', 'jwt', 'token',
    'cache', 'redis', 'memcached', 'session', 'queue', 'rabbitmq', 'kafka',
    'mail', 'email', 'smtp', 'imap', 'pop3', 'webmail',
    'ftp', 'sftp', 'ssh', 'vpn', 'proxy', 'gateway',
    'internal', 'private', 'secret', 'hidden', 'secure',
    'beta', 'alpha', 'demo', 'sandbox', 'playground', 'preview',
    'mobile', 'm', 'wap', 'amp', 'pwa',
    'cdn', 'edge', 'origin', 'loadbalancer', 'lb', 'haproxy', 'nginx',
    'registry', 'artifacts', 'packages', 'releases', 'builds',
    'docs', 'documentation', 'wiki', 'readme', 'changelog', 'license',
    'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'security.txt',
    '.git', '.svn', '.hg', '.bzr', '.idea', '.vscode', '.vs',
    'node_modules', 'vendor', 'composer', 'npm', 'yarn', 'pnpm',
    'requirements.txt', 'package.json', 'composer.json', 'Gemfile',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'kubernetes', 'k8s', 'helm', 'chart', 'values.yaml',
    'terraform', 'ansible', 'playbook', 'inventory',
    'jenkins', 'gitlab-ci', 'github-actions', 'bitbucket-pipelines',
    'prometheus', 'grafana', 'alertmanager', 'loki', 'tempo',
    'elasticsearch', 'kibana', 'logstash', 'filebeat', 'metricbeat',
    'jaeger', 'zipkin', 'skywalking', 'pinpoint',
    'consul', 'vault', 'nomad', 'etcd', 'zookeeper',
    'kafka', 'rabbitmq', 'redis', 'mongodb', 'postgresql', 'mysql',
    'minio', 's3', 'gcs', 'azure-blob', 'swift',
]

DEFAULT_FILES = [
    'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'security.txt',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    '.htaccess', '.htpasswd', '.htaccess.bak', '.htpasswd.bak',
    'web.config', 'web.config.bak',
    'phpinfo.php', 'info.php', 'test.php', 'debug.php',
    'server-status', 'server-info', 'status', 'health', 'ping',
    'README', 'README.md', 'README.txt', 'CHANGELOG', 'CHANGELOG.md',
    'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING',
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock',
    'requirements.txt', 'requirements-dev.txt', 'Pipfile', 'Pipfile.lock',
    'setup.py', 'setup.cfg', 'pyproject.toml', 'poetry.lock',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore',
    'Makefile', 'makefile', 'CMakeLists.txt', 'build.gradle', 'pom.xml',
    '.gitignore', '.gitattributes', '.gitmodules', '.gitkeep',
    '.env', '.env.example', '.env.local', '.env.production', '.env.development',
    '.env.staging', '.env.test', '.env.backup', '.env.bak',
    'config.json', 'config.yaml', 'config.yml', 'config.toml', 'config.ini',
    'settings.json', 'settings.yaml', 'settings.yml', 'settings.py',
    'database.yml', 'database.yaml', 'database.json',
    'secrets.yml', 'secrets.yaml', 'secrets.json', 'vault.yml',
    'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_dsa.pub', 'id_ecdsa', 'id_ecdsa.pub',
    'authorized_keys', 'known_hosts', 'ssh_config', 'sshd_config',
    'backup.sql', 'dump.sql', 'database.sql', 'backup.zip', 'backup.tar.gz',
    'error.log', 'access.log', 'debug.log', 'application.log', 'laravel.log',
    'wp-config.php', 'wp-config.php.bak', 'wp-config.php.save',
    'configuration.php', 'configuration.php.bak',
    'LocalSettings.php', 'LocalSettings.php.bak',
    'settings.php', 'settings.php.bak', 'settings.py.bak',
    'parameters.yml', 'parameters.yml.dist', 'parameters.php',
    '.DS_Store', 'Thumbs.db', 'desktop.ini',
    'php.ini', 'php-fpm.conf', 'www.conf', 'nginx.conf', 'apache.conf',
    'httpd.conf', 'httpd-vhosts.conf', 'mime.types',
    'robots.txt.bak', 'sitemap.xml.bak', 'security.txt.bak',
]

# Technology-specific wordlists
TECH_WORDLISTS = {
    'wordpress': [
        'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login.php',
        'xmlrpc.php', 'wp-cron.php', 'wp-load.php', 'wp-config.php',
        'wp-content/uploads', 'wp-content/plugins', 'wp-content/themes',
        'wp-content/backup', 'wp-content/backups', 'wp-content/cache',
        'wp-content/debug.log', 'wp-content/error.log',
        'wp-includes/js', 'wp-includes/css', 'wp-includes/images',
    ],
    'drupal': [
        'sites/default/files', 'sites/default/settings.php', 'sites/default/settings.php.bak',
        'modules', 'themes', 'profiles', 'libraries', 'drush',
        'core', 'vendor', 'composer.json', 'composer.lock',
        'sites/all/modules', 'sites/all/themes', 'sites/default/private',
    ],
    'laravel': [
        'public', 'storage', 'bootstrap', 'vendor', 'app', 'config',
        'database', 'resources', 'routes', 'tests', 'artisan',
        'storage/logs', 'storage/framework', 'storage/app',
        '.env', '.env.example', '.env.production', '.env.staging',
        'public/storage', 'public/build', 'public/hot', 'public/mix-manifest.json',
    ],
    'django': [
        'static', 'media', 'admin', 'api', 'rest', 'graphql',
        'manage.py', 'requirements.txt', 'settings.py', 'urls.py', 'wsgi.py', 'asgi.py',
        'static/admin', 'static/rest_framework', 'media/uploads',
        'logs', 'celery', 'celerybeat', 'gunicorn', 'uwsgi',
    ],
    'nodejs': [
        'node_modules', 'package.json', 'package-lock.json', 'yarn.lock',
        'public', 'build', 'dist', 'src', 'lib', 'server', 'app',
        'routes', 'controllers', 'models', 'views', 'middleware',
        'config', 'utils', 'helpers', 'services', 'validators',
        '.env', '.env.example', '.env.production', '.env.development',
        'webpack.config.js', 'vite.config.js', 'next.config.js', 'nuxt.config.js',
    ],
    'spring': [
        'WEB-INF', 'META-INF', 'actuator', 'health', 'info', 'metrics',
        'env', 'configprops', 'beans', 'mappings', 'trace', 'dump',
        'heapdump', 'threaddump', 'logfile', 'auditevents', 'httptrace',
        'application.yml', 'application.yaml', 'application.properties',
        'bootstrap.yml', 'bootstrap.yaml', 'bootstrap.properties',
    ],
    'php': [
        'vendor', 'composer.json', 'composer.lock', 'autoload.php',
        'public', 'web', 'www', 'htdocs', 'html',
        'index.php', 'app.php', 'bootstrap.php', 'config.php',
        'cache', 'logs', 'var', 'storage', 'tmp',
        'phpunit.xml', 'phpunit.xml.dist', 'phpstan.neon', 'psalm.xml',
    ],
    'python': [
        'venv', 'env', '.venv', '.env', 'virtualenv',
        'requirements.txt', 'requirements-dev.txt', 'setup.py', 'setup.cfg',
        'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
        'src', 'lib', 'tests', 'test', 'docs', 'examples',
        '__pycache__', '.pytest_cache', '.mypy_cache', '.coverage',
        'pytest.ini', 'tox.ini', 'mypy.ini', 'pyproject.toml',
    ],
    'ruby': [
        'Gemfile', 'Gemfile.lock', 'vendor', 'bundle', '.bundle',
        'config', 'db', 'lib', 'app', 'spec', 'test', 'features',
        'config.ru', 'Rakefile', 'rakefile', 'Guardfile',
        '.ruby-version', '.ruby-gemset', '.rbenv-version',
    ],
    'go': [
        'go.mod', 'go.sum', 'vendor', 'cmd', 'pkg', 'internal',
        'api', 'web', 'api', 'handler', 'service', 'repository',
        'config', 'configs', 'deployment', 'deployments', 'k8s',
        'Dockerfile', 'docker-compose.yml', 'Makefile', 'makefile',
    ],
    'java': [
        'pom.xml', 'build.gradle', 'gradle.properties', 'settings.gradle',
        'src/main/java', 'src/main/resources', 'src/test/java', 'src/test/resources',
        'target', 'build', 'out', 'bin', 'lib', 'libs',
        'WEB-INF', 'META-INF', 'application.yml', 'application.yaml',
        'application.properties', 'bootstrap.yml', 'bootstrap.yaml',
    ],
    'dotnet': [
        'bin', 'obj', 'Properties', 'wwwroot', 'Views', 'Controllers',
        'Models', 'Data', 'Services', 'Middleware', 'Extensions',
        'appsettings.json', 'appsettings.Development.json', 'appsettings.Production.json',
        'web.config', 'web.Debug.config', 'web.Release.config',
        'Startup.cs', 'Program.cs', 'Global.asax', 'Global.asax.cs',
        'packages.config', 'project.json', '*.csproj', '*.sln',
    ],
}


class DirEnumerator:
    """Directory & File Enumerator"""
    
    def __init__(self, base_url: str, stealth_scheduler: Optional[StealthScheduler] = None,
                 timeout: int = 10, threads: int = 20, recursive: bool = False,
                 max_depth: int = 3, extensions: List[str] = None,
                 detect_tech: bool = True, follow_redirects: bool = True,
                 status_codes: List[int] = None, exclude_status: List[int] = None):
        self.base_url = base_url.rstrip('/')
        self.stealth_scheduler = stealth_scheduler
        self.timeout = timeout
        self.threads = threads
        self.recursive = recursive
        self.max_depth = max_depth
        self.extensions = extensions or ['', '.php', '.html', '.js', '.json', '.xml', '.txt', '.bak', '.backup', '.old', '.orig', '.swp', '.tmp', '.temp', '.log', '.sql', '.zip', '.tar.gz', '.tgz', '.rar', '.7z', '.gz', '.bz2', '.xz']
        self.detect_tech = detect_tech
        self.follow_redirects = follow_redirects
        self.status_codes = status_codes or [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
        self.exclude_status = exclude_status or [404]
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = ScanStats()
        self.found_entries: List[DirEntry] = []
        self.response_signatures: Dict[str, List[DirEntry]] = defaultdict(list)
        self.soft_404_signatures: Set[str] = set()
        self.detected_tech: Set[str] = set()
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(limit=self.threads, limit_per_host=self.threads)
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
    
    def _get_wordlist(self) -> List[str]:
        """Get combined wordlist based on detected tech"""
        wordlist = set(DEFAULT_DIRECTORIES + DEFAULT_FILES)
        
        if self.detect_tech and self.detected_tech:
            for tech in self.detected_tech:
                if tech in TECH_WORDLISTS:
                    wordlist.update(TECH_WORDLISTS[tech])
        
        # Add extensions to files (not directories)
        extended = set()
        for word in wordlist:
            if '.' not in word.split('/')[-1]:  # Likely a directory
                extended.add(word)
                extended.add(word + '/')
            else:  # Likely a file
                extended.add(word)
                for ext in self.extensions:
                    if ext:
                        base = word.rsplit('.', 1)[0]
                        extended.add(base + ext)
        
        return sorted(list(extended))
    
    def _calculate_similarity(self, entry1: DirEntry, entry2: DirEntry) -> float:
        """Calculate similarity between two responses"""
        # Simple similarity based on content length and status
        if entry1.status_code != entry2.status_code:
            return 0.0
        
        len1, len2 = entry1.content_length, entry2.content_length
        if len1 == 0 and len2 == 0:
            return 1.0
        if len1 == 0 or len2 == 0:
            return 0.0
        
        ratio = min(len1, len2) / max(len1, len2)
        return ratio
    
    def _cluster_responses(self):
        """Cluster similar responses to detect soft 404s"""
        clusters = []
        cluster_id = 0
        
        for entry in self.found_entries:
            if entry.similarity_cluster is not None:
                continue
            
            # Find similar entries
            similar = [entry]
            for other in self.found_entries:
                if other is entry or other.similarity_cluster is not None:
                    continue
                if self._calculate_similarity(entry, other) > 0.95:
                    similar.append(other)
            
            if len(similar) > 3:  # Likely soft 404 pattern
                for e in similar:
                    e.similarity_cluster = cluster_id
                clusters.append(similar)
                cluster_id += 1
        
        # Mark soft 404 signatures
        for cluster in clusters:
            if len(cluster) > 5:
                sig = f"{cluster[0].status_code}:{cluster[0].content_length}"
                self.soft_404_signatures.add(sig)
    
    def _is_soft_404(self, entry: DirEntry) -> bool:
        """Check if response is likely a soft 404"""
        sig = f"{entry.status_code}:{entry.content_length}"
        return sig in self.soft_404_signatures
    
    async def _request(self, path: str) -> Optional[DirEntry]:
        """Make a single request"""
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        
        try:
            session = await self._get_session()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=self.timeout, method='GET',
                    allow_redirects=self.follow_redirects
                )
            else:
                resp = await session.get(url, timeout=self.timeout, allow_redirects=self.follow_redirects)
            
            if resp is None:
                return None
            
            body = await resp.read()
            content_length = len(body)
            content_type = resp.headers.get('Content-Type', '')
            
            # Calculate hash for deduplication
            content_hash = hashlib.md5(body).hexdigest()[:16]
            
            # Check if directory
            is_dir = path.endswith('/') or content_type.startswith('text/html')
            
            entry = DirEntry(
                url=str(resp.url),
                path=path,
                status_code=resp.status,
                content_length=content_length,
                content_type=content_type,
                response_time=0,  # Would need timing
                redirect_url=str(resp.url) if str(resp.url) != url else None,
                is_directory=is_dir,
                hash=content_hash
            )
            
            return entry
            
        except asyncio.TimeoutError:
            return None
        except aiohttp.ClientError:
            return None
        except Exception:
            return None
    
    async def _scan_paths(self, paths: List[str], depth: int = 0) -> List[DirEntry]:
        """Scan a list of paths"""
        semaphore = asyncio.Semaphore(self.threads)
        results = []
        
        async def scan_path(path: str):
            async with semaphore:
                entry = await self._request(path)
                if entry and entry.status_code in self.status_codes:
                    if entry.status_code not in self.exclude_status:
                        results.append(entry)
                        self.stats.found += 1
                        if entry.is_directory:
                            self.stats.directories += 1
                        else:
                            self.stats.files += 1
                        if entry.redirect_url:
                            self.stats.redirects += 1
                self.stats.total_requests += 1
        
        tasks = [scan_path(path) for path in paths]
        await asyncio.gather(*tasks)
        
        return results
    
    async def run(self) -> Dict[str, Any]:
        """Run directory enumeration"""
        import time
        self.stats.start_time = time.time()
        
        print(f"[+] Starting directory enumeration for {self.base_url}")
        
        # Initial scan to detect technology
        if self.detect_tech:
            await self._detect_technology()
        
        # Get wordlist
        wordlist = self._get_wordlist()
        print(f"[+] Wordlist size: {len(wordlist)}")
        
        # Scan
        self.found_entries = await self._scan_paths(wordlist)
        
        # Cluster responses to detect soft 404s
        self._cluster_responses()
        
        # Filter out soft 404s
        filtered_entries = [e for e in self.found_entries if not self._is_soft_404(e)]
        soft_404_count = len(self.found_entries) - len(filtered_entries)
        if soft_404_count > 0:
            print(f"[+] Filtered {soft_404_count} soft 404 responses")
        
        self.found_entries = filtered_entries
        
        # Recursive scan for directories
        if self.recursive and self.max_depth > 0:
            await self._recursive_scan(depth=1)
        
        self.stats.end_time = time.time()
        
        # Prepare results
        results = {
            'target': self.base_url,
            'stats': {
                'total_requests': self.stats.total_requests,
                'found': self.stats.found,
                'directories': self.stats.directories,
                'files': self.stats.files,
                'redirects': self.stats.redirects,
                'errors': self.stats.errors,
                'duration': round(self.stats.end_time - self.stats.start_time, 2),
                'soft_404s_filtered': soft_404_count
            },
            'detected_technologies': list(self.detected_tech),
            'entries': [self._entry_to_dict(e) for e in self.found_entries]
        }
        
        print(f"[+] Found {self.stats.found} entries ({self.stats.directories} dirs, {self.stats.files} files)")
        print(f"[+] Duration: {results['stats']['duration']}s")
        
        return results
    
    async def _detect_technology(self):
        """Detect technology from main page"""
        try:
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(session, self.base_url, self.stealth_scheduler)
            else:
                resp = await session.get(self.base_url, timeout=self.timeout)
            
            if resp and resp.status == 200:
                body = await resp.text()
                headers = dict(resp.headers)
                
                # Simple tech detection
                body_lower = body.lower()
                headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
                
                tech_signatures = {
                    'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                    'drupal': ['drupal', 'sites/default/files'],
                    'laravel': ['laravel_session', 'laravel_token'],
                    'django': ['csrftoken', 'django'],
                    'nodejs': ['express', 'next.js', 'nuxt'],
                    'spring': ['spring', 'jsessionid'],
                    'php': ['php', 'x-powered-by: php'],
                    'python': ['python', 'django', 'flask', 'fastapi'],
                    'ruby': ['ruby', 'rails', 'rack'],
                    'go': ['go', 'gin', 'echo'],
                    'java': ['java', 'tomcat', 'jetty', 'spring'],
                    'dotnet': ['asp.net', 'iis', 'x-powered-by: asp.net'],
                }
                
                for tech, signatures in tech_signatures.items():
                    for sig in signatures:
                        if sig in body_lower or any(sig in h for h in headers_lower.values()):
                            self.detected_tech.add(tech)
                            break
                
                if self.detected_tech:
                    print(f"[+] Detected technologies: {', '.join(self.detected_tech)}")
                    
        except Exception:
            pass
    
    async def _recursive_scan(self, depth: int):
        """Recursively scan discovered directories"""
        if depth > self.max_depth:
            return
        
        directories = [e for e in self.found_entries if e.is_directory and e.status_code in [200, 301, 302, 307, 308]]
        
        for dir_entry in directories[:20]:  # Limit to prevent explosion
            dir_path = dir_entry.path.rstrip('/')
            wordlist = self._get_wordlist()
            
            # Build paths for this directory
            recursive_paths = [f"{dir_path}/{word}" for word in wordlist]
            
            print(f"[+] Recursive scan depth {depth}: {dir_path} ({len(recursive_paths)} paths)")
            
            results = await self._scan_paths(recursive_paths, depth)
            self.found_entries.extend(results)
            
            # Re-cluster after recursive scan
            self._cluster_responses()
    
    def _entry_to_dict(self, entry: DirEntry) -> Dict[str, Any]:
        """Convert DirEntry to dict"""
        return {
            'url': entry.url,
            'path': entry.path,
            'status_code': entry.status_code,
            'content_length': entry.content_length,
            'content_type': entry.content_type,
            'response_time': entry.response_time,
            'redirect_url': entry.redirect_url,
            'is_directory': entry.is_directory,
            'hash': entry.hash,
            'similarity_cluster': entry.similarity_cluster
        }


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dir_enum.py <target_url>")
        return
    
    target = sys.argv[1]
    enum = DirEnumerator(target, recursive=True, max_depth=2)
    results = await enum.run()
    await enum.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())