"""
GitHub/GitLab Recon Module - OSINT Phase 2
- Public repository enumeration
- Secret/credential scanning
- Contributor/member enumeration
- Issue/PR analysis
- Organization/user profiling
- Stealth integration
"""

import asyncio
import aiohttp
import re
import json
import base64
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, quote_plus, urlparse
from collections import defaultdict
from datetime import datetime

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class Repository:
    """Repository information"""
    name: str
    full_name: str
    description: Optional[str] = None
    html_url: str = ""
    clone_url: str = ""
    language: Optional[str] = None
    stars: int = 0
    forks: int = 0
    watchers: int = 0
    size: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    pushed_at: Optional[str] = None
    default_branch: str = "main"
    topics: List[str] = field(default_factory=list)
    license: Optional[str] = None
    is_fork: bool = False
    is_private: bool = False
    archived: bool = False
    disabled: bool = False
    owner: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis results
    secrets_found: List[Dict] = field(default_factory=list)
    contributors: List[Dict] = field(default_factory=list)
    issues_count: int = 0
    prs_count: int = 0
    commits_count: int = 0
    last_commit: Optional[str] = None


@dataclass
class Contributor:
    """Repository contributor"""
    login: str
    name: Optional[str] = None
    email: Optional[str] = None
    avatar_url: str = ""
    html_url: str = ""
    contributions: int = 0
    company: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    twitter: Optional[str] = None
    blog: Optional[str] = None
    hireable: Optional[bool] = None
    public_repos: int = 0
    followers: int = 0
    following: int = 0
    created_at: Optional[str] = None


@dataclass
class SecretFinding:
    """Secret/credential finding"""
    file_path: str
    line_number: int
    secret_type: str
    matched_content: str
    confidence: int
    rule_name: str
    commit_sha: Optional[str] = None
    commit_date: Optional[str] = None
    author: Optional[str] = None


@dataclass
class GitHubOrg:
    """GitHub organization"""
    login: str
    name: Optional[str] = None
    description: Optional[str] = None
    html_url: str = ""
    avatar_url: str = ""
    location: Optional[str] = None
    email: Optional[str] = None
    twitter: Optional[str] = None
    blog: Optional[str] = None
    company: Optional[str] = None
    public_repos: int = 0
    public_gists: int = 0
    followers: int = 0
    following: int = 0
    created_at: Optional[str] = None
    members: List[Contributor] = field(default_factory=list)
    repositories: List[Repository] = field(default_factory=list)


@dataclass
class GitLabProject:
    """GitLab project"""
    id: int
    name: str
    name_with_namespace: str
    path_with_namespace: str
    description: Optional[str] = None
    web_url: str = ""
    ssh_url_to_repo: str = ""
    http_url_to_repo: str = ""
    default_branch: str = "main"
    visibility: str = "private"
    star_count: int = 0
    forks_count: int = 0
    last_activity_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    topics: List[str] = field(default_factory=list)
    namespace: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeReconConfig:
    """Configuration for code repository reconnaissance"""
    # API Keys
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    gitlab_url: str = "https://gitlab.com"
    
    # Search settings
    max_repos_per_org: int = 100
    max_contributors_per_repo: int = 50
    max_commits_per_repo: int = 100
    max_files_per_repo: int = 500
    request_delay: float = 1.0
    
    # Sources
    use_github: bool = True
    use_gitlab: bool = True
    
    # Analysis
    scan_secrets: bool = True
    scan_contributors: bool = True
    scan_issues: bool = True
    scan_commits: bool = True
    deep_scan: bool = False
    
    # Filters
    min_stars: int = 0
    min_size: int = 0
    languages: List[str] = field(default_factory=list)
    exclude_forks: bool = True
    exclude_archived: bool = True
    
    # Secret patterns
    custom_patterns: List[Dict] = field(default_factory=list)


class CodeRecon:
    """GitHub/GitLab reconnaissance"""
    
    # Secret detection patterns
    SECRET_PATTERNS = [
        {
            'name': 'AWS Access Key',
            'pattern': r'AKIA[0-9A-Z]{16}',
            'type': 'aws_access_key'
        },
        {
            'name': 'AWS Secret Key',
            'pattern': r'(?i)aws(.{0,20})?secret(.{0,20})?[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
            'type': 'aws_secret_key'
        },
        {
            'name': 'GitHub Token',
            'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'type': 'github_token'
        },
        {
            'name': 'GitLab Token',
            'pattern': r'glpat-[A-Za-z0-9_-]{20,}',
            'type': 'gitlab_token'
        },
        {
            'name': 'Slack Token',
            'pattern': r'xox[baprs]-[A-Za-z0-9-]{10,48}',
            'type': 'slack_token'
        },
        {
            'name': 'Stripe Key',
            'pattern': r'sk_live_[A-Za-z0-9]{24,}',
            'type': 'stripe_key'
        },
        {
            'name': 'Google API Key',
            'pattern': r'AIza[0-9A-Za-z-_]{35}',
            'type': 'google_api_key'
        },
        {
            'name': 'Firebase Key',
            'pattern': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'type': 'firebase_key'
        },
        {
            'name': 'Private Key',
            'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'type': 'private_key'
        },
        {
            'name': 'SSH Private Key',
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'type': 'ssh_private_key'
        },
        {
            'name': 'JWT Token',
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'type': 'jwt_token'
        },
        {
            'name': 'Generic API Key',
            'pattern': r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s:=]+["\']?[A-Za-z0-9_\-]{20,}["\']?',
            'type': 'generic_api_key'
        },
        {
            'name': 'Database URL',
            'pattern': r'(?i)(mongodb|postgres|mysql|redis)://[^:\s]+:[^@\s]+@[^/\s]+',
            'type': 'database_url'
        },
        {
            'name': 'Docker Config',
            'pattern': r'"auths"\s*:\s*\{[^}]+"auth"\s*:\s*"[A-Za-z0-9+/=]+"',
            'type': 'docker_config'
        },
        {
            'name': 'npm Token',
            'pattern': r'npm_[A-Za-z0-9]{36}',
            'type': 'npm_token'
        },
        {
            'name': 'PyPI Token',
            'pattern': r'pypi-[A-Za-z0-9_-]{40,}',
            'type': 'pypi_token'
        },
    ]
    
    def __init__(self, target: str, config: CodeReconConfig,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.target = target.lower()
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Results
        self.github_orgs: Dict[str, GitHubOrg] = {}
        self.gitlab_groups: Dict[str, Any] = {}
        self.all_repositories: List[Repository] = []
        self.all_secrets: List[SecretFinding] = []
        self.all_contributors: Dict[str, Contributor] = {}
        
        self.stats = {
            'github_orgs': 0,
            'github_repos': 0,
            'gitlab_groups': 0,
            'gitlab_projects': 0,
            'secrets_found': 0,
            'contributors_found': 0,
            'errors': 0
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 CodeRecon)'}
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
                timeout=60, method='GET', headers=headers, **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=60, headers=headers, **kwargs)
            except Exception:
                return None
    
    def _get_github_headers(self) -> Dict[str, str]:
        """Get GitHub API headers"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 CodeRecon)'
        }
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        return headers
    
    def _get_gitlab_headers(self) -> Dict[str, str]:
        """Get GitLab API headers"""
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 CodeRecon)'
        }
        if self.config.gitlab_token:
            headers['Authorization'] = f'Bearer {self.config.gitlab_token}'
        return headers
    
    # ==================== GitHub Methods ====================
    
    async def enumerate_github_org(self, org_name: str) -> Optional[GitHubOrg]:
        """Enumerate GitHub organization"""
        print(f"[+] Enumerating GitHub org: {org_name}")
        
        headers = self._get_github_headers()
        org = GitHubOrg(login=org_name)
        
        try:
            session = await self._get_session()
            
            # Get org info
            url = f"https://api.github.com/orgs/{org_name}"
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    headers=headers, method='GET'
                )
            else:
                resp = await session.get(url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                org.name = data.get('name')
                org.description = data.get('description')
                org.html_url = data.get('html_url')
                org.avatar_url = data.get('avatar_url')
                org.location = data.get('location')
                org.email = data.get('email')
                org.twitter = data.get('twitter_username')
                org.blog = data.get('blog')
                org.company = data.get('company')
                org.public_repos = data.get('public_repos', 0)
                org.public_gists = data.get('public_gists', 0)
                org.followers = data.get('followers', 0)
                org.following = data.get('following', 0)
                org.created_at = data.get('created_at')
                
                # Get members
                if self.config.scan_contributors:
                    org.members = await self._get_github_org_members(org_name, headers)
                
                # Get repositories
                org.repositories = await self._get_github_org_repos(org_name, headers)
                
                self.github_orgs[org_name] = org
                self.stats['github_orgs'] += 1
                self.stats['github_repos'] += len(org.repositories)
                
                return org
            
            elif resp and resp.status == 404:
                print(f"[!] GitHub org not found: {org_name}")
            elif resp and resp.status == 403:
                print("[!] GitHub: Rate limited or invalid token")
                
        except Exception as e:
            print(f"[!] GitHub org {org_name} error: {e}")
            self.stats['errors'] += 1
        
        return None
    
    async def _get_github_org_members(self, org_name: str, headers: Dict) -> List[Contributor]:
        """Get GitHub organization members"""
        members = []
        
        try:
            session = await self._get_session()
            url = f"https://api.github.com/orgs/{org_name}/members"
            params = {'per_page': 100}
            
            page = 1
            while page <= 10:  # Max 1000 members
                params['page'] = page
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    members_data = await resp.json()
                    if not members_data:
                        break
                    
                    for member in members_data:
                        # Get detailed user info
                        user_detail = await self._get_github_user(member.get('url'), headers)
                        if user_detail:
                            members.append(user_detail)
                    
                    page += 1
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                else:
                    break
                    
        except Exception as e:
            print(f"[!] GitHub org members error: {e}")
        
        return members
    
    async def _get_github_user(self, user_url: str, headers: Dict) -> Optional[Contributor]:
        """Get GitHub user details"""
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
                
                return Contributor(
                    login=data.get('login'),
                    name=data.get('name'),
                    email=data.get('email'),
                    avatar_url=data.get('avatar_url'),
                    html_url=data.get('html_url'),
                    company=data.get('company'),
                    location=data.get('location'),
                    bio=data.get('bio'),
                    twitter=data.get('twitter_username'),
                    blog=data.get('blog'),
                    hireable=data.get('hireable'),
                    public_repos=data.get('public_repos', 0),
                    followers=data.get('followers', 0),
                    following=data.get('following', 0),
                    created_at=data.get('created_at')
                )
        except Exception:
            pass
        
        return None
    
    async def _get_github_org_repos(self, org_name: str, headers: Dict) -> List[Repository]:
        """Get GitHub organization repositories"""
        repos = []
        
        try:
            session = await self._get_session()
            url = f"https://api.github.com/orgs/{org_name}/repos"
            params = {'per_page': 100, 'type': 'public'}
            
            page = 1
            while page <= 10:  # Max 1000 repos
                params['page'] = page
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    repos_data = await resp.json()
                    if not repos_data:
                        break
                    
                    for repo_data in repos_data:
                        # Apply filters
                        if self.config.exclude_forks and repo_data.get('fork'):
                            continue
                        if self.config.exclude_archived and repo_data.get('archived'):
                            continue
                        if repo_data.get('stargazers_count', 0) < self.config.min_stars:
                            continue
                        if repo_data.get('size', 0) < self.config.min_size:
                            continue
                        if self.config.languages and repo_data.get('language') not in self.config.languages:
                            continue
                        
                        repo = Repository(
                            name=repo_data.get('name'),
                            full_name=repo_data.get('full_name'),
                            description=repo_data.get('description'),
                            html_url=repo_data.get('html_url'),
                            clone_url=repo_data.get('clone_url'),
                            language=repo_data.get('language'),
                            stars=repo_data.get('stargazers_count', 0),
                            forks=repo_data.get('forks_count', 0),
                            watchers=repo_data.get('watchers_count', 0),
                            size=repo_data.get('size', 0),
                            created_at=repo_data.get('created_at'),
                            updated_at=repo_data.get('updated_at'),
                            pushed_at=repo_data.get('pushed_at'),
                            default_branch=repo_data.get('default_branch', 'main'),
                            topics=repo_data.get('topics', []),
                            license=repo_data.get('license', {}).get('name') if repo_data.get('license') else None,
                            is_fork=repo_data.get('fork', False),
                            is_private=repo_data.get('private', False),
                            archived=repo_data.get('archived', False),
                            disabled=repo_data.get('disabled', False),
                            owner=repo_data.get('owner', {})
                        )
                        
                        # Deep scan
                        if self.config.deep_scan:
                            await self._enrich_github_repo(repo, headers)
                        
                        repos.append(repo)
                        self.all_repositories.append(repo)
                    
                    page += 1
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                else:
                    break
                    
        except Exception as e:
            print(f"[!] GitHub org repos error: {e}")
        
        return repos
    
    async def _enrich_github_repo(self, repo: Repository, headers: Dict):
        """Enrich repository with additional data"""
        try:
            session = await self._get_session()
            base_url = f"https://api.github.com/repos/{repo.full_name}"
            
            # Get contributors
            if self.config.scan_contributors:
                contributors_url = f"{base_url}/contributors"
                params = {'per_page': self.config.max_contributors_per_repo}
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, contributors_url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(contributors_url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    contributors_data = await resp.json()
                    for contrib in contributors_data[:self.config.max_contributors_per_repo]:
                        user_detail = await self._get_github_user(contrib.get('url'), headers)
                        if user_detail:
                            user_detail.contributions = contrib.get('contributions', 0)
                            repo.contributors.append({
                                'login': user_detail.login,
                                'name': user_detail.name,
                                'contributions': contrib.get('contributions', 0),
                                'html_url': user_detail.html_url
                            })
                            # Track unique contributors
                            if user_detail.login not in self.all_contributors:
                                self.all_contributors[user_detail.login] = user_detail
                                self.stats['contributors_found'] += 1
            
            # Get commits
            if self.config.scan_commits:
                commits_url = f"{base_url}/commits"
                params = {'per_page': self.config.max_commits_per_repo}
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, commits_url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(commits_url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    commits_data = await resp.json()
                    repo.commits_count = len(commits_data)
                    if commits_data:
                        repo.last_commit = commits_data[0].get('commit', {}).get('author', {}).get('date')
            
            # Scan for secrets
            if self.config.scan_secrets:
                await self._scan_repo_secrets(repo, headers)
                
        except Exception as e:
            print(f"[!] Enrich repo {repo.full_name} error: {e}")
    
    async def _scan_repo_secrets(self, repo: Repository, headers: Dict):
        """Scan repository for secrets"""
        try:
            session = await self._get_session()
            
            # Get repository tree
            tree_url = f"https://api.github.com/repos/{repo.full_name}/git/trees/{repo.default_branch}?recursive=1"
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, tree_url, self.stealth_scheduler,
                    headers=headers, method='GET'
                )
            else:
                resp = await session.get(tree_url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                tree_data = await resp.json()
                files = tree_data.get('tree', [])
                
                # Filter interesting files
                interesting_extensions = [
                    '.env', '.config', '.json', '.yaml', '.yml', '.toml', '.ini',
                    '.properties', '.conf', '.config', '.settings',
                    '.js', '.ts', '.py', '.go', '.java', '.rb', '.php',
                    '.sh', '.bash', '.zsh', '.dockerfile', '.dockerignore',
                    '.gitignore', '.gitlab-ci.yml', '.github', '.circleci',
                    'docker-compose', 'Dockerfile', 'Makefile', 'package.json',
                    'requirements.txt', 'Pipfile', 'poetry.lock', 'Cargo.toml',
                    'pom.xml', 'build.gradle', 'settings.gradle'
                ]
                
                interesting_files = []
                for item in files:
                    if item.get('type') == 'blob':
                        path = item.get('path', '')
                        if any(path.endswith(ext) for ext in interesting_extensions):
                            interesting_files.append(item)
                
                # Limit files to scan
                for file_item in interesting_files[:self.config.max_files_per_repo]:
                    await self._scan_file_for_secrets(repo, file_item, headers)
                    
        except Exception as e:
            print(f"[!] Scan secrets error: {e}")
    
    async def _scan_file_for_secrets(self, repo: Repository, file_item: Dict, headers: Dict):
        """Scan a single file for secrets"""
        try:
            session = await self._get_session()
            file_url = f"https://api.github.com/repos/{repo.full_name}/contents/{file_item['path']}"
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, file_url, self.stealth_scheduler,
                    headers=headers, method='GET'
                )
            else:
                resp = await session.get(file_url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                file_data = await resp.json()
                content = file_data.get('content', '')
                encoding = file_data.get('encoding', 'base64')
                
                if encoding == 'base64' and content:
                    try:
                        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                        self._find_secrets_in_content(repo, file_item['path'], decoded)
                    except Exception:
                        pass
                        
        except Exception as e:
            print(f"[!] Scan file error: {e}")
    
    def _find_secrets_in_content(self, repo: Repository, file_path: str, content: str):
        """Find secrets in file content"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern_info in self.SECRET_PATTERNS:
                matches = re.finditer(pattern_info['pattern'], line)
                for match in matches:
                    secret = SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=pattern_info['type'],
                        matched_content=match.group()[:100],
                        confidence=85,
                        rule_name=pattern_info['name']
                    )
                    repo.secrets_found.append({
                        'file': file_path,
                        'line': line_num,
                        'type': pattern_info['type'],
                        'match': match.group()[:100],
                        'rule': pattern_info['name']
                    })
                    self.all_secrets.append(secret)
                    self.stats['secrets_found'] += 1
    
    # ==================== GitLab Methods ====================
    
    async def enumerate_gitlab_group(self, group_path: str) -> Optional[Dict]:
        """Enumerate GitLab group"""
        if not self.config.use_gitlab:
            return None
        
        print(f"[+] Enumerating GitLab group: {group_path}")
        
        headers = self._get_gitlab_headers()
        
        try:
            session = await self._get_session()
            
            # Get group info
            encoded_path = quote_plus(group_path)
            url = f"{self.config.gitlab_url}/api/v4/groups/{encoded_path}"
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    headers=headers, method='GET'
                )
            else:
                resp = await session.get(url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                data = await resp.json()
                
                group = {
                    'id': data.get('id'),
                    'name': data.get('name'),
                    'path': data.get('path'),
                    'description': data.get('description'),
                    'web_url': data.get('web_url'),
                    'visibility': data.get('visibility'),
                    'projects_count': data.get('projects_count', 0),
                    'subgroups_count': data.get('subgroups_count', 0),
                }
                
                # Get projects
                projects = await self._get_gitlab_group_projects(group['id'], headers)
                group['projects'] = projects
                self.stats['gitlab_projects'] += len(projects)
                self.stats['gitlab_groups'] += 1
                
                return group
            
            elif resp and resp.status == 404:
                print(f"[!] GitLab group not found: {group_path}")
            elif resp and resp.status == 403:
                print("[!] GitLab: Rate limited or invalid token")
                
        except Exception as e:
            print(f"[!] GitLab group {group_path} error: {e}")
            self.stats['errors'] += 1
        
        return None
    
    async def _get_gitlab_group_projects(self, group_id: int, headers: Dict) -> List[GitLabProject]:
        """Get GitLab group projects"""
        projects = []
        
        try:
            session = await self._get_session()
            url = f"{self.config.gitlab_url}/api/v4/groups/{group_id}/projects"
            params = {'per_page': 100, 'include_subgroups': True}
            
            page = 1
            while page <= 10:
                params['page'] = page
                
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        params=params, headers=headers, method='GET'
                    )
                else:
                    resp = await session.get(url, params=params, headers=headers, timeout=30)
                
                if resp and resp.status == 200:
                    projects_data = await resp.json()
                    if not projects_data:
                        break
                    
                    for proj_data in projects_data:
                        project = GitLabProject(
                            id=proj_data.get('id'),
                            name=proj_data.get('name'),
                            name_with_namespace=proj_data.get('name_with_namespace'),
                            path_with_namespace=proj_data.get('path_with_namespace'),
                            description=proj_data.get('description'),
                            web_url=proj_data.get('web_url'),
                            ssh_url_to_repo=proj_data.get('ssh_url_to_repo'),
                            http_url_to_repo=proj_data.get('http_url_to_repo'),
                            default_branch=proj_data.get('default_branch', 'main'),
                            visibility=proj_data.get('visibility', 'private'),
                            star_count=proj_data.get('star_count', 0),
                            forks_count=proj_data.get('forks_count', 0),
                            last_activity_at=proj_data.get('last_activity_at'),
                            created_at=proj_data.get('created_at'),
                            updated_at=proj_data.get('updated_at'),
                            topics=proj_data.get('topics', []),
                            namespace=proj_data.get('namespace', {})
                        )
                        projects.append(project)
                    
                    page += 1
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                else:
                    break
                    
        except Exception as e:
            print(f"[!] GitLab group projects error: {e}")
        
        return projects
    
    # ==================== Search Methods ====================
    
    async def search_github_repos(self, query: str) -> List[Repository]:
        """Search GitHub repositories"""
        if not self.config.use_github:
            return []
        
        print(f"[+] Searching GitHub repos: {query}")
        repos = []
        
        headers = self._get_github_headers()
        
        try:
            session = await self._get_session()
            url = "https://api.github.com/search/repositories"
            params = {'q': query, 'per_page': 100, 'sort': 'stars', 'order': 'desc'}
            
            page = 1
            while page <= 5:
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
                    
                    for repo_data in items:
                        repo = Repository(
                            name=repo_data.get('name'),
                            full_name=repo_data.get('full_name'),
                            description=repo_data.get('description'),
                            html_url=repo_data.get('html_url'),
                            clone_url=repo_data.get('clone_url'),
                            language=repo_data.get('language'),
                            stars=repo_data.get('stargazers_count', 0),
                            forks=repo_data.get('forks_count', 0),
                            watchers=repo_data.get('watchers_count', 0),
                            size=repo_data.get('size', 0),
                            created_at=repo_data.get('created_at'),
                            updated_at=repo_data.get('updated_at'),
                            pushed_at=repo_data.get('pushed_at'),
                            default_branch=repo_data.get('default_branch', 'main'),
                            topics=repo_data.get('topics', []),
                            license=repo_data.get('license', {}).get('name') if repo_data.get('license') else None,
                            is_fork=repo_data.get('fork', False),
                            is_private=repo_data.get('private', False),
                            archived=repo_data.get('archived', False),
                            disabled=repo_data.get('disabled', False),
                            owner=repo_data.get('owner', {})
                        )
                        repos.append(repo)
                        self.all_repositories.append(repo)
                    
                    page += 1
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                else:
                    break
                    
        except Exception as e:
            print(f"[!] GitHub search error: {e}")
        
        return repos
    
    # ==================== Main Run Method ====================
    
    async def run(self) -> Dict[str, Any]:
        """Run code reconnaissance"""
        print(f"[+] Starting code reconnaissance for {self.target}")
        
        # Try to find GitHub org from domain
        possible_orgs = [
            self.target.split('.')[0],
            self.target.replace('.', ''),
            self.target.replace('.', '-'),
        ]
        
        # GitHub enumeration
        if self.config.use_github:
            for org in possible_orgs:
                await self.enumerate_github_org(org)
            
            # Search for repos mentioning domain
            search_queries = [
                f'"{self.target}" in:readme',
                f'"{self.target}" in:description',
                f'{self.target} org:',
            ]
            
            for query in search_queries:
                await self.search_github_repos(query)
        
        # GitLab enumeration
        if self.config.use_gitlab:
            for group in possible_orgs:
                await self.enumerate_gitlab_group(group)
        
        # Prepare results
        results = {
            'target': self.target,
            'stats': self.stats,
            'github_organizations': {
                name: {
                    'login': org.login,
                    'name': org.name,
                    'description': org.description,
                    'html_url': org.html_url,
                    'location': org.location,
                    'email': org.email,
                    'twitter': org.twitter,
                    'blog': org.blog,
                    'company': org.company,
                    'public_repos': org.public_repos,
                    'members_count': len(org.members),
                    'repositories_count': len(org.repositories),
                    'members': [
                        {
                            'login': m.login,
                            'name': m.name,
                            'email': m.email,
                            'company': m.company,
                            'location': m.location,
                            'bio': m.bio,
                            'twitter': m.twitter,
                            'blog': m.blog,
                            'public_repos': m.public_repos,
                            'followers': m.followers,
                            'following': m.following
                        }
                        for m in org.members
                    ],
                    'repositories': [
                        {
                            'name': r.name,
                            'full_name': r.full_name,
                            'description': r.description,
                            'html_url': r.html_url,
                            'language': r.language,
                            'stars': r.stars,
                            'forks': r.forks,
                            'topics': r.topics,
                            'secrets_count': len(r.secrets_found),
                            'contributors_count': len(r.contributors)
                        }
                        for r in org.repositories
                    ]
                }
                for name, org in self.github_orgs.items()
            },
            'gitlab_groups': self.gitlab_groups,
            'all_repositories': [
                {
                    'name': r.name,
                    'full_name': r.full_name,
                    'description': r.description,
                    'html_url': r.html_url,
                    'language': r.language,
                    'stars': r.stars,
                    'forks': r.forks,
                    'topics': r.topics,
                    'secrets_count': len(r.secrets_found),
                    'contributors_count': len(r.contributors)
                }
                for r in self.all_repositories
            ],
            'secrets_found': [
                {
                    'file': s.file_path,
                    'line': s.line_number,
                    'type': s.secret_type,
                    'match': s.matched_content,
                    'rule': s.rule_name,
                    'confidence': s.confidence
                }
                for s in self.all_secrets
            ],
            'contributors': [
                {
                    'login': c.login,
                    'name': c.name,
                    'email': c.email,
                    'company': c.company,
                    'location': c.location,
                    'bio': c.bio,
                    'twitter': c.twitter,
                    'blog': c.blog,
                    'public_repos': c.public_repos,
                    'followers': c.followers,
                    'following': c.following
                }
                for c in self.all_contributors.values()
            ]
        }
        
        print(f"[+] GitHub orgs: {self.stats['github_orgs']}, repos: {self.stats['github_repos']}")
        print(f"[+] GitLab groups: {self.stats['gitlab_groups']}, projects: {self.stats['gitlab_projects']}")
        print(f"[+] Secrets found: {self.stats['secrets_found']}")
        print(f"[+] Contributors: {self.stats['contributors_found']}")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python code_recon.py <domain> [--github-token TOKEN] [--gitlab-token TOKEN]")
        return
    
    domain = sys.argv[1]
    
    # Parse optional args
    github_token = None
    gitlab_token = None
    for i, arg in enumerate(sys.argv):
        if arg == '--github-token' and i + 1 < len(sys.argv):
            github_token = sys.argv[i + 1]
        elif arg == '--gitlab-token' and i + 1 < len(sys.argv):
            gitlab_token = sys.argv[i + 1]
    
    config = CodeReconConfig(
        github_token=github_token,
        gitlab_token=gitlab_token
    )
    
    recon = CodeRecon(domain, config)
    results = await recon.run()
    await recon.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())