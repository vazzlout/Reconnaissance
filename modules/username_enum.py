"""
Username Enumeration Module - OSINT Phase 2
- Cross-platform username enumeration
- GitHub, Twitter, LinkedIn, Instagram, Reddit, etc.
- Username permutation generation
- Profile validation
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
class UsernameResult:
    """Username enumeration result"""
    username: str
    platform: str
    exists: bool
    profile_url: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    location: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    posts_count: Optional[int] = None
    verified: bool = False
    confidence: int = 50
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UsernameEnumConfig:
    """Configuration for username enumeration"""
    # Base usernames to check (from email harvester, employee enum, or manual)
    base_usernames: List[str] = field(default_factory=list)
    
    # Generate permutations
    generate_permutations: bool = True
    permutation_patterns: List[str] = field(default_factory=lambda: [
        '{username}',
        '{username}{year}',
        '{username}{number}',
        '{username}_',
        '_{username}',
        '{username}.',
        '.{username}',
        '{first}{last}',
        '{first}.{last}',
        '{first}_{last}',
        '{f}{last}',
        '{first}{l}',
    ])
    
    # Years to try
    years: List[int] = field(default_factory=lambda: list(range(2020, 2025)))
    
    # Numbers to try
    numbers: List[int] = field(default_factory=lambda: list(range(1, 100)))
    
    # Platforms to check
    platforms: List[str] = field(default_factory=lambda: [
        'github', 'twitter', 'linkedin', 'instagram', 'reddit',
        'facebook', 'youtube', 'tiktok', 'pinterest', 'medium',
        'devto', 'stackoverflow', 'gitlab', 'bitbucket',
        'telegram', 'discord', 'slack', 'keybase'
    ])
    
    # Request settings
    max_concurrent: int = 10
    request_delay: float = 1.0
    timeout: int = 10
    
    # Verification
    verify_profiles: bool = True
    min_confidence: int = 50


class UsernameEnumerator:
    """Cross-platform username enumerator"""
    
    # Platform configurations
    PLATFORMS = {
        'github': {
            'url': 'https://github.com/{username}',
            'api_url': 'https://api.github.com/users/{username}',
            'check_method': 'api',
            'not_found_indicators': ['Not Found', '404'],
            'rate_limit_header': 'X-RateLimit-Remaining',
        },
        'twitter': {
            'url': 'https://twitter.com/{username}',
            'api_url': 'https://api.twitter.com/2/users/by/username/{username}',
            'check_method': 'web',
            'not_found_indicators': ['This account doesn\'t exist', 'Account suspended', '404'],
            'requires_auth': True,
        },
        'linkedin': {
            'url': 'https://www.linkedin.com/in/{username}',
            'check_method': 'web',
            'not_found_indicators': ['Page not found', '404', 'This profile is not available'],
            'requires_auth': True,
        },
        'instagram': {
            'url': 'https://www.instagram.com/{username}/',
            'api_url': 'https://www.instagram.com/api/v1/users/web_profile_info/?username={username}',
            'check_method': 'api',
            'not_found_indicators': ['User not found', '404', 'Page Not Found'],
        },
        'reddit': {
            'url': 'https://www.reddit.com/user/{username}',
            'api_url': 'https://www.reddit.com/user/{username}/about.json',
            'check_method': 'api',
            'not_found_indicators': ['Not Found', '404', 'user not found'],
        },
        'facebook': {
            'url': 'https://www.facebook.com/{username}',
            'check_method': 'web',
            'not_found_indicators': ['Page not found', '404', 'This content isn\'t available'],
            'requires_auth': True,
        },
        'youtube': {
            'url': 'https://www.youtube.com/@{username}',
            'api_url': 'https://www.youtube.com/@{username}',
            'check_method': 'web',
            'not_found_indicators': ['404', 'This page isn\'t available'],
        },
        'tiktok': {
            'url': 'https://www.tiktok.com/@{username}',
            'check_method': 'web',
            'not_found_indicators': ['Couldn\'t find this account', '404'],
        },
        'pinterest': {
            'url': 'https://www.pinterest.com/{username}/',
            'check_method': 'web',
            'not_found_indicators': ['Sorry, we couldn\'t find that page', '404'],
        },
        'medium': {
            'url': 'https://medium.com/@{username}',
            'check_method': 'web',
            'not_found_indicators': ['404', 'Page not found'],
        },
        'devto': {
            'url': 'https://dev.to/{username}',
            'api_url': 'https://dev.to/api/users/by_username?username={username}',
            'check_method': 'api',
            'not_found_indicators': ['Not Found', '404'],
        },
        'stackoverflow': {
            'url': 'https://stackoverflow.com/users/{username}',
            'api_url': 'https://api.stackexchange.com/2.3/users/{username}?site=stackoverflow',
            'check_method': 'api',
            'not_found_indicators': ['User not found', '404'],
        },
        'gitlab': {
            'url': 'https://gitlab.com/{username}',
            'api_url': 'https://gitlab.com/api/v4/users?username={username}',
            'check_method': 'api',
            'not_found_indicators': ['404', 'Not Found'],
        },
        'bitbucket': {
            'url': 'https://bitbucket.org/{username}',
            'api_url': 'https://api.bitbucket.org/2.0/users/{username}',
            'check_method': 'api',
            'not_found_indicators': ['404', 'Not Found'],
        },
        'telegram': {
            'url': 'https://t.me/{username}',
            'check_method': 'web',
            'not_found_indicators': ['If you have Telegram, you can contact', '404'],
        },
        'discord': {
            'url': 'https://discord.com/users/{username}',
            'check_method': 'web',
            'not_found_indicators': ['404', 'Not Found'],
            'requires_auth': True,
        },
        'slack': {
            'url': 'https://{username}.slack.com',
            'check_method': 'web',
            'not_found_indicators': ['404', 'not found'],
        },
        'keybase': {
            'url': 'https://keybase.io/{username}',
            'api_url': 'https://keybase.io/_/api/1.0/user/lookup.json?username={username}',
            'check_method': 'api',
            'not_found_indicators': ['not found', '404'],
        },
    }
    
    def __init__(self, config: UsernameEnumConfig, 
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: Dict[str, List[UsernameResult]] = defaultdict(list)
        self.stats = {
            'total_checked': 0,
            'found': 0,
            'by_platform': defaultdict(int),
            'errors': 0
        }
        self._generated_usernames: Set[str] = set()
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(limit=self.config.max_concurrent)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 UsernameEnumerator)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def generate_usernames(self) -> List[str]:
        """Generate username permutations from base usernames"""
        usernames = set(self.config.base_usernames)
        
        if not self.config.generate_permutations:
            return list(usernames)
        
        # Extract first/last names from base usernames
        name_parts = {}
        for base in self.config.base_usernames:
            # Try to split by common separators
            for sep in ['.', '_', '-']:
                if sep in base:
                    parts = base.split(sep)
                    if len(parts) >= 2:
                        name_parts[base] = {
                            'first': parts[0],
                            'last': sep.join(parts[1:]),
                            'f': parts[0][0] if parts[0] else '',
                            'l': parts[-1][0] if parts[-1] else ''
                        }
                        break
        
        # Generate permutations
        for base in self.config.base_usernames:
            usernames.add(base)
            
            parts = name_parts.get(base, {})
            first = parts.get('first', base)
            last = parts.get('last', '')
            f = parts.get('f', first[0] if first else '')
            l = parts.get('l', last[0] if last else '')
            
            for pattern in self.config.permutation_patterns:
                try:
                    # Basic patterns
                    username = pattern.format(
                        username=base,
                        first=first,
                        last=last,
                        f=f,
                        l=l
                    )
                    usernames.add(username)
                    
                    # With years
                    for year in self.config.years:
                        usernames.add(f"{username}{year}")
                        usernames.add(f"{username}_{year}")
                        usernames.add(f"{username}-{year}")
                    
                    # With numbers
                    for num in self.config.numbers:
                        usernames.add(f"{username}{num}")
                        usernames.add(f"{username}_{num}")
                        usernames.add(f"{username}-{num}")
                        
                except KeyError:
                    continue
        
        # Filter valid usernames (alphanumeric, underscore, hyphen, dot)
        valid_usernames = []
        for u in usernames:
            if re.match(r'^[a-zA-Z0-9._-]{1,39}$', u) and not u.startswith('.') and not u.endswith('.'):
                valid_usernames.append(u)
        
        self._generated_usernames = set(valid_usernames)
        return valid_usernames
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(limit=self.config.max_concurrent)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 UsernameEnumerator)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _stealth_get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=self.config.timeout, method='GET', **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=self.config.timeout, **kwargs)
            except Exception:
                return None
    
    async def check_username(self, username: str, platform: str) -> Optional[UsernameResult]:
        """Check if username exists on a platform"""
        if platform not in self.PLATFORMS:
            return None
        
        platform_config = self.PLATFORMS[platform]
        self.stats['total_checked'] += 1
        
        try:
            if platform_config['check_method'] == 'api' and 'api_url' in platform_config:
                return await self._check_via_api(username, platform, platform_config)
            else:
                return await self._check_via_web(username, platform, platform_config)
                
        except Exception as e:
            self.stats['errors'] += 1
            return None
    
    async def _check_via_api(self, username: str, platform: str, 
                              platform_config: Dict) -> Optional[UsernameResult]:
        """Check username via API"""
        api_url = platform_config['api_url'].format(username=username)
        
        session = await self._get_session()
        
        if self.stealth_scheduler:
            resp = await fetch_with_stealth(
                session, api_url, self.stealth_scheduler,
                timeout=self.config.timeout, method='GET'
            )
        else:
            resp = await session.get(api_url, timeout=self.config.timeout)
        
        if resp is None:
            return None
        
        if resp.status == 404:
            return UsernameResult(
                username=username, platform=platform, exists=False,
                source='api', confidence=90
            )
        
        if resp.status == 200:
            try:
                data = await resp.json()
                return self._parse_api_response(username, platform, data, platform_config)
            except Exception:
                pass
        
        return None
    
    async def _check_via_web(self, username: str, platform: str,
                              platform_config: Dict) -> Optional[UsernameResult]:
        """Check username via web scraping"""
        url = platform_config['url'].format(username=username)
        
        session = await self._get_session()
        
        if self.stealth_scheduler:
            resp = await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=self.config.timeout, method='GET'
            )
        else:
            resp = await session.get(url, timeout=self.config.timeout)
        
        if resp is None:
            return None
        
        if resp.status == 404:
            return UsernameResult(
                username=username, platform=platform, exists=False,
                source='web', confidence=80
            )
        
        if resp.status == 200:
            html = await resp.text()
            
            # Check for not found indicators
            for indicator in platform_config.get('not_found_indicators', []):
                if indicator.lower() in html.lower():
                    return UsernameResult(
                        username=username, platform=platform, exists=False,
                        source='web', confidence=70
                    )
            
            # Profile exists, try to extract info
            return self._parse_web_response(username, platform, html, url)
        
        return None
    
    def _parse_api_response(self, username: str, platform: str, 
                             data: Dict, platform_config: Dict) -> UsernameResult:
        """Parse API response for profile info"""
        result = UsernameResult(
            username=username, platform=platform, exists=True,
            profile_url=platform_config['url'].format(username=username),
            source='api', confidence=95
        )
        
        # Platform-specific parsing
        if platform == 'github':
            result.display_name = data.get('name')
            result.bio = data.get('bio')
            result.location = data.get('location')
            result.followers = data.get('followers')
            result.following = data.get('following')
            result.posts_count = data.get('public_repos')
            result.verified = data.get('verified', False)
            result.metadata = {
                'company': data.get('company'),
                'blog': data.get('blog'),
                'twitter': data.get('twitter_username'),
                'created_at': data.get('created_at')
            }
        elif platform == 'instagram':
            user_data = data.get('data', {}).get('user', {})
            result.display_name = user_data.get('full_name')
            result.bio = user_data.get('biography')
            result.followers = user_data.get('edge_followed_by', {}).get('count')
            result.following = user_data.get('edge_follow', {}).get('count')
            result.posts_count = user_data.get('edge_owner_to_timeline_media', {}).get('count')
            result.verified = user_data.get('is_verified', False)
        elif platform == 'reddit':
            user_data = data.get('data', {})
            result.display_name = user_data.get('name')
            result.posts_count = user_data.get('link_karma') + user_data.get('comment_karma')
            result.verified = user_data.get('is_gold', False)
        elif platform == 'devto':
            result.display_name = data.get('name')
            result.bio = data.get('bio')
            result.location = data.get('location')
            result.followers = data.get('followers_count')
            result.posts_count = data.get('posts_count')
        elif platform == 'gitlab':
            result.display_name = data.get('name')
            result.bio = data.get('bio')
            result.location = data.get('location')
            result.posts_count = data.get('projects_count')
        elif platform == 'bitbucket':
            result.display_name = data.get('display_name')
            result.location = data.get('location')
        elif platform == 'keybase':
            result.display_name = data.get('full_name')
            result.location = data.get('location')
        
        return result
    
    def _parse_web_response(self, username: str, platform: str,
                             html: str, url: str) -> UsernameResult:
        """Parse web response for profile info"""
        result = UsernameResult(
            username=username, platform=platform, exists=True,
            profile_url=url, source='web', confidence=80
        )
        
        # Try to extract basic info from HTML
        # This is simplified - real implementation would be more sophisticated
        
        # Try to find display name
        name_patterns = [
            r'<title>([^<]+)</title>',
            r'<meta property="og:title" content="([^"]+)"',
            r'<h1[^>]*>([^<]+)</h1>',
        ]
        
        for pattern in name_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                result.display_name = match.group(1).strip()
                break
        
        # Try to find bio/description
        bio_patterns = [
            r'<meta property="og:description" content="([^"]+)"',
            r'<meta name="description" content="([^"]+)"',
        ]
        
        for pattern in bio_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                result.bio = match.group(1).strip()[:500]
                break
        
        return result
    
    async def check_all_platforms(self, username: str) -> List[UsernameResult]:
        """Check username across all configured platforms"""
        tasks = []
        for platform in self.config.platforms:
            if platform in self.PLATFORMS:
                tasks.append(self.check_username(username, platform))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for r in results:
            if isinstance(r, UsernameResult) and r.exists:
                self.stats['found'] += 1
                self.stats['by_platform'][r.platform] += 1
                valid_results.append(r)
        
        return valid_results
    
    async def run(self) -> Dict[str, Any]:
        """Run username enumeration"""
        print(f"[+] Starting username enumeration")
        
        # Generate usernames
        usernames = self.generate_usernames()
        print(f"[+] Generated {len(usernames)} usernames to check")
        
        # Check each username across platforms
        all_results = []
        
        # Process in batches to avoid overwhelming
        batch_size = 50
        for i in range(0, len(usernames), batch_size):
            batch = usernames[i:i+batch_size]
            
            for username in batch:
                results = await self.check_all_platforms(username)
                all_results.extend(results)
                
                # Small delay between usernames
                if self.stealth_scheduler:
                    await self.stealth_scheduler.wait_before_request()
            
            print(f"[+] Progress: {min(i+batch_size, len(usernames))}/{len(usernames)} usernames checked")
        
        # Group results by username
        by_username = defaultdict(list)
        for r in all_results:
            by_username[r.username].append(r)
        
        # Prepare results
        results = {
            'total_usernames_checked': len(usernames),
            'stats': self.stats,
            'by_username': {
                username: [
                    {
                        'platform': r.platform,
                        'exists': r.exists,
                        'profile_url': r.profile_url,
                        'display_name': r.display_name,
                        'bio': r.bio,
                        'location': r.location,
                        'followers': r.followers,
                        'following': r.following,
                        'posts_count': r.posts_count,
                        'verified': r.verified,
                        'confidence': r.confidence,
                        'source': r.source,
                        'metadata': r.metadata
                    }
                    for r in platforms
                ]
                for username, platforms in by_username.items()
            }
        }
        
        print(f"[+] Found {self.stats['found']} profiles across {len(by_username)} usernames")
        print(f"[+] By platform: {dict(self.stats['by_platform'])}")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python username_enum.py <base_username> [base_username2 ...]")
        print("       python username_enum.py --from-file usernames.txt")
        return
    
    base_usernames = sys.argv[1:]
    
    config = UsernameEnumConfig(
        base_usernames=base_usernames,
        platforms=['github', 'twitter', 'instagram', 'reddit', 'devto', 'gitlab', 'keybase']
    )
    
    enumerator = UsernameEnumerator(config)
    results = await enumerator.run()
    await enumerator.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())