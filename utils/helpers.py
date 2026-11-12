"""
Helper utilities
"""

import asyncio
import aiohttp
import time
import random
from typing import List, Set, Optional, Callable, Any
from dataclasses import dataclass
from collections import deque


# ==================== Stealth/Evasion Utilities ====================

@dataclass
class StealthConfig:
    """Configuration for stealth/evasion behavior"""
    # Initial random delay before starting (seconds)
    initial_delay_min: float = 5.0
    initial_delay_max: float = 30.0
    
    # Delay between requests (seconds)
    request_delay_min: float = 1.0
    request_delay_max: float = 5.0
    
    # Jitter factor (0.0 - 1.0) - adds randomness to delays
    jitter_factor: float = 0.3
    
    # Rate limiting (requests per second)
    rate_limit: float = 10.0
    
    # Burst allowance
    burst_allowance: int = 5
    
    # Enable stealth mode
    enabled: bool = True
    
    # Randomize request order
    randomize_order: bool = True
    
    # Rotate user agents
    rotate_user_agent: bool = True


class TokenBucketRateLimiter:
    """Token bucket rate limiter for request throttling"""
    
    def __init__(self, rate: float, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, returns wait time"""
        async with self._lock:
            now = time.monotonic()
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0
            
            # Need to wait for tokens
            wait_time = (tokens - self.tokens) / self.rate
            self.tokens = 0
            return wait_time


class StealthScheduler:
    """Manages stealth timing for requests"""
    
    def __init__(self, config: StealthConfig):
        self.config = config
        self.rate_limiter = TokenBucketRateLimiter(config.rate_limit, config.burst_allowance)
        self.last_request_time = 0.0
        self.request_count = 0
    
    async def wait_before_request(self) -> float:
        """Wait appropriate time before making a request. Returns actual wait time."""
        if not self.config.enabled:
            return 0.0
        
        total_wait = 0.0
        
        # Initial random delay on first request
        if self.request_count == 0:
            initial_delay = random.uniform(
                self.config.initial_delay_min, 
                self.config.initial_delay_max
            )
            await asyncio.sleep(initial_delay)
            total_wait += initial_delay
        
        # Rate limiting
        rate_wait = await self.rate_limiter.acquire()
        if rate_wait > 0:
            await asyncio.sleep(rate_wait)
            total_wait += rate_wait
        
        # Random delay between requests
        base_delay = random.uniform(
            self.config.request_delay_min,
            self.config.request_delay_max
        )
        
        # Add jitter
        jitter = base_delay * self.config.jitter_factor * random.uniform(-1, 1)
        delay = max(0.1, base_delay + jitter)
        
        # Ensure minimum time since last request
        time_since_last = time.monotonic() - self.last_request_time
        if time_since_last < delay:
            extra_wait = delay - time_since_last
            await asyncio.sleep(extra_wait)
            total_wait += extra_wait
        else:
            await asyncio.sleep(delay)
            total_wait += delay
        
        self.last_request_time = time.monotonic()
        self.request_count += 1
        
        return total_wait
    
    def get_stats(self) -> dict:
        """Get scheduler statistics"""
        return {
            "request_count": self.request_count,
            "tokens_available": self.rate_limiter.tokens,
            "rate_limit": self.config.rate_limit,
        }


def create_stealth_config_from_dict(config_dict: dict) -> StealthConfig:
    """Create StealthConfig from dictionary"""
    return StealthConfig(
        initial_delay_min=config_dict.get('initial_delay_min', 5.0),
        initial_delay_max=config_dict.get('initial_delay_max', 30.0),
        request_delay_min=config_dict.get('request_delay_min', 1.0),
        request_delay_max=config_dict.get('request_delay_max', 5.0),
        jitter_factor=config_dict.get('jitter_factor', 0.3),
        rate_limit=config_dict.get('rate_limit', 10.0),
        burst_allowance=config_dict.get('burst_allowance', 5),
        enabled=config_dict.get('enabled', True),
        randomize_order=config_dict.get('randomize_order', True),
        rotate_user_agent=config_dict.get('rotate_user_agent', True),
    )


# ==================== Original Helper Functions ====================

async def fetch_url(session: aiohttp.ClientSession, url: str, timeout: int = 10) -> str:
    """Fetch URL content"""
    try:
        async with session.get(url, timeout=timeout) as response:
            return await response.text()
    except Exception:
        return ""


async def fetch_json(session: aiohttp.ClientSession, url: str, timeout: int = 10) -> dict:
    """Fetch and parse JSON"""
    try:
        async with session.get(url, timeout=timeout) as response:
            return await response.json()
    except Exception:
        return {}


async def fetch_with_stealth(
    session: aiohttp.ClientSession, 
    url: str, 
    scheduler: StealthScheduler,
    timeout: int = 10,
    method: str = 'GET',
    **kwargs
) -> Optional[aiohttp.ClientResponse]:
    """Fetch URL with stealth timing"""
    await scheduler.wait_before_request()
    
    # Rotate user agent if enabled
    if scheduler.config.rotate_user_agent:
        headers = kwargs.get('headers', {})
        headers['User-Agent'] = random_user_agent()
        kwargs['headers'] = headers
    
    try:
        if method == 'GET':
            return await session.get(url, timeout=timeout, **kwargs)
        elif method == 'POST':
            return await session.post(url, timeout=timeout, **kwargs)
    except Exception:
        return None


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []


def generate_subdomain_wordlist(base_words: List[str], tlds: List[str] = None) -> List[str]:
    """Generate subdomain variations"""
    tlds = tlds or ['com', 'net', 'org', 'io', 'dev', 'app']
    variations = []
    
    for word in base_words:
        variations.append(word)
        variations.append(f"{word}-dev")
        variations.append(f"{word}-test")
        variations.append(f"{word}-staging")
        variations.append(f"{word}-prod")
        variations.append(f"{word}-api")
        variations.append(f"{word}-admin")
        variations.append(f"{word}-mail")
        variations.append(f"{word}-web")
        variations.append(f"{word}1")
        variations.append(f"{word}2")
    
    return list(set(variations))


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    """Validate IP address"""
    import socket
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def parse_port_range(port_str: str) -> List[int]:
    """Parse port range string (e.g., '1-1000,8080,8443')"""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def random_user_agent() -> str:
    """Get random user agent"""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
    ]
    return random.choice(agents)


async def run_with_semaphore(tasks: List, max_concurrent: int = 50):
    """Run async tasks with semaphore limit"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_task(task):
        async with semaphore:
            return await task
    
    return await asyncio.gather(*[limited_task(t) for t in tasks])