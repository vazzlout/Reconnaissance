#!/usr/bin/env python3
"""
Recon Tool - A reconnaissance tool for information gathering
"""

import argparse
import asyncio
import sys
import os
from typing import Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import SubdomainEnumerator, PortScanner, DNSEnumerator
from utils import (
    load_wordlist, save_json, save_csv, save_txt, 
    print_json, print_table, print_tree,
    StealthConfig, StealthScheduler, create_stealth_config_from_dict
)


class ReconTool:
    """Main reconnaissance tool class"""
    
    def __init__(self, target: str, output_format: str = "json", config: Dict = None, stealth_enabled: bool = True):
        self.target = target
        self.output_format = output_format
        self.config = config or {}
        self.results = {}
        
        # Initialize stealth scheduler
        stealth_config_dict = self.config.get('stealth', {})
        if not stealth_enabled:
            stealth_config_dict['enabled'] = False
        self.stealth_config = create_stealth_config_from_dict(stealth_config_dict)
        self.stealth_scheduler = StealthScheduler(self.stealth_config)
    
    async def run_subdomain_enum(self) -> Dict[str, Any]:
        """Run subdomain enumeration"""
        print(f"[+] Starting subdomain enumeration for {self.target}")
        if self.stealth_config.enabled:
            print(f"[+] Stealth mode enabled: rate_limit={self.stealth_config.rate_limit}/s, "
                  f"delay={self.stealth_config.request_delay_min}-{self.stealth_config.request_delay_max}s, "
                  f"jitter={self.stealth_config.jitter_factor}")
        
        subdomain_config = self.config.get('subdomain_enum', {})
        wordlist_path = subdomain_config.get('wordlist', 'wordlists/subdomains.txt')
        threads = subdomain_config.get('threads', 50)
        api_keys = subdomain_config.get('api_keys', {})
        recursive = subdomain_config.get('recursive', False)
        max_depth = subdomain_config.get('max_depth', 2)
        sources = subdomain_config.get('sources', None)
        
        # Load wordlist
        wordlist = load_wordlist(wordlist_path)
        if not wordlist:
            print(f"[!] Wordlist not found at {wordlist_path}, using default")
            wordlist = ['www', 'mail', 'ftp', 'api', 'admin', 'dev', 'test', 'staging', 'prod']
        
        # Randomize wordlist order if stealth enabled
        if self.stealth_config.randomize_order:
            import random
            random.shuffle(wordlist)
        
        enum = SubdomainEnumerator(
            self.target, 
            wordlist_path, 
            threads,
            api_keys=api_keys,
            recursive=recursive,
            max_depth=max_depth,
            stealth_scheduler=self.stealth_scheduler
        )
        subdomains = await enum.run(wordlist=wordlist, sources=sources)
        
        await enum.close()
        
        result = {"subdomains": [{"subdomain": s} for s in subdomains]}
        print(f"[+] Found {len(subdomains)} subdomains")
        return result
    
    def run_port_scan(self) -> Dict[str, Any]:
        """Run port scanning"""
        print(f"[+] Starting port scan for {self.target}")
        
        ports = self.config.get('port_scan', {}).get('ports', '1-1000')
        scan_type = self.config.get('port_scan', {}).get('scan_type', 'syn')
        timeout = self.config.get('port_scan', {}).get('timeout', 5)
        use_nmap = self.config.get('port_scan', {}).get('use_nmap', True)
        
        scanner = PortScanner(self.target, ports, scan_type, timeout)
        results = scanner.run(use_nmap=use_nmap)
        
        # Format results
        formatted = {"open_ports": []}
        for host, protocols in results.items():
            for proto, ports_dict in protocols.items():
                for port, info in ports_dict.items():
                    formatted["open_ports"].append({
                        "host": host,
                        "protocol": proto,
                        "port": port,
                        **info
                    })
        
        print(f"[+] Found {len(formatted['open_ports'])} open ports")
        return formatted
    
    def run_dns_enum(self) -> Dict[str, Any]:
        """Run DNS enumeration"""
        print(f"[+] Starting DNS enumeration for {self.target}")
        
        record_types = self.config.get('dns_enum', {}).get('record_types', ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'])
        resolvers = self.config.get('dns_enum', {}).get('resolvers', ['8.8.8.8', '1.1.1.1'])
        try_zt = self.config.get('dns_enum', {}).get('try_zone_transfer', True)
        
        enum = DNSEnumerator(self.target, resolvers, record_types)
        results = enum.run()
        
        # Format results
        formatted = {"records": []}
        for rtype, records in results.items():
            for record in records:
                formatted["records"].append({
                    "type": rtype,
                    **record
                })
        
        print(f"[+] Found {len(formatted['records'])} DNS records")
        return formatted
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all reconnaissance modules"""
        self.results["subdomain_enum"] = await self.run_subdomain_enum()
        self.results["port_scan"] = self.run_port_scan()
        self.results["dns_enum"] = self.run_dns_enum()
        return self.results
    
    def save_results(self, output_file: str):
        """Save results to file"""
        if self.output_format == "json":
            save_json(self.results, output_file)
        elif self.output_format == "csv":
            save_csv(self.results, output_file)
        elif self.output_format == "txt":
            save_txt(self.results, output_file)
    
    def print_results(self):
        """Print results to console"""
        if self.output_format == "json":
            print_json(self.results)
        elif self.output_format == "table":
            print_table(self.results, f"Recon Results for {self.target}")
        elif self.output_format == "tree":
            print_tree(self.results, f"Recon Results for {self.target}")
        else:
            print_json(self.results)


def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file"""
    try:
        import yaml
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Could not load config: {e}")
        return {}


async def main():
    parser = argparse.ArgumentParser(description="Recon Tool - Reconnaissance toolkit")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt", "table", "tree"], default="json", help="Output format")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("--subdomain", action="store_true", help="Run subdomain enumeration only")
    parser.add_argument("--portscan", action="store_true", help="Run port scan only")
    parser.add_argument("--dns", action="store_true", help="Run DNS enumeration only")
    
    # Stealth/Evasion options
    stealth_group = parser.add_argument_group('Stealth/Evasion Options')
    stealth_group.add_argument("--no-stealth", action="store_true", help="Disable stealth mode (faster but more detectable)")
    stealth_group.add_argument("--stealth-rate", type=float, help="Override stealth rate limit (requests/second)")
    stealth_group.add_argument("--stealth-delay-min", type=float, help="Override minimum delay between requests (seconds)")
    stealth_group.add_argument("--stealth-delay-max", type=float, help="Override maximum delay between requests (seconds)")
    stealth_group.add_argument("--stealth-initial-min", type=float, help="Override minimum initial delay (seconds)")
    stealth_group.add_argument("--stealth-initial-max", type=float, help="Override maximum initial delay (seconds)")
    
    args = parser.parse_args()
    
    # Load config
    config = {}
    if args.config:
        config = load_config(args.config)
    elif os.path.exists("config.yaml"):
        config = load_config("config.yaml")
    
    # Override stealth config from CLI args
    if args.no_stealth:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['enabled'] = False
    
    if args.stealth_rate is not None:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['rate_limit'] = args.stealth_rate
    
    if args.stealth_delay_min is not None:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['request_delay_min'] = args.stealth_delay_min
    
    if args.stealth_delay_max is not None:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['request_delay_max'] = args.stealth_delay_max
    
    if args.stealth_initial_min is not None:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['initial_delay_min'] = args.stealth_initial_min
    
    if args.stealth_initial_max is not None:
        if 'stealth' not in config:
            config['stealth'] = {}
        config['stealth']['initial_delay_max'] = args.stealth_initial_max
    
    tool = ReconTool(args.target, args.format, config, stealth_enabled=not args.no_stealth)
    
    if args.subdomain:
        tool.results["subdomain_enum"] = await tool.run_subdomain_enum()
    elif args.portscan:
        tool.results["port_scan"] = tool.run_port_scan()
    elif args.dns:
        tool.results["dns_enum"] = tool.run_dns_enum()
    else:
        await tool.run_all()
    
    if args.output:
        tool.save_results(args.output)
    else:
        tool.print_results()


if __name__ == "__main__":
    asyncio.run(main())