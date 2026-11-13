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

from modules import SubdomainEnumerator, PortScanner, DNSEnumerator, HTTPRecon, SSLAnalyzer, DirEnumerator, TechFingerprinter, EmailHarvester, EmailHarvestConfig, EmployeeEnumerator, EmployeeEnumConfig, UsernameEnumerator, UsernameEnumConfig, DocumentIntelligence, DocumentIntelConfig, CodeRecon, CodeReconConfig, BreachIntelligence, BreachIntelConfig, AutoUpdater, AutoUpdateConfig
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
    
    async def run_http_recon(self) -> Dict[str, Any]:
        """Run HTTP reconnaissance"""
        print(f"[+] Starting HTTP reconnaissance for {self.target}")
        
        http_config = self.config.get('http_recon', {})
        timeout = http_config.get('timeout', 10)
        follow_redirects = http_config.get('follow_redirects', True)
        test_methods = http_config.get('test_methods', True)
        
        recon = HTTPRecon(
            self.target,
            stealth_scheduler=self.stealth_scheduler,
            timeout=timeout,
            follow_redirects=follow_redirects
        )
        
        results = await recon.run()
        await recon.close()
        
        return results
    
    async def run_ssl_analyzer(self) -> Dict[str, Any]:
        """Run SSL/TLS certificate analysis"""
        print(f"[+] Starting SSL analysis for {self.target}")
        
        ssl_config = self.config.get('ssl_analyzer', {})
        port = ssl_config.get('port', 443)
        timeout = ssl_config.get('timeout', 10)
        
        analyzer = SSLAnalyzer(
            self.target,
            port=port,
            stealth_scheduler=self.stealth_scheduler,
            timeout=timeout
        )
        
        results = await analyzer.run()
        await analyzer.close()
        
        # Convert to dict for serialization
        def default_serializer(obj):
            if hasattr(obj, '__dict__'):
                return obj.__dict__
            return str(obj)
        
        import json
        return json.loads(json.dumps(results.__dict__, default=default_serializer))
    
    async def run_dir_enum(self) -> Dict[str, Any]:
        """Run directory/file enumeration"""
        print(f"[+] Starting directory enumeration for {self.target}")
        
        dir_config = self.config.get('dir_enum', {})
        timeout = dir_config.get('timeout', 10)
        threads = dir_config.get('threads', 20)
        recursive = dir_config.get('recursive', False)
        max_depth = dir_config.get('max_depth', 3)
        extensions = dir_config.get('extensions', None)
        detect_tech = dir_config.get('detect_tech', True)
        follow_redirects = dir_config.get('follow_redirects', True)
        status_codes = dir_config.get('status_codes', None)
        exclude_status = dir_config.get('exclude_status', None)
        
        enum = DirEnumerator(
            self.target,
            stealth_scheduler=self.stealth_scheduler,
            timeout=timeout,
            threads=threads,
            recursive=recursive,
            max_depth=max_depth,
            extensions=extensions,
            detect_tech=detect_tech,
            follow_redirects=follow_redirects,
            status_codes=status_codes,
            exclude_status=exclude_status
        )
        
        results = await enum.run()
        await enum.close()
        
        return results
    
    async def run_tech_fingerprint(self) -> Dict[str, Any]:
        """Run technology fingerprinting"""
        print(f"[+] Starting technology fingerprinting for {self.target}")
        
        tech_config = self.config.get('tech_fingerprint', {})
        timeout = tech_config.get('timeout', 10)
        custom_fingerprints = tech_config.get('custom_fingerprints', None)
        
        fingerprinter = TechFingerprinter(
            stealth_scheduler=self.stealth_scheduler,
            timeout=timeout,
            custom_fingerprints=custom_fingerprints
        )
        
        # Build URLs to fingerprint
        urls = [self.target]
        if not self.target.startswith(('http://', 'https://')):
            urls = [f"https://{self.target}", f"http://{self.target}"]
        
        results = await fingerprinter.fingerprint_multiple(urls)
        await fingerprinter.close()
        
        # Convert to serializable format
        serializable_results = {}
        for url, techs in results.items():
            serializable_results[url] = [
                {
                    'name': t.name,
                    'version': t.version,
                    'categories': t.categories,
                    'confidence': t.confidence,
                    'evidence': t.evidence
                }
                for t in techs
            ]
        
        return serializable_results
    
    async def run_email_harvester(self) -> Dict[str, Any]:
        """Run email harvesting"""
        print(f"[+] Starting email harvesting for {self.target}")
        
        email_config = self.config.get('email_harvester', {})
        
        config = EmailHarvestConfig(
            hunter_api_key=email_config.get('hunter_api_key'),
            clearbit_api_key=email_config.get('clearbit_api_key'),
            github_token=email_config.get('github_token'),
            linkedin_cookie=email_config.get('linkedin_cookie'),
            max_results_per_source=email_config.get('max_results_per_source', 100),
            max_pages_per_engine=email_config.get('max_pages_per_engine', 10),
            request_delay=email_config.get('request_delay', 2.0),
            use_hunter=email_config.get('use_hunter', True),
            use_clearbit=email_config.get('use_clearbit', True),
            use_github=email_config.get('use_github', True),
            use_whois=email_config.get('use_whois', True),
            use_search_engines=email_config.get('use_search_engines', True),
            use_web_crawl=email_config.get('use_web_crawl', True),
            verify_emails=email_config.get('verify_emails', False),
            smtp_check=email_config.get('smtp_check', False),
        )
        
        harvester = EmailHarvester(
            self.target,
            config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await harvester.run()
        await harvester.close()
        
        return results
    
    async def run_employee_enum(self) -> Dict[str, Any]:
        """Run employee enumeration"""
        print(f"[+] Starting employee enumeration for {self.target}")
        
        employee_config = self.config.get('employee_enum', {})
        
        config = EmployeeEnumConfig(
            linkedin_cookie=employee_config.get('linkedin_cookie'),
            github_token=employee_config.get('github_token'),
            hunter_api_key=employee_config.get('hunter_api_key'),
            clearbit_api_key=employee_config.get('clearbit_api_key'),
            max_results_per_source=employee_config.get('max_results_per_source', 100),
            max_pages=employee_config.get('max_pages', 10),
            request_delay=employee_config.get('request_delay', 2.0),
            use_linkedin=employee_config.get('use_linkedin', True),
            use_github=employee_config.get('use_github', True),
            use_company_pages=employee_config.get('use_company_pages', True),
            use_search_engines=employee_config.get('use_search_engines', True),
            use_hunter=employee_config.get('use_hunter', True),
            keywords=employee_config.get('keywords', []),
            exclude_keywords=employee_config.get('exclude_keywords', []),
            locations=employee_config.get('locations', []),
            verify_emails=employee_config.get('verify_emails', False),
        )
        
        enumerator = EmployeeEnumerator(
            self.target,
            company_name=employee_config.get('company_name'),
            config=config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await enumerator.run()
        await enumerator.close()
        
        return results
    
    async def run_username_enum(self) -> Dict[str, Any]:
        """Run username enumeration"""
        print(f"[+] Starting username enumeration for {self.target}")
        
        username_config = self.config.get('username_enum', {})
        
        # Get base usernames from email harvester and employee enum results
        base_usernames = username_config.get('base_usernames', [])
        
        # If no base usernames provided, try to extract from email harvester results
        if not base_usernames and 'email_harvester' in self.results:
            for email_data in self.results['email_harvester'].get('emails', []):
                email = email_data.get('email', '')
                if '@' in email:
                    base_usernames.append(email.split('@')[0])
        
        # If still no base usernames, try to extract from employee enum results
        if not base_usernames and 'employee_enum' in self.results:
            for emp_data in self.results['employee_enum'].get('employees', []):
                github = emp_data.get('github', '')
                if github and 'github.com/' in github:
                    base_usernames.append(github.split('github.com/')[-1])
                linkedin = emp_data.get('linkedin', '')
                if linkedin and 'linkedin.com/in/' in linkedin:
                    base_usernames.append(linkedin.split('linkedin.com/in/')[-1])
        
        # Build config dict, only including non-None values to allow dataclass defaults
        config_kwargs = {
            'base_usernames': base_usernames,
            'generate_permutations': username_config.get('generate_permutations', True),
            'max_concurrent': username_config.get('max_concurrent', 10),
            'request_delay': username_config.get('request_delay', 1.0),
            'timeout': username_config.get('timeout', 10),
            'verify_profiles': username_config.get('verify_profiles', True),
            'min_confidence': username_config.get('min_confidence', 50),
        }
        
        # Only add optional fields if they are not None in config
        if username_config.get('permutation_patterns') is not None:
            config_kwargs['permutation_patterns'] = username_config['permutation_patterns']
        if username_config.get('years') is not None:
            config_kwargs['years'] = username_config['years']
        if username_config.get('numbers') is not None:
            config_kwargs['numbers'] = username_config['numbers']
        if username_config.get('platforms') is not None:
            config_kwargs['platforms'] = username_config['platforms']
        
        config = UsernameEnumConfig(**config_kwargs)
        
        enumerator = UsernameEnumerator(
            config=config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await enumerator.run()
        await enumerator.close()
        
        return results
    
    async def run_document_intel(self) -> Dict[str, Any]:
        """Run document intelligence gathering"""
        print(f"[+] Starting document intelligence for {self.target}")
        
        doc_config = self.config.get('document_intel', {})
        
        config = DocumentIntelConfig(
            max_results_per_query=doc_config.get('max_results_per_query', 50),
            max_pages_per_engine=doc_config.get('max_pages_per_engine', 5),
            request_delay=doc_config.get('request_delay', 2.0),
            file_types=doc_config.get('file_types', None),
            use_google=doc_config.get('use_google', True),
            use_bing=doc_config.get('use_bing', True),
            use_duckduckgo=doc_config.get('use_duckduckgo', True),
            crawl_website=doc_config.get('crawl_website', True),
            max_crawl_pages=doc_config.get('max_crawl_pages', 100),
            max_file_size=doc_config.get('max_file_size', 50 * 1024 * 1024),
            extract_pdf=doc_config.get('extract_pdf', True),
            extract_office=doc_config.get('extract_office', True),
            extract_exif=doc_config.get('extract_exif', True),
            extract_custom=doc_config.get('extract_custom', True),
            download_files=doc_config.get('download_files', True),
            save_to_disk=doc_config.get('save_to_disk', False),
            output_dir=doc_config.get('output_dir', './documents'),
            min_file_size=doc_config.get('min_file_size', 1024),
            keywords=doc_config.get('keywords', []),
            exclude_keywords=doc_config.get('exclude_keywords', []),
        )
        
        intel = DocumentIntelligence(
            self.target,
            config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await intel.run()
        await intel.close()
        
        return results
    
    async def run_osint_github(self) -> Dict[str, Any]:
        """Run GitHub/GitLab reconnaissance"""
        print(f"[+] Starting GitHub/GitLab reconnaissance for {self.target}")
        
        github_config = self.config.get('osint_github', {})
        
        config = CodeReconConfig(
            github_token=github_config.get('github_token'),
            gitlab_token=github_config.get('gitlab_token'),
            gitlab_url=github_config.get('gitlab_url', 'https://gitlab.com'),
            max_repos_per_org=github_config.get('max_repos_per_org', 100),
            max_contributors_per_repo=github_config.get('max_contributors_per_repo', 50),
            max_commits_per_repo=github_config.get('max_commits_per_repo', 100),
            max_files_per_repo=github_config.get('max_files_per_repo', 500),
            request_delay=github_config.get('request_delay', 1.0),
            use_github=github_config.get('use_github', True),
            use_gitlab=github_config.get('use_gitlab', True),
            scan_secrets=github_config.get('scan_secrets', True),
            scan_contributors=github_config.get('scan_contributors', True),
            scan_issues=github_config.get('scan_issues', True),
            scan_commits=github_config.get('scan_commits', True),
            deep_scan=github_config.get('deep_scan', False),
            min_stars=github_config.get('min_stars', 0),
            min_size=github_config.get('min_size', 0),
            languages=github_config.get('languages', []),
            exclude_forks=github_config.get('exclude_forks', True),
            exclude_archived=github_config.get('exclude_archived', True),
        )
        
        recon = CodeRecon(
            self.target,
            config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await recon.run()
        await recon.close()
        
        return results
    
    async def run_breach_intel(self) -> Dict[str, Any]:
        """Run breach intelligence"""
        print(f"[+] Starting breach intelligence for {self.target}")
        
        breach_config = self.config.get('breach_intel', {})
        
        # Get emails from other modules
        emails = breach_config.get('emails', [])
        
        # If no emails provided, try to get from email_harvester results
        if not emails and 'email_harvester' in self.results:
            for email_data in self.results['email_harvester'].get('emails', []):
                email = email_data.get('email', '')
                if email:
                    emails.append(email)
        
        # If still no emails, try to get from employee_enum results
        if not emails and 'employee_enum' in self.results:
            for emp_data in self.results['employee_enum'].get('employees', []):
                email = emp_data.get('email', '')
                if email:
                    emails.append(email)
        
        config = BreachIntelConfig(
            hibp_api_key=breach_config.get('hibp_api_key'),
            dehashed_email=breach_config.get('dehashed_email'),
            dehashed_key=breach_config.get('dehashed_key'),
            leakcheck_key=breach_config.get('leakcheck_key'),
            use_hibp=breach_config.get('use_hibp', True),
            use_dehashed=breach_config.get('use_dehashed', True),
            use_leakcheck=breach_config.get('use_leakcheck', True),
            request_delay=breach_config.get('request_delay', 1.5),
            timeout=breach_config.get('timeout', 30),
            max_retries=breach_config.get('max_retries', 3),
            check_domain_breaches=breach_config.get('check_domain_breaches', True),
            search_pastes=breach_config.get('search_pastes', True),
            min_breach_size=breach_config.get('min_breach_size', 0),
            exclude_spam_lists=breach_config.get('exclude_spam_lists', True),
            exclude_malware=breach_config.get('exclude_malware', True),
            target_domain=self.target,
        )
        
        intel = BreachIntelligence(
            self.target,
            config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        results = await intel.run(emails=emails)
        await intel.close()
        
        return results
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all reconnaissance modules"""
        self.results["subdomain_enum"] = await self.run_subdomain_enum()
        self.results["port_scan"] = self.run_port_scan()
        self.results["dns_enum"] = self.run_dns_enum()
        self.results["http_recon"] = await self.run_http_recon()
        self.results["ssl_analyzer"] = await self.run_ssl_analyzer()
        self.results["dir_enum"] = await self.run_dir_enum()
        self.results["tech_fingerprint"] = await self.run_tech_fingerprint()
        self.results["email_harvester"] = await self.run_email_harvester()
        self.results["employee_enum"] = await self.run_employee_enum()
        self.results["username_enum"] = await self.run_username_enum()
        self.results["document_intel"] = await self.run_document_intel()
        self.results["osint_github"] = await self.run_osint_github()
        self.results["breach_intel"] = await self.run_breach_intel()
        return self.results
    
    async def run_auto_update(self) -> Dict[str, Any]:
        """Run auto-update check"""
        print(f"[+] Starting auto-update check for {self.target}")
        
        update_config = self.config.get('auto_update', {})
        
        config = AutoUpdateConfig(
            repo_owner=update_config.get('repo_owner', 'vazzlout'),
            repo_name=update_config.get('repo_name', 'Reconnaissance'),
            current_version=update_config.get('current_version', '1.0.0'),
            check_interval_hours=update_config.get('check_interval_hours', 24),
            auto_pull=update_config.get('auto_pull', False),
            auto_install_deps=update_config.get('auto_install_deps', False),
            backup_before_update=update_config.get('backup_before_update', True),
            notify_only=update_config.get('notify_only', False),
            github_token=update_config.get('github_token'),
        )
        
        updater = AutoUpdater(
            config,
            stealth_scheduler=self.stealth_scheduler
        )
        
        # Check for updates
        update_info = await updater.check_for_updates()
        await updater.close()
        
        # Convert to serializable format
        return {
            'current_version': update_info.current_version,
            'latest_version': update_info.latest_version,
            'update_available': update_info.update_available,
            'release_url': update_info.release_url,
            'changelog': update_info.changelog,
            'published_at': update_info.published_at,
            'assets': update_info.assets
        }
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all reconnaissance modules"""
        self.results["subdomain_enum"] = await self.run_subdomain_enum()
        self.results["port_scan"] = self.run_port_scan()
        self.results["dns_enum"] = self.run_dns_enum()
        self.results["http_recon"] = await self.run_http_recon()
        self.results["ssl_analyzer"] = await self.run_ssl_analyzer()
        self.results["dir_enum"] = await self.run_dir_enum()
        self.results["tech_fingerprint"] = await self.run_tech_fingerprint()
        self.results["email_harvester"] = await self.run_email_harvester()
        self.results["employee_enum"] = await self.run_employee_enum()
        self.results["username_enum"] = await self.run_username_enum()
        self.results["document_intel"] = await self.run_document_intel()
        self.results["osint_github"] = await self.run_osint_github()
        self.results["breach_intel"] = await self.run_breach_intel()
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


async def run_module(tool: 'ReconTool', module_name: str, module_func, results: Dict) -> bool:
    """Run a single module and handle errors"""
    try:
        print(f"\n[+] Running {module_name}...")
        result = await module_func()
        results[module_name] = result
        print(f"[+] {module_name} completed successfully")
        return True
    except Exception as e:
        print(f"\n[!] Error in {module_name}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        results[module_name] = {"error": str(e), "type": type(e).__name__}
        return False


async def interactive_menu(tool: 'ReconTool', args):
    """Interactive menu for running modules"""
    modules = [
        ("subdomain_enum", "Subdomain Enumeration", tool.run_subdomain_enum),
        ("port_scan", "Port Scan", tool.run_port_scan),
        ("dns_enum", "DNS Enumeration", tool.run_dns_enum),
        ("http_recon", "HTTP Reconnaissance", tool.run_http_recon),
        ("ssl_analyzer", "SSL/TLS Analysis", tool.run_ssl_analyzer),
        ("dir_enum", "Directory/File Enumeration", tool.run_dir_enum),
        ("tech_fingerprint", "Technology Fingerprinting", tool.run_tech_fingerprint),
        ("email_harvester", "Email Harvesting", tool.run_email_harvester),
        ("employee_enum", "Employee Enumeration", tool.run_employee_enum),
        ("username_enum", "Username Enumeration", tool.run_username_enum),
        ("document_intel", "Document Intelligence", tool.run_document_intel),
        ("osint_github", "GitHub/GitLab Reconnaissance", tool.run_osint_github),
        ("breach_intel", "Breach Intelligence", tool.run_breach_intel),
        ("auto_update", "Check for Updates", tool.run_auto_update),
    ]
    
    while True:
        print("\n" + "=" * 50)
        print(f"  Recon Tool - Target: {tool.target}")
        print("=" * 50)
        for i, (key, name, _) in enumerate(modules, 1):
            status = "✓" if key in tool.results else " "
            print(f"  [{i:2d}] {name} {status}")
        print("  [ 0] Run All Modules")
        print("  [ q] Quit")
        print("-" * 50)
        
        choice = input("Select module (number, 0 for all, q to quit): ").strip().lower()
        
        if choice == 'q':
            break
        elif choice == '0':
            print("\n[+] Running all modules...")
            await tool.run_all()
            print("[+] All modules completed")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(modules):
                    key, name, func = modules[idx]
                    await run_module(tool, key, func, tool.results)
                else:
                    print("[!] Invalid selection")
            except ValueError:
                print("[!] Invalid input")
        
        # Show results summary
        if tool.results:
            print("\n--- Current Results Summary ---")
            for key, result in tool.results.items():
                if isinstance(result, dict) and "error" in result:
                    print(f"  {key}: ERROR - {result['error']}")
                elif isinstance(result, dict):
                    print(f"  {key}: OK ({len(result)} keys)")
                else:
                    print(f"  {key}: {type(result).__name__}")
    
    # Save/print final results
    if args.output:
        tool.save_results(args.output)
        print(f"\n[+] Results saved to {args.output}")
    else:
        tool.print_results()


async def main():
    parser = argparse.ArgumentParser(description="Recon Tool - Reconnaissance toolkit")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt", "table", "tree"], default="json", help="Output format")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("--subdomain", action="store_true", help="Run subdomain enumeration only")
    parser.add_argument("--portscan", action="store_true", help="Run port scan only")
    parser.add_argument("--dns", action="store_true", help="Run DNS enumeration only")
    parser.add_argument("--http", action="store_true", help="Run HTTP reconnaissance only")
    parser.add_argument("--ssl", action="store_true", help="Run SSL/TLS analysis only")
    parser.add_argument("--dir", action="store_true", help="Run directory/file enumeration only")
    parser.add_argument("--tech", action="store_true", help="Run technology fingerprinting only")
    parser.add_argument("--email", action="store_true", help="Run email harvesting only")
    parser.add_argument("--employee", action="store_true", help="Run employee enumeration only")
    parser.add_argument("--username", action="store_true", help="Run username enumeration only")
    parser.add_argument("--docs", action="store_true", help="Run document intelligence only")
    parser.add_argument("--github", action="store_true", help="Run GitHub/GitLab reconnaissance only")
    parser.add_argument("--breach", action="store_true", help="Run breach intelligence only")
    parser.add_argument("--update", action="store_true", help="Check and apply updates")
    parser.add_argument("--menu", action="store_true", help="Run interactive menu mode")
    
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
    
    # Check if any specific module flag is set
    module_flags = [
        args.subdomain, args.portscan, args.dns, args.http, args.ssl,
        args.dir, args.tech, args.email, args.employee, args.username,
        args.docs, args.github, args.breach, args.update
    ]
    
    if args.menu or not any(module_flags):
        # Interactive menu mode
        await interactive_menu(tool, args)
    else:
        # Direct module execution (original behavior)
        if args.subdomain:
            tool.results["subdomain_enum"] = await tool.run_subdomain_enum()
        elif args.portscan:
            tool.results["port_scan"] = tool.run_port_scan()
        elif args.dns:
            tool.results["dns_enum"] = tool.run_dns_enum()
        elif args.http:
            tool.results["http_recon"] = await tool.run_http_recon()
        elif args.ssl:
            tool.results["ssl_analyzer"] = await tool.run_ssl_analyzer()
        elif args.dir:
            tool.results["dir_enum"] = await tool.run_dir_enum()
        elif args.tech:
            tool.results["tech_fingerprint"] = await tool.run_tech_fingerprint()
        elif args.email:
            tool.results["email_harvester"] = await tool.run_email_harvester()
        elif args.employee:
            tool.results["employee_enum"] = await tool.run_employee_enum()
        elif args.username:
            tool.results["username_enum"] = await tool.run_username_enum()
        elif args.docs:
            tool.results["document_intel"] = await tool.run_document_intel()
        elif args.github:
            tool.results["osint_github"] = await tool.run_osint_github()
        elif args.breach:
            tool.results["breach_intel"] = await tool.run_breach_intel()
        elif args.update:
            tool.results["auto_update"] = await tool.run_auto_update()
        else:
            await tool.run_all()
        
        if args.output:
            tool.save_results(args.output)
        else:
            tool.print_results()


if __name__ == "__main__":
    asyncio.run(main())