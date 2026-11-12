"""
DNS Enumeration Module
"""

import dns.resolver
import dns.zone
import dns.query
import dns.reversename
from typing import Dict, List, Optional
import socket


class DNSEnumerator:
    """DNS enumeration for various record types"""
    
    def __init__(self, domain: str, resolvers: List[str] = None, record_types: List[str] = None):
        self.domain = domain
        self.resolvers = resolvers or ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.record_types = record_types or ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']
        self.resolver = dns.resolver.Resolver()
        self.results = {}
    
    def set_resolver(self, resolver_ip: str):
        """Set custom resolver"""
        self.resolver.nameservers = [resolver_ip]
    
    def query_record(self, record_type: str) -> List[Dict]:
        """Query a specific record type"""
        records = []
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            for rdata in answers:
                record = {'type': record_type, 'value': str(rdata)}
                if record_type == 'MX':
                    record['preference'] = rdata.preference
                    record['exchange'] = str(rdata.exchange)
                records.append(record)
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception as e:
            print(f"[!] Error querying {record_type}: {e}")
        
        return records
    
    def query_all(self) -> Dict[str, List[Dict]]:
        """Query all record types"""
        results = {}
        for record_type in self.record_types:
            records = self.query_record(record_type)
            if records:
                results[record_type] = records
                print(f"[+] Found {len(records)} {record_type} record(s)")
        return results
    
    def try_zone_transfer(self) -> List[str]:
        """Attempt zone transfer"""
        subdomains = []
        try:
            # Get NS records first
            ns_records = self.query_record('NS')
            for ns in ns_records:
                ns_server = ns['value'].rstrip('.')
                try:
                    # Try zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}".rstrip('.')
                        if subdomain != self.domain:
                            subdomains.append(subdomain)
                    print(f"[+] Zone transfer successful from {ns_server}: {len(subdomains)} records")
                except Exception as e:
                    print(f"[!] Zone transfer failed for {ns_server}: {e}")
        except Exception as e:
            print(f"[!] Zone transfer error: {e}")
        
        return subdomains
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            return str(answers[0]).rstrip('.')
        except:
            return None
    
    def run(self) -> Dict:
        """Run all DNS enumeration"""
        self.results = self.query_all()
        
        # Try zone transfer
        zt_results = self.try_zone_transfer()
        if zt_results:
            self.results['ZONE_TRANSFER'] = [{'type': 'ZONE_TRANSFER', 'value': s} for s in zt_results]
        
        return self.results


def main():
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python dns_enum.py <domain>")
        return
    
    domain = sys.argv[1]
    enum = DNSEnumerator(domain)
    results = enum.run()
    
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()