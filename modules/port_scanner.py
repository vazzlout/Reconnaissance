"""
Port Scanner Module
"""

import nmap
import socket
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """Port scanning using nmap and socket"""
    
    def __init__(self, target: str, ports: str = "1-1000", scan_type: str = "syn", timeout: int = 5):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
        self.nm = nmap.PortScanner()
    
    def scan_nmap(self) -> Dict:
        """Scan using nmap"""
        try:
            # Determine scan arguments based on scan_type
            scan_args = ""
            if self.scan_type == "syn":
                scan_args = "-sS"
            elif self.scan_type == "connect":
                scan_args = "-sT"
            elif self.scan_type == "udp":
                scan_args = "-sU"
            
            self.nm.scan(self.target, self.ports, arguments=f"{scan_args} -T4 --open")
            
            results = {}
            for host in self.nm.all_hosts():
                results[host] = {}
                for proto in self.nm[host].all_protocols():
                    results[host][proto] = {}
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        results[host][proto][port] = {
                            'state': port_info['state'],
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
            return results
        except Exception as e:
            print(f"[!] Nmap scan error: {e}")
            return {}
    
    def scan_socket(self, ports: List[int] = None) -> Dict:
        """Simple socket-based port scan (fallback)"""
        if ports is None:
            # Parse port range
            if '-' in self.ports:
                start, end = map(int, self.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(self.ports)]
        
        open_ports = {}
        
        def check_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports[port] = {'state': 'open', 'name': self._get_service_name(port)}
        
        return {self.target: {'tcp': open_ports}}
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            8080: 'http-proxy', 8443: 'https-alt'
        }
        return common_ports.get(port, 'unknown')
    
    def run(self, use_nmap: bool = True) -> Dict:
        """Run port scan"""
        if use_nmap:
            try:
                return self.scan_nmap()
            except:
                print("[!] Nmap not available, falling back to socket scan")
                return self.scan_socket()
        else:
            return self.scan_socket()


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [ports]")
        return
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
    
    scanner = PortScanner(target, ports)
    results = scanner.run()
    
    import json
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()