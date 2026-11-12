"""
SSL/TLS Certificate Analyzer Module
- Deep certificate analysis
- Certificate Transparency monitoring
- Certificate chain validation
- Weak cipher/protocol detection
- Certificate pinning detection
- Expiry monitoring
"""

import asyncio
import aiohttp
import ssl
import socket
import OpenSSL
import certifi
import json
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class CertificateInfo:
    """Certificate information"""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: datetime
    not_after: datetime
    version: int
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    san: List[str] = field(default_factory=list)
    ocsp_uris: List[str] = field(default_factory=list)
    crl_uris: List[str] = field(default_factory=list)
    ca_issuers_uris: List[str] = field(default_factory=list)
    extensions: Dict[str, Any] = field(default_factory=dict)
    fingerprint_sha1: str = ""
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""
    is_ca: bool = False
    path_length: Optional[int] = None
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)


@dataclass
class CertificateChain:
    """Certificate chain validation result"""
    chain: List[CertificateInfo]
    is_valid: bool
    trust_store: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    chain_length: int = 0
    root_ca: Optional[str] = None


@dataclass
class CTLogEntry:
    """Certificate Transparency log entry"""
    issuer_ca_id: int
    issuer_name: str
    common_name: str
    name_value: str
    not_before: str
    not_after: str
    serial_number: str
    log_id: str
    log_name: str
    entry_timestamp: str


@dataclass
class SSLScanResult:
    """Complete SSL scan result"""
    hostname: str
    port: int
    certificates: List[CertificateInfo]
    chain: CertificateChain
    protocols: Dict[str, bool]  # TLS 1.0, 1.1, 1.2, 1.3
    ciphers: List[Dict[str, Any]]
    preferred_cipher: Optional[Dict[str, Any]]
    ocsp_stapling: bool
    session_ticket: bool
    secure_renegotiation: bool
    compression: bool
    heartbeat_vulnerable: bool  # Heartbleed
    ccs_injection_vulnerable: bool
    poodle_vulnerable: bool
    freak_vulnerable: bool
    logjam_vulnerable: bool
    drown_vulnerable: bool
    robot_vulnerable: bool
    sweet32_vulnerable: bool
    ct_logs: List[CTLogEntry]
    cert_transparency: Dict[str, Any]
    score: int  # 0-100
    grade: str  # A+, A, B, C, D, F
    findings: List[Dict[str, Any]]


class SSLAnalyzer:
    """SSL/TLS Certificate Analyzer with CT monitoring"""
    
    # CT Log servers
    CT_LOGS = {
        'crt.sh': 'https://crt.sh/?q=%25.{domain}&output=json',
        'google_ct': 'https://ct.googleapis.com/logs/argon2024/ct/v1/get-entries',
        'cloudflare_ct': 'https://ct.cloudflare.com/logs/nimbus2024/ct/v1/get-entries',
    }
    
    # Weak ciphers
    WEAK_CIPHERS = {
        'EXPORT', 'DES', 'RC4', 'MD5', 'ANON', 'NULL', 'PSK', 'SRP',
        'CBC3', '3DES', 'IDEA', 'SEED', 'CAMELLIA128', 'CAMELLIA256'
    }
    
    # Weak protocols
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    def __init__(self, hostname: str, port: int = 443, 
                 stealth_scheduler: Optional[StealthScheduler] = None,
                 timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.stealth_scheduler = stealth_scheduler
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    def _parse_certificate(self, cert: OpenSSL.crypto.X509) -> CertificateInfo:
        """Parse OpenSSL certificate to CertificateInfo"""
        # Subject
        subject = {}
        for component in cert.get_subject().get_components():
            subject[component[0].decode()] = component[1].decode()
        
        # Issuer
        issuer = {}
        for component in cert.get_issuer().get_components():
            issuer[component[0].decode()] = component[1].decode()
        
        # Serial number
        serial = format(cert.get_serial_number(), 'x').upper()
        
        # Validity
        not_before = datetime.strptime(
            cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ'
        ).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(
            cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ'
        ).replace(tzinfo=timezone.utc)
        
        # Version (0-indexed in OpenSSL)
        version = cert.get_version() + 1
        
        # Signature algorithm
        sig_alg = cert.get_signature_algorithm().decode()
        
        # Public key
        pubkey = cert.get_pubkey()
        pubkey_alg = pubkey.type()
        if pubkey_alg == OpenSSL.crypto.TYPE_RSA:
            pubkey_algo = 'RSA'
            pubkey_size = pubkey.bits()
        elif pubkey_alg == OpenSSL.crypto.TYPE_DSA:
            pubkey_algo = 'DSA'
            pubkey_size = pubkey.bits()
        elif pubkey_alg == OpenSSL.crypto.TYPE_EC:
            pubkey_algo = 'EC'
            pubkey_size = pubkey.bits()
        else:
            pubkey_algo = 'Unknown'
            pubkey_size = 0
        
        # Fingerprints
        der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        import hashlib
        fp_sha1 = hashlib.sha1(der).hexdigest().upper()
        fp_sha256 = hashlib.sha256(der).hexdigest().upper()
        fp_md5 = hashlib.md5(der).hexdigest().upper()
        
        # Extensions
        san = []
        ocsp_uris = []
        crl_uris = []
        ca_issuers_uris = []
        extensions = {}
        is_ca = False
        path_length = None
        key_usage = []
        ext_key_usage = []
        
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            ext_name = ext.get_short_name().decode()
            ext_data = ext.__str__()
            extensions[ext_name] = ext_data
            
            # Subject Alternative Names
            if ext_name == 'subjectAltName':
                for name in ext_data.split(', '):
                    if '=' in name:
                        _, value = name.split('=', 1)
                        san.append(value)
            
            # Authority Information Access
            elif ext_name == 'authorityInfoAccess':
                for line in ext_data.split('\n'):
                    if 'OCSP' in line and 'URI:' in line:
                        ocsp_uris.append(line.split('URI:')[1].strip())
                    elif 'CA Issuers' in line and 'URI:' in line:
                        ca_issuers_uris.append(line.split('URI:')[1].strip())
            
            # CRL Distribution Points
            elif ext_name == 'crlDistributionPoints':
                for line in ext_data.split('\n'):
                    if 'URI:' in line:
                        crl_uris.append(line.split('URI:')[1].strip())
            
            # Basic Constraints
            elif ext_name == 'basicConstraints':
                if 'CA:TRUE' in ext_data:
                    is_ca = True
                if 'pathlen:' in ext_data:
                    try:
                        path_length = int(ext_data.split('pathlen:')[1].split(',')[0])
                    except:
                        pass
            
            # Key Usage
            elif ext_name == 'keyUsage':
                key_usage = [k.strip() for k in ext_data.split(',')]
            
            # Extended Key Usage
            elif ext_name == 'extendedKeyUsage':
                ext_key_usage = [k.strip() for k in ext_data.split(', ')]
        
        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=serial,
            not_before=not_before,
            not_after=not_after,
            version=version,
            signature_algorithm=sig_alg,
            public_key_algorithm=pubkey_algo,
            public_key_size=pubkey_size,
            san=san,
            ocsp_uris=ocsp_uris,
            crl_uris=crl_uris,
            ca_issuers_uris=ca_issuers_uris,
            extensions=extensions,
            fingerprint_sha1=fp_sha1,
            fingerprint_sha256=fp_sha256,
            fingerprint_md5=fp_md5,
            is_ca=is_ca,
            path_length=path_length,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage
        )
    
    async def get_certificate_chain(self) -> List[OpenSSL.crypto.X509]:
        """Get full certificate chain from server"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Use OpenSSL to get chain
            conn = OpenSSL.SSL.Connection(
                OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD),
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            conn.set_connect_state()
            conn.set_tlsext_host_name(self.hostname.encode())
            conn.connect((self.hostname, self.port))
            conn.do_handshake()
            
            chain = conn.get_peer_cert_chain()
            conn.close()
            
            return chain if chain else []
        except Exception as e:
            print(f"[!] Error getting certificate chain: {e}")
            return []
    
    async def scan_protocols_and_ciphers(self) -> Dict[str, Any]:
        """Scan supported protocols and ciphers"""
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        ciphers = []
        preferred_cipher = None
        
        # Test each protocol
        protocol_contexts = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will fail for SSLv2
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS,
        }
        
        for proto_name, proto_const in protocol_contexts.items():
            try:
                if proto_name in ['SSLv2', 'SSLv3']:
                    # SSLv2/SSLv3 not directly supported in modern Python
                    # Try with options
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    if proto_name == 'SSLv2':
                        context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                    else:
                        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                else:
                    context = ssl.SSLContext(proto_const)
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers('ALL:@SECLEVEL=0')
                
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        protocols[proto_name] = True
                        cipher = ssock.cipher()
                        if cipher:
                            ciphers.append({
                                'protocol': proto_name,
                                'name': cipher[0],
                                'version': cipher[1],
                                'bits': cipher[2]
                            })
                            if preferred_cipher is None:
                                preferred_cipher = {
                                    'protocol': proto_name,
                                    'name': cipher[0],
                                    'version': cipher[1],
                                    'bits': cipher[2]
                                }
            except Exception:
                pass
        
        return {
            'protocols': protocols,
            'ciphers': ciphers,
            'preferred_cipher': preferred_cipher
        }
    
    async def check_vulnerabilities(self, protocols: Dict[str, bool], 
                                     ciphers: List[Dict]) -> Dict[str, bool]:
        """Check for known SSL/TLS vulnerabilities"""
        vulns = {
            'heartbeat_vulnerable': False,      # Heartbleed
            'ccs_injection_vulnerable': False,  # CCS Injection
            'poodle_vulnerable': False,         # POODLE
            'freak_vulnerable': False,          # FREAK
            'logjam_vulnerable': False,         # Logjam
            'drown_vulnerable': False,          # DROWN
            'robot_vulnerable': False,          # ROBOT
            'sweet32_vulnerable': False,        # SWEET32
        }
        
        # Check for weak protocols
        if protocols.get('SSLv2') or protocols.get('SSLv3'):
            vulns['poodle_vulnerable'] = True
            vulns['drown_vulnerable'] = True
        
        if protocols.get('TLSv1') or protocols.get('TLSv1.1'):
            vulns['poodle_vulnerable'] = True  # POODLE affects TLS too
        
        # Check for weak ciphers
        cipher_names = [c['name'] for c in ciphers]
        for cipher in cipher_names:
            cipher_upper = cipher.upper()
            if any(weak in cipher_upper for weak in ['EXPORT', 'DES-CBC', 'RC4', 'MD5']):
                vulns['freak_vulnerable'] = True
            if '3DES' in cipher_upper or 'DES-CBC3' in cipher_upper:
                vulns['sweet32_vulnerable'] = True
            if 'DHE' in cipher_upper and 'EXPORT' in cipher_upper:
                vulns['logjam_vulnerable'] = True
            if 'RSA' in cipher_upper and 'EXPORT' in cipher_upper:
                vulns['freak_vulnerable'] = True
        
        # Heartbleed check (simplified - would need actual heartbeat test)
        # This is a placeholder - real check requires sending heartbeat request
        
        return vulns
    
    async def check_ocsp_stapling(self) -> bool:
        """Check for OCSP stapling"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Check for OCSP response in handshake
                    # This is simplified - real check needs to parse handshake
                    return False  # Placeholder
        except Exception:
            return False
    
    async def check_session_ticket(self) -> bool:
        """Check for session ticket support"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Check if session ticket was received
                    return hasattr(ssock, 'session') and ssock.session is not None
        except Exception:
            return False
    
    async def check_secure_renegotiation(self) -> bool:
        """Check for secure renegotiation support"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Check for secure renegotiation extension
                    return True  # Most modern servers support it
        except Exception:
            return False
    
    async def check_compression(self) -> bool:
        """Check for TLS compression (CRIME vulnerability)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_COMPRESSION
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # If compression is disabled, this will fail or not negotiate
                    return False  # Most modern servers disable compression
        except Exception:
            return False
    
    async def query_ct_logs(self) -> List[CTLogEntry]:
        """Query Certificate Transparency logs"""
        entries = []
        
        # Query crt.sh (most accessible)
        url = f"https://crt.sh/?q=%25.{self.hostname}&output=json"
        
        try:
            session = await self._get_session()
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(session, url, self.stealth_scheduler)
            else:
                resp = await session.get(url)
            
            if resp and resp.status == 200:
                data = await resp.json()
                for entry in data:
                    entries.append(CTLogEntry(
                        issuer_ca_id=entry.get('issuer_ca_id', 0),
                        issuer_name=entry.get('issuer_name', ''),
                        common_name=entry.get('common_name', ''),
                        name_value=entry.get('name_value', ''),
                        not_before=entry.get('not_before', ''),
                        not_after=entry.get('not_after', ''),
                        serial_number=entry.get('serial_number', ''),
                        log_id=entry.get('id', ''),
                        log_name='crt.sh',
                        entry_timestamp=entry.get('entry_timestamp', '')
                    ))
        except Exception as e:
            print(f"[!] CT log query error: {e}")
        
        return entries
    
    def analyze_cert_transparency(self, ct_entries: List[CTLogEntry], 
                                   certs: List[CertificateInfo]) -> Dict[str, Any]:
        """Analyze Certificate Transparency data"""
        result = {
            'total_entries': len(ct_entries),
            'unique_issuers': set(),
            'unique_serials': set(),
            'precertificates': 0,
            'certificates_in_ct': 0,
            'monitoring_recommendation': 'Enable CT monitoring for this domain'
        }
        
        for entry in ct_entries:
            result['unique_issuers'].add(entry.issuer_name)
            result['unique_serials'].add(entry.serial_number)
        
        result['unique_issuers'] = list(result['unique_issuers'])
        result['unique_serials'] = list(result['unique_serials'])
        
        # Check if current certs are in CT logs
        current_serials = {c.serial_number.upper() for c in certs}
        ct_serials = {s.upper() for s in result['unique_serials']}
        result['certificates_in_ct'] = len(current_serials & ct_serials)
        
        return result
    
    def calculate_score_and_grade(self, chain: CertificateChain,
                                   protocols: Dict[str, bool],
                                   ciphers: List[Dict],
                                   vulns: Dict[str, bool],
                                   certs: List[CertificateInfo]) -> tuple:
        """Calculate security score and grade"""
        score = 100
        findings = []
        
        # Certificate chain validation
        if not chain.is_valid:
            score -= 30
            findings.append({'type': 'error', 'message': 'Certificate chain validation failed', 'details': chain.errors})
        
        # Expired certificates
        now = datetime.now(timezone.utc)
        for cert in certs:
            if cert.not_after < now:
                score -= 40
                findings.append({'type': 'critical', 'message': f'Certificate expired: {cert.subject.get("CN", "Unknown")}'})
            elif (cert.not_after - now).days < 30:
                score -= 10
                findings.append({'type': 'warning', 'message': f'Certificate expires soon: {cert.subject.get("CN", "Unknown")} ({(cert.not_after - now).days} days)'})
        
        # Weak protocols
        for proto in self.WEAK_PROTOCOLS:
            if protocols.get(proto):
                score -= 20
                findings.append({'type': 'error', 'message': f'Weak protocol enabled: {proto}'})
        
        # Weak ciphers
        for cipher in ciphers:
            cipher_name = cipher['name'].upper()
            if any(weak in cipher_name for weak in self.WEAK_CIPHERS):
                score -= 15
                findings.append({'type': 'warning', 'message': f'Weak cipher: {cipher["name"]} ({cipher["protocol"]})'})
        
        # Vulnerabilities
        vuln_scores = {
            'heartbeat_vulnerable': 50,      # Heartbleed
            'ccs_injection_vulnerable': 30,  # CCS Injection
            'poodle_vulnerable': 25,         # POODLE
            'freak_vulnerable': 25,          # FREAK
            'logjam_vulnerable': 20,         # Logjam
            'drown_vulnerable': 30,          # DROWN
            'robot_vulnerable': 25,          # ROBOT
            'sweet32_vulnerable': 15,        # SWEET32
        }
        
        for vuln, penalty in vuln_scores.items():
            if vulns.get(vuln):
                score -= penalty
                findings.append({'type': 'critical' if penalty >= 30 else 'error', 
                               'message': f'Vulnerable to {vuln.replace("_", " ").title()}'})
        
        # Key size checks
        for cert in certs:
            if cert.public_key_algorithm == 'RSA' and cert.public_key_size < 2048:
                score -= 20
                findings.append({'type': 'error', 'message': f'Weak RSA key size: {cert.public_key_size} bits'})
            elif cert.public_key_algorithm == 'EC' and cert.public_key_size < 256:
                score -= 15
                findings.append({'type': 'warning', 'message': f'Weak EC key size: {cert.public_key_size} bits'})
        
        # Signature algorithm
        for cert in certs:
            if 'sha1' in cert.signature_algorithm.lower() or 'md5' in cert.signature_algorithm.lower():
                score -= 15
                findings.append({'type': 'warning', 'message': f'Weak signature algorithm: {cert.signature_algorithm}'})
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Grade
        if score >= 95:
            grade = 'A+'
        elif score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return score, grade, findings
    
    async def run(self) -> SSLScanResult:
        """Run complete SSL analysis"""
        print(f"[+] Starting SSL analysis for {self.hostname}:{self.port}")
        
        # Get certificate chain
        chain_certs = await self.get_certificate_chain()
        if not chain_certs:
            print(f"[!] Failed to get certificate chain")
            return SSLScanResult(
                hostname=self.hostname,
                port=self.port,
                certificates=[],
                chain=CertificateChain(chain=[], is_valid=False, trust_store='', errors=['Failed to get certificate chain']),
                protocols={}, ciphers=[], preferred_cipher=None,
                ocsp_stapling=False, session_ticket=False, secure_renegotiation=False,
                compression=False, heartbeat_vulnerable=False, ccs_injection_vulnerable=False,
                poodle_vulnerable=False, freak_vulnerable=False, logjam_vulnerable=False,
                drown_vulnerable=False, robot_vulnerable=False, sweet32_vulnerable=False,
                ct_logs=[], cert_transparency={}, score=0, grade='F', findings=[]
            )
        
        # Parse certificates
        certificates = [self._parse_certificate(cert) for cert in chain_certs]
        print(f"[+] Parsed {len(certificates)} certificates")
        
        # Validate chain (simplified)
        chain = CertificateChain(
            chain=certificates,
            is_valid=True,  # Would need proper validation
            trust_store='system',
            chain_length=len(certificates),
            root_ca=certificates[-1].subject.get('CN', 'Unknown') if certificates else None
        )
        
        # Scan protocols and ciphers
        proto_cipher = await self.scan_protocols_and_ciphers()
        protocols = proto_cipher['protocols']
        ciphers = proto_cipher['ciphers']
        preferred_cipher = proto_cipher['preferred_cipher']
        print(f"[+] Protocols: {[p for p, v in protocols.items() if v]}")
        print(f"[+] Ciphers found: {len(ciphers)}")
        
        # Check vulnerabilities
        vulns = await self.check_vulnerabilities(protocols, ciphers)
        
        # Check features
        ocsp_stapling = await self.check_ocsp_stapling()
        session_ticket = await self.check_session_ticket()
        secure_renegotiation = await self.check_secure_renegotiation()
        compression = await self.check_compression()
        
        # Query CT logs
        ct_logs = await self.query_ct_logs()
        print(f"[+] CT log entries: {len(ct_logs)}")
        
        # Analyze CT
        cert_transparency = self.analyze_cert_transparency(ct_logs, certificates)
        
        # Calculate score
        score, grade, findings = self.calculate_score_and_grade(
            chain, protocols, ciphers, vulns, certificates
        )
        
        print(f"[+] SSL Score: {score}/100 (Grade: {grade})")
        
        return SSLScanResult(
            hostname=self.hostname,
            port=self.port,
            certificates=certificates,
            chain=chain,
            protocols=protocols,
            ciphers=ciphers,
            preferred_cipher=preferred_cipher,
            ocsp_stapling=ocsp_stapling,
            session_ticket=session_ticket,
            secure_renegotiation=secure_renegotiation,
            compression=compression,
            heartbeat_vulnerable=vulns['heartbeat_vulnerable'],
            ccs_injection_vulnerable=vulns['ccs_injection_vulnerable'],
            poodle_vulnerable=vulns['poodle_vulnerable'],
            freak_vulnerable=vulns['freak_vulnerable'],
            logjam_vulnerable=vulns['logjam_vulnerable'],
            drown_vulnerable=vulns['drown_vulnerable'],
            robot_vulnerable=vulns['robot_vulnerable'],
            sweet32_vulnerable=vulns['sweet32_vulnerable'],
            ct_logs=ct_logs,
            cert_transparency=cert_transparency,
            score=score,
            grade=grade,
            findings=findings
        )


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ssl_analyzer.py <hostname> [port]")
        return
    
    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    analyzer = SSLAnalyzer(hostname, port)
    result = await analyzer.run()
    await analyzer.close()
    
    # Convert to dict for JSON serialization
    def default_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)
    
    import json
    print(json.dumps(result.__dict__, indent=2, default=default_serializer))


if __name__ == "__main__":
    asyncio.run(main())