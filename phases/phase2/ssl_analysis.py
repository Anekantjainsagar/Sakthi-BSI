"""
Phase 2: SSL/TLS Analysis
Handles SSL certificate analysis and TLS configuration checks
"""

import logging
import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class SSLAnalysis:
    """Handles SSL/TLS analysis"""

    async def analyze_ssl(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration and return findings + weaknesses"""
        try:
            cert_info = self._get_certificate_info(domain)
            tls_result = self._check_tls_versions(domain)
            hsts = self._check_hsts(domain)
            cipher_info = self._get_cipher_info(domain)

            weaknesses = self._build_weaknesses(cert_info, tls_result, hsts, cipher_info)

            return {
                'certificate_info': cert_info,
                'tls_versions_supported': tls_result.get('supported', []),
                'tls_versions_rejected': tls_result.get('rejected', []),
                'hsts_enabled': hsts,
                'cipher_info': cipher_info,
                'weaknesses': weaknesses,
                'vulnerabilities': [w['title'] for w in weaknesses.get('issues', [])],
            }
        except Exception as e:
            logger.error(f"SSL analysis failed for {domain}: {e}")
            return {'error': str(e), 'weaknesses': {}}

    def _get_certificate_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    not_after = cert.get('notAfter', '')
                    expired = False
                    days_until_expiry = None
                    if not_after:
                        try:
                            expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_dt - datetime.utcnow()).days
                            expired = days_until_expiry < 0
                        except Exception:
                            pass

                    # Flatten subject/issuer tuples
                    def flatten_rdns(rdns):
                        result = {}
                        for rdn in rdns:
                            for k, v in rdn:
                                result[k] = v
                        return result

                    subject = flatten_rdns(cert.get('subject', []))
                    issuer = flatten_rdns(cert.get('issuer', []))
                    is_self_signed = subject == issuer

                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': not_after,
                        'days_until_expiry': days_until_expiry,
                        'expired': expired,
                        'self_signed': is_self_signed,
                        'san_domains': [san[1] for san in cert.get('subjectAltName', [])],
                    }
        except ssl.SSLCertVerificationError as e:
            return {'error': f'Certificate verification failed: {e}', 'self_signed': True, 'expired': False}
        except Exception as e:
            logger.error(f"Certificate retrieval failed for {domain}: {e}")
            return {'error': str(e)}

    def _check_tls_versions(self, domain: str) -> Dict[str, List[str]]:
        """Check which TLS versions are supported"""
        supported = []
        rejected = []

        # Map version name → ssl constant
        versions_to_check = []

        # TLSv1.3 — check via TLS_CLIENT context
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported.append('TLSv1.3')
        except Exception:
            rejected.append('TLSv1.3')

        # TLSv1.2
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported.append('TLSv1.2')
        except Exception:
            rejected.append('TLSv1.2')

        # TLSv1.1 (deprecated/weak)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported.append('TLSv1.1')
        except Exception:
            rejected.append('TLSv1.1')

        # TLSv1.0 (deprecated/weak)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported.append('TLSv1.0')
        except Exception:
            rejected.append('TLSv1.0')

        return {'supported': supported, 'rejected': rejected}

    def _check_hsts(self, domain: str) -> bool:
        """Check if HSTS header is present"""
        try:
            import urllib.request
            req = urllib.request.Request(
                f"https://{domain}",
                headers={'User-Agent': 'BSI-Scanner/1.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 'strict-transport-security' in {k.lower() for k in resp.headers.keys()}
        except Exception:
            return False

    def _get_cipher_info(self, domain: str) -> Dict[str, Any]:
        """Get negotiated cipher suite info"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    return {
                        'name': cipher[0] if cipher else 'unknown',
                        'protocol': cipher[1] if cipher else 'unknown',
                        'bits': cipher[2] if cipher else 0,
                    }
        except Exception as e:
            return {'error': str(e)}

    def _build_weaknesses(self, cert_info: Dict, tls_result: Dict,
                          hsts: bool, cipher_info: Dict) -> Dict[str, Any]:
        """Build ssl_weaknesses dict for Phase 4 consumption"""
        issues = []

        # HSTS
        if not hsts:
            issues.append({'title': 'HSTS Not Configured', 'severity': 'Medium',
                           'description': 'Strict-Transport-Security header missing'})

        # Expired cert
        if cert_info.get('expired'):
            issues.append({'title': 'SSL Certificate Expired', 'severity': 'Critical',
                           'description': 'The SSL certificate has expired'})
        elif cert_info.get('days_until_expiry') is not None and cert_info['days_until_expiry'] < 30:
            issues.append({'title': 'SSL Certificate Expiring Soon', 'severity': 'High',
                           'description': f"Certificate expires in {cert_info['days_until_expiry']} days"})

        # Self-signed
        if cert_info.get('self_signed'):
            issues.append({'title': 'Self-Signed Certificate', 'severity': 'High',
                           'description': 'Certificate is self-signed and not trusted by browsers'})

        # Weak TLS versions
        supported = tls_result.get('supported', [])
        if 'TLSv1.0' in supported:
            issues.append({'title': 'TLSv1.0 Supported (Deprecated)', 'severity': 'High',
                           'description': 'TLSv1.0 is deprecated and vulnerable to POODLE/BEAST attacks'})
        if 'TLSv1.1' in supported:
            issues.append({'title': 'TLSv1.1 Supported (Deprecated)', 'severity': 'Medium',
                           'description': 'TLSv1.1 is deprecated and should be disabled'})
        if 'TLSv1.2' not in supported and 'TLSv1.3' not in supported:
            issues.append({'title': 'No Modern TLS Support', 'severity': 'Critical',
                           'description': 'Neither TLSv1.2 nor TLSv1.3 is supported'})

        # Weak cipher
        bits = cipher_info.get('bits', 256)
        if isinstance(bits, int) and bits < 128:
            issues.append({'title': 'Weak Cipher Suite', 'severity': 'High',
                           'description': f'Negotiated cipher uses only {bits}-bit key'})

        return {
            'hsts_missing': not hsts,
            'expired_cert': cert_info.get('expired', False),
            'self_signed': cert_info.get('self_signed', False),
            'weak_tls_versions': [v for v in ['TLSv1.0', 'TLSv1.1'] if v in supported],
            'issues': issues,
            'issue_count': len(issues),
        }
