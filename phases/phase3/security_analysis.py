"""
Phase 3: Security Analysis
Handles security posture assessment
"""

import logging
import requests
from typing import Dict, List, Any

logger = logging.getLogger(__name__)
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; BSI-Scanner/1.0)'}


class SecurityAnalysis:
    """Handles security posture analysis"""

    def analyze_security_headers(self, domain: str) -> Dict[str, Any]:
        """Analyze security headers and score them"""
        try:
            resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=15, allow_redirects=True)
            h = resp.headers

            security_headers = {
                'Strict-Transport-Security': h.get('Strict-Transport-Security'),
                'Content-Security-Policy': h.get('Content-Security-Policy'),
                'X-Frame-Options': h.get('X-Frame-Options'),
                'X-Content-Type-Options': h.get('X-Content-Type-Options'),
                'Referrer-Policy': h.get('Referrer-Policy'),
                'Permissions-Policy': h.get('Permissions-Policy') or h.get('Feature-Policy'),
                'X-XSS-Protection': h.get('X-XSS-Protection'),
                'Cross-Origin-Opener-Policy': h.get('Cross-Origin-Opener-Policy'),
                'Cross-Origin-Resource-Policy': h.get('Cross-Origin-Resource-Policy'),
            }

            present = sum(1 for v in security_headers.values() if v is not None)
            total = len(security_headers)
            score = int((present / total) * 100)

            missing = [k for k, v in security_headers.items() if v is None]

            return {
                'security_headers': security_headers,
                'present_count': present,
                'missing_count': len(missing),
                'missing_headers': missing,
                'score': score,
                'success': True,
            }
        except Exception as e:
            logger.error(f"Security header analysis failed: {e}")
            return {'security_headers': {}, 'score': 0, 'success': False, 'error': str(e)}

    def check_admin_panels(self, domain: str) -> Dict[str, Any]:
        """Check for exposed admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/admin/', '/admin.php',
            '/wp-admin', '/wp-admin/', '/wp-login.php',
            '/login', '/login.php', '/signin',
            '/user/login', '/users/sign_in',
            '/dashboard', '/controlpanel', '/cpanel',
            '/manage', '/management', '/manager',
            '/backend', '/backoffice',
            '/portal', '/console',
            '/admin/login', '/admin/dashboard',
            '/superadmin', '/siteadmin',
        ]

        found_panels = []
        for path in admin_paths:
            try:
                resp = requests.get(
                    f"https://{domain}{path}", headers=HEADERS,
                    timeout=5, allow_redirects=True
                )
                if resp.status_code == 200:
                    found_panels.append({'path': path, 'status': resp.status_code, 'access': 'OPEN'})
                elif resp.status_code in (401, 403):
                    found_panels.append({'path': path, 'status': resp.status_code, 'access': 'PROTECTED'})
            except Exception:
                pass

        return {'admin_panels': found_panels, 'success': True}

    def check_cookies(self, domain: str) -> Dict[str, Any]:
        """Check cookie security attributes"""
        try:
            resp = requests.get(f"https://{domain}", headers=HEADERS, timeout=15, allow_redirects=True)
            cookies = []
            for cookie in resp.cookies:
                # Use has_nonstandard_attr for HttpOnly/Secure (avoids deprecated _rest)
                http_only = cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly')
                secure = cookie.secure
                samesite = (
                    cookie.get_nonstandard_attr('SameSite') or
                    cookie.get_nonstandard_attr('samesite') or
                    'Not Set'
                )
                cookies.append({
                    'name': cookie.name,
                    'httponly': http_only,
                    'secure': secure,
                    'samesite': samesite,
                    'issues': self._cookie_issues(cookie.name, http_only, secure, samesite),
                })
            return {'cookie_security': cookies, 'success': True}
        except Exception as e:
            logger.error(f"Cookie security check failed: {e}")
            return {'cookie_security': [], 'success': False, 'error': str(e)}

    def _cookie_issues(self, name: str, httponly: bool, secure: bool, samesite: str) -> List[str]:
        """Return list of security issues for a cookie"""
        issues = []
        if not httponly:
            issues.append('Missing HttpOnly flag (XSS risk)')
        if not secure:
            issues.append('Missing Secure flag (transmitted over HTTP)')
        if samesite in ('Not Set', None, ''):
            issues.append('Missing SameSite attribute (CSRF risk)')
        return issues
