"""
Phase 3: Main Application Scanner
Orchestrates all application landscape analysis
"""

import logging
import os
import re
import requests
from typing import Dict, Any, List
from .tech_detection import TechDetection
from .api_discovery import APIDiscovery
from .security_analysis import SecurityAnalysis

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; BSI-Scanner/1.0)'}


class CompleteBSIScanner:
    """Main orchestrator for Phase 3: Application Landscape Assessment"""

    def __init__(self, domain: str):
        self.domain = domain
        self.tech_detection = TechDetection()
        self.api_discovery = APIDiscovery()
        self.security_analysis = SecurityAnalysis()
        self._base_response = None  # cache first HTTP response
        logger.info(f"CompleteBSIScanner initialized for {domain}")

    def _get_base_response(self):
        """Fetch and cache the base domain response"""
        if self._base_response is None:
            try:
                self._base_response = requests.get(
                    f"https://{self.domain}", headers=HEADERS, timeout=15, allow_redirects=True
                )
            except Exception as e:
                logger.error(f"Base request failed for {self.domain}: {e}")
        return self._base_response

    def run_full_scan(self) -> Dict[str, Any]:
        """Run complete application landscape scan"""
        logger.info(f"Starting full scan for {self.domain}")

        result = {
            'domain': self.domain,
            '1_application_discovery': self._application_discovery(),
            '2_web_server_stack': self._web_server_technology_stack(),
            '3_erp_sap_detection': self._erp_sap_detection(),
            '4_third_party_software': self._third_party_software_inventory(),
            '5_code_repositories': self._code_repository_analysis(),
            '6_outdated_software': self._outdated_software_detection(),
            '7_security_posture': self._security_posture_analysis(),
            '8_api_discovery': self._api_endpoint_discovery(),
            '9_database_detection': self._database_detection(),
            '10_threat_intelligence': self._threat_intelligence(),
            '11_data_leak_detection': self._data_leak_detection(),
            '12_s3_bucket_exposure': self._s3_bucket_exposure(),
        }

        logger.info(f"Full scan complete for {self.domain}")
        return result

    def _application_discovery(self) -> Dict[str, Any]:
        """Basic application discovery"""
        try:
            resp = self._get_base_response()
            if resp is None:
                return {'status': 'Unreachable', 'error': 'Could not connect'}
            return {
                'status': 'Active' if resp.status_code < 400 else 'Error',
                'http_status': resp.status_code,
                'server': resp.headers.get('Server', 'Not disclosed'),
                'powered_by': resp.headers.get('X-Powered-By', ''),
                'response_time_ms': int(resp.elapsed.total_seconds() * 1000),
                'content_length': len(resp.content),
                'final_url': resp.url,
                'redirect_count': len(resp.history),
            }
        except Exception as e:
            logger.error(f"Application discovery failed: {e}")
            return {'status': 'Error', 'error': str(e)}

    def _web_server_technology_stack(self) -> Dict[str, Any]:
        """Detect web technology stack"""
        cms = self.tech_detection.detect_cms(self.domain)
        frameworks = self.tech_detection.detect_frameworks(self.domain)
        js_libs = self.tech_detection.detect_javascript_libraries(self.domain)
        return {
            'cms': cms.get('cms', []),
            'frameworks': frameworks.get('frameworks', []),
            'javascript_libraries': js_libs.get('libraries', []),
        }

    def _erp_sap_detection(self) -> Dict[str, Any]:
        """Detect ERP/SAP systems by checking known paths"""
        erp_paths = [
            ('/sap/bc/gui/sap/its/webgui', 'SAP WebGUI'),
            ('/sap/hana/xs/ide/', 'SAP HANA XS'),
            ('/irj/portal', 'SAP NetWeaver Portal'),
            ('/nwbc', 'SAP NetWeaver Business Client'),
            ('/dynamics/', 'Microsoft Dynamics'),
            ('/oracle/', 'Oracle ERP'),
            ('/peoplesoft/', 'PeopleSoft'),
            ('/workday/', 'Workday'),
        ]
        detected = []
        for path, name in erp_paths:
            try:
                resp = requests.get(f"https://{self.domain}{path}", headers=HEADERS, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 401, 403):
                    detected.append({'system': name, 'path': path, 'status': resp.status_code})
            except Exception:
                pass
        return {'detected_systems': detected}

    def _third_party_software_inventory(self) -> Dict[str, Any]:
        """Detect third-party scripts and services from page source"""
        resp = self._get_base_response()
        if resp is None:
            return {'analytics': [], 'payment': [], 'chat': [], 'cdn': [], 'marketing': []}

        content = resp.text.lower()
        inventory = {
            'analytics': [],
            'payment': [],
            'chat': [],
            'cdn': [],
            'marketing': [],
        }

        checks = {
            'analytics': [
                ('google-analytics.com', 'Google Analytics'),
                ('googletagmanager.com', 'Google Tag Manager'),
                ('segment.com', 'Segment'),
                ('mixpanel.com', 'Mixpanel'),
                ('hotjar.com', 'Hotjar'),
                ('amplitude.com', 'Amplitude'),
                ('heap.io', 'Heap'),
            ],
            'payment': [
                ('stripe.com', 'Stripe'),
                ('paypal.com', 'PayPal'),
                ('braintreegateway.com', 'Braintree'),
                ('square.com', 'Square'),
                ('adyen.com', 'Adyen'),
            ],
            'chat': [
                ('intercom.io', 'Intercom'),
                ('zendesk.com', 'Zendesk'),
                ('drift.com', 'Drift'),
                ('crisp.chat', 'Crisp'),
                ('tawk.to', 'Tawk.to'),
                ('freshchat.com', 'Freshchat'),
            ],
            'cdn': [
                ('cloudflare.com', 'Cloudflare'),
                ('fastly.net', 'Fastly'),
                ('akamaihd.net', 'Akamai'),
                ('cloudfront.net', 'AWS CloudFront'),
                ('cdn.jsdelivr.net', 'jsDelivr'),
            ],
            'marketing': [
                ('hubspot.com', 'HubSpot'),
                ('marketo.com', 'Marketo'),
                ('salesforce.com', 'Salesforce'),
                ('mailchimp.com', 'Mailchimp'),
                ('klaviyo.com', 'Klaviyo'),
            ],
        }

        for category, services in checks.items():
            for pattern, name in services:
                if pattern in content:
                    inventory[category].append(name)

        return inventory

    def _code_repository_analysis(self) -> Dict[str, Any]:
        """Check robots.txt for disallowed paths and look for repo hints"""
        result = {'robots_disallow': [], 'github_repos': [], 'exposed_paths': []}
        try:
            resp = requests.get(f"https://{self.domain}/robots.txt", headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            result['robots_disallow'].append(path)
        except Exception:
            pass

        # Check for .git exposure
        try:
            resp = requests.get(f"https://{self.domain}/.git/HEAD", headers=HEADERS, timeout=5)
            if resp.status_code == 200 and 'ref:' in resp.text:
                result['exposed_paths'].append({'path': '/.git/HEAD', 'severity': 'Critical', 'issue': 'Git repository exposed'})
        except Exception:
            pass

        # Check for .env exposure
        try:
            resp = requests.get(f"https://{self.domain}/.env", headers=HEADERS, timeout=5)
            if resp.status_code == 200 and ('DB_' in resp.text or 'APP_KEY' in resp.text or 'SECRET' in resp.text):
                result['exposed_paths'].append({'path': '/.env', 'severity': 'Critical', 'issue': '.env file exposed'})
        except Exception:
            pass

        return result

    def _outdated_software_detection(self) -> Dict[str, Any]:
        """Detect outdated/vulnerable software from headers and page content"""
        vulnerable = []
        libraries = []

        resp = self._get_base_response()
        if resp is None:
            return {'vulnerable': [], 'libraries': []}

        # Check server header for version info
        server = resp.headers.get('Server', '')
        if server:
            libraries.append({'name': 'Web Server', 'version': server})
            # Known vulnerable patterns
            vuln_patterns = [
                (r'Apache/2\.2\.', 'Apache 2.2.x', 'High', 'End-of-life, multiple CVEs'),
                (r'Apache/2\.4\.(1[0-9]|[0-9])\b', 'Apache 2.4 (old)', 'Medium', 'Outdated minor version'),
                (r'nginx/1\.(1[0-2]|[0-9])\.', 'nginx (old)', 'Medium', 'Outdated nginx version'),
                (r'PHP/5\.', 'PHP 5.x', 'Critical', 'End-of-life PHP version'),
                (r'PHP/7\.[0-2]\.', 'PHP 7.0-7.2', 'High', 'End-of-life PHP version'),
                (r'OpenSSL/1\.0\.', 'OpenSSL 1.0.x', 'High', 'Outdated OpenSSL'),
            ]
            for pattern, name, severity, desc in vuln_patterns:
                if re.search(pattern, server, re.IGNORECASE):
                    vulnerable.append({'library': name, 'version': server, 'severity': severity, 'description': desc})

        # Check X-Powered-By
        powered_by = resp.headers.get('X-Powered-By', '')
        if powered_by:
            libraries.append({'name': 'Backend', 'version': powered_by})
            if re.search(r'PHP/[45]\.', powered_by):
                vulnerable.append({'library': 'PHP', 'version': powered_by, 'severity': 'Critical', 'description': 'End-of-life PHP version'})

        # Check page content for JS library versions
        content = resp.text
        js_version_patterns = [
            (r'jquery[/-](\d+\.\d+\.\d+)', 'jQuery'),
            (r'bootstrap[/-](\d+\.\d+\.\d+)', 'Bootstrap'),
            (r'angular[/-](\d+\.\d+\.\d+)', 'Angular'),
            (r'react[/-](\d+\.\d+\.\d+)', 'React'),
        ]
        for pattern, name in js_version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                libraries.append({'name': name, 'version': version})
                # Flag very old jQuery
                if name == 'jQuery' and version.startswith('1.'):
                    vulnerable.append({'library': 'jQuery', 'version': version, 'severity': 'Medium', 'description': 'jQuery 1.x has known XSS vulnerabilities'})

        return {'vulnerable': vulnerable, 'libraries': libraries}

    def _security_posture_analysis(self) -> Dict[str, Any]:
        """Analyze security posture: headers, admin panels, cookies"""
        headers_data = self.security_analysis.analyze_security_headers(self.domain)
        admin_data = self.security_analysis.check_admin_panels(self.domain)
        cookie_data = self.security_analysis.check_cookies(self.domain)

        # Build missing headers list for Phase 4
        security_headers = headers_data.get('security_headers', {})
        missing_headers = [h for h, v in security_headers.items() if v is None]

        return {
            'security_headers': security_headers,
            'missing_headers': missing_headers,
            'admin_panels': admin_data.get('admin_panels', []),
            'cookie_security': cookie_data.get('cookie_security', []),
            'header_score': headers_data.get('score', 0),
        }

    def _api_endpoint_discovery(self) -> Dict[str, Any]:
        """Discover API endpoints"""
        api_data = self.api_discovery.discover_api_endpoints(self.domain)
        graphql_data = self.api_discovery.discover_graphql(self.domain)
        swagger_data = self.api_discovery.discover_swagger(self.domain)
        return {
            'api_endpoints': api_data.get('api_endpoints', []),
            'graphql_endpoints': graphql_data.get('graphql_endpoints', []),
            'swagger_docs': swagger_data.get('swagger_docs', []),
        }

    def _database_detection(self) -> Dict[str, Any]:
        """Detect exposed database interfaces"""
        exposed = []
        db_paths = [
            ('/phpmyadmin', 'phpMyAdmin'),
            ('/phpmyadmin/', 'phpMyAdmin'),
            ('/pma', 'phpMyAdmin'),
            ('/adminer.php', 'Adminer'),
            ('/adminer', 'Adminer'),
            ('/db', 'Database Interface'),
            ('/database', 'Database Interface'),
            ('/_db', 'Database Interface'),
            ('/mongo-express', 'Mongo Express'),
            ('/redis-commander', 'Redis Commander'),
            ('/kibana', 'Kibana'),
            ('/elasticsearch', 'Elasticsearch'),
        ]
        for path, name in db_paths:
            try:
                resp = requests.get(f"https://{self.domain}{path}", headers=HEADERS, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 401, 403):
                    exposed.append({
                        'name': name,
                        'path': path,
                        'status': resp.status_code,
                        'severity': 'Critical' if resp.status_code == 200 else 'High',
                        'exposed': resp.status_code == 200,
                    })
            except Exception:
                pass
        return {'database_interfaces': exposed, 'exposed_count': sum(1 for d in exposed if d['exposed'])}

    def _threat_intelligence(self) -> Dict[str, Any]:
        """Query VirusTotal for domain threat intelligence"""
        vt_key = os.getenv('VIRUSTOTAL_KEY')
        if not vt_key:
            return {'status': 'no_key', 'malicious': 0, 'suspicious': 0}
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            headers = {'x-apikey': vt_key}
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'status': 'success',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': data.get('reputation', 0),
                    'categories': data.get('categories', {}),
                }
            return {'status': f'HTTP {resp.status_code}', 'malicious': 0, 'suspicious': 0}
        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return {'status': 'error', 'error': str(e), 'malicious': 0, 'suspicious': 0}

    def _data_leak_detection(self) -> Dict[str, Any]:
        """Query LeakIX for data leak information"""
        leakix_key = os.getenv('LEAKIX_KEY')
        if not leakix_key:
            return {'status': 'no_key', 'leaks': []}
        try:
            url = f"https://leakix.net/domain/{self.domain}"
            headers = {'api-key': leakix_key, 'Accept': 'application/json'}
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {'status': 'success', 'leaks': data if isinstance(data, list) else [data]}
            return {'status': f'HTTP {resp.status_code}', 'leaks': []}
        except Exception as e:
            logger.error(f"LeakIX query failed: {e}")
            return {'status': 'error', 'error': str(e), 'leaks': []}

    def _s3_bucket_exposure(self) -> Dict[str, Any]:
        """Check for exposed S3 buckets using GrayHatWarfare"""
        ghw_key = os.getenv('GRAYHATWARFARE_KEY')
        if not ghw_key:
            return {'status': 'no_key', 'buckets': []}
        try:
            company = self.domain.split('.')[0]
            url = "https://buckets.grayhatwarfare.com/api/v1/buckets"
            headers = {'Authorization': f'Bearer {ghw_key}'}
            params = {'keywords': company, 'limit': 20}
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                buckets = data.get('buckets', [])
                return {'status': 'success', 'buckets': buckets, 'count': len(buckets)}
            return {'status': f'HTTP {resp.status_code}', 'buckets': []}
        except Exception as e:
            logger.error(f"GrayHatWarfare query failed: {e}")
            return {'status': 'error', 'error': str(e), 'buckets': []}
