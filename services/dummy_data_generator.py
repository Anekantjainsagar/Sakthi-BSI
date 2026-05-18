#!/usr/bin/env python3
"""
Dummy Data Generator
Generates realistic dummy data for testing database integration without external APIs
"""

import json
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dummy-data-generator")


class DummyDataGenerator:
    """
    Generates realistic dummy data for all 5 analysis phases
    """
    
    def __init__(self, domain: str = "example.com"):
        """
        Initialize dummy data generator
        
        Args:
            domain: Domain to generate data for
        """
        self.domain = domain
        self.base_domain = domain.replace('www.', '')
        self.company_name = self.base_domain.split('.')[0].title()
    
    def generate_phase1_data(self) -> Dict[str, Any]:
        """
        Generate Phase 1: Business Domain Intelligence data
        
        Returns:
            Realistic business intelligence data
        """
        logger.info(f"Generating Phase 1 data for {self.domain}")
        
        return {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'hunter_io': {
                'emails': [
                    {'value': f'info@{self.base_domain}', 'type': 'generic', 'confidence': 95},
                    {'value': f'contact@{self.base_domain}', 'type': 'generic', 'confidence': 90},
                    {'value': f'admin@{self.base_domain}', 'type': 'generic', 'confidence': 85},
                    {'value': f'support@{self.base_domain}', 'type': 'generic', 'confidence': 80},
                ],
                'status': 'success'
            },
            'host_io': {
                'domain': self.base_domain,
                'ip': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'rank': random.randint(1000, 1000000),
                'email': f'admin@{self.base_domain}',
                'web': {
                    'domain': self.base_domain,
                    'ip': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
                    'rank': random.randint(1000, 1000000),
                    'links': [
                        'facebook.com',
                        'twitter.com',
                        'linkedin.com',
                        f'blog.{self.base_domain}',
                        f'shop.{self.base_domain}'
                    ]
                },
                'dns': {
                    'a': [f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}'],
                    'mx': [f'mail.{self.base_domain}', f'mail2.{self.base_domain}'],
                    'ns': [f'ns1.{self.base_domain}', f'ns2.{self.base_domain}']
                },
                'status': 'success'
            },
            'abstractapi_company': {
                'name': self.company_name,
                'domain': self.base_domain,
                'industry': random.choice(['Technology', 'Finance', 'Healthcare', 'Retail', 'Manufacturing']),
                'employees_count': random.choice(['10-50', '50-100', '100-500', '500-1000', '1000+']),
                'year_founded': random.randint(1990, 2020),
                'country': 'United States',
                'linkedin_url': f'https://linkedin.com/company/{self.company_name.lower()}',
                'status': 'success'
            },
            'whois_data': {
                'domain': self.base_domain,
                'registrar': random.choice(['GoDaddy', 'Namecheap', 'Google Domains', 'AWS Route 53']),
                'creation_date': (datetime.now() - timedelta(days=random.randint(365, 7300))).isoformat(),
                'expiration_date': (datetime.now() + timedelta(days=random.randint(30, 365))).isoformat(),
                'organization': self.company_name,
                'country': 'US'
            },
            'ai_analysis': {
                'company_overview': {
                    'primary_business': f'{self.company_name} provides innovative solutions in their industry',
                    'industry_vertical': random.choice(['Technology', 'Finance', 'Healthcare', 'Retail']),
                    'business_model': random.choice(['B2B', 'B2C', 'B2B2C', 'SaaS']),
                    'company_size': random.choice(['Small (10-50)', 'Medium (50-500)', 'Large (500+)']),
                    'founded_year': random.randint(1990, 2020),
                    'headquarters': random.choice(['San Francisco, CA', 'New York, NY', 'Austin, TX', 'Seattle, WA']),
                    'company_maturity': random.choice(['Startup', 'Growth', 'Mature', 'Established']),
                    'critical_data': ['Customer data', 'Financial records', 'Intellectual property']
                },
                'financial_intelligence': {
                    'annual_revenue': f'${random.randint(1, 100)}M',
                    'revenue_year': 2024,
                    'company_type': random.choice(['Public', 'Private']),
                    'is_public': random.choice([True, False]),
                    'market_cap': f'${random.randint(100, 10000)}M' if random.choice([True, False]) else 'N/A',
                    'funding_raised': f'${random.randint(1, 500)}M'
                },
                'threat_intelligence': {
                    'industry_apt_groups': [
                        {'name': 'APT28', 'description': 'Russian state-sponsored group'},
                        {'name': 'Lazarus', 'description': 'North Korean threat actor'}
                    ],
                    'critical_assets': ['Customer database', 'Financial systems', 'Intellectual property']
                },
                'regulatory_compliance': {
                    'confirmed_public': ['ISO 27001', 'SOC 2 Type II'],
                    'ai_suggested': ['GDPR', 'CCPA', 'HIPAA'],
                    'data_protection_requirements': ['Data encryption', 'Access controls', 'Audit logging']
                }
            }
        }
    
    def generate_phase2_data(self) -> Dict[str, Any]:
        """
        Generate Phase 2: Infrastructure Discovery data
        
        Returns:
            Realistic infrastructure data
        """
        logger.info(f"Generating Phase 2 data for {self.domain}")
        
        base_ip = f'192.168.{random.randint(1, 255)}'
        subdomains = [
            f'www.{self.base_domain}',
            f'mail.{self.base_domain}',
            f'api.{self.base_domain}',
            f'admin.{self.base_domain}',
            f'blog.{self.base_domain}',
            f'shop.{self.base_domain}',
            f'cdn.{self.base_domain}',
            f'staging.{self.base_domain}'
        ]
        
        return {
            'target': self.domain,
            'scan_date': datetime.now().isoformat(),
            'subdomains': subdomains,
            'open_ports': {
                base_ip: [80, 443, 22, 25, 53, 3306, 5432]
            },
            'port_banners': {
                base_ip: {
                    '80': 'Apache/2.4.41 (Ubuntu)',
                    '443': 'nginx/1.18.0',
                    '22': 'OpenSSH_7.4',
                    '25': 'Postfix 3.4.8',
                    '3306': 'MySQL 5.7.32',
                    '5432': 'PostgreSQL 12.4'
                }
            },
            'ssl_analysis': {
                'certificate_valid': True,
                'issuer': 'Let\'s Encrypt',
                'expiration_date': (datetime.now() + timedelta(days=random.randint(30, 365))).isoformat(),
                'tls_version': 'TLS 1.3',
                'cipher_suites': ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']
            },
            'dns_records': {
                'A': [f'{base_ip}.{random.randint(1, 255)}'],
                'MX': [f'mail.{self.base_domain}', f'mail2.{self.base_domain}'],
                'NS': [f'ns1.{self.base_domain}', f'ns2.{self.base_domain}'],
                'TXT': [f'v=spf1 include:{self.base_domain} ~all'],
                'CAA': [f'0 issue "letsencrypt.org"'],
                'DNSSEC': {'enabled': True}
            },
            'mail_server_analysis': {
                'spf_record': f'v=spf1 include:{self.base_domain} ~all',
                'dmarc_record': 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{self.base_domain}',
                'dkim_record': 'v=DKIM1; k=rsa; p=MIGfMA0BgkqhkiG9w0BAQEFAAOCAQ8A...'
            },
            'ip_reputation': {
                base_ip: {
                    'abuseipdb': {'abuse_score': random.randint(0, 30)},
                    'alienvault': {'pulse_count': random.randint(0, 5)},
                    'virustotal': {'malicious': random.randint(0, 3)}
                }
            },
            'blacklisted_ips': [],
            'security_misconfigs': {
                'open_admin_panels': [],
                'open_databases': [],
                'exposed_files': []
            }
        }
    
    def generate_phase3_data(self) -> Dict[str, Any]:
        """
        Generate Phase 3: Application Landscape Assessment data
        
        Returns:
            Realistic application stack data
        """
        logger.info(f"Generating Phase 3 data for {self.domain}")
        
        return {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            '1_application_discovery': {
                'status': 'Active',
                'status_code': 200,
                'server': 'Apache/2.4.41 (Ubuntu)',
                'server_version': '2.4.41',
                'powered_by': 'PHP/7.4.3',
                'response_time_ms': random.randint(100, 500),
                'content_length': random.randint(10000, 100000),
                'detection_method': 'Direct HTTP request + HTML parsing'
            },
            '2_web_server_stack': {
                'web_server': 'Apache/2.4.41',
                'cms': random.choice([['WordPress'], ['Drupal'], ['Joomla'], []]),
                'cms_version': random.choice(['5.4', '6.0', '7.0', None]),
                'frameworks': random.choice([['React'], ['Angular'], ['Vue.js'], []]),
                'javascript_libraries': ['jQuery', 'Bootstrap', 'Lodash'],
                'javascript_versions': {
                    'jQuery': '3.6.0',
                    'Bootstrap': '4.6.0',
                    'Lodash': '4.17.21'
                },
                'analytics': ['Google Analytics', 'Hotjar'],
                'cdn': ['Cloudflare', 'AWS CloudFront'],
                'fonts': ['Google Fonts'],
                'all_detected': ['WordPress', 'jQuery', 'Bootstrap', 'Google Analytics']
            },
            '3_erp_sap_detection': {
                'detected': False,
                'indicators': []
            },
            '4_third_party_software': {
                'detected': ['Stripe', 'PayPal', 'Auth0', 'Sentry'],
                'count': 4
            },
            '5_code_repositories': {
                'github': f'https://github.com/{self.company_name.lower()}',
                'gitlab': None,
                'bitbucket': None,
                'public_repos': random.randint(0, 10)
            },
            '6_outdated_software': {
                'detected': [
                    {'name': 'jQuery', 'version': '3.6.0', 'latest': '3.7.0', 'risk': 'Low'},
                    {'name': 'Bootstrap', 'version': '4.6.0', 'latest': '5.3.0', 'risk': 'Medium'}
                ]
            },
            '7_security_posture': {
                'security_headers': {
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'Strict-Transport-Security': 'max-age=31536000',
                    'Content-Security-Policy': "default-src 'self'"
                },
                'missing_headers': ['X-XSS-Protection'],
                'score': random.randint(70, 95)
            },
            '8_api_discovery': {
                'endpoints': [
                    '/api/v1/users',
                    '/api/v1/products',
                    '/api/v1/orders',
                    '/api/v2/auth'
                ],
                'count': 4
            },
            '9_database_detection': {
                'detected': ['MySQL', 'PostgreSQL'],
                'versions': {'MySQL': '5.7.32', 'PostgreSQL': '12.4'}
            }
        }
    
    def generate_phase4_data(self) -> Dict[str, Any]:
        """
        Generate Phase 4: Threat Correlation & CVE Analysis data
        
        Returns:
            Realistic threat correlation data
        """
        logger.info(f"Generating Phase 4 data for {self.domain}")
        
        return {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'technologies': [
                {'name': 'WordPress', 'version': '5.4', 'type': 'CMS', 'cpe': 'cpe:/a:wordpress:wordpress:5.4'},
                {'name': 'jQuery', 'version': '3.6.0', 'type': 'JavaScript Library'},
                {'name': 'Apache', 'version': '2.4.41', 'type': 'Web Server'},
                {'name': 'PHP', 'version': '7.4.3', 'type': 'Programming Language'},
                {'name': 'MySQL', 'version': '5.7.32', 'type': 'Database'}
            ],
            'cves_all': [
                {
                    'cve': 'CVE-2021-24499',
                    'tech': 'WordPress',
                    'version': '5.4',
                    'cvss': 9.8,
                    'description': 'Unauthenticated arbitrary options update in WordPress',
                    'exploit_available': True
                },
                {
                    'cve': 'CVE-2021-21985',
                    'tech': 'jQuery',
                    'version': '3.6.0',
                    'cvss': 6.1,
                    'description': 'jQuery prototype pollution vulnerability',
                    'exploit_available': False
                },
                {
                    'cve': 'CVE-2021-41773',
                    'tech': 'Apache',
                    'version': '2.4.41',
                    'cvss': 7.5,
                    'description': 'Apache HTTP Server path traversal vulnerability',
                    'exploit_available': True
                }
            ],
            'security_issues': [
                {
                    'type': 'Missing Security Header',
                    'header': 'X-XSS-Protection',
                    'severity': 'MEDIUM',
                    'description': 'X-XSS-Protection header not set'
                },
                {
                    'type': 'Weak TLS Configuration',
                    'header': 'TLS 1.0 supported',
                    'severity': 'HIGH',
                    'description': 'Deprecated TLS versions supported'
                },
                {
                    'type': 'Exposed Admin Panel',
                    'header': '/wp-admin',
                    'severity': 'HIGH',
                    'description': 'WordPress admin panel publicly accessible'
                }
            ],
            'attack_vectors': [
                'Unauthenticated RCE via WordPress plugin vulnerability',
                'SQL injection via outdated MySQL version',
                'XSS via jQuery prototype pollution',
                'Path traversal via Apache vulnerability'
            ],
            'apt_mapping': [
                {'group': 'APT28', 'techniques': ['Initial Access', 'Execution', 'Persistence']},
                {'group': 'Lazarus', 'techniques': ['Lateral Movement', 'Exfiltration']}
            ]
        }
    
    def generate_phase5_data(self) -> Dict[str, Any]:
        """
        Generate Phase 5: Risk Assessment & Categorization data
        
        Returns:
            Realistic risk assessment data
        """
        logger.info(f"Generating Phase 5 data for {self.domain}")
        
        return {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'business_risk': {
                'risk_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'business_impact_score': random.uniform(3.0, 9.0),
                'categories': [
                    'Data Breach Risk',
                    'Operational Disruption',
                    'Compliance Violation',
                    'Reputational Damage'
                ],
                'analysis': 'The organization faces significant risks from outdated software and exposed admin panels.'
            },
            'infrastructure_risk': {
                'risk_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'attack_surface_score': random.uniform(3.0, 9.0),
                'risk_areas': [
                    'Exposed admin interfaces',
                    'Weak TLS configuration',
                    'Open database ports',
                    'Unpatched services'
                ],
                'analysis': 'Infrastructure has multiple exposed services and weak security configurations.'
            },
            'application_risk': {
                'risk_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'vulnerability_density': random.uniform(3.0, 9.0),
                'risk_categories': [
                    'WordPress RCE vulnerability',
                    'Outdated JavaScript libraries',
                    'Missing security headers',
                    'Weak authentication'
                ],
                'analysis': 'Application stack contains multiple known vulnerabilities with available exploits.'
            },
            'business_impact': {
                'overall_impact': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'financial_range': f'${random.randint(100, 5000)}K - ${random.randint(5000, 50000)}K',
                'recovery_time': f'{random.randint(1, 12)} weeks',
                'impact_dimensions': {
                    'financial': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'operational': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'data_breach': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'customer_trust': random.choice(['Critical', 'High', 'Medium', 'Low']),
                    'regulatory': random.choice(['Critical', 'High', 'Medium', 'Low'])
                },
                'analysis': 'A successful breach could result in significant financial and reputational damage.'
            },
            'risk_matrix': {
                'composite_risk_score': random.uniform(3.0, 9.0),
                'risk_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'interpretation': 'The organization faces a high-risk security posture requiring immediate remediation.',
                'dimensions': {
                    'business': {'score': random.randint(1, 4), 'level': random.choice(['Critical', 'High', 'Medium', 'Low'])},
                    'infrastructure': {'score': random.randint(1, 4), 'level': random.choice(['Critical', 'High', 'Medium', 'Low'])},
                    'application': {'score': random.randint(1, 4), 'level': random.choice(['Critical', 'High', 'Medium', 'Low'])},
                    'business_impact': {'score': random.randint(1, 4), 'level': random.choice(['Critical', 'High', 'Medium', 'Low'])}
                }
            },
            'remediation_recommendations': [
                'Update WordPress to latest version immediately',
                'Patch Apache HTTP Server to 2.4.50+',
                'Restrict access to /wp-admin to known IPs',
                'Enable TLS 1.2+ only',
                'Implement Web Application Firewall (WAF)',
                'Enable security headers',
                'Implement intrusion detection system'
            ]
        }
    
    def generate_all_phases(self) -> Dict[str, Dict[str, Any]]:
        """
        Generate data for all 5 phases
        
        Returns:
            Dictionary with all phase data
        """
        logger.info(f"Generating all phase data for {self.domain}")
        
        return {
            'phase1': self.generate_phase1_data(),
            'phase2': self.generate_phase2_data(),
            'phase3': self.generate_phase3_data(),
            'phase4': self.generate_phase4_data(),
            'phase5': self.generate_phase5_data()
        }


# Example usage
if __name__ == "__main__":
    generator = DummyDataGenerator("example.com")
    
    # Generate all phases
    all_data = generator.generate_all_phases()
    
    # Print summary
    for phase, data in all_data.items():
        print(f"\n{phase.upper()}:")
        print(json.dumps(data, indent=2, default=str)[:500] + "...")
