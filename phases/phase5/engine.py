"""
Phase 5: Main Risk Assessment Engine
Orchestrates risk assessment and categorization
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, List
from .risk_assessment import RiskAssessment

logger = logging.getLogger(__name__)


class RiskAssessmentEngine:
    """Main orchestrator for Phase 5: Risk Assessment"""

    def __init__(self):
        self.risk_assessment = RiskAssessment()
        self.assessment_data = None
        logger.info("RiskAssessmentEngine initialized")

    def run_full_assessment(self, correlation_data: Dict, infra_data: Dict,
                            domain_data: Dict, app_data: Dict) -> Dict[str, Any]:
        """Run full risk assessment"""
        try:
            risk_overview = self.risk_assessment.assess_risk(
                correlation_data, infra_data, domain_data, app_data
            )

            assessment = {
                'risk_overview': risk_overview,
                'asset_risks': self._assess_asset_risks(infra_data, app_data),
                'threat_landscape': self._analyze_threat_landscape(correlation_data),
                'compliance_status': self._assess_compliance(domain_data, app_data),
                'business_impact': self._assess_business_impact(risk_overview, domain_data),
                'recommendations': self._generate_recommendations(risk_overview, correlation_data, infra_data, app_data),
                # Keys expected by DataStreamer metrics
                'business_risk': {'risk_level': risk_overview.get('overall_risk_level', 'Unknown')},
                'infrastructure_risk': {'risk_level': self._infra_risk_level(infra_data)},
                'application_risk': {'risk_level': self._app_risk_level(app_data)},
            }

            self.assessment_data = assessment
            self._save_report(assessment)
            logger.info("Risk assessment complete")
            return assessment

        except Exception as e:
            logger.error(f"Risk assessment failed: {e}", exc_info=True)
            return {'error': str(e)}

    def _assess_asset_risks(self, infra_data: Dict, app_data: Dict) -> List[Dict]:
        """Assess individual asset risks"""
        assets = []

        # IP assets
        for ip in infra_data.get('ip_addresses', []):
            blacklisted = any(b.get('ip') == ip for b in infra_data.get('blacklisted_ips', []))
            assets.append({
                'name': f'IP: {ip}',
                'type': 'IP Address',
                'risk_level': 'High' if blacklisted else 'Low',
                'blacklisted': blacklisted,
                'vulnerabilities': [],
            })

        # Subdomain assets (top 10)
        for sub in infra_data.get('subdomains', [])[:10]:
            assets.append({
                'name': sub,
                'type': 'Subdomain',
                'risk_level': 'Low',
                'vulnerabilities': [],
            })

        # Application assets
        app_discovery = app_data.get('1_application_discovery', {})
        if app_discovery.get('status') == 'Active':
            security = app_data.get('7_security_posture', {})
            open_panels = [p for p in security.get('admin_panels', []) if p.get('access') == 'OPEN']
            assets.append({
                'name': f"Web Application ({app_data.get('domain', 'unknown')})",
                'type': 'Web Application',
                'risk_level': 'Critical' if open_panels else 'Medium',
                'open_admin_panels': len(open_panels),
                'header_score': security.get('header_score', 0),
                'vulnerabilities': [p['path'] for p in open_panels],
            })

        return assets

    def _analyze_threat_landscape(self, correlation_data: Dict) -> Dict[str, Any]:
        """Analyze threat landscape from correlation data"""
        return {
            'threat_actors': correlation_data.get('threat_actors', []),
            'attack_vectors': correlation_data.get('attack_chains', []),
            'mitre_techniques': list(correlation_data.get('mitre_mapping', {}).keys()),
            'industry_threats': [],
            'risk_factors': correlation_data.get('risk_factors', []),
        }

    def _assess_compliance(self, domain_data: Dict, app_data: Dict) -> Dict[str, Any]:
        """Assess compliance status based on available data"""
        security = app_data.get('7_security_posture', {})
        headers = security.get('security_headers', {})
        missing = security.get('missing_headers', [])

        # GDPR indicators
        has_csp = headers.get('Content-Security-Policy') is not None
        has_hsts = headers.get('Strict-Transport-Security') is not None
        gdpr_gaps = []
        if not has_hsts:
            gdpr_gaps.append('HSTS not configured')
        if not has_csp:
            gdpr_gaps.append('CSP not configured')

        # PCI-DSS indicators
        ssl_weak = app_data.get('ssl_weaknesses', {}) or {}
        pci_gaps = []
        if ssl_weak.get('weak_tls_versions'):
            pci_gaps.append(f"Deprecated TLS: {', '.join(ssl_weak['weak_tls_versions'])}")
        if ssl_weak.get('expired_cert'):
            pci_gaps.append('Expired SSL certificate')

        # HIPAA indicators
        hipaa_gaps = list(gdpr_gaps)  # HIPAA requires similar controls

        return {
            'GDPR': {
                'status': 'Partial' if not gdpr_gaps else 'Non-Compliant',
                'gaps': gdpr_gaps,
            },
            'PCI-DSS': {
                'status': 'Non-Compliant' if pci_gaps else 'Partial',
                'gaps': pci_gaps,
            },
            'HIPAA': {
                'status': 'Partial' if not hipaa_gaps else 'Non-Compliant',
                'gaps': hipaa_gaps,
            },
            'ISO-27001': {
                'status': 'Unknown',
                'gaps': ['Manual assessment required'],
            },
        }

    def _assess_business_impact(self, risk_overview: Dict, domain_data: Dict) -> Dict[str, Any]:
        """Assess business impact"""
        risk_level = risk_overview.get('overall_risk_level', 'Unknown')
        impact_map = {
            'Critical': ('Severe', 'Immediate action required — potential for significant financial and reputational damage'),
            'High': ('Significant', 'Address within 30 days — risk of data breach or service disruption'),
            'Medium': ('Moderate', 'Address within 90 days — limited exposure'),
            'Low': ('Minor', 'Address within 6 months — minimal risk'),
            'Minimal': ('Negligible', 'No immediate action required'),
        }
        impact, description = impact_map.get(risk_level, ('Unknown', 'Unable to assess'))

        # Try to get company info for context
        ai = domain_data.get('ai_analysis', {}) if domain_data else {}
        company_size = ai.get('company_overview', {}).get('company_size', 'Unknown')
        industry = ai.get('company_overview', {}).get('industry_vertical', 'Unknown')

        return {
            'potential_impact': impact,
            'description': description,
            'financial_risk': 'High' if risk_level in ('Critical', 'High') else 'Medium' if risk_level == 'Medium' else 'Low',
            'operational_impact': 'High' if risk_level in ('Critical', 'High') else 'Low',
            'reputational_risk': 'High' if risk_level == 'Critical' else 'Medium',
            'company_size': company_size,
            'industry': industry,
        }

    def _generate_recommendations(self, risk_overview: Dict, correlation_data: Dict,
                                   infra_data: Dict, app_data: Dict) -> List[Dict]:
        """Generate prioritized recommendations"""
        recs = []
        risk_score = risk_overview.get('risk_score', 0)

        # Critical: exposed admin panels
        security = app_data.get('7_security_posture', {})
        open_panels = [p for p in security.get('admin_panels', []) if p.get('access') == 'OPEN']
        if open_panels:
            recs.append({
                'priority': 'Critical',
                'title': 'Restrict Admin Panel Access',
                'description': f"Admin panels at {', '.join(p['path'] for p in open_panels)} are publicly accessible",
                'action': 'Implement IP allowlisting or VPN requirement for admin access',
                'timeline': 'Immediate',
                'impact': 'Prevents unauthorized administrative access',
            })

        # Critical: exposed .env / .git
        exposed_repos = app_data.get('5_code_repositories', {}).get('exposed_paths', [])
        for exposed in exposed_repos:
            recs.append({
                'priority': 'Critical',
                'title': f"Remove Exposed File: {exposed.get('path')}",
                'description': exposed.get('issue', 'Sensitive file publicly accessible'),
                'action': f"Block access to {exposed.get('path')} via web server configuration",
                'timeline': 'Immediate',
                'impact': 'Prevents credential/source code exposure',
            })

        # Critical: expired SSL
        ssl_weak = infra_data.get('ssl_weaknesses', {})
        if ssl_weak.get('expired_cert'):
            recs.append({
                'priority': 'Critical',
                'title': 'Renew SSL Certificate',
                'description': 'SSL certificate has expired',
                'action': 'Renew SSL certificate immediately',
                'timeline': 'Immediate',
                'impact': 'Restores encrypted communication and user trust',
            })

        # High: blacklisted IPs
        blacklisted = infra_data.get('blacklisted_ips', [])
        if blacklisted:
            recs.append({
                'priority': 'High',
                'title': 'Investigate Blacklisted IP Addresses',
                'description': f"{len(blacklisted)} IP(s) flagged by reputation services",
                'action': 'Investigate and remediate compromised infrastructure',
                'timeline': '7 days',
                'impact': 'Removes malicious reputation and prevents email/traffic blocking',
            })

        # High: deprecated TLS
        if ssl_weak.get('weak_tls_versions'):
            recs.append({
                'priority': 'High',
                'title': 'Disable Deprecated TLS Versions',
                'description': f"TLS versions {', '.join(ssl_weak['weak_tls_versions'])} are deprecated",
                'action': 'Configure server to only accept TLSv1.2 and TLSv1.3',
                'timeline': '7 days',
                'impact': 'Prevents POODLE/BEAST attacks',
            })

        # Medium: missing security headers
        missing_headers = security.get('missing_headers', [])
        if missing_headers:
            recs.append({
                'priority': 'Medium',
                'title': 'Implement Missing Security Headers',
                'description': f"Missing: {', '.join(missing_headers[:5])}",
                'action': 'Add security headers to web server configuration',
                'timeline': '30 days',
                'impact': 'Reduces XSS, clickjacking, and MITM attack surface',
            })

        # Medium: outdated software
        outdated = app_data.get('6_outdated_software', {}).get('vulnerable', [])
        if outdated:
            recs.append({
                'priority': 'Medium',
                'title': 'Update Outdated Software Components',
                'description': f"{len(outdated)} outdated component(s) detected",
                'action': 'Apply security patches and update to supported versions',
                'timeline': '30 days',
                'impact': 'Eliminates known CVE exposure',
            })

        # Low: HSTS
        if ssl_weak.get('hsts_missing'):
            recs.append({
                'priority': 'Low',
                'title': 'Enable HSTS',
                'description': 'Strict-Transport-Security header not configured',
                'action': 'Add HSTS header with max-age of at least 1 year',
                'timeline': '90 days',
                'impact': 'Prevents protocol downgrade attacks',
            })

        # Sort by priority
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        recs.sort(key=lambda r: priority_order.get(r.get('priority', 'Low'), 4))

        return recs

    def _infra_risk_level(self, infra_data: Dict) -> str:
        score = 0
        if infra_data.get('blacklisted_ips'):
            score += 30
        ssl_weak = infra_data.get('ssl_weaknesses', {})
        if ssl_weak.get('expired_cert'):
            score += 30
        if ssl_weak.get('weak_tls_versions'):
            score += 20
        if ssl_weak.get('hsts_missing'):
            score += 10
        if score >= 60:
            return 'High'
        elif score >= 30:
            return 'Medium'
        return 'Low'

    def _app_risk_level(self, app_data: Dict) -> str:
        score = 0
        security = app_data.get('7_security_posture', {})
        open_panels = [p for p in security.get('admin_panels', []) if p.get('access') == 'OPEN']
        if open_panels:
            score += 40
        if app_data.get('5_code_repositories', {}).get('exposed_paths'):
            score += 40
        if app_data.get('6_outdated_software', {}).get('vulnerable'):
            score += 20
        if score >= 60:
            return 'High'
        elif score >= 30:
            return 'Medium'
        return 'Low'

    def _save_report(self, assessment: Dict):
        """Save assessment report to reports/ folder"""
        try:
            outdir = "reports"
            os.makedirs(outdir, exist_ok=True)
            filename = os.path.join(
                outdir,
                f"Phase5_RiskAssessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(assessment, f, indent=2, default=str)
            logger.info(f"Assessment saved to {filename}")
        except Exception as e:
            logger.error(f"Report save failed: {e}")
