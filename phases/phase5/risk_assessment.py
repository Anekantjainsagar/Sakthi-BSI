"""
Phase 5: Risk Assessment
Handles risk scoring and assessment using actual Phase 4 data
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

SEVERITY_SCORE = {'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 2, 'Info': 0}


class RiskAssessment:
    """Handles risk assessment"""

    def assess_risk(self, correlation_data: Dict, infra_data: Dict,
                    domain_data: Dict, app_data: Dict) -> Dict[str, Any]:
        """Assess overall risk from all phase data"""

        risk_score = self._calculate_risk_score(correlation_data, infra_data, app_data)
        risk_level = self._score_to_level(risk_score)

        return {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'exposure_level': 'High' if risk_score >= 60 else ('Medium' if risk_score >= 30 else 'Low'),
            'key_findings': self._extract_key_findings(correlation_data, infra_data, app_data),
            'critical_count': correlation_data.get('summary', {}).get('critical_count', 0),
            'high_count': correlation_data.get('summary', {}).get('high_count', 0),
            'medium_count': correlation_data.get('summary', {}).get('medium_count', 0),
            'low_count': correlation_data.get('summary', {}).get('low_count', 0),
            'total_vulnerabilities': correlation_data.get('summary', {}).get('total', 0),
        }

    def _calculate_risk_score(self, correlation_data: Dict, infra_data: Dict,
                               app_data: Dict) -> int:
        """Calculate composite risk score"""
        score = 0

        # From Phase 4 correlation score (50% weight)
        corr_score = correlation_data.get('overall_risk_score', 0)
        score += corr_score * 0.5

        # From Phase 2 infrastructure
        blacklisted = infra_data.get('blacklisted_ips', [])
        if blacklisted:
            score += min(len(blacklisted) * 10, 20)

        ssl_weak = infra_data.get('ssl_weaknesses', {})
        if ssl_weak.get('expired_cert'):
            score += 15
        if ssl_weak.get('hsts_missing'):
            score += 5
        if ssl_weak.get('weak_tls_versions'):
            score += 10

        # From Phase 3 application
        security = app_data.get('7_security_posture', {})
        open_panels = [p for p in security.get('admin_panels', []) if p.get('access') == 'OPEN']
        if open_panels:
            score += len(open_panels) * 15

        exposed_repos = app_data.get('5_code_repositories', {}).get('exposed_paths', [])
        if exposed_repos:
            score += len(exposed_repos) * 20

        exposed_dbs = [d for d in app_data.get('9_database_detection', {}).get('database_interfaces', []) if d.get('exposed')]
        if exposed_dbs:
            score += len(exposed_dbs) * 20

        threat_intel = app_data.get('10_threat_intelligence', {})
        if threat_intel.get('malicious', 0) > 0:
            score += 25

        return min(int(score), 100)

    def _score_to_level(self, score: int) -> str:
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        return 'Minimal'

    def _extract_key_findings(self, correlation_data: Dict, infra_data: Dict,
                               app_data: Dict) -> List[str]:
        """Extract key findings for executive summary"""
        findings = []

        # From correlation
        summary = correlation_data.get('summary', {})
        if summary.get('critical_count', 0) > 0:
            findings.append(f"{summary['critical_count']} critical vulnerabilities require immediate remediation")
        if summary.get('high_count', 0) > 0:
            findings.append(f"{summary['high_count']} high-severity issues identified")

        # From infrastructure
        blacklisted = infra_data.get('blacklisted_ips', [])
        if blacklisted:
            findings.append(f"{len(blacklisted)} IP address(es) flagged by reputation services")

        ssl_weak = infra_data.get('ssl_weaknesses', {})
        if ssl_weak.get('expired_cert'):
            findings.append("SSL certificate has expired")
        if ssl_weak.get('weak_tls_versions'):
            findings.append(f"Deprecated TLS versions supported: {', '.join(ssl_weak['weak_tls_versions'])}")

        # From application
        security = app_data.get('7_security_posture', {})
        open_panels = [p for p in security.get('admin_panels', []) if p.get('access') == 'OPEN']
        if open_panels:
            findings.append(f"{len(open_panels)} admin panel(s) publicly accessible")

        exposed_repos = app_data.get('5_code_repositories', {}).get('exposed_paths', [])
        if exposed_repos:
            findings.append(f"Sensitive files exposed: {', '.join(e['path'] for e in exposed_repos)}")

        exposed_dbs = [d for d in app_data.get('9_database_detection', {}).get('database_interfaces', []) if d.get('exposed')]
        if exposed_dbs:
            findings.append(f"{len(exposed_dbs)} database interface(s) publicly accessible")

        threat_intel = app_data.get('10_threat_intelligence', {})
        if threat_intel.get('malicious', 0) > 0:
            findings.append(f"Domain flagged as malicious by {threat_intel['malicious']} security vendors")

        leaks = app_data.get('11_data_leak_detection', {})
        if leaks.get('leaks'):
            findings.append(f"Domain found in {len(leaks['leaks'])} data leak record(s)")

        if not findings:
            findings.append("No critical issues detected in this scan")

        return findings
