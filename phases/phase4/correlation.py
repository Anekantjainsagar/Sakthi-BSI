"""
Phase 4: Vulnerability Correlation
Correlates vulnerabilities across all phases
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

SEVERITY_SCORE = {'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 2, 'Info': 0}


class VulnerabilityCorrelation:
    """Correlates vulnerabilities from Phase 1, 2, and 3"""

    def correlate_vulnerabilities(self, phase1_data: Dict, phase2_data: Dict,
                                  phase3_data: Dict) -> Dict[str, Any]:
        """Correlate vulnerabilities from all phases"""

        all_vulns: List[Dict] = []
        risk_factors: List[str] = []

        # Extract from each phase
        all_vulns += self._extract_phase1_vulns(phase1_data)
        all_vulns += self._extract_phase2_vulns(phase2_data)
        all_vulns += self._extract_phase3_vulns(phase3_data)

        # Count by severity
        summary = {'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0, 'total': len(all_vulns)}
        for v in all_vulns:
            sev = v.get('severity', 'Low')
            if sev == 'Critical':
                summary['critical_count'] += 1
            elif sev == 'High':
                summary['high_count'] += 1
            elif sev == 'Medium':
                summary['medium_count'] += 1
            else:
                summary['low_count'] += 1

        # Build risk factors narrative
        if summary['critical_count']:
            risk_factors.append(f"{summary['critical_count']} critical vulnerabilities require immediate attention")
        if summary['high_count']:
            risk_factors.append(f"{summary['high_count']} high-severity issues identified")

        # MITRE ATT&CK mapping (basic)
        mitre_mapping = self._map_to_mitre(all_vulns)

        # Threat actors (based on industry from Phase 1)
        threat_actors = self._identify_threat_actors(phase1_data, all_vulns)

        # Attack chains
        attack_chains = self._build_attack_chains(all_vulns)

        overall_score = self._calculate_risk_score(all_vulns)

        logger.info(f"Correlated {len(all_vulns)} vulnerabilities (score: {overall_score})")

        return {
            'summary': summary,
            'vulnerabilities': all_vulns,
            'mitre_mapping': mitre_mapping,
            'threat_actors': threat_actors,
            'attack_chains': attack_chains,
            'overall_risk_score': overall_score,
            'risk_factors': risk_factors,
            # Aliases used by Phase 5
            'cves_all': [v for v in all_vulns if v.get('cve')],
            'security_issues': all_vulns,
            'attack_vectors': attack_chains,
        }

    # ── Phase 1 ──────────────────────────────────────────────────────────────

    def _extract_phase1_vulns(self, phase1_data: Dict) -> List[Dict]:
        """Extract risk indicators from Phase 1 business intelligence"""
        vulns = []
        if not phase1_data or 'error' in phase1_data:
            return vulns

        # Old domain with no HTTPS could be a risk indicator
        whois = phase1_data.get('whois_data', {})
        if whois.get('domain_age_years') and float(whois.get('domain_age_years', 0)) < 1:
            vulns.append({
                'title': 'Newly Registered Domain',
                'severity': 'Medium',
                'source': 'Phase 1 - WHOIS',
                'description': 'Domain registered less than 1 year ago — potential phishing/fraud risk',
            })

        # Emails exposed
        hunter = phase1_data.get('hunter_io', {})
        emails = hunter.get('emails', [])
        if len(emails) > 20:
            vulns.append({
                'title': f'Large Email Exposure ({len(emails)} addresses)',
                'severity': 'Medium',
                'source': 'Phase 1 - Hunter.io',
                'description': 'High number of corporate emails publicly discoverable — phishing risk',
            })

        return vulns

    # ── Phase 2 ──────────────────────────────────────────────────────────────

    def _extract_phase2_vulns(self, phase2_data: Dict) -> List[Dict]:
        """Extract vulnerabilities from Phase 2 infrastructure data"""
        vulns = []
        if not phase2_data or 'error' in phase2_data:
            return vulns

        # Blacklisted IPs
        for ip_entry in phase2_data.get('blacklisted_ips', []):
            vulns.append({
                'title': f"Blacklisted IP: {ip_entry.get('ip', 'unknown')}",
                'severity': 'High',
                'source': 'Phase 2 - IP Reputation',
                'description': ip_entry.get('reason', 'IP flagged by reputation service'),
                'ip': ip_entry.get('ip'),
            })

        # SSL weaknesses
        ssl_weak = phase2_data.get('ssl_weaknesses', {})
        for issue in ssl_weak.get('issues', []):
            vulns.append({
                'title': issue.get('title', 'SSL Issue'),
                'severity': issue.get('severity', 'Medium'),
                'source': 'Phase 2 - SSL Analysis',
                'description': issue.get('description', ''),
            })

        # Fallback: check ssl_analysis directly
        ssl_analysis = phase2_data.get('ssl_analysis', {})
        if ssl_analysis.get('weaknesses'):
            for issue in ssl_analysis['weaknesses'].get('issues', []):
                title = issue.get('title', '')
                if not any(v['title'] == title for v in vulns):
                    vulns.append({
                        'title': title,
                        'severity': issue.get('severity', 'Medium'),
                        'source': 'Phase 2 - SSL Analysis',
                        'description': issue.get('description', ''),
                    })

        # Large subdomain footprint
        subdomains = phase2_data.get('subdomains', [])
        if len(subdomains) > 50:
            vulns.append({
                'title': f'Large Attack Surface ({len(subdomains)} subdomains)',
                'severity': 'Low',
                'source': 'Phase 2 - Subdomains',
                'description': 'Large number of subdomains increases attack surface',
            })

        return vulns

    # ── Phase 3 ──────────────────────────────────────────────────────────────

    def _extract_phase3_vulns(self, phase3_data: Dict) -> List[Dict]:
        """Extract vulnerabilities from Phase 3 application data"""
        vulns = []
        if not phase3_data or 'error' in phase3_data:
            return vulns

        # Outdated software
        outdated = phase3_data.get('6_outdated_software', {})
        for item in outdated.get('vulnerable', []):
            vulns.append({
                'title': f"Outdated Software: {item.get('library', 'Unknown')}",
                'severity': item.get('severity', 'Medium'),
                'source': 'Phase 3 - Outdated Software',
                'description': item.get('description', f"Version: {item.get('version', 'unknown')}"),
                'library': item.get('library'),
                'version': item.get('version'),
            })

        # Security posture
        security = phase3_data.get('7_security_posture', {})

        # Exposed admin panels
        for panel in security.get('admin_panels', []):
            if panel.get('access') == 'OPEN':
                vulns.append({
                    'title': f"Exposed Admin Panel: {panel.get('path')}",
                    'severity': 'Critical',
                    'source': 'Phase 3 - Admin Panels',
                    'description': f"Admin panel at {panel.get('path')} is publicly accessible",
                    'path': panel.get('path'),
                })

        # Missing security headers
        missing_headers = security.get('missing_headers', [])
        if 'Strict-Transport-Security' in missing_headers:
            vulns.append({
                'title': 'Missing HSTS Header',
                'severity': 'Medium',
                'source': 'Phase 3 - Security Headers',
                'description': 'Strict-Transport-Security header not set',
            })
        if 'Content-Security-Policy' in missing_headers:
            vulns.append({
                'title': 'Missing Content-Security-Policy Header',
                'severity': 'Medium',
                'source': 'Phase 3 - Security Headers',
                'description': 'CSP header not set — XSS risk',
            })
        if 'X-Frame-Options' in missing_headers:
            vulns.append({
                'title': 'Missing X-Frame-Options Header',
                'severity': 'Low',
                'source': 'Phase 3 - Security Headers',
                'description': 'Clickjacking protection not configured',
            })

        # Cookie issues
        for cookie in security.get('cookie_security', []):
            for issue in cookie.get('issues', []):
                vulns.append({
                    'title': f"Cookie Issue ({cookie.get('name', 'unknown')}): {issue}",
                    'severity': 'Low',
                    'source': 'Phase 3 - Cookie Security',
                    'description': issue,
                    'cookie': cookie.get('name'),
                })

        # Exposed code repos / .env
        repos = phase3_data.get('5_code_repositories', {})
        for exposed in repos.get('exposed_paths', []):
            vulns.append({
                'title': exposed.get('issue', 'Exposed Sensitive Path'),
                'severity': exposed.get('severity', 'Critical'),
                'source': 'Phase 3 - Code Repositories',
                'description': f"Sensitive path exposed: {exposed.get('path')}",
                'path': exposed.get('path'),
            })

        # Exposed database interfaces
        db_data = phase3_data.get('9_database_detection', {})
        for db in db_data.get('database_interfaces', []):
            if db.get('exposed'):
                vulns.append({
                    'title': f"Exposed Database Interface: {db.get('name')}",
                    'severity': 'Critical',
                    'source': 'Phase 3 - Database Detection',
                    'description': f"{db.get('name')} at {db.get('path')} is publicly accessible",
                    'path': db.get('path'),
                })

        # VirusTotal threat intel
        threat_intel = phase3_data.get('10_threat_intelligence', {})
        if threat_intel.get('malicious', 0) > 0:
            vulns.append({
                'title': f"Domain Flagged as Malicious by {threat_intel['malicious']} AV Engines",
                'severity': 'Critical',
                'source': 'Phase 3 - VirusTotal',
                'description': f"VirusTotal: {threat_intel['malicious']} malicious, {threat_intel.get('suspicious', 0)} suspicious",
            })

        # Data leaks
        leaks = phase3_data.get('11_data_leak_detection', {})
        if leaks.get('leaks'):
            vulns.append({
                'title': f"Data Leaks Detected ({len(leaks['leaks'])} records)",
                'severity': 'High',
                'source': 'Phase 3 - LeakIX',
                'description': 'Domain found in data leak databases',
            })

        # S3 buckets
        s3 = phase3_data.get('12_s3_bucket_exposure', {})
        if s3.get('count', 0) > 0:
            vulns.append({
                'title': f"Exposed S3 Buckets ({s3['count']} found)",
                'severity': 'High',
                'source': 'Phase 3 - S3 Exposure',
                'description': 'Public S3 buckets associated with this domain',
            })

        return vulns

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        score = sum(SEVERITY_SCORE.get(v.get('severity', 'Low'), 2) for v in vulnerabilities)
        return min(score, 100)

    def _map_to_mitre(self, vulnerabilities: List[Dict]) -> Dict[str, List[str]]:
        """Basic MITRE ATT&CK mapping based on vulnerability types"""
        mapping: Dict[str, List[str]] = {}
        keyword_map = {
            'admin panel': ('T1078', 'Valid Accounts'),
            'exposed': ('T1190', 'Exploit Public-Facing Application'),
            'outdated': ('T1190', 'Exploit Public-Facing Application'),
            'blacklisted': ('T1071', 'Application Layer Protocol'),
            'ssl': ('T1557', 'Adversary-in-the-Middle'),
            'cookie': ('T1539', 'Steal Web Session Cookie'),
            'email': ('T1598', 'Phishing for Information'),
            'git': ('T1213', 'Data from Information Repositories'),
            '.env': ('T1552', 'Unsecured Credentials'),
            'database': ('T1190', 'Exploit Public-Facing Application'),
            's3': ('T1530', 'Data from Cloud Storage'),
            'leak': ('T1530', 'Data from Cloud Storage'),
        }
        for vuln in vulnerabilities:
            title_lower = vuln.get('title', '').lower()
            for keyword, (technique_id, technique_name) in keyword_map.items():
                if keyword in title_lower:
                    if technique_id not in mapping:
                        mapping[technique_id] = {'name': technique_name, 'vulnerabilities': []}
                    mapping[technique_id]['vulnerabilities'].append(vuln['title'])
                    break
        return mapping

    def _identify_threat_actors(self, phase1_data: Dict, vulnerabilities: List[Dict]) -> List[Dict]:
        """Identify likely threat actors based on industry and vulnerabilities"""
        actors = []
        industry = ''
        if phase1_data:
            ai = phase1_data.get('ai_analysis', {})
            industry = ai.get('company_overview', {}).get('industry_vertical', '').lower()

        has_critical = any(v.get('severity') == 'Critical' for v in vulnerabilities)
        has_data_leak = any('leak' in v.get('title', '').lower() or 's3' in v.get('title', '').lower() for v in vulnerabilities)

        if 'finance' in industry or 'bank' in industry:
            actors.append({'name': 'FIN7', 'motivation': 'Financial', 'likelihood': 'High'})
            actors.append({'name': 'Carbanak', 'motivation': 'Financial', 'likelihood': 'Medium'})
        if 'health' in industry or 'medical' in industry:
            actors.append({'name': 'Lazarus Group', 'motivation': 'Data Theft', 'likelihood': 'Medium'})
        if has_critical:
            actors.append({'name': 'Generic Opportunistic Attackers', 'motivation': 'Exploitation', 'likelihood': 'High'})
        if has_data_leak:
            actors.append({'name': 'Data Brokers / Ransomware Groups', 'motivation': 'Data Monetization', 'likelihood': 'Medium'})

        return actors

    def _build_attack_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Build potential attack chains from vulnerabilities"""
        chains = []
        titles = [v.get('title', '').lower() for v in vulnerabilities]

        # Recon → Initial Access → Persistence
        if any('email' in t for t in titles) and any('admin' in t for t in titles):
            chains.append({
                'name': 'Phishing → Admin Access',
                'steps': ['Email reconnaissance via Hunter.io', 'Spear phishing attack', 'Admin panel compromise'],
                'severity': 'Critical',
            })

        if any('.env' in t or 'git' in t for t in titles):
            chains.append({
                'name': 'Credential Exposure → Full Compromise',
                'steps': ['Exposed .env/.git file', 'Extract credentials/secrets', 'Database/infrastructure access'],
                'severity': 'Critical',
            })

        if any('outdated' in t for t in titles) and any('database' in t for t in titles):
            chains.append({
                'name': 'Outdated Software → Database Breach',
                'steps': ['Exploit outdated software CVE', 'Pivot to database interface', 'Data exfiltration'],
                'severity': 'High',
            })

        return chains
