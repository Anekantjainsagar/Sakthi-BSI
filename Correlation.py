#!/usr/bin/env python3
import requests
import json
import time
from datetime import datetime
from colorama import Fore, Back, Style, init
import re
from urllib.parse import quote
from bs4 import BeautifulSoup
import sys
import os  # NEW

from gemini_config import call_gemini as _gemini_call, GEMINI_MODEL, GEMINI_API_KEYS

GEMINI_AVAILABLE = len(GEMINI_API_KEYS) > 0

init(autoreset=True)

# ── Centralised FIX_MAP — used by both CLI (save_report) and Streamlit (run_correlation) ──
FIX_MAP = {
    # Security Headers
    'Missing Security Header':          lambda s: f"Add '{s.get('header', '')}' HTTP response header to web server / reverse-proxy configuration",
    'Misconfigured CSP Header':          lambda s: "Tighten Content-Security-Policy — remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes instead",
    'Weak HSTS Configuration':           lambda s: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    'Missing Cross-Origin Policy':       lambda s: "Add Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp headers",
    'Weak Referrer Policy':              lambda s: "Set Referrer-Policy: strict-origin-when-cross-origin to prevent leaking full URLs to third parties",
    'Misconfigured Security Header':     lambda s: f"Review and fix misconfigured header: {s.get('header', 'security header')}",
    # Cookies
    'Insecure Cookie Configuration':     lambda s: f"Set HttpOnly, Secure, and SameSite=Strict on cookie '{s.get('cookie', s.get('header', ''))}'",
    # TLS / SSL
    'Weak TLS Protocols':                lambda s: "Disable TLS 1.0 and TLS 1.1 in web server / load balancer; enforce TLS 1.2+ only",
    'SSL/TLS Weakness':                  lambda s: f"Remediate SSL/TLS issue: {s.get('header', 'SSL weakness')} — disable weak protocols and ciphers",
    'SSL Certificate Issue':             lambda s: f"Renew/replace SSL certificate ({s.get('header', 'cert issue')}); ensure it is issued by a trusted CA",
    # Database / Ports
    'Exposed Database Port':             lambda s: f"Restrict access to {s.get('header', 'database port')} via firewall rules; bind service to localhost only",
    'Exposed Service: FTP':              lambda s: f"Disable FTP on {s.get('header', '')}; replace with SFTP or FTPS",
    'Exposed Service: Telnet':           lambda s: f"Disable Telnet on {s.get('header', '')}; replace with SSH",
    'Exposed Service: MySQL':            lambda s: f"Firewall MySQL port on {s.get('header', '')}; bind to localhost or private network only",
    'Exposed Service: PostgreSQL':       lambda s: f"Firewall PostgreSQL port on {s.get('header', '')}; bind to localhost or private network only",
    'Exposed Service: MSSQL':            lambda s: f"Firewall MSSQL port on {s.get('header', '')}; restrict access to trusted IPs only",
    'Exposed Service: RDP':              lambda s: f"Restrict RDP access on {s.get('header', '')} to VPN only; enable Network Level Authentication",
    'Exposed Service: VNC':              lambda s: f"Disable VNC on {s.get('header', '')} or restrict to VPN/SSH tunnel only",
    'Exposed Service: SSH':              lambda s: f"Restrict SSH on {s.get('header', '')} to known IPs via firewall; disable password auth, use keys only",
    'Exposed Service: SMTP':             lambda s: f"Restrict SMTP relay on {s.get('header', '')}; configure to reject open relay",
    # Email Security
    'Missing SPF Record':                lambda s: "Add SPF TXT record: v=spf1 include:yourmailprovider.com -all",
    'Missing DMARC Record':              lambda s: "Add DMARC TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    'Missing DKIM Record':               lambda s: "Configure DKIM signing in mail server; add DKIM public key TXT record to DNS",
    # DNS
    'Missing CAA DNS Record':            lambda s: "Add CAA DNS record to restrict SSL cert issuance to trusted CAs only: e.g. 0 issue \"letsencrypt.org\"",
    'DNSSEC Not Enabled':                lambda s: "Enable DNSSEC via your domain registrar to prevent DNS spoofing and cache poisoning",
    # Admin / Files
    'Exposed Administrative Interface':  lambda s: f"Restrict access to {s.get('header', 'admin interface')} via IP allowlist or VPN",
    'Exposed Admin Panel':               lambda s: f"Restrict access to {s.get('url', s.get('header', 'admin panel'))} — require VPN or IP allowlist; disable if unused",
    'Exposed Sensitive File':            lambda s: f"Remove or block public access to {s.get('header', 'sensitive file')} via server deny rules",
    # App Vulnerabilities
    'Open Redirect Vulnerability':       lambda s: "Validate redirect URLs against an allowlist; reject all external domains",
    'Clickjacking Vulnerability':        lambda s: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none' header",
    'Missing Subresource Integrity (SRI)': lambda s: "Add integrity= and crossorigin= attributes to all external <script> and <link> tags",
    'Exposed Client-Side Secret':        lambda s: f"Remove {s.get('header', 'hardcoded credential')} from client-side code; use server-side secrets manager",
    'Exposed Database Connection String': lambda s: "Remove database credentials from client-accessible code; use environment variables or secrets manager",
    'Public Source Code Repository':     lambda s: f"Audit {s.get('header', 'public repository')} for exposed secrets/credentials; rotate any found keys and set repo to private",
    # IP Reputation / Threat Intel
    'IP Reputation / Blacklist':         lambda s: f"Investigate IP {s.get('header', '')}; clean and request delisting from blacklists: {s.get('description','')}",
    'Threat Intelligence Alert':         lambda s: f"Block IP {s.get('header', '')} at firewall — detected as active threat by MetaDefender; investigate for indicators of compromise",
    'IP Reputation Risk':                lambda s: f"Block IP {s.get('header', '')} — high AbuseIPDB score; investigate origin of traffic and add firewall deny rule",
    'APT Threat Association':            lambda s: f"Block IP {s.get('header', '')} — associated with APT threat actors; investigate host for compromise indicators",
    'Malicious Scanner Activity':        lambda s: f"Block IP {s.get('header', '')} at perimeter firewall — classified as malicious scanner by GreyNoise",
    'Malicious Activity (Honey Pot)':    lambda s: f"Block IP {s.get('header', '')} — flagged by Project Honey Pot as malicious; investigate related traffic",
    'Known Vulnerability (InternetDB)':  lambda s: f"Patch service with {s.get('header', 'known CVE')} — apply vendor security update immediately",
    # Data Leaks / Breaches
    'Data Breach - Email Compromised':   lambda s: f"Force password reset for affected accounts; enable MFA; check {s.get('header', 'email')} at HaveIBeenPwned",
    'Data Exposure - Service Leak':      lambda s: f"Patch {s.get('header', 'exposed service')} — credentials or data found exposed via LeakIX; rotate all credentials",
    'Credential Leak - PasteBin':        lambda s: f"Rotate all credentials found in paste ({s.get('header', 'paste')}); remove paste if possible; check for further exposure",
    'Dark Web Exposure - IntelligenceX': lambda s: f"Rotate all credentials; enable dark web monitoring; {s.get('header', 'breach records')} — investigate full scope of exposure",
    # Cloud
    'Cloud Storage Exposure - S3 Bucket': lambda s: f"Immediately block public access on {s.get('header', 'S3 bucket')}; audit bucket policy; rotate any exposed credentials",
    # Brand / Other
    'Brand Abuse / Typosquatting Risk':  lambda s: "Register common typosquatting variants; monitor via DMARC aggregate reports and brand alerting services",
}


class AIPhase4Scanner:
    def __init__(self):
        # Phase data
        self.domain = ""
        self.phase1_data = {}
        self.phase2_data = {}
        self.phase3_data = {}
        # Derived results
        self.technologies = []
        self.security_issues = []
        self.cve_results = []
        self.threat_intel = {}
        self.attack_vectors = []
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        # GitHub token for PoC search + Metasploit module search
        self.github_token = os.getenv('GITHUB_TOKEN', '')
        # ExploitDB CSV loaded once at startup
        self.exploitdb_df = self._load_exploitdb_csv()
        # Gemini setup — keys and model from gemini_config (no hardcoded keys)
        self.use_gemini = GEMINI_AVAILABLE and len(GEMINI_API_KEYS) > 0
        if self.use_gemini:
            print("✅ Correlation Gemini initialized")

    def log(self, msg, level="info"):
        colors = {"success": Fore.GREEN, "error": Fore.RED, "warning": Fore.YELLOW, "info": Fore.BLUE}
        symbols = {"success": "✓", "error": "✗", "warning": "⚠", "info": "ℹ"}
        print(f"{colors[level]}{symbols[level]} {msg}{Style.RESET_ALL}")

    def header(self, text):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*100}\n{text.center(100)}\n{'='*100}{Style.RESET_ALL}\n")

    def setup_gemini(self):
        print(f"\n{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.YELLOW}║          Gemini AI Setup (Optional - Enhanced Analysis)        ║")
        print(f"{Fore.YELLOW}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Get FREE API key: {Fore.WHITE}https://makersuite.google.com/app/apikey{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Benefits: AI-powered APT mapping & attack vector analysis{Style.RESET_ALL}\n")
        api_key = input(f"{Fore.GREEN}Enter Gemini API key (or press Enter to skip): {Style.RESET_ALL}").strip()
        if api_key:
            self.gemini_api_key = api_key
            self.use_gemini = True
            self.log("Gemini AI enabled - Advanced analysis activated", "success")
        else:
            self.log("Gemini AI skipped - Will generate prompts for manual use", "warning")
        print()

    # === PHASE 1 LOADING ===
    def load_phase1(self, filepath):
        """Load Phase 1 business domain data"""
        self.log(f"Loading Phase 1 data: {filepath}", "info")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.phase1_data = json.load(f)
            if not self.domain:
                self.domain = self.phase1_data.get('domain', self.domain)
            self.log("Successfully loaded Phase 1", "success")
            return True
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "error")
        except json.JSONDecodeError:
            self.log("Invalid Phase 1 JSON file", "error")
        except Exception as e:
            self.log(f"Phase 1 load error: {e}", "error")
        return False

    # === PHASE 2 LOADING (NEW) ===
    def load_phase2(self, filepath):
        self.log(f"Loading Phase 2 data: {filepath}", "info")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.phase2_data = json.load(f)
            if not self.domain:
                self.domain = self.phase2_data.get('target', self.domain)
            self.log("Successfully loaded Phase 2", "success")
            return True
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "error")
        except json.JSONDecodeError:
            self.log("Invalid Phase 2 JSON file", "error")
        except Exception as e:
            self.log(f"Phase 2 load error: {e}", "error")
        return False

    def load_phase3(self, filepath):
        self.log(f"Loading Phase 3 data: {filepath}", "info")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.phase3_data = json.load(f)
                self.domain = self.phase3_data.get('domain', '')
                self.log(f"Successfully loaded: {self.domain}", "success")
                return True
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "error")
            return False
        except json.JSONDecodeError:
            self.log(f"Invalid JSON file", "error")
            return False
        except Exception as e:
            self.log(f"Load error: {e}", "error")
            return False

    # === DEDUPLICATION HELPER ===
    def _deduplicate_security_issues(self):
        """
        Remove duplicate security issues that may appear because Phase 2 and Phase 3
        both detect the same thing (e.g. admin panels, SSL issues).
        Deduplication key: (type, header/cookie) — keeps the first occurrence (highest severity
        since issues are added critical-first from Phase 2, then Phase 3).
        """
        seen = set()
        unique = []
        for s in self.security_issues:
            key = (
                s.get('type', ''),
                s.get('header', s.get('cookie', s.get('url', ''))).strip().rstrip('/')
            )
            if key not in seen:
                seen.add(key)
                unique.append(s)
        removed = len(self.security_issues) - len(unique)
        if removed > 0:
            self.log(f"Deduplication: removed {removed} duplicate security issue(s)", "info")
        self.security_issues = unique

    # === PHASE 2 → TECHNOLOGIES (ENHANCED) ===
    def merge_phase2_technologies(self):
        """
        Convert select infra artifacts into 'technologies' so NVD/CIRCL search can pick them up.
        ✅ ENHANCED: Now extracts service versions with CPEs from InternetDB data
        """
        if not self.phase2_data or not isinstance(self.phase2_data, dict):
            return
        if not isinstance(self.technologies, list):
            self.technologies = []

        added = []

        # ── Extract service versions from port_services (InternetDB) OR fall back to
        #    open_ports + port_banners (Phase 2 actual output structure)
        try:
            port_services = self.phase2_data.get('port_services') or {}
            # Phase 2 outputs open_ports {IP: [port,...]} and port_banners {IP: {port: banner_str}}
            # Build port_services on-the-fly if it's empty
            if not port_services:
                open_ports = self.phase2_data.get('open_ports', {})
                port_banners = self.phase2_data.get('port_banners', {})
                for ip, ports in open_ports.items():
                    port_services[ip] = {}
                    banners_for_ip = port_banners.get(ip, {}) if isinstance(port_banners, dict) else {}
                    for port in (ports or []):
                        banner = banners_for_ip.get(str(port), banners_for_ip.get(port, ''))
                        port_services[ip][str(port)] = {'name': '', 'version': '', 'banner': str(banner)}

            for ip, services in port_services.items():
                for port_str, svc in (services or {}).items():
                    if isinstance(svc, dict):
                        name = svc.get('name', '')
                        version = svc.get('version', '')
                        vendor = svc.get('vendor', '')
                        cpe = svc.get('cpe', '')
                        # Only add if we have BOTH name and version
                        if name and version and version not in ['', 'unknown', 'latest']:
                            tech_entry = {'name': name, 'version': version, 'type': 'Infrastructure Service'}
                            if vendor: tech_entry['vendor'] = vendor
                            if cpe:    tech_entry['cpe'] = cpe
                            added.append(tech_entry)
                            self.log(f"Infra Service: {name} {version} (IP: {ip}, Port: {port_str})", "success")
        except Exception as e:
            self.log(f"Error extracting infra services: {e}", "warning")

        # cPanel exposure via subdomains/misconfigurations → technology signal
        try:
            subs = [s.lower() for s in self.phase2_data.get('subdomains', [])]
            has_cpanel_sub = any('cpanel.' in s or s.startswith('cpanel.') for s in subs)
            _sm = self.phase2_data.get('security_misconfigs', {})
            misconfigs = _sm.get('open_admin_panels', []) + _sm.get('exposed_files', [])
            has_cpanel_mis = any('cpanel' in str(m.get('url', m.get('target',''))).lower() for m in misconfigs)
            if has_cpanel_sub or has_cpanel_mis:
                # cPanel exposure is a security finding, not a versioned tech — goes to security_issues not tech stack
                self.security_issues.append({
                    'type': 'Exposed Administrative Interface',
                    'header': 'cPanel & WHM',
                    'description': 'cPanel/WHM admin panel exposed via subdomain or misconfiguration',
                    'severity': 'HIGH'
                })
        except Exception:
            pass

        # High-signal services -> product names (helps CVE lookups)
        # Reads from open_ports directly (Phase 2 actual output) since port_services may be absent
        port_map_precise = {
            22:  'OpenSSH',
            3306:'MySQL',
            5432:'PostgreSQL',
            1433:'Microsoft SQL Server',
            3389:'Microsoft RDP',
            5900:'VNC'
        }
        try:
            open_ports = self.phase2_data.get('open_ports', {})
            for ip, ports in open_ports.items():
                for port in (ports or []):
                    try:
                        port_int = int(port)
                    except:
                        continue
                    if port_int in port_map_precise:
                        product_name = port_map_precise[port_int]
                        if not any(t.get('name') == product_name and t.get('version') not in ['unknown', ''] for t in added):
                            added.append({'name': product_name, 'version': 'unknown', 'type': 'Infrastructure'})
        except Exception:
            pass

        # Deduplicate with existing techs
        existing = {(t.get('name',''), t.get('version',''), t.get('type','')) for t in self.technologies}
        for t in added:
            key = (t['name'], t['version'], t.get('type',''))
            if key not in existing:
                self.technologies.append(t)
                existing.add(key)

    # === PHASE 2 → SECURITY ISSUES (ENHANCED) ===
    def merge_phase2_security_issues(self, infra):
        """
        ✅ ENHANCED: Now extracts InternetDB CVEs, typosquatting domains, and all other misconfigurations
        """
        if not infra:
            return

        issues = []

        # 1) Exposed admin panels (from security_misconfigs.open_admin_panels — Phase 2 actual structure)
        misconfigs = infra.get('security_misconfigs', {})
        for panel in misconfigs.get('open_admin_panels', []):
            if panel.get('false_positive'):
                continue  # skip confirmed false positives
            sev = panel.get('severity', 'HIGH')
            url = panel.get('url', '')
            if url and sev in ('CRITICAL', 'HIGH'):  # only flag real open panels, skip LOW/INFO
                issues.append({
                    'type': 'Exposed Admin Panel',
                    'header': url,
                    'description': f"Admin panel publicly accessible at {url} — exposed to brute force and credential stuffing",
                    'severity': sev
                })

        # Read from correct Phase 2 key: security_misconfigs (not misconfigurations)
        _sm = infra.get('security_misconfigs', {})

        # Exposed admin interfaces from security_misconfigs.open_admin_panels
        for m in _sm.get('open_admin_panels', []):
            if not m.get('false_positive') and m.get('access') == 'OPEN':
                issues.append({
                    'type': 'Exposed Administrative Interface',
                    'header': m.get('url', m.get('target', '')),
                    'description': 'Administrative interface publicly reachable',
                    'severity': m.get('severity', 'HIGH')
                })

        # InternetDB CVEs from security_misconfigs (if stored there by Phase 2)
        for m in _sm.get('open_databases', []):
            cve_desc = m.get('description', '')
            cve_match = re.search(r'(CVE-\d{4}-\d+)', cve_desc)
            if cve_match:
                cve_id = cve_match.group(1)
                issues.append({
                    'type': 'Known Vulnerability (InternetDB)',
                    'header': cve_id,
                    'description': f"Detected on {m.get('target', 'infrastructure')}",
                    'severity': m.get('severity', 'HIGH'),
                    'source': 'internetdb',
                    'cve_id': cve_id
                })
                self.log(f"InternetDB CVE: {cve_id} on {m.get('target')}", "warning")

        # Exposed databases from security_misconfigs.open_databases
        for m in _sm.get('open_databases', []):
            issues.append({
                'type': 'Exposed Database Port',
                'header': m.get('target', m.get('service', 'Database')),
                'description': m.get('description', 'Database port publicly accessible'),
                'severity': m.get('severity', 'CRITICAL')
            })

        # 2) Blacklisted IPs
        for hit in infra.get('blacklisted_ips', []):
            ip = hit.get('ip')
            raw_bl = hit.get('blacklists', [])
            bl = ', '.join([b.get('blacklist', str(b)) if isinstance(b, dict) else str(b) for b in raw_bl]) if raw_bl else ''
            if ip and bl:
                issues.append({
                    'type': 'IP Reputation / Blacklist',
                    'header': ip,
                    'description': f'Listed on: {bl}',
                    'severity': 'HIGH'
                })

        # 2b) Full IP reputation scan (Phase 2 checks ALL IPs — fills gap where Phase 3 only checks 1 IP)
        ip_rep = infra.get('ip_reputation', {})
        if isinstance(ip_rep, dict):
            for ip, rep_data in ip_rep.items():
                if not isinstance(rep_data, dict):
                    continue
                abuse_score = rep_data.get('abuseipdb', {}).get('abuse_score', 0) or 0
                pulses      = rep_data.get('alienvault', {}).get('pulse_count', 0) or 0
                vt_malicious = rep_data.get('virustotal', {}).get('malicious', 0) or 0
                if abuse_score > 50:
                    issues.append({
                        'type': 'IP Reputation Risk',
                        'header': f"IP {ip} — Abuse Score {abuse_score}%",
                        'description': f"Reported as malicious by AbuseIPDB: {abuse_score}% confidence",
                        'severity': 'CRITICAL' if abuse_score > 90 else 'HIGH',
                        'source': 'AbuseIPDB'
                    })
                if pulses > 5:
                    issues.append({
                        'type': 'APT Threat Association',
                        'header': f"IP {ip} in {pulses} threat feeds",
                        'description': f"IP found in {pulses} AlienVault OTX threat intelligence pulse(s)",
                        'severity': 'CRITICAL' if pulses > 20 else 'HIGH',
                        'source': 'AlienVault OTX'
                    })
                if vt_malicious > 3:
                    issues.append({
                        'type': 'Threat Intelligence Alert',
                        'header': f"IP {ip} — VirusTotal {vt_malicious} detections",
                        'description': f"VirusTotal flagged this IP as malicious by {vt_malicious} security vendors",
                        'severity': 'HIGH',
                        'source': 'VirusTotal'
                    })

        # 3) Dangerous open ports (concrete evidence)
        dangerous = {
            21: ('FTP', 'FTP service exposed — unencrypted, credentials sent in plaintext'),
            22: ('SSH', 'Exposure of remote admin service'),
            23: ('Telnet', 'Legacy remote admin service exposed'),
            25: ('SMTP', 'Mail transfer agent exposed'),
            3306: ('MySQL', 'Database port exposed'),
            5432: ('PostgreSQL', 'Database port exposed'),
            1433: ('MSSQL', 'Database port exposed'),
            3389: ('RDP', 'RDP service exposed'),
            5900: ('VNC', 'VNC remote desktop exposed'),
            2375: ('Docker', 'Docker API exposed — unauthenticated access possible'),
        }
        for ip, ports in infra.get('open_ports', {}).items():
            for p in ports:
                if p in dangerous:
                    svc, desc = dangerous[p]
                    issues.append({
                        'type': f'Exposed Service: {svc}',
                        'header': f'{ip}:{p}',
                        'description': desc,
                        'severity': 'HIGH' if p in (23, 3389, 1433, 3306, 5432) else 'MEDIUM'
                    })

        # 4a) SSL weaknesses — Phase 2 stores as dict with specific fields
        ssl_w = infra.get('ssl_weaknesses', {})
        if isinstance(ssl_w, dict):
            # Use actual version values (e.g. "TLS 1.0, TLS 1.1") as the header, not generic labels
            weak_tls = ssl_w.get('weak_tls_versions')
            if weak_tls:
                tls_label = ', '.join(weak_tls) if isinstance(weak_tls, list) else str(weak_tls)
                issues.append({'type': 'SSL/TLS Weakness', 'header': tls_label,
                                'description': f"Deprecated TLS versions supported: {tls_label} — vulnerable to POODLE, BEAST, downgrade attacks",
                                'severity': 'HIGH'})
            weak_ciphers = ssl_w.get('weak_ciphers')
            if weak_ciphers:
                cipher_label = ', '.join(weak_ciphers) if isinstance(weak_ciphers, list) else str(weak_ciphers)
                issues.append({'type': 'SSL/TLS Weakness', 'header': cipher_label,
                                'description': f"Weak cipher suites detected: {cipher_label}",
                                'severity': 'MEDIUM'})
            if ssl_w.get('hsts_missing'):
                issues.append({'type': 'SSL/TLS Weakness', 'header': 'HSTS not configured',
                                'description': 'Strict-Transport-Security header absent — SSL stripping / downgrade attacks possible',
                                'severity': 'MEDIUM'})
            if ssl_w.get('self_signed'):
                issues.append({'type': 'SSL/TLS Weakness', 'header': 'Self-Signed Certificate',
                                'description': 'Certificate is self-signed — no trusted CA; clients will see browser warnings',
                                'severity': 'HIGH'})
            for s in ssl_w.get('summary', []):
                if s and 'No SSL weaknesses' not in str(s):
                    issues.append({'type': 'SSL/TLS Weakness', 'header': str(s)[:80], 'description': str(s), 'severity': 'MEDIUM'})
        elif isinstance(ssl_w, list):
            for weakness in ssl_w:
                if isinstance(weakness, dict):
                    issues.append({'type': 'SSL/TLS Weakness',
                                   'header': weakness.get('type', weakness.get('version', 'SSL Issue')),
                                   'description': weakness.get('description', weakness.get('detail', 'SSL weakness')),
                                   'severity': weakness.get('severity', 'MEDIUM')})
                elif isinstance(weakness, str):
                    issues.append({'type': 'SSL/TLS Weakness', 'header': weakness, 'description': weakness, 'severity': 'MEDIUM'})

        # 4b) Exposed sensitive files from Phase 2 (non-INFO severity only)
        misconfigs_data = infra.get('security_misconfigs', {})
        for item in misconfigs_data.get('exposed_files', []):
            sev = item.get('severity', 'INFO')
            if sev == 'INFO':
                continue  # skip informational (like robots.txt accessible)
            issues.append({
                'type': 'Exposed Sensitive File',
                'header': item.get('url', ''),
                'description': item.get('desc', 'Sensitive file publicly accessible'),
                'severity': sev
            })

        # 4c) CAA record missing (from Phase 2 dns_records)
        caa = infra.get('dns_records', {}).get('CAA', None)
        if caa is not None and len(caa) == 0:
            issues.append({
                'type': 'Missing CAA DNS Record',
                'header': self.domain,
                'description': 'No CAA record — any Certificate Authority can issue SSL certs for this domain',
                'severity': 'MEDIUM'
            })

        # 4d) DNSSEC not enabled (from Phase 2 dns_records)
        dnssec = infra.get('dns_records', {}).get('DNSSEC', None)
        if dnssec is not None and not dnssec.get('enabled', True):
            issues.append({
                'type': 'DNSSEC Not Enabled',
                'header': self.domain,
                'description': 'DNSSEC disabled — DNS responses can be spoofed (DNS cache poisoning)',
                'severity': 'MEDIUM'
            })

        # 4) Weak TLS (only if explicitly detected)
        ssl_info = infra.get('ssl_analysis', {})
        supported = set(ssl_info.get('tls_versions_supported', []))
        if ssl_info.get('tls_version'):
            supported.add(ssl_info['tls_version'])

        weak = {'TLS 1.0', 'TLS 1.1', 'SSLv3', 'SSLv2'}
        if supported & weak:
            issues.append({
                'type': 'Weak TLS Protocols',
                'header': ', '.join(sorted(list(supported & weak))),
                'description': 'Deprecated TLS/SSL versions supported',
                'severity': 'HIGH'
            })

        # 5) Mail server — SPF / DMARC / DKIM
        mail = infra.get('mail_server_analysis') or {}
        spf   = mail.get('spf_record')
        dmarc = mail.get('dmarc_record')
        dkim  = mail.get('dkim_record')
        # Phase 2 sometimes stores mx_count:1 but mx_records:None — check both
        has_mx = bool(mail.get('mx_records')) or (mail.get('mx_count', 0) or 0) > 0
        if has_mx:
            if not spf:
                issues.append({
                    'type': 'Missing SPF Record',
                    'header': self.domain,
                    'description': 'No SPF record — domain vulnerable to email spoofing/phishing',
                    'severity': 'HIGH'
                })
            if not dmarc:
                issues.append({
                    'type': 'Missing DMARC Record',
                    'header': self.domain,
                    'description': 'No DMARC policy — no protection against email impersonation',
                    'severity': 'HIGH'
                })
            if not dkim:
                issues.append({
                    'type': 'Missing DKIM Record',
                    'header': self.domain,
                    'description': 'No DKIM signing — emails can be forged without detection',
                    'severity': 'MEDIUM'
                })

        # ── Subdomain Takeover Check ──────────────────────────────────────────
        # Check if any subdomains have dangling CNAMEs pointing to cloud services that
        # don't own that subdomain — classic subdomain takeover vulnerability
        TAKEOVER_SERVICES = {
            'github.io':           'GitHub Pages',
            'amazonaws.com':       'AWS S3',
            's3.amazonaws.com':    'AWS S3',
            'azurewebsites.net':   'Azure Web Apps',
            'cloudapp.net':        'Azure',
            'trafficmanager.net':  'Azure Traffic Manager',
            'herokussl.com':       'Heroku',
            'herokudns.com':       'Heroku',
            'unbouncepages.com':   'Unbounce',
            'pantheonsite.io':     'Pantheon',
            'fastly.net':          'Fastly',
            'myshopify.com':       'Shopify',
            'zendesk.com':         'Zendesk',
        }
        dns_records = infra.get('dns_records', {})
        cname_records = dns_records.get('CNAME', [])
        if isinstance(cname_records, list):
            for cname_entry in cname_records:
                cname_target = str(cname_entry).lower() if isinstance(cname_entry, str) else str(cname_entry.get('value', '')).lower()
                for svc_domain, svc_name in TAKEOVER_SERVICES.items():
                    if svc_domain in cname_target:
                        issues.append({
                            'type': 'Subdomain Takeover Risk',
                            'header': cname_target[:120],
                            'description': f"CNAME points to {svc_name} ({svc_domain}) — if the {svc_name} resource is unclaimed, attacker can register it and take over this subdomain",
                            'severity': 'HIGH'
                        })
                        self.log(f"Subdomain takeover risk: CNAME → {cname_target} ({svc_name})", "warning")

        # Merge into existing list
        self.security_issues.extend(issues)

    #✅ NEW: Extract Phase 3 NEW Sections (10, 11, 12)
    def merge_phase3_new_api_data(self):
        """
        Extract threat intelligence, leak detection, and cloud exposure data
        from Phase 3 sections 10, 11, and 12
        """
        if not self.phase3_data or not isinstance(self.phase3_data, dict):
            return

        issues = []

        # ========================
        # SECTION 10: THREAT INTELLIGENCE
        # ========================
        threat_intel = self.phase3_data.get('10_threat_intelligence', {})
        
        if threat_intel:
            self.log("Processing Threat Intelligence data (Section 10)...", "info")
        
        # MetaDefender
        for result in threat_intel.get('metadefender', []):
            if isinstance(result, dict) and result.get('threat_detected'):
                issues.append({
                    'type': 'Threat Intelligence Alert',
                    'header': f"IP {result.get('ip', 'Unknown')} - MetaDefender",
                    'description': f"Threat Type: {result.get('threat_type', 'Unknown')} | Detection: {result.get('detection_rate', 'N/A')}",
                    'severity': 'CRITICAL',
                    'source': 'MetaDefender'
                })
                self.log(f"MetaDefender threat: {result.get('ip')} - {result.get('threat_type')}", "warning")
        
        # AbuseIPDB
        for result in threat_intel.get('abuseipdb', []):
            if isinstance(result, dict):
                score = result.get('abuse_confidence_score', 0)
                if score > 75:
                    issues.append({
                        'type': 'IP Reputation Risk',
                        'header': f"IP {result.get('ip', 'Unknown')} - Abuse Score {score}%",
                        'description': f"Reported {result.get('total_reports', 0)} times | Country: {result.get('country', 'Unknown')} | Type: {result.get('usage_type', 'Unknown')}",
                        'severity': 'HIGH' if score > 90 else 'MEDIUM',
                        'source': 'AbuseIPDB'
                    })
                    self.log(f"AbuseIPDB: {result.get('ip')} has abuse score of {score}%", "warning")
        
        # AlienVault OTX
        for result in threat_intel.get('alienvault', []):
            if isinstance(result, dict) and result.get('pulse_count', 0) > 0:
                issues.append({
                    'type': 'APT Threat Association',
                    'header': f"IP {result.get('ip', 'Unknown')} in {result.get('pulse_count')} threat feeds",
                    'description': f"Reputation: {result.get('reputation', 'Unknown')} | Details: {result.get('description', 'APT/Malware infrastructure')}",
                    'severity': 'CRITICAL',
                    'source': 'AlienVault OTX'
                })
                self.log(f"AlienVault: {result.get('ip')} associated with {result.get('pulse_count')} threat pulses", "warning")
        
        # GreyNoise
        for result in threat_intel.get('greynoise', []):
            if isinstance(result, dict) and result.get('classification') == 'malicious':
                tags = result.get('tags', [])
                tags_str = ', '.join(tags) if isinstance(tags, list) else str(tags)
                issues.append({
                    'type': 'Malicious Scanner Activity',
                    'header': f"IP {result.get('ip', 'Unknown')} - GreyNoise",
                    'description': f"Classification: Malicious | Tags: {tags_str} | First seen: {result.get('first_seen', 'Unknown')}",
                    'severity': 'HIGH',
                    'source': 'GreyNoise'
                })
                self.log(f"GreyNoise: {result.get('ip')} classified as malicious", "warning")
        
        # Project Honey Pot
        for result in threat_intel.get('projecthoneypot', []):
            if isinstance(result, dict):
                threat_score = result.get('threat_score', 0)
                if threat_score > 50:
                    issues.append({
                        'type': 'Malicious Activity (Honey Pot)',
                        'header': f"IP {result.get('ip', 'Unknown')} - Threat Score {threat_score}/255",
                        'description': f"Type: {result.get('threat_type', 'Unknown')} | Last activity: {result.get('days_since_last_activity', 'Unknown')} days ago",
                        'severity': 'HIGH' if threat_score > 150 else 'MEDIUM',
                        'source': 'Project Honey Pot'
                    })
                    self.log(f"Honey Pot: {result.get('ip')} has threat score {threat_score}", "warning")

        # ========================
        # SECTION 11: LEAK DETECTION
        # ========================
        leak_data = self.phase3_data.get('11_leak_detection', {})
        
        if leak_data:
            self.log("Processing Leak Detection data (Section 11)...", "info")
        
        # Citadel (leak-lookup.com)
        for leak in leak_data.get('citadel', []):
            if isinstance(leak, dict) and leak.get('found'):
                sources = leak.get('sources', [])
                breach_count = len(sources) if isinstance(sources, list) else leak.get('breach_count', 0)
                sources_str = ', '.join(sources[:3]) if isinstance(sources, list) else str(sources)
                issues.append({
                    'type': 'Data Breach - Email Compromised',
                    'header': f"Email: {leak.get('email', 'Unknown')}",
                    'description': f"Found in {breach_count} breaches: {sources_str}",
                    'severity': 'CRITICAL',
                    'source': 'Citadel'
                })
                self.log(f"Citadel: {leak.get('email')} found in {breach_count} breaches", "warning")
        
        # LeakIX
        for leak in leak_data.get('leakix', []):
            if isinstance(leak, dict) and leak.get('type') == 'leak':
                issues.append({
                    'type': 'Data Exposure - Service Leak',
                    'header': f"{leak.get('service', 'Unknown')} on {leak.get('host', 'Unknown')}",
                    'description': f"Port: {leak.get('port', 'Unknown')} | {leak.get('summary', 'Exposed service detected')}",
                    'severity': 'CRITICAL' if leak.get('credentials_found') else 'HIGH',
                    'source': 'LeakIX'
                })
                self.log(f"LeakIX: {leak.get('service')} exposed on {leak.get('host')}", "warning")
        
        # PasteBin Search
        pastebin_data = leak_data.get('pastebin_search', {})
        if isinstance(pastebin_data, dict):
            if pastebin_data.get('status') == 'success':
                verified_leaks = pastebin_data.get('verified_leaks', [])
                verified_count = pastebin_data.get('verified_count', 0)
                
                if verified_count > 0:
                    for leak in verified_leaks:
                        issues.append({
                            'type': 'Credential Leak - PasteBin',
                            'header': f"Verified leak: {leak.get('title', 'N/A')}",
                            'description': f"URL: {leak.get('url', 'N/A')} | Snippet: {leak.get('snippet', 'N/A')[:100]}",
                            'severity': 'HIGH',
                            'source': 'PasteBin'
                        })
                        self.log(f"PasteBin: Potential leak in {leak.get('url')}", "warning")
        
        # IntelligenceX (Dark Web)
        intelx_data = leak_data.get('intelx', {})
        if isinstance(intelx_data, dict) and intelx_data.get('status') == 'active':
            all_results = intelx_data.get('all_results', [])
            total_records = intelx_data.get('total_records', 0)
            
            if total_records > 0:
                # Count by type
                pastes = len([r for r in all_results if r.get('type') == 'leak'])
                darknet = len([r for r in all_results if r.get('type') == 'darknet'])
                
                severity = 'CRITICAL' if darknet > 10 else 'HIGH'
                
                issues.append({
                    'type': 'Dark Web Exposure - IntelligenceX',
                    'header': f"{total_records} breach record(s) found",
                    'description': f"{pastes} paste leak(s), {darknet} darknet mention(s) in dark web databases",
                    'severity': severity,
                    'source': 'IntelligenceX'
                })
                self.log(f"IntelligenceX: {total_records} records found ({darknet} darknet)", "warning")

        # ========================
        # SECTION 12: S3 EXPOSURE
        # ========================
        s3_data = self.phase3_data.get('12_s3_exposure', {})
        
        if s3_data:
            self.log("Processing S3 Exposure data (Section 12)...", "info")
        
        # GrayHatWarfare
        for bucket in s3_data.get('grayhatwarfare', []):
            if isinstance(bucket, dict) and bucket.get('found') and bucket.get('publicly_accessible'):
                files = bucket.get('files', [])
                file_count = len(files) if isinstance(files, list) else bucket.get('file_count', 0)
                
                # Get sensitive file names
                sensitive_files = []
                if isinstance(files, list):
                    sensitive_files = [f.get('filename', '') for f in files[:5] if isinstance(f, dict)]
                
                issues.append({
                    'type': 'Cloud Storage Exposure - S3 Bucket',
                    'header': f"Bucket: {bucket.get('bucket', 'Unknown')}",
                    'description': f"Publicly accessible | {file_count} files | Total: {bucket.get('total_size', 'Unknown')} | Sensitive files: {', '.join(sensitive_files)}",
                    'severity': 'CRITICAL',
                    'source': 'GrayHatWarfare'
                })
                self.log(f"GrayHatWarfare: Exposed S3 bucket '{bucket.get('bucket')}' with {file_count} files", "warning")

        # Add all new issues to security_issues
        self.security_issues.extend(issues)
        
        if issues:
            self.log(f"Added {len(issues)} new security issues from Phase 3 sections 10-12", "success")

    def extract_tech_stack(self):
        self.header("EXTRACTING TECHNOLOGY STACK FROM PHASE 3")
        # FIX #7: Validate Phase 3 data before processing
        if not self.phase3_data or not isinstance(self.phase3_data, dict):
            self.log("Phase 3 data is empty or invalid", "error")
            return []
        data = self.phase3_data
        techs = []
        security_issues = []
        
        # Web Server Version
        app_discovery = data.get('1_application_discovery', {})
        server_full = app_discovery.get('server', '')
        server_version = app_discovery.get('server_version', '')
        
        print(f"\n{Fore.CYAN}[DEBUG] Raw server header: {server_full}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Extracted version: {server_version}{Style.RESET_ALL}\n")
        
        if server_full and str(server_full) not in ['None', '', 'null', 'Not disclosed']:
            server_match = re.search(r'(Apache|nginx|IIS|LiteSpeed)[/\s](\d+\.\d+\.?\d*)', str(server_full), re.IGNORECASE)
            
            if server_match:
                server_name = server_match.group(1)
                version = server_match.group(2)
                techs.append({
                    'name': server_name,
                    'version': version,
                    'type': 'Web Server'
                })
                self.log(f"Web Server: {server_name} {version}", "success")
        
        web_stack = data.get('2_web_server_stack', {})
        
        # CMS
        # CMS (only add if version exists)
        cms_list = web_stack.get('cms', [])
        cms_version = web_stack.get('cms_version', 'latest')
        if isinstance(cms_list, list):
            for cms in cms_list:
                if cms and str(cms) not in ['None', '', 'null']:
                    # Check if version is valid
                    version_str = str(cms_version)
                    if version_str and version_str not in ['latest', 'none', 'None', 'unknown', 'Unknown', '', 'version unknown']:
                        techs.append({'name': str(cms), 'version': version_str, 'type': 'CMS'})
                        self.log(f"CMS: {cms} {version_str}", "success")
                    else:
                        self.log(f"CMS SKIPPED (no version): {cms}", "warning")
        
        # JavaScript Libraries — only add if a real version exists
        js_libs = web_stack.get('javascript_libraries', [])
        js_versions = web_stack.get('javascript_versions', {})
        for lib in js_libs:
            if lib and str(lib) not in ['None', '']:
                version = js_versions.get(lib, '')
                if version and str(version) not in ['latest', 'unknown', 'Unknown', '']:
                    techs.append({'name': str(lib), 'version': str(version), 'type': 'JavaScript'})
                    self.log(f"JavaScript: {lib} {version}", "success")
                else:
                    self.log(f"JavaScript SKIPPED (no version): {lib}", "warning")
        
        # Frameworks — now use framework_versions dict from Phase 3 (Fix: no longer skipped)
        fw_versions = web_stack.get('framework_versions', {})
        frameworks = web_stack.get('frameworks', [])
        for fw in frameworks:
            if fw and str(fw) not in ['None', '']:
                fw_ver = fw_versions.get(fw, '')
                if fw_ver and fw_ver not in ['unknown', 'latest', '']:
                    techs.append({'name': str(fw), 'version': fw_ver, 'type': 'Framework'})
                    self.log(f"Framework: {fw} {fw_ver}", "success")
                else:
                    self.log(f"Framework SKIPPED (no version): {fw}", "warning")
        
        # Outdated/Vulnerable Libraries
        outdated = data.get('6_outdated_software', {})
        for lib_info in outdated.get('vulnerable', []):
            lib_name = lib_info.get('library', '')
            current_ver = lib_info.get('current_version', 'unknown')
            severity = lib_info.get('severity', 'Unknown')
            if lib_name and not any(t['name'] == lib_name for t in techs):
                techs.append({'name': lib_name, 'version': current_ver, 'type': 'Vulnerable Library', 'severity': severity})
                self.log(f"Vulnerable: {lib_name} {current_ver} ({severity})", "warning")
        
        # CMS versions dict (Drupal / Joomla / Magento) — Phase 3 new field
        cms_versions_dict = web_stack.get('cms_versions', {})
        if not isinstance(cms_versions_dict, dict):
            cms_versions_dict = {}
        for cms_name, cms_ver in cms_versions_dict.items():
            if cms_ver and str(cms_ver) not in ['unknown', 'Unknown', '', 'latest']:
                if not any(t['name'] == cms_name for t in techs):
                    techs.append({'name': cms_name, 'version': str(cms_ver), 'type': 'CMS'})
                    self.log(f"CMS (from cms_versions): {cms_name} {cms_ver}", "success")

        # ERP versions — SAP — Phase 3 new field
        erp_data = data.get('3_erp_sap_detection', {})
        erp_versions = erp_data.get('erp_versions', {})
        for erp_name, erp_ver in erp_versions.items():
            if erp_ver and str(erp_ver) not in ['unknown', 'Unknown', '', 'latest']:
                if not any(t['name'] == erp_name for t in techs):
                    techs.append({'name': erp_name, 'version': str(erp_ver), 'type': 'ERP'})
                    self.log(f"ERP: {erp_name} {erp_ver}", "success")

        # PHP Detection — check X-Powered-By header first for real version
        fingerprints = data.get('1_application_discovery', {}).get('header_fingerprints', {})
        xpb_name = fingerprints.get('X-Powered-By-Name', '')
        xpb_ver  = fingerprints.get('X-Powered-By-Version', '')
        if xpb_name and xpb_ver and xpb_ver not in ['latest', 'unknown', 'Unknown', '']:
            if not any(t['name'].lower() == xpb_name.lower() for t in techs):
                techs.append({'name': xpb_name, 'version': xpb_ver, 'type': 'Backend'})
                self.log(f"Backend: {xpb_name} {xpb_ver} (from X-Powered-By header)", "success")

        # PHPSESSID cookie: only add PHP if version not already captured above
        cookies = data.get('7_security_posture', {}).get('cookie_security', [])
        for cookie in cookies:
            if cookie.get('cookie', '').upper() == 'PHPSESSID':
                if not any(t['name'].lower() == 'php' for t in techs):
                    # No version available — skip CVE search, just log
                    self.log("Backend: PHP detected (PHPSESSID cookie) but version unknown — skipped for CVE search", "warning")
                break

        # Security Posture Analysis
        print(f"\n{Fore.YELLOW}Analyzing Security Posture...{Style.RESET_ALL}\n")
        security_posture = data.get('7_security_posture', {})
        
        # Missing Security Headers + VALUE checks on present headers
        headers = security_posture.get('security_headers', {})
        for header, info in headers.items():
            if not info.get('present', False):
                security_issues.append({
                    'type': 'Missing Security Header',
                    'header': header,
                    'description': info.get('description', ''),
                    'severity': 'HIGH' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'MEDIUM'
                })
                self.log(f"Missing: {header}", "warning")
            else:
                # Header is present — check if the VALUE is weak/insecure
                value = str(info.get('value', '')).lower()
                if header == 'Strict-Transport-Security':
                    # Check max-age is at least 6 months (15552000s)
                    ma = re.search(r'max-age=(\d+)', value)
                    if ma and int(ma.group(1)) < 15552000:
                        security_issues.append({
                            'type': 'Weak HSTS Configuration',
                            'header': f"HSTS max-age={ma.group(1)} (too short — minimum 15552000)",
                            'description': f"HSTS max-age is only {ma.group(1)}s — browsers will not enforce HTTPS after expiry",
                            'severity': 'MEDIUM'
                        })
                elif header == 'Content-Security-Policy' and value:
                    if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                        security_issues.append({
                            'type': 'Misconfigured CSP Header',
                            'header': "CSP contains 'unsafe-inline' or 'unsafe-eval'",
                            'description': "Content-Security-Policy allows unsafe-inline/unsafe-eval — XSS attacks can bypass CSP",
                            'severity': 'HIGH'
                        })
                elif header == 'X-Frame-Options' and value not in ('deny', 'sameorigin'):
                    security_issues.append({
                        'type': 'Misconfigured Security Header',
                        'header': f"X-Frame-Options: {info.get('value','')}",
                        'description': f"X-Frame-Options value '{info.get('value','')}' does not prevent framing — use DENY or SAMEORIGIN",
                        'severity': 'MEDIUM'
                    })

        # Misconfigured Security Headers (present but weak/unsafe — from header_issues list)
        # e.g. weak HSTS max-age, CSP with unsafe-inline/unsafe-eval, weak Referrer-Policy
        for issue_text in security_posture.get('header_issues', []):
            issue_text = str(issue_text).strip()
            if not issue_text:
                continue
            # Determine severity from content
            if any(k in issue_text.lower() for k in ['unsafe-inline', 'unsafe-eval', 'csp']):
                sev = 'HIGH'
                htype = 'Misconfigured CSP Header'
            elif 'hsts' in issue_text.lower() or 'strict-transport' in issue_text.lower():
                sev = 'MEDIUM'
                htype = 'Weak HSTS Configuration'
            elif any(k in issue_text.lower() for k in ['coep', 'coop', 'corp', 'cross-origin']):
                sev = 'MEDIUM'
                htype = 'Missing Cross-Origin Policy'
            elif 'referrer' in issue_text.lower():
                sev = 'LOW'
                htype = 'Weak Referrer Policy'
            else:
                sev = 'MEDIUM'
                htype = 'Misconfigured Security Header'
            security_issues.append({
                'type': htype,
                'header': issue_text,
                'description': issue_text,
                'severity': sev
            })
            self.log(f"Misconfigured header: {issue_text[:80]}", "warning")
        
        # Insecure Cookies — check actual SameSite value, not just boolean
        for cookie in cookies:
            cookie_issues = []
            if not cookie.get('httponly', False):
                cookie_issues.append('Missing HttpOnly flag')
            if not cookie.get('secure', False):
                cookie_issues.append('Missing Secure flag')
            ss_val = cookie.get('samesite_value', '') or ''
            if not ss_val or ss_val.lower() in ('not set', ''):
                cookie_issues.append('Missing SameSite flag')
            elif ss_val.lower() == 'none' and not cookie.get('secure', False):
                cookie_issues.append('SameSite=None without Secure — CSRF risk')

            if cookie_issues:
                security_issues.append({
                    'type': 'Insecure Cookie Configuration',
                    'cookie': cookie.get('cookie', 'Unknown'),
                    'issues': cookie_issues,
                    'severity': 'HIGH'
                })
                self.log(f"Insecure Cookie: {cookie.get('cookie', 'Unknown')} - {', '.join(cookie_issues)}", "warning")

        # Cert issues — self-signed, expired, domain mismatch
        cert_issues = security_posture.get('cert_issues', [])
        for issue in cert_issues:
            security_issues.append({
                'type': 'SSL Certificate Issue',
                'header': issue,
                'description': f'SSL/TLS certificate problem: {issue}',
                'severity': 'HIGH'
            })
            self.log(f"Cert issue: {issue}", "warning")

        # Open redirect
        open_redirects = security_posture.get('open_redirect', [])
        if open_redirects:
            security_issues.append({
                'type': 'Open Redirect Vulnerability',
                'header': ', '.join([f"?{r.get('param')}" for r in open_redirects]),
                'description': 'Redirect parameters accept external URLs — enables phishing chain attacks',
                'severity': 'MEDIUM'
            })
            self.log(f"Open redirect: {len(open_redirects)} parameter(s)", "warning")

        # Clickjacking
        cj = security_posture.get('clickjacking', {})
        if cj and not cj.get('protected', True):
            security_issues.append({
                'type': 'Clickjacking Vulnerability',
                'header': self.domain,
                'description': 'No X-Frame-Options or CSP frame-ancestors — page can be embedded in iframes',
                'severity': 'MEDIUM'
            })
            self.log("Clickjacking: no frame protection detected", "warning")

        # SRI missing — supply chain attack vector
        sri_missing = security_posture.get('sri_missing', [])
        if sri_missing:
            security_issues.append({
                'type': 'Missing Subresource Integrity (SRI)',
                'header': f'{len(sri_missing)} external script(s) / link(s)',
                'description': 'External CDN resources loaded without integrity= attribute — supply chain attack risk',
                'severity': 'MEDIUM'
            })
            self.log(f"SRI missing on {len(sri_missing)} resource(s)", "warning")

        # Exposed client-side secrets — CRITICAL
        exposed_secrets = data.get('4_third_party_software', {}).get('exposed_secrets', [])
        for secret in exposed_secrets:
            security_issues.append({
                'type': 'Exposed Client-Side Secret',
                'header': secret.get('type', 'Unknown Secret Type'),
                'description': f"Hardcoded credential found in page source: {secret.get('snippet', '')[:80]}",
                'severity': 'CRITICAL'
            })
            self.log(f"Exposed secret: {secret.get('type')}", "warning")

        # Exposed DB connection strings — CRITICAL
        db_conn_strings = data.get('9_database_detection', {}).get('connection_strings', [])
        for cs in db_conn_strings:
            security_issues.append({
                'type': 'Exposed Database Connection String',
                'header': cs.get('type', 'Database'),
                'description': f"Database credentials exposed in page source: {cs.get('snippet', '')[:80]}",
                'severity': 'CRITICAL'
            })
            self.log(f"DB connection string exposed: {cs.get('type')}", "warning")

        # Section 5: Code Repository Analysis — public GitHub repos only
        # NOTE: robots.txt Disallow paths are NOT flagged — Disallow is a protective measure,
        # not a vulnerability. Phase 2 already catches actual exposed admin panels directly.
        repo_data = data.get('5_code_repositories', {})
        github_repos = repo_data.get('github_repos', [])
        if github_repos:
            repo_names = ', '.join([r.get('name', '') for r in github_repos[:5]])
            security_issues.append({
                'type': 'Public Source Code Repository',
                'header': repo_names,
                'description': f"{len(github_repos)} public GitHub repo(s) found — source code may expose secrets, credentials, or internal architecture",
                'severity': 'MEDIUM'
            })
            self.log(f"Public GitHub repos found: {repo_names}", "warning")

        # Third-party services (same logic as Apache - skip if no version)
        third_party = data.get('4_third_party_software', {})
        for category in ['analytics', 'payment', 'chat', 'captcha']:
            for service in third_party.get(category, []):
                if service and str(service) not in ['None', '']:
                    # Try to extract version from service name
                    version_match = re.search(r'(\d+\.\d+\.?\d*)', str(service))
            
                    if version_match:
                        # Version found - add to tech stack for CVE search
                        version = version_match.group(1)
                        clean_name = re.sub(r'[\d\.\s]+', '', service).strip()
                        techs.append({
                            'name': clean_name,
                            'version': version,
                            'type': f'Third-party ({category})'
                        })
                        self.log(f"Third-party: {clean_name} {version} ({category})", "success")
                    else:
                        # No version - SKIP (same as Apache without version)
                        self.log(f"Third-party SKIPPED (no version): {service} ({category})", "warning")
        
        # Merge Phase-3 techs with Phase-2 techs already loaded — do NOT overwrite
        existing_keys = {(t.get('name',''), t.get('version',''), t.get('type','')) for t in self.technologies}
        for t in techs:
            key = (t.get('name',''), t.get('version',''), t.get('type',''))
            if key not in existing_keys:
                self.technologies.append(t)
                existing_keys.add(key)
        # Merge Phase-2 posture we added earlier with Phase-3 posture here
        self.security_issues.extend(security_issues)

        self.merge_phase3_new_api_data()

        # Deduplicate after all 3 merge passes (Phase 2 + Phase 3 section 1-9 + Phase 3 section 10-12)
        self._deduplicate_security_issues()

        print(f"\n{Fore.CYAN}Total Technologies Found: {Fore.WHITE}{len(self.technologies)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Security Issues Found (deduplicated): {Fore.WHITE}{len(self.security_issues)}{Style.RESET_ALL}\n")
        return self.technologies

    def search_nvd(self, product, version):
        """Search NVD for software vulnerabilities"""
        clean_product = product.split('/')[0].strip()
        clean_product = re.sub(r'\(.*?\)', '', clean_product).strip()
        
        clean_version = version.replace('latest', '').strip()
        clean_version = re.sub(r'\(.*?\)', '', clean_version).strip()
        
        if clean_version and clean_version not in ['latest', 'unknown', '']:
            search_query = f"{clean_product} {clean_version}"
        else:
            search_query = clean_product
        
        self.log(f"Querying NVD API: {search_query}", "info")
        cves = []
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': search_query,
                'resultsPerPage': 100
            }
            r = self.session.get(url, params=params, timeout=20)
            
            if r.status_code == 200:
                response_data = r.json()
                vulnerabilities = response_data.get('vulnerabilities', [])
                
                # ✅ CHECK: If no vulnerabilities found, return empty list
                if not vulnerabilities:
                    self.log(f"✓ NVD: 0 CVEs found for {search_query}", "warning")
                    return []
                
                self.log(f"✓ NVD: Found {len(vulnerabilities)} potential CVEs", "info")
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', '')
                    
                    # ✅ VALIDATE: Skip if no valid CVE ID
                    if not cve_id or not cve_id.startswith('CVE-'):
                        self.log(f"⚠ Skipped invalid CVE ID: {cve_id}", "warning")
                        continue
                    
                    # Extract CVSS scores
                    cvss = 0.0
                    vector = ""
                    severity = "UNKNOWN"
                    
                    metrics = cve.get('metrics', {})
                    for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if ver in metrics and len(metrics[ver]) > 0:
                            if 'cvssData' in metrics[ver][0]:
                                cvss = metrics[ver][0]['cvssData'].get('baseScore', 0.0)
                                vector = metrics[ver][0]['cvssData'].get('vectorString', '')
                                severity = metrics[ver][0].get('baseSeverity', '')
                                break
                    # Derive severity from CVSS score if NVD didn't provide it
                    if not severity or severity == 'UNKNOWN':
                        if cvss >= 9.0:   severity = 'CRITICAL'
                        elif cvss >= 7.0: severity = 'HIGH'
                        elif cvss >= 4.0: severity = 'MEDIUM'
                        elif cvss > 0:    severity = 'LOW'
                        else:             severity = 'MEDIUM'
                    
                    # Extract description
                    desc = ""
                    for d in cve.get('descriptions', []):
                        if d.get('lang') == 'en':
                            desc = d.get('value', '')
                            break
                    
                    # Extract CWE
                    cwe = "Unknown"
                    for w in cve.get('weaknesses', []):
                        for c in w.get('description', []):
                            cwe = c.get('value', 'Unknown')
                            break
                        if cwe != "Unknown":
                            break
                    
                    # ✅ Version relevance check — skip CVEs that mention a different major version
                    # e.g. if we're scanning Apache 2.4, skip CVEs that only mention Apache 2.2
                    version_relevant = True
                    if clean_version and clean_version not in ['unknown', 'latest', '']:
                        major = clean_version.split('.')[0]
                        # If description mentions a version AND it starts with a different major, skip
                        ver_mentions = re.findall(r'\b(\d+\.\d+)', desc)
                        if ver_mentions:
                            same_major = any(v.startswith(major + '.') or v == major for v in ver_mentions)
                            if not same_major:
                                version_relevant = False

                    # ✅ ONLY ADD if valid CVE with CVSS score and version-relevant
                    if cvss > 0 and cve_id.startswith('CVE-') and version_relevant:
                        cves.append({
                            'id': cve_id,
                            'cvss': cvss,
                            'severity': severity,
                            'vector': vector,
                            'cwe': cwe,
                            'description': desc[:200],
                            'published': cve.get('published', '')[:10]
                        })
                
                if len(cves) > 0:
                    self.log(f"✓ Added {len(cves)} valid CVEs (with CVSS > 0)", "success")
                else:
                    self.log(f"⚠ 0 valid CVEs found (all had CVSS = 0)", "warning")
            
            time.sleep(7)
            
        except Exception as e:
            self.log(f"NVD error: {e}", "error")
        
        return cves

    # CIRCL requires vendor/product format — map common product names to their vendor
    CIRCL_VENDOR_MAP = {
        'drupal':          'drupal',
        'wordpress':       'wordpress',
        'joomla':          'joomla',
        'magento':         'magento',
        'apache':          'apache',
        'nginx':           'nginx',
        'iis':             'microsoft',
        'php':             'php',
        'mysql':           'oracle',
        'postgresql':      'postgresql',
        'openssh':         'openbsd',
        'openssl':         'openssl',
        'jquery':          'jquery',
        'bootstrap':       'getbootstrap',
        'react':           'facebook',
        'angular':         'google',
        'vue':             'vuejs',
        'laravel':         'laravel',
        'django':          'djangoproject',
        'flask':           'pallets',
        'spring':          'pivotal',
        'tomcat':          'apache',
        'redis':           'redis',
        'mongodb':         'mongodb',
        'elasticsearch':   'elastic',
        'microsoft sql server': 'microsoft',
        'microsoft rdp':   'microsoft',
    }

    def search_circl(self, product, version):
        """Search CIRCL for additional CVEs — uses vendor/product format for accuracy."""
        clean_product = product.split('/')[0].strip()
        clean_product = re.sub(r'\(.*?\)', '', clean_product).strip()

        clean_version = version.replace('latest', '').strip()
        clean_version = re.sub(r'\(.*?\)', '', clean_version).strip()

        # Build vendor/product path using lookup map
        product_lower = clean_product.lower()
        vendor = self.CIRCL_VENDOR_MAP.get(product_lower, product_lower)
        product_slug = product_lower.replace(' ', '_')

        if clean_version and clean_version not in ['latest', 'unknown', '']:
            search_path = f"{vendor}/{product_slug}/{clean_version}"
        else:
            search_path = f"{vendor}/{product_slug}"
        
        self.log(f"Querying CIRCL API: {search_path}", "info")
        cves = []
        
        try:
            url = f"https://cve.circl.lu/api/search/{quote(search_path)}"
            r = self.session.get(url, timeout=15)
            
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    for cve_id, cve_data in data.items():
                        # Validate ID format at entry — reject anything not CVE- or CWE-
                        if not (str(cve_id).startswith('CVE-') or str(cve_id).startswith('CWE-')):
                            continue
                        try:
                            cvss_val = float(cve_data.get('cvss', 0.0))
                        except Exception:
                            cvss_val = 0.0
                        severity = 'CRITICAL' if cvss_val >= 9 else ('HIGH' if cvss_val >= 7 else ('MEDIUM' if cvss_val >= 4 else 'LOW'))
                        # FIX #3: Extract CWE from CIRCL data instead of hardcoding
                        cves.append({
                            'id': cve_id,
                            'cvss': cvss_val,
                            'severity': severity,
                            'vector': cve_data.get('cvss-vector', ''),
                            'cwe': cve_data.get('cwe', 'Unknown'),
                            'description': cve_data.get('summary', ''),
                            'published': cve_data.get('Published', '')[:10]
                        })
                
                self.log(f"CIRCL returned {len(cves)} CVEs", "success" if len(cves) > 0 else "warning")
            
            time.sleep(2)
            
        except Exception as e:
            self.log(f"CIRCL error: {e}", "error")
        
        return cves

    def _load_exploitdb_csv(self):
        """Load ExploitDB exploit list from their GitLab CSV — no API key needed."""
        try:
            import pandas as pd
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            df = pd.read_csv(url, usecols=['id', 'file', 'description', 'codes', 'type', 'platform'], timeout=20)
            self.log(f"ExploitDB CSV loaded: {len(df)} exploits", "success")
            return df
        except Exception as e:
            self.log(f"ExploitDB CSV load failed (offline mode): {e}", "warning")
            return None

    def search_github(self, cve_id):
        """Search GitHub for PoC repos using the GitHub API (needs GITHUB_TOKEN in .env)."""
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            url = "https://api.github.com/search/repositories"
            params = {'q': f'{cve_id} exploit poc', 'sort': 'stars', 'per_page': 5}
            r = self.session.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                count = r.json().get('total_count', 0)
                time.sleep(1)
                return count
            elif r.status_code == 403:
                self.log("GitHub API: rate limited or no token — add GITHUB_TOKEN to .env", "warning")
            elif r.status_code == 422:
                pass  # No results found — expected
        except Exception as e:
            self.log(f"GitHub API error: {e}", "warning")
        return 0

    def search_exploitdb(self, cve_id):
        """Search ExploitDB CSV (loaded at startup) — no scraping, no API key."""
        try:
            if self.exploitdb_df is not None:
                matches = self.exploitdb_df[
                    self.exploitdb_df['codes'].str.contains(cve_id, na=False, case=False)
                ]
                return len(matches)
        except Exception as e:
            self.log(f"ExploitDB search error: {e}", "warning")
        return 0

    def search_metasploit(self, cve_id):
        """Search Metasploit modules via GitHub API on the rapid7/metasploit-framework repo."""
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            url = "https://api.github.com/search/code"
            params = {'q': f'{cve_id} repo:rapid7/metasploit-framework', 'per_page': 5}
            r = self.session.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                count = r.json().get('total_count', 0)
                time.sleep(1)
                return count
            elif r.status_code == 403:
                self.log("GitHub API: rate limited or no token — add GITHUB_TOKEN to .env", "warning")
        except Exception as e:
            self.log(f"Metasploit search error: {e}", "warning")
        return 0

    # === AI: SECURITY HEADERS/Cookies → REAL CVEs (EXISTING) ===
    def build_comprehensive_summary(self):
        """
        Build a complete security summary from ALL Phase 2 and Phase 3 data.
        Strips bulk noise (e.g. 492 lookalike domain names → just the count).
        Returns a plain-text string for AI to read.
        """
        lines = []
        p2 = self.phase2_data or {}
        p3 = self.phase3_data or {}

        # ── PHASE 2 ──────────────────────────────────────────────────────────
        lines.append("=== PHASE 2: INFRASTRUCTURE FINDINGS ===")

        # Open ports — only truly dangerous ports (not 80/443/8080/8443/53 which are noise)
        open_ports = p2.get('open_ports', {})
        critical_ports = {
            21: 'FTP (unencrypted)', 23: 'Telnet (unencrypted)',
            3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL',
            3389: 'RDP', 5900: 'VNC', 2375: 'Docker API'
        }
        notable_ports = {25: 'SMTP mail relay'}
        found_critical = []
        found_notable = []
        for ip, ports in open_ports.items():
            for port in ports:
                if port in critical_ports:
                    found_critical.append(f"{critical_ports[port]} ({port}) on {ip}")
                elif port in notable_ports:
                    found_notable.append(f"{notable_ports[port]} ({port}) on {ip}")
        for p in found_critical:
            lines.append(f"CRITICAL OPEN PORT: {p}")
        for p in found_notable:
            lines.append(f"NOTABLE OPEN PORT: {p}")

        # Admin panels — group by severity to avoid noise
        sm = p2.get('security_misconfigs', {})
        critical_panels, high_panels, low_panels = [], [], []
        for panel in sm.get('open_admin_panels', []):
            if panel.get('false_positive'):
                continue
            sev = panel.get('severity', 'HIGH')
            url = panel.get('url', '')
            if not url:
                continue
            if sev == 'CRITICAL':
                critical_panels.append(url)
            elif sev == 'HIGH':
                high_panels.append(url)
            else:
                low_panels.append(url)
        for url in critical_panels:
            lines.append(f"ADMIN PANEL EXPOSED [CRITICAL]: {url}")
        if high_panels:
            lines.append(f"ADMIN PANEL EXPOSED [HIGH]: {len(high_panels)} admin panels open — {', '.join(high_panels[:3])}")
        if low_panels:
            lines.append(f"ADMIN PANEL EXPOSED [LOW/RESTRICTED]: {len(low_panels)} restricted panels found")

        # Exposed sensitive files (non-INFO)
        for item in sm.get('exposed_files', []):
            if item.get('severity', 'INFO') != 'INFO':
                lines.append(f"EXPOSED FILE [{item['severity']}]: {item.get('url','')} — {item.get('desc','')}")

        # Dangerous ports section (if present from Phase 2 fix)
        for dp in sm.get('dangerous_ports', []):
            lines.append(f"DANGEROUS PORT [{dp.get('severity','HIGH')}]: {dp.get('service','')} on {dp.get('ip','')}:{dp.get('port','')} — {dp.get('detail','')}")

        # Blacklisted IPs (from top-level blacklisted_ips)
        for hit in p2.get('blacklisted_ips', []):
            ip = hit.get('ip', '')
            bl = hit.get('blacklists', [])
            bl_str = ', '.join([b.get('blacklist', str(b)) if isinstance(b, dict) else str(b) for b in bl])
            if ip and bl_str:
                lines.append(f"IP BLACKLISTED: {ip} on {bl_str}")

        # IP reputation — Phase 2 stores as dict keyed by IP
        ip_rep = p2.get('ip_reputation', {})
        if isinstance(ip_rep, dict):
            for ip, data in ip_rep.items():
                abuse = data.get('abuseipdb', {}).get('abuse_score', 0) or 0
                blacklists = data.get('blacklists', [])
                pulses = data.get('alienvault', {}).get('pulse_count', 0) or 0
                bl_names = [b.get('blacklist', str(b)) if isinstance(b, dict) else str(b) for b in blacklists if b]
                if abuse > 10:
                    lines.append(f"IP REPUTATION: {ip} — AbuseIPDB abuse score {abuse}%")
                if bl_names:
                    lines.append(f"IP BLACKLISTED: {ip} on {', '.join(bl_names)}")
                if pulses > 0:
                    lines.append(f"IP THREAT INTEL: {ip} — found in {pulses} AlienVault threat pulse(s)")

        # SSL weaknesses — Phase 2 stores as dict, not list
        ssl_w = p2.get('ssl_weaknesses', {})
        if isinstance(ssl_w, dict):
            if ssl_w.get('weak_tls_versions'):
                lines.append(f"SSL WEAKNESS: Weak TLS versions supported — {ssl_w['weak_tls_versions']}")
            if ssl_w.get('weak_ciphers'):
                lines.append(f"SSL WEAKNESS: Weak cipher suites detected — {ssl_w['weak_ciphers']}")
            if ssl_w.get('hsts_missing'):
                lines.append("SSL WEAKNESS: HSTS header missing")
            if ssl_w.get('self_signed'):
                lines.append("SSL WEAKNESS: Self-signed certificate")
            summary = ssl_w.get('summary', [])
            if summary and 'No SSL weaknesses' not in str(summary):
                lines.append(f"SSL WEAKNESS: {'; '.join(summary)}")
        elif isinstance(ssl_w, list):
            for w in ssl_w:
                if isinstance(w, dict):
                    lines.append(f"SSL WEAKNESS: {w.get('type', w.get('issue',''))} — {w.get('description', w.get('detail',''))}")
                elif isinstance(w, str):
                    lines.append(f"SSL WEAKNESS: {w}")

        # DNS issues
        dns = p2.get('dns_records', {})
        caa = dns.get('CAA', None)
        if caa is not None and len(caa) == 0:
            lines.append("DNS ISSUE: CAA record missing — any CA can issue SSL certs for this domain")
        dnssec = dns.get('DNSSEC', None)
        if dnssec is not None and not dnssec.get('enabled', True):
            lines.append("DNS ISSUE: DNSSEC not enabled — DNS spoofing/cache poisoning possible")

        # Mail security
        mail = p2.get('mail_server_analysis') or {}
        if mail.get('mx_count') or mail.get('mx_records'):
            spf = mail.get('spf_record')
            dmarc = mail.get('dmarc_record')
            dkim = mail.get('dkim_record')
            spf_strength = mail.get('spf_strength', {})
            dmarc_policy = mail.get('dmarc_policy', '')
            if not spf:
                lines.append("EMAIL SECURITY: SPF record missing — email spoofing possible")
            elif '+all' in str(spf):
                lines.append("EMAIL SECURITY: SPF uses +all — allows any server to send as this domain")
            elif spf_strength.get('level') == 'WEAK':
                lines.append(f"EMAIL SECURITY: SPF is WEAK ({spf_strength.get('mechanism','~all')}) — spoofed emails not rejected, only marked")
            if not dmarc:
                lines.append("EMAIL SECURITY: DMARC record missing — no email impersonation protection")
            elif dmarc_policy in ('none', ''):
                lines.append("EMAIL SECURITY: DMARC policy is 'none' — no enforcement, only monitoring")
            if not dkim:
                lines.append("EMAIL SECURITY: DKIM missing — emails can be forged")

        # WAF
        waf = p2.get('waf_detection', {})
        if waf.get('detected'):
            lines.append(f"WAF DETECTED: {waf.get('waf_name','Unknown')} — some attacks may be filtered")
        else:
            lines.append("WAF: Not detected — no web application firewall protection")

        # Typosquatting — Phase 2 stores as dict {registered_domains, lookalike_details}
        lookalikes = p2.get('dnstwist_lookalikes', {})
        if isinstance(lookalikes, dict):
            reg_count = lookalikes.get('registered_domains', 0)
            if reg_count:
                lines.append(f"TYPOSQUATTING: {reg_count} lookalike domains registered — phishing/brand abuse risk")
        elif isinstance(lookalikes, list) and lookalikes:
            lines.append(f"TYPOSQUATTING: {len(lookalikes)} lookalike domains registered — phishing/brand abuse risk")

        # Subdomains
        active = p2.get('active_subdomains', [])
        if active:
            lines.append(f"SUBDOMAINS: {len(active)} active subdomains found")

        # ── PHASE 3 ──────────────────────────────────────────────────────────
        lines.append("")
        lines.append("=== PHASE 3: WEB APPLICATION FINDINGS ===")

        # CMS — stored in 2_web_server_stack.cms and cms_versions
        web_stack = p3.get('2_web_server_stack', {})
        cms_list = web_stack.get('cms', [])
        cms_versions = web_stack.get('cms_versions', {})
        if cms_list:
            cms_with_ver = []
            for cms in cms_list:
                ver = cms_versions.get(cms, '')
                cms_with_ver.append(f"{cms} {ver}".strip())
            lines.append(f"CMS DETECTED: {', '.join(cms_with_ver)}")

        # Security header issues (misconfigured + missing)
        posture = p3.get('7_security_posture', {})
        for issue in posture.get('header_issues', []):
            lines.append(f"HEADER ISSUE: {issue}")
        for hdr, info in posture.get('security_headers', {}).items():
            if not info.get('present', False):
                lines.append(f"MISSING HEADER: {hdr}")

        # Cookies
        for cookie in posture.get('cookie_security', []):
            cookie_problems = []
            if not cookie.get('httponly'):
                cookie_problems.append('missing HttpOnly')
            if not cookie.get('secure'):
                cookie_problems.append('missing Secure flag')
            ss = cookie.get('samesite_value', '') or ''
            if not ss or ss.lower() == 'not set':
                cookie_problems.append('missing SameSite')
            if cookie_problems:
                lines.append(f"INSECURE COOKIE: {cookie.get('cookie','Unknown')} — {', '.join(cookie_problems)}")

        # SSL cert
        ssl_cert = posture.get('ssl_certificate', {})
        if ssl_cert.get('self_signed'):
            lines.append("SSL CERT: Self-signed certificate detected")
        if ssl_cert.get('expired'):
            lines.append("SSL CERT: Certificate is expired")

        # Open redirect
        redirects = posture.get('open_redirect', [])
        if redirects:
            lines.append(f"OPEN REDIRECT: {len(redirects)} vulnerable parameter(s) found")

        # WAF already reported from Phase 2 (network level) — no duplicate here

        # Admin panels Phase 3
        ap3 = posture.get('admin_panels', [])
        for ap in ap3:
            lines.append(f"ADMIN PANEL (Phase 3): {ap.get('path','')} — {ap.get('status','')}")

        # SRI missing — stored in 7_security_posture.sri_missing
        missing_sri = posture.get('sri_missing', [])
        if missing_sri:
            srcs = ', '.join([s.get('src', '') for s in missing_sri[:3]])
            lines.append(f"SRI MISSING: {len(missing_sri)} external scripts without subresource integrity — {srcs}")

        # Threat intelligence (Section 10)
        threat = p3.get('10_threat_intelligence', {})
        for key, val in threat.items():
            if isinstance(val, dict):
                score = val.get('abuse_confidence_score', val.get('abuseConfidenceScore', 0))
                if score and int(score) > 25:
                    lines.append(f"THREAT INTEL: {key} — abuse score {score}%")
                pulses = val.get('pulse_count', val.get('pulseCount', 0))
                if pulses and int(pulses) > 0:
                    lines.append(f"THREAT INTEL: {key} found in {pulses} threat pulse(s)")

        # IntelligenceX dark web — stored in 11_leak_detection.intelx
        leak_sec = p3.get('11_leak_detection', {})
        intel_x = leak_sec.get('intelx', {})
        if not intel_x:
            intel_x = p3.get('10_threat_intelligence', {}).get('intelligencex', {})
        if intel_x and isinstance(intel_x, dict):
            all_results = intel_x.get('all_results', [])
            total = len(all_results) if all_results else intel_x.get('total_results', intel_x.get('total', 0))
            darknet = sum(1 for r in all_results if r.get('type') == 'darknet') if all_results else intel_x.get('darknet_count', 0)
            leaks_count = sum(1 for r in all_results if 'leak' in r.get('bucket', '').lower()) if all_results else intel_x.get('leaks_count', 0)
            if total:
                lines.append(f"DARK WEB: IntelligenceX found {total} intelligence records for this domain ({darknet} darknet sources, {leaks_count} leak log entries) — exact content requires manual review; do not assume credentials are confirmed")

        # Leak detection (Section 11) — citadel key is domain-specific e.g. domochemicals.com_citadel
        for key, val in leak_sec.items():
            if 'citadel' in key.lower() and isinstance(val, dict):
                if val.get('found') or val.get('breach_count', 0) > 0:
                    lines.append(f"DATA BREACH: Citadel found breached credentials for {self.domain}")
        leakix = leak_sec.get('leakix', [])
        if leakix:
            lines.append(f"LEAK DETECTION: LeakIX found {len(leakix)} exposed service(s)")

        # S3 / cloud buckets (Section 12)
        s3 = p3.get('12_s3_exposure', {})
        exposed_files = s3.get('exposed_files', [])
        if exposed_files:
            lines.append(f"CLOUD STORAGE: {len(exposed_files)} exposed S3/cloud file(s) found")

        # GitHub repos
        repos = p3.get('5_code_repositories', {})
        github = repos.get('github_repos', [])
        if github:
            names = ', '.join([r.get('name','') for r in github[:3]])
            lines.append(f"PUBLIC REPOS: {len(github)} GitHub repo(s) found — {names}")

        # ERP / SAP detection (Phase 3 section 3) — previously never sent
        erp = p3.get('3_erp_sap_detection', {})
        erp_versions = erp.get('erp_versions', {})
        for product, version in erp_versions.items():
            lines.append(f"ERP/SAP DETECTED: {product} version {version}")

        # Third-party software — exposed secrets (API keys in client-side JS)
        third_party = p3.get('4_third_party_software', {})
        exposed_secrets = third_party.get('exposed_secrets', [])
        for secret in exposed_secrets:
            lines.append(f"EXPOSED SECRET IN JS: {secret.get('type', 'API Key')} — {secret.get('value', '')[:60]} (found in client-side code)")

        # API discovery (Phase 3 section 8) — previously never sent
        api_disc_full = p3.get('8_api_discovery', {})
        api_endpoints = api_disc_full.get('endpoints', [])
        if api_endpoints:
            ep_list = ', '.join([e.get('path', str(e)) for e in api_endpoints[:5]])
            lines.append(f"API ENDPOINTS EXPOSED: {len(api_endpoints)} endpoints found — {ep_list}")
        graphql = api_disc_full.get('graphql', {})
        if graphql and graphql.get('found'):
            lines.append(f"GRAPHQL ENDPOINT EXPOSED: {graphql.get('url', 'GraphQL endpoint detected')}")

        # Database detection (Phase 3 section 9) — previously never sent
        db_det = p3.get('9_database_detection', {})
        conn_strings = db_det.get('connection_strings', [])
        for cs in conn_strings:
            lines.append(f"DATABASE CONNECTION STRING EXPOSED: {str(cs)[:100]}")
        databases = db_det.get('databases', [])
        for db in databases:
            lines.append(f"DATABASE DETECTED: {db.get('type', '')} at {db.get('url', '')}")

        # LeakIX detailed services (previously only count was sent)
        leakix_detail = leak_sec.get('leakix', [])
        for svc in leakix_detail[:5]:
            if isinstance(svc, dict):
                lines.append(f"LEAKIX EXPOSED SERVICE: {svc.get('service', '')} at {svc.get('ip', '')} — {svc.get('summary', '')[:100]}")

        # Pastebin pastes with details
        pastebin_data = leak_sec.get('pastebin_search', {})
        pastes = pastebin_data.get('results', []) if isinstance(pastebin_data, dict) else []
        for paste in pastes[:5]:
            if isinstance(paste, dict):
                lines.append(f"PASTEBIN PASTE: '{paste.get('title', 'Untitled')}' — {paste.get('url', '')} — {paste.get('snippet', '')[:80]}")

        # S3 bucket names (previously only count was sent)
        grayhat = p3.get('12_s3_exposure', {}).get('grayhatwarfare', {})
        buckets = grayhat.get('buckets', []) if isinstance(grayhat, dict) else []
        for bucket in buckets[:5]:
            bname = bucket.get('bucket', str(bucket))
            bfiles = bucket.get('files', 0)
            lines.append(f"S3 BUCKET EXPOSED: {bname} — {bfiles} files publicly accessible")

        return '\n'.join(lines)

    def _correlate_batch(self, batch_lines):
        """Send one batch of findings to AI and return parsed results."""
        batch_text = '\n'.join(batch_lines)
        prompt = f"""You are a CVE/CWE security expert. Map each finding below to a real CVE or CWE.

FINDINGS:
{batch_text}

Rules:
- Prefer real CVE IDs (e.g. CVE-2018-7600) over CWE when a specific CVE exists for that technology/service
- Use CWE only when no specific CVE applies (e.g. missing headers use CWE-693, CWE-319 etc.)
- Output exactly one line per finding above, in this format:
FINDING|CVE_OR_CWE_ID|CVSS|SEVERITY|ATTACK_TYPE|REAL_WORLD
- REAL_WORLD: true if CVE-*, false if CWE-*
- SEVERITY: CRITICAL, HIGH, MEDIUM, or LOW

Output ONLY pipe-separated lines. No explanation, no headers."""

        raw = self.call_gemini(prompt)
        results = []
        if not raw:
            return results
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or '|' not in line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 5:
                continue
            finding, cve_id, cvss_str, severity, attack_type = parts[0], parts[1], parts[2], parts[3], parts[4]
            real_world = len(parts) > 5 and parts[5].lower() == 'true'
            if not (cve_id.startswith('CVE-') or cve_id.startswith('CWE-')):
                continue
            try:
                cvss = float(cvss_str)
            except:
                cvss = 5.0
            if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                severity = 'MEDIUM'
            is_real_cve = cve_id.startswith('CVE-')
            results.append({
                'tech':              finding,
                'version':           'N/A',
                'cve':               cve_id,
                'cvss':              cvss,
                'severity':          severity,
                'desc':              f"{attack_type} — {finding}",
                'vector':            '',
                'cwe':               cve_id if cve_id.startswith('CWE-') else 'Unknown',
                'published':         datetime.now().strftime('%Y-%m-%d'),
                'github_pocs':       0,
                'exploitdb':         0,
                'metasploit':        0,
                'source':            'AI-Correlated (Real CVE)' if is_real_cve else 'AI-Correlated (CWE)',
                'attack_type':       attack_type,
                'real_world_attack': real_world and is_real_cve
            })
        return results

    def ai_correlate_all(self):
        """
        Batched AI correlation — splits findings into groups of 7 and calls AI
        once per batch so Gemini covers every single finding.
        """
        if not self.use_gemini:
            self.log("Skipping AI correlation (Gemini not enabled)", "warning")
            return []

        self.header("AI-POWERED COMPREHENSIVE CVE/CWE CORRELATION")
        self.log("Building comprehensive summary from ALL Phase 2 + Phase 3 data...", "info")

        summary = self.build_comprehensive_summary()
        if not summary.strip():
            self.log("No data to correlate", "warning")
            return []

        # Extract individual finding lines (skip section headers)
        finding_lines = [
            l for l in summary.splitlines()
            if l.strip() and not l.startswith('===')
        ]

        print(f"\n{Fore.YELLOW}Findings to correlate ({len(finding_lines)} total — sending as ONE unified call):{Style.RESET_ALL}")
        for l in finding_lines:
            print(f"  {l}")

        # Send ALL findings in one call so AI has full context (no batch fragmentation)
        self.log(f"Sending all {len(finding_lines)} findings in one unified AI call...", "info")
        all_results = self._correlate_batch(finding_lines)
        self.log(f"AI correlated {len(all_results)} CVE/CWE mappings from {len(finding_lines)} findings", "success" if all_results else "warning")
        return all_results

    def ai_find_security_cves(self):
        """AI finds REAL CVE IDs for security headers and cookies from actual attacks"""
        # FIX #5: Check both security_issues AND phase2_data before skipping
        if not self.security_issues and not self.phase2_data:
            return []
    
        if not self.use_gemini:
            self.log("Skipping AI CVE search (Gemini not enabled)", "warning")
            return []
    
        self.header("AI-POWERED CVE SEARCH FOR SECURITY MISCONFIGURATIONS")
    
        def _sanitize(text):
            """Remove characters that break JSON when Gemini embeds them in strings"""
            return str(text).replace('"', "'").replace('\n', ' ').replace('\r', ' ').replace('\\', '/').strip()

        issues_summary = "\n".join([
            f"- {_sanitize(s['type'])}: {_sanitize(s.get('header', s.get('cookie', 'Unknown')))} - {_sanitize(s.get('description', ', '.join(s.get('issues', []))))}"
            for s in self.security_issues
        ])
    
        prompt = f"""You are a CVE/CWE security expert. For each security issue below, find the best matching CVE or CWE.

SECURITY ISSUES TO MAP:
{issues_summary}

OUTPUT FORMAT — one line per issue, pipe-separated, no JSON, no markdown:
ISSUE|CVE_ID|CWE_ID|CVSS|SEVERITY|ATTACK_TYPE|REAL_WORLD

Rules:
- CVE_ID: use real CVE like CVE-2024-12345, or N/A if none exists
- CWE_ID: always provide e.g. CWE-79, CWE-319, CWE-1021, CWE-693
- CVSS: numeric score like 6.1 or 5.0
- SEVERITY: CRITICAL, HIGH, MEDIUM, or LOW
- ATTACK_TYPE: short label like XSS, Clickjacking, CSRF, SSL-Strip, Phishing
- REAL_WORLD: true or false

Common mappings to use (cover ALL issue types):
- Missing CSP / unsafe-inline: CWE-79, XSS attacks, CVSS 6.1, HIGH
- Missing Permissions-Policy: CWE-693, Feature abuse, CVSS 4.3, MEDIUM
- Missing COEP/COOP/CORP: CWE-346, Cross-origin attacks, CVSS 5.4, MEDIUM
- Missing HSTS or weak HSTS: CWE-319, SSL stripping, CVSS 6.5, MEDIUM
- Missing X-Frame-Options: CWE-1021, Clickjacking, CVSS 6.1, MEDIUM, false
- Missing X-Content-Type-Options: CWE-693, MIME sniffing, CVSS 4.3, MEDIUM, false
- IntelligenceX breach / dark web records: CWE-359, Credential theft, CVSS 8.1, HIGH, false
- Dark web breach records / leaked credentials: CWE-359, Credential exposure, CVSS 8.0, HIGH, false
- Missing SRI / no subresource integrity: CWE-353, Supply chain injection, CVSS 6.1, MEDIUM, false
- Admin panel exposed: CWE-284, Unauthorized access, CVSS 7.5, HIGH, false
- CAA record missing: CWE-295, Certificate spoofing, CVSS 5.3, MEDIUM, false

CRITICAL: You MUST output ONE line for EVERY issue listed above in SECURITY ISSUES TO MAP. Do not skip any issue.

Output ONLY the pipe-separated lines, one per issue. No headers, no explanation."""

        try:
            self.log("Asking AI to find REAL CVE IDs from actual attacks...", "info")
            result = self.call_gemini(prompt)
            if not result:
                self.log("AI failed to find CVE IDs", "error")
                return []

            ai_cves = []
            for line in result.strip().splitlines():
                line = line.strip()
                if not line or line.startswith('#') or '|' not in line:
                    continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) < 6:
                    continue
                issue, cve_id, cwe_id, cvss_str, severity, attack_type = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                real_world = len(parts) > 6 and parts[6].lower() == 'true'
                try:
                    cvss = float(cvss_str)
                except:
                    cvss = 5.0
                if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                    severity = 'MEDIUM'
                is_real_cve = cve_id.startswith('CVE-') and cve_id != 'N/A'
                ai_cves.append({
                    'tech':              issue,
                    'version':           'misconfigured',
                    'cve':               cve_id if is_real_cve else (cwe_id if cwe_id.startswith('CWE-') else 'N/A'),
                    'cvss':              cvss,
                    'severity':          severity,
                    'desc':              f"{attack_type} risk from: {issue}",
                    'vector':            '',
                    'cwe':               cwe_id if cwe_id.startswith('CWE-') else 'Unknown',
                    'published':         datetime.now().strftime('%Y-%m-%d'),
                    'github_pocs':       0,
                    'exploitdb':         0,
                    'metasploit':        0,
                    'source':            'AI-Generated (Real CVE)' if is_real_cve else 'AI-Generated (CWE)',
                    'attack_type':       attack_type,
                    'real_world_attack': real_world and is_real_cve
                })

            self.log(f"AI found {len(ai_cves)} CVE/CWE mappings from real attacks", "success")
            return ai_cves
        except Exception as e:
            self.log(f"AI CVE search error: {e}", "error")
            return []

    # === AI: PHASE-2 infra → REAL CVEs/CWEs (NEW) ===
    def ai_find_infra_cves(self):
        """
        Ask Gemini for CVE/CWE mapping ONLY if we have concrete Phase-2 evidence.
        Drop outputs without CVE- or CWE-; no 'N/A' entries are kept.
        """
        # Build evidence list from already-merged infra issues (added above)
        infra_evidence = [
            s for s in self.security_issues
            if s['type'].startswith('Exposed ') or
            s['type'] in ('IP Reputation / Blacklist', 'Weak TLS Protocols')
        ]

        if not infra_evidence:
            self.log("No concrete infra evidence found — skipping AI infra CVE mapping", "warning")
            return []

        if not self.use_gemini:
            self.log("Skipping AI infra mapping (Gemini not enabled)", "warning")
            return []

        self.header("AI-POWERED CVE SEARCH FOR INFRASTRUCTURE EXPOSURES")
        self.log("Asking AI for infra-driven CVE/CWE mappings...", "info")

        # Summarize hard evidence — no guesses here
        ev_lines = []
        for e in infra_evidence:
            name = e.get('type', 'Evidence')
            item = e.get('header', '')
            desc = e.get('description', '')
            ev_lines.append(f"- {name}: {item} :: {desc}")

        prompt = f"""You are a CVE database expert focusing on infrastructure exposures.

TARGET: {self.domain}

HARD EVIDENCE FROM PHASE 2 (observed facts only):
{chr(10).join(ev_lines)}

TASK: For EACH evidence item above, return ONE line mapping it to a real CVE or CWE.

OUTPUT FORMAT — pipe-separated, one line per evidence item:
EVIDENCE_TYPE|CVE_OR_CWE_ID|CVSS|SEVERITY|ATTACK_TYPE|REAL_WORLD

Rules:
- CVE_OR_CWE_ID: real CVE like CVE-2019-10149, or CWE like CWE-284
- CVSS: numeric e.g. 9.8
- SEVERITY: CRITICAL, HIGH, MEDIUM, or LOW
- ATTACK_TYPE: short label e.g. RCE, Open Relay, Reconnaissance
- REAL_WORLD: true if real CVE, false if CWE only
- OMIT any item you cannot map to CVE or CWE

Common mappings:
- Exposed SMTP service: CVE-2019-10149 (Exim RCE), CVSS 9.8, CRITICAL, RCE, true
- Exposed FTP service: CWE-321, CVSS 7.5, HIGH, Credential theft, false
- Exposed RDP: CVE-2019-0708 (BlueKeep), CVSS 9.8, CRITICAL, RCE, true
- IP blacklisted: CWE-284, CVSS 5.0, MEDIUM, Abuse, false
- Weak TLS: CWE-326, CVSS 5.9, MEDIUM, Protocol downgrade, false

Output ONLY pipe-separated lines. No headers, no explanation, no markdown."""

        try:
            raw = self.call_gemini(prompt)
            if not raw:
                self.log("AI infra mapping returned no content", "warning")
                return []

            out = []
            for line in raw.strip().splitlines():
                line = line.strip()
                if not line or '|' not in line:
                    continue
                parts = [p.strip() for p in line.split('|')]
                if len(parts) < 5:
                    continue
                evidence_type, cve_id, cvss_str, severity, attack_type = parts[0], parts[1], parts[2], parts[3], parts[4]
                real_world = len(parts) > 5 and parts[5].lower() == 'true'
                # Must be a real CVE or CWE
                if not (cve_id.startswith('CVE-') or cve_id.startswith('CWE-')):
                    continue
                try:
                    cvss = float(cvss_str)
                except:
                    cvss = 5.0
                if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                    severity = 'MEDIUM'
                out.append({
                    'tech':              evidence_type,
                    'version':           'infrastructure',
                    'cve':               cve_id,
                    'cvss':              cvss,
                    'severity':          severity,
                    'desc':              f"{attack_type} risk from infrastructure exposure: {evidence_type}",
                    'vector':            '',
                    'cwe':               cve_id if cve_id.startswith('CWE-') else 'Unknown',
                    'published':         datetime.now().strftime('%Y-%m-%d'),
                    'github_pocs':       0,
                    'exploitdb':         0,
                    'metasploit':        0,
                    'source':            'AI-Generated (Infra)',
                    'attack_type':       attack_type,
                    'real_world_attack': real_world and cve_id.startswith('CVE-')
                })

            self.log(f"AI (infra) produced {len(out)} mappings", "success" if out else "warning")
            return out

        except Exception as e:
            self.log(f"AI infra CVE mapping error: {e}", "error")
            return []


    def correlate_cves(self):
        self.header("STEP 1: CVE CORRELATION & EXPLOITABILITY ASSESSMENT")
        print(f"{Fore.YELLOW}Task 1.1: CVE ID Mapping to Assets{Style.RESET_ALL}\n")
        all_results = []

        # ONE comprehensive AI call — correlates ALL Phase 2 + Phase 3 findings together
        ai_correlated = self.ai_correlate_all()

        if ai_correlated:
            print(f"\n{Fore.GREEN}{'='*100}")
            print(f"AI-CORRELATED CVE/CWE MAPPINGS — ALL PHASE 2 + PHASE 3 FINDINGS")
            print(f"{'='*100}{Style.RESET_ALL}\n")

            for idx, cve_data in enumerate(ai_correlated, 1):
                is_real = cve_data.get('real_world_attack', False) and cve_data.get('cve', '').startswith('CVE-')
                symbol = "🔴" if is_real else "⚪"

                print(f"{symbol} {Fore.CYAN}[{idx}/{len(ai_correlated)}] {cve_data['cve']}")
                print(f"Finding: {cve_data['tech']}")
                print(f"Risk Score: {cve_data['cvss']} ({cve_data['severity']})")

                if is_real:
                    print(f"{Fore.GREEN}✓ REAL CVE from actual attack{Style.RESET_ALL}")
                    print(f"Attack Type: {cve_data.get('attack_type', 'Unknown')}")
                else:
                    print(f"{Fore.YELLOW}○ CWE mapping (no specific CVE){Style.RESET_ALL}")

                print(f"Description: {cve_data['desc']}")
                print(f"Source: {cve_data['source']}{Style.RESET_ALL}\n")

                all_results.append(cve_data)

        
        # Second: Normal NVD/CIRCL search for software (Phase 3 tech + Phase 2 merged tech)
        for tech in self.technologies:
            print(f"\n{Fore.CYAN}{'─'*100}")
            print(f"Technology: {tech['name']} {tech['version']} ({tech.get('type','')})")
            print(f"{'─'*100}{Style.RESET_ALL}\n")
    
            # CRITICAL: Skip if no valid version number
            version = tech.get('version', '')
            if not version or version in ['None', 'none', 'latest', 'unknown', 'Unknown', '']:
                self.log(f"SKIPPED: {tech['name']} - No valid version number", "warning")
                continue
            
            nvd_cves = self.search_nvd(tech['name'], tech['version'])
            circl_cves = self.search_circl(tech['name'], tech['version'])
            
            merged = {}
            for cve in nvd_cves + circl_cves:
                # FIX #4: Validate CVE dict structure before accessing
                if not isinstance(cve, dict) or 'id' not in cve:
                    continue
                cve_id = str(cve.get('id', ''))
                
                # ✅ Filter out ONLY invalid/fake IDs, keep all valid CVE/CWE entries
                if not cve_id or cve_id in ['results', 'None', '', 'null']:
                    continue
                
                if not (cve_id.startswith('CVE-') or cve_id.startswith('CWE-')):
                    self.log(f"⚠ Skipped invalid ID format: {cve_id}", "warning")
                    continue
                
                if cve_id not in merged or cve.get('cvss', 0) > merged[cve_id].get('cvss', 0):
                    merged[cve_id] = cve

            cves = list(merged.values())
            
            if not cves:
                self.log(f"No CVEs found for {tech['name']} {tech['version']}", "warning")
                continue
            
            print(f"\n{Fore.GREEN}Found {len(cves)} CVEs (deduplicated){Style.RESET_ALL}\n")
            print(f"{Fore.YELLOW}Task 1.2: CVSS Score & Vector Analysis{Style.RESET_ALL}\n")
            
            for idx, cve in enumerate(sorted(cves, key=lambda x: x['cvss'], reverse=True)[:15], 1):
                print(f"{Fore.CYAN}[{idx}/{min(15, len(cves))}] CVE: {cve['id']}")
                print(f"CVSS: {cve['cvss']} ({cve['severity']})")
                print(f"Vector: {cve['vector']}")
                print(f"CWE: {cve['cwe']}")
                print(f"Published: {cve['published']}")
                print(f"Description: {cve['description'][:200]}...{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}Task 1.3: Exploitability Assessment{Style.RESET_ALL}")
                self.log(f"Searching GitHub...", "info")
                github = self.search_github(cve['id'])
                self.log(f"Searching Exploit-DB...", "info")
                exploitdb = self.search_exploitdb(cve['id'])
                self.log(f"Searching Metasploit...", "info")
                metasploit = self.search_metasploit(cve['id'])
                
                print(f"\n{Fore.CYAN}Public Exploit Availability:{Style.RESET_ALL}")
                print(f"  GitHub PoCs: {github}")
                print(f"  Exploit-DB: {exploitdb}")
                print(f"  Metasploit Modules: {metasploit}\n")
                
                all_results.append({
                    'tech': tech['name'],
                    'version': tech['version'],
                    'cve': cve['id'],
                    'cvss': cve['cvss'],
                    'severity': cve['severity'],
                    'desc': cve['description'],
                    'vector': cve['vector'],
                    'cwe': cve['cwe'],
                    'published': cve['published'],
                    'github_pocs': github,
                    'exploitdb': exploitdb,
                    'metasploit': metasploit
                })
        
        # Enhancement 4: Compute composite threat score (CVSS + real exploit availability boost)
        for r in all_results:
            g = r.get('github_pocs', 0) or 0
            e = r.get('exploitdb', 0) or 0
            m = r.get('metasploit', 0) or 0
            r['composite_score'] = min(10.0, r.get('cvss', 0) + (1.0 if g > 0 else 0) + (1.5 if e > 0 else 0) + (2.0 if m > 0 else 0))

        # Enhancement 2: Global CVE deduplication across AI + NVD/CIRCL combined results
        dedup_map = {}
        non_cve = []
        for r in all_results:
            cve_id = str(r.get('cve', ''))
            if cve_id.startswith('CVE-') or cve_id.startswith('CWE-'):
                if cve_id not in dedup_map or r.get('composite_score', 0) > dedup_map[cve_id].get('composite_score', 0):
                    dedup_map[cve_id] = r
            else:
                non_cve.append(r)
        all_results = list(dedup_map.values()) + non_cve

        self.cve_results = sorted(all_results, key=lambda x: x.get('composite_score', x.get('cvss', 0)), reverse=True)

        # Check if no CVEs found
        if not self.cve_results:
            self.log("✅ No CVEs found - All software versions are up to date or no versioned software detected", "success")
            print(f"\n{Fore.GREEN}{'='*100}")
            print(f"GOOD NEWS: No Common Vulnerabilities and Exposures (CVEs) were identified")
            print(f"{'='*100}{Style.RESET_ALL}\n")
            print(f"{Fore.CYAN}This could mean:{Style.RESET_ALL}")
            print(f"  • All detected software is up-to-date")
            print(f"  • No software versions were detected (version numbers missing)")
            print(f"  • The technology stack is secure\n")

        return self.cve_results

    def detect_industry(self):
        """AI-powered industry detection based on website analysis"""
        self.log(f"Analyzing website with AI: {self.domain}", "info")
        
        if not self.use_gemini:
            self.log("Gemini AI not enabled - using domain analysis", "warning")
            # Better fallback: analyze domain name
            return self._analyze_domain_for_industry(self.domain)
        
        try:
            # Method 1: Try to fetch website content
            website_text = ""
            title_text = ""
            description = ""
            
            try:
                r = self.session.get(f"https://{self.domain}", timeout=10, verify=False)
                if r.status_code == 200:
                    text = r.text[:10000]
                    
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    title = soup.find('title')
                    title_text = title.get_text() if title else ""
                    
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    description = meta_desc.get('content', '') if meta_desc else ""
                    
                    # Get some body text
                    body = soup.find('body')
                    if body:
                        website_text = body.get_text()[:3000]
            except Exception as e:
                self.log(f"Website fetch failed: {e}", "warning")
            
            # Method 2: Use Phase 1 data if available (BETTER SOURCE!)
            phase1_industry = "Unknown"
            if hasattr(self, 'phase1_data') and self.phase1_data:
                ai_analysis = self.phase1_data.get('ai_analysis', {})
                company_overview = ai_analysis.get('company_overview', {})
                phase1_industry = company_overview.get('industry_vertical', 'Unknown')
                
                if phase1_industry and phase1_industry != 'Unknown':
                    self.log(f"Industry from Phase 1: {phase1_industry}", "success")
                    return phase1_industry
            
            # Method 3: Ask AI with available context
            prompt = f"""Analyze this company and determine its industry sector.

    COMPANY: {self.domain}

    WEBSITE DATA:
    - Title: {title_text}
    - Description: {description}
    - Content: {website_text[:1000] if website_text else 'Not available'}

    DOMAIN NAME HINTS:
    - Domain: {self.domain}
    - Possible keywords: {self._extract_domain_keywords(self.domain)}

    What industry/sector does this company operate in? Be VERY specific.

    Examples:
    - "Healthcare Technology" (not just "Technology")
    - "Financial Services - Banking" (not just "Finance")
    - "E-commerce - Fashion Retail" (not just "E-commerce")
    - "Cloud Infrastructure Services"
    - "Cybersecurity Software"
    - "Enterprise SaaS"
    - "Digital Marketing Agency"

    Rules:
    1. Be specific (2-4 words)
    2. If you can't determine from data, analyze the domain name itself
    3. NEVER return just "Technology" - be more specific like "Software Development", "IT Consulting", "Cloud Services", etc.

    Respond with ONLY the industry name (no explanation):"""

            result = self.call_gemini(prompt, max_tokens=50)
            
            if result and result not in ["AI_ERROR", "AI_NOT_AVAILABLE"]:
                industry = result.strip().replace('"', '').replace("'", '')
                
                # Validate it's not too generic
                if industry.lower() not in ['technology', 'tech', 'unknown', 'company']:
                    self.log(f"AI detected industry: {industry}", "success")
                    return industry
            
            # Method 4: Fallback - analyze domain name
            return self._analyze_domain_for_industry(self.domain)
                
        except Exception as e:
            self.log(f"Industry detection error: {e}", "warning")
            return self._analyze_domain_for_industry(self.domain)

    def _extract_domain_keywords(self, domain: str) -> str:
        """Extract meaningful keywords from domain name"""
        # Remove TLD
        name = domain.split('.')[0]
        
        # Split by common separators
        import re
        words = re.split(r'[-_]', name)
        
        return ', '.join(words)

    def _analyze_domain_for_industry(self, domain: str) -> str:
        """Analyze domain name to guess industry (better fallback)"""
        domain_lower = domain.lower()
        
        # Industry keyword mapping
        industry_keywords = {
            'health|medical|pharma|care|clinic|hospital': 'Healthcare',
            'bank|finance|invest|capital|fund|credit': 'Financial Services',
            'shop|store|retail|commerce|buy|sell': 'E-commerce/Retail',
            'tech|soft|app|dev|code|digital': 'Technology/Software',
            'consult|advisory|service': 'Professional Services',
            'edu|school|learn|course|train': 'Education',
            'travel|tour|hotel|booking': 'Travel & Hospitality',
            'food|restaurant|cafe|delivery': 'Food & Beverage',
            'real|estate|property|rent': 'Real Estate',
            'media|news|blog|content': 'Media & Publishing',
            'auto|car|vehicle|motor': 'Automotive',
            'energy|power|solar|electric': 'Energy',
            'logistics|shipping|freight|transport': 'Logistics & Transportation',
            'security|cyber|protect|safe': 'Cybersecurity',
            'cloud|host|server|data': 'Cloud Services',
            'marketing|ad|seo|social': 'Digital Marketing',
            'insurance|policy|coverage': 'Insurance',
            'legal|law|attorney': 'Legal Services',
            'manufacture|factory|industrial': 'Manufacturing',
            'fashion|clothing|apparel': 'Fashion & Apparel'
        }
        
        import re
        for pattern, industry in industry_keywords.items():
            if re.search(pattern, domain_lower):
                self.log(f"Industry detected from domain: {industry}", "info")
                return industry
        
        # Ultimate fallback - but more specific
        self.log("Could not determine specific industry - using generic Tech", "warning")
        return "Technology Services"

    def fetch_mitre_apts(self):
        self.log("Fetching MITRE ATT&CK APT groups...", "info")
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            r = self.session.get(url, timeout=30)
            if r.status_code == 200:
                groups = [o for o in r.json()['objects'] if o['type'] == 'intrusion-set']
                apts = []
                for g in groups:
                    apts.append({
                        'name': g.get('name', 'Unknown'),
                        'aliases': g.get('aliases', []),
                        'description': g.get('description', ''),
                        'id': g.get('id', '')
                    })
                self.log(f"Loaded {len(apts)} APT groups", "success")
                return apts
        except Exception as e:
            self.log(f"MITRE fetch error: {e}", "error")
        return []

    def ai_apt_threat_mapping(self):
        self.header("STEP 2: THREAT INTELLIGENCE - APT GROUP THREAT MAPPING")
        sector = self.detect_industry()
        apts = self.fetch_mitre_apts()
        self.threat_intel['sector'] = sector
        self.threat_intel['apt_groups'] = apts
        
        if not self.cve_results and not self.security_issues:
            self.log("No vulnerabilities to analyze - Generating low-risk assessment", "warning")
            
            # Generate minimal threat intel report
            self.threat_intel['apt_mapping'] = f"""
# APT Threat Mapping

**Status:** No vulnerabilities detected in Phase 4 analysis.

**Industry:** {sector.upper()}

**Threat Level:** LOW

Since no CVEs or security configuration issues were identified, there are no immediate 
vulnerabilities for APT groups to exploit. However, organizations should maintain:

- Regular security updates and patch management
- Continuous security monitoring
- Security awareness training programs
- Incident response planning

**Note:** The absence of detected vulnerabilities does not guarantee complete security. 
Consider conducting active penetration testing for comprehensive assessment.
"""
            
            # Save to markdown
            safe = (self.domain or "domain").replace(".", "_")
            md = f"APT_Threat_Mapping_{safe}.md"
            with open(md, "w", encoding="utf-8") as f:
                f.write(self.threat_intel['apt_mapping'])
            self.log(f"Saved: {md}", "success")
            
            return
        
        vuln_summary = "\n".join([f"- {v['cve']}: {v['tech']} {v.get('version', '')} (CVSS: {v['cvss']}, {v['severity']})" for v in self.cve_results[:20]])
        security_summary = "\n".join([f"- {s['type']}: {s.get('header', s.get('cookie', 'Unknown'))}" for s in self.security_issues[:10]])
        apt_summary = "\n".join([f"- {apt['name']}: {apt['description'][:200]}..." for apt in apts[:30]])
        
        prompt = f"""You are a security intelligence analyst preparing a defensive report.

TARGET PROFILE:
- Domain: {self.domain}
- Industry: {sector}

BUSINESS CONTEXT (from Phase 1):
{self._build_phase1_context()}

TECHNICAL FINDINGS:
{vuln_summary}

CONFIGURATION ISSUES:
{security_summary}

KNOWN THREAT GROUPS (from MITRE ATT&CK framework):
{apt_summary}

DEFENSIVE INTELLIGENCE REQUEST:

Based on this company's specific industry ({sector}) and their vulnerabilities, identify which 5 threat groups pose the highest risk.

Consider:
1. Groups that historically target the {sector} industry
2. Groups whose techniques align with the discovered vulnerabilities
3. The company's likely value as a target based on their industry

For each of the TOP 5 threat groups, provide:
1. Group Name
2. Risk Relevance Score (1-10)
3. Why they would target a {sector} company
4. Technical Alignment with discovered vulnerabilities
5. Historical attacks on similar {sector} organizations

Format response clearly with headers for each group.

Focus on realistic defensive intelligence based on:
- Industry targeting patterns
- Technical capabilities
- Historical attack patterns
- Geopolitical factors
"""

        if self.use_gemini:
            print(f"{Fore.CYAN}Calling Gemini AI for Threat Analysis...{Style.RESET_ALL}\n")
            result = self.call_gemini(prompt)
            if result:
                print(f"\n{Fore.GREEN}{'='*100}\nAPT THREAT MAPPING COMPLETE\n{'='*100}{Style.RESET_ALL}\n")
                print(result)
                self.threat_intel['apt_mapping'] = result

                # NEW: Save to Markdown
                safe = (self.domain or "domain").replace(".", "_")
                md = f"APT_Threat_Mapping_{safe}.md"
                with open(md, "w", encoding="utf-8") as f:
                    f.write(result)
                self.log(f"Saved: {md}", "success")

            else:
                self.log("AI failed - saving prompt", "warning")
                fname = f"APT_Prompt_{self.domain.replace('.', '_')}.txt"
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write(prompt)
                self.log(f"Saved: {fname}", "success")
                print(f"\n{Fore.YELLOW}Use this prompt manually at: https://gemini.google.com{Style.RESET_ALL}\n")
        else:
            fname = f"APT_Prompt_{self.domain.replace('.', '_')}.txt"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(prompt)
            self.log(f"Saved: {fname}", "success")


    def _build_phase1_context(self):
        """Extract business context from Phase 1 for AI prompts"""
        if not self.phase1_data:
            return "Phase 1 data not available."
        ai = self.phase1_data.get('ai_analysis', {})
        overview = ai.get('company_overview', {})
        lines = []
        if overview.get('industry_vertical'):
            lines.append(f"Industry: {overview['industry_vertical']}")
        if overview.get('company_size'):
            lines.append(f"Company Size: {overview['company_size']}")
        if overview.get('revenue'):
            lines.append(f"Revenue: {overview['revenue']}")
        critical_data = ai.get('critical_data', overview.get('critical_data', []))
        if critical_data:
            lines.append(f"Critical Data Held: {', '.join(critical_data) if isinstance(critical_data, list) else critical_data}")
        # Phase 1 stores compliance under regulatory_compliance.confirmed_public + ai_suggested
        reg = ai.get('regulatory_compliance', {})
        confirmed = reg.get('confirmed_public', []) if isinstance(reg, dict) else []
        ai_suggested = reg.get('ai_suggested', []) if isinstance(reg, dict) else []
        all_compliance = []
        if isinstance(confirmed, list): all_compliance += [c.get('name', str(c)) if isinstance(c, dict) else str(c) for c in confirmed]
        if isinstance(ai_suggested, list): all_compliance += [c.get('name', str(c)) if isinstance(c, dict) else str(c) for c in ai_suggested]
        if not all_compliance:
            all_compliance = overview.get('compliance', [])
        if all_compliance:
            lines.append(f"Compliance Requirements: {', '.join(all_compliance[:8])}")
        attack_surface = ai.get('attack_surface', {})
        if attack_surface:
            lines.append(f"Attack Surface Notes: {str(attack_surface)[:200]}")
        return '\n'.join(lines) if lines else "Phase 1 context limited."

    def _build_leak_intel_summary(self):
        """Build summary of leak detection findings for AI prompt"""
        leak_issues = [
            s for s in self.security_issues 
            if any(x in s['type'] for x in ['IntelligenceX', 'PasteBin', 'Citadel', 'LeakIX', 'S3 Bucket'])
        ]
        
        if not leak_issues:
            return "No data leaks or breaches detected."
        
        summary_lines = []
        for issue in leak_issues:
            summary_lines.append(
                f"**{issue['type']}**\n"
                f"Finding: {issue.get('header', 'N/A')}\n"
                f"Details: {issue.get('description', 'N/A')}\n"
                f"Severity: {issue.get('severity', 'UNKNOWN')}"
            )
        
        return "\n\n".join(summary_lines)

    def _build_threat_intel_summary(self):
        """Build summary of threat intelligence findings for AI prompt"""
        threat_issues = [
            s for s in self.security_issues 
            if any(x in s['type'] for x in ['Threat Intelligence', 'IP Reputation', 'Malicious', 'Project Honey Pot', 'APT Threat'])
        ]
        
        if not threat_issues:
            return "No malicious IP activity or threat indicators detected."
        
        summary_lines = []
        for issue in threat_issues:
            summary_lines.append(
                f"**{issue['type']}**\n"
                f"Target: {issue.get('header', 'N/A')}\n"
                f"Details: {issue.get('description', 'N/A')}\n"
                f"Severity: {issue.get('severity', 'UNKNOWN')}\n"
                f"Source: {issue.get('source', 'Unknown')}"
            )
        
        return "\n\n".join(summary_lines)


    def ai_attack_vector_correlation(self):
        self.header("STEP 3: ATTACK VECTOR CORRELATION (AI-POWERED)")
        

        if not self.cve_results and not self.security_issues:
            self.log("No vulnerabilities to analyze - Generating secure posture report", "warning")
            
            self.attack_vectors = """
# Attack Vector Correlation & MITRE ATT&CK Mapping

**Status:** No vulnerabilities detected in Phase 4 analysis.

## 1. TOP 3 THREAT SCENARIOS (Most Critical)

**No attack scenarios identified** - No exploitable vulnerabilities were found.

## 2. VULNERABILITY CORRELATION ANALYSIS

No CVEs or security configuration issues were identified that could be chained together 
for exploitation. This indicates a strong security posture.

## 3. MITRE ATT&CK DEFENSIVE MAPPING

No specific MITRE ATT&CK techniques were identified due to absence of exploitable vulnerabilities.

### General Recommendations:

**TA0001 - Initial Access**
- Continue monitoring for phishing attempts
- Maintain strong perimeter defenses

**TA0002 - Execution**  
- Keep systems patched and updated
- Implement application whitelisting

**TA0005 - Defense Evasion**
- Maintain security monitoring solutions
- Regular log reviews

## Recommendations

1. **Maintain Current Security Posture**
   - Continue regular patching and updates
   - Monitor for new vulnerabilities in installed software

2. **Proactive Security Measures**
   - Implement SIEM for continuous monitoring
   - Conduct periodic penetration testing
   - Maintain incident response plans

3. **Continuous Improvement**
   - Stay informed about emerging threats
   - Regular security awareness training
   - Third-party security audits
"""
            
            # Save to markdown
            safe = (self.domain or "domain").replace(".", "_")
            md = f"Attack_Vector_Correlation_{safe}.md"
            with open(md, "w", encoding="utf-8") as f:
                f.write(self.attack_vectors)
            self.log(f"Saved: {md}", "success")
            
            return
        
        # ── Build scenario-specific vulnerability subsets so each story has a different entry ──
        all_sorted = sorted(self.cve_results, key=lambda x: x.get('cvss', 0), reverse=True)

        # Scenario 1 (Ransomware Operator) — top CVSS vulns, fastest to monetize
        s1_vulns = all_sorted[:5]

        # Scenario 2 (Nation-State APT) — vulns with public exploit code already available
        s2_vulns = [v for v in all_sorted
                    if (v.get('github_pocs', 0) + v.get('exploitdb', 0) + v.get('metasploit', 0)) > 0][:5]
        if not s2_vulns:
            s2_vulns = all_sorted[3:8] if len(all_sorted) > 3 else all_sorted[:5]

        # Scenario 3 (Opportunistic / Hacktivist) — misconfigs + medium CVSS vulns
        s3_config_issues = [s for s in self.security_issues if s.get('severity') in ('CRITICAL', 'HIGH')][:6]
        s3_vulns = [v for v in self.cve_results if 4.0 <= v.get('cvss', 0) < 8.0][:5]

        def _fmt_vulns(vulns):
            if not vulns:
                return "  - No specific CVEs identified for this scenario"
            return "\n".join([
                f"  - {v['cve']} | {v['tech']} {v.get('version', '')} | CVSS {v['cvss']} ({v['severity']}) "
                f"| PoCs: GitHub={v.get('github_pocs', 0)}, ExploitDB={v.get('exploitdb', 0)}, MSF={v.get('metasploit', 0)}"
                for v in vulns
            ])

        def _fmt_config(issues):
            if not issues:
                return "  - No critical misconfigurations identified"
            return "\n".join([
                f"  - {s['type']}: {s.get('header', s.get('url', s.get('cookie', 'Unknown')))} [{s['severity']}]"
                for s in issues
            ])

        # Build additional attack surface context
        api_disc = self.phase3_data.get('8_api_discovery', {})
        active_api_vers = api_disc.get('active_api_versions', {})
        api_context = ', '.join([f"{b}: {', '.join(v)}" for b, v in active_api_vers.items()]) if active_api_vers else "None detected"
        admin_panels = self.phase3_data.get('7_security_posture', {}).get('admin_panels', [])
        admin_context = ', '.join([p.get('path', '') for p in admin_panels[:5]]) if admin_panels else "None found"

        leak_summary = self._build_leak_intel_summary()
        threat_summary = self._build_threat_intel_summary()

        # For Scenario 2 entry: prefer dark web/credential intel over CVEs if available
        s2_entry_context = leak_summary if leak_summary != "No data leaks or breaches detected." else _fmt_vulns(s2_vulns)

        prompt = f"""You are a senior offensive security analyst with 12 years of red team and threat intelligence experience. You are writing a realistic threat assessment for a defensive security report.

TARGET: {self.domain} ({self.threat_intel.get('sector', 'Unknown').upper()} sector)

=== BUSINESS CONTEXT ===
{self._build_phase1_context()}

=== DARK WEB & BREACH INTELLIGENCE (CONFIRMED FINDINGS ONLY) ===
{leak_summary}

=== THREAT INTELLIGENCE & IP REPUTATION ===
{threat_summary}

=== EXPOSED ATTACK SURFACE ===
- Active API Versions: {api_context}
- Admin Panels Found: {admin_context}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL INSTRUCTION: Generate 3 COMPLETELY DIFFERENT attack scenarios.
Each scenario MUST use a different attacker persona, a different entry point,
and a different attack path. DO NOT repeat the same entry point across scenarios.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACKER PERSONAS — FIXED (do not change or merge these)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PERSONA 1 — "The Ransomware Operator"
  Role: Financially motivated cybercriminal running a Ransomware-as-a-Service (RaaS) operation
  Backstory: 7 years in cybercrime, part of an Eastern European RaaS group specialising in
    double-extortion (encrypt + exfiltrate). Has hit dozens of chemical/industrial companies. Uses
    automated scanning (Shodan, Nuclei, Metasploit) to find targets fast. Prefers high-CVSS CVEs that
    commodity tools can exploit in under 2 hours. Moves quickly — in and out within 48-72 hours.
  Motivation: Maximum financial return — ransomware payment + dark web data sale
  Toolset: Metasploit, Cobalt Strike, automated exploit frameworks, ransomware payloads
  Risk Tolerance: Medium — triggers alerts but doesn't care after deployment
  ASSIGNED ENTRY VULNERABILITIES (use these, not others):
{_fmt_vulns(s1_vulns)}

PERSONA 2 — "The Nation-State APT Operative"
  Role: State-sponsored intelligence operative targeting chemical/industrial IP
  Backstory: 12+ years in signals intelligence and cyber operations. Member of an APT group focused on
    stealing trade secrets, chemical formulas, R&D data, and supply chain intelligence. Patient and
    methodical — maintains access for months undetected. Prefers legitimate credentials and
    living-off-the-land techniques (LOLBins) to avoid EDR. When dark web intelligence is available
    (leaked credentials, domain records), this is always the preferred entry over noisy CVE exploitation.
  Motivation: Espionage — steal proprietary formulas, R&D data, client lists, supply chain data
  Toolset: Custom implants, LOLBins, legitimate admin tools, stolen/purchased credentials
  Risk Tolerance: Very low — stealth paramount; aborts if detection risk is high
  ASSIGNED ENTRY CONTEXT (intelligence-led approach):
{s2_entry_context}

PERSONA 3 — "The Opportunistic Script Kiddie / Hacktivist"
  Role: Low-to-medium skill opportunist / hacktivist
  Backstory: Found this target via a Shodan scan or Google dork. No custom exploits — purely uses
    public CVE PoCs with Metasploit modules, SQLMap, Nikto, and misconfiguration checkers. Motivated
    by notoriety, ideology (anti-chemical-industry sentiment), or a quick data dump for social media.
    Loud and fast — doesn't care about being detected after the fact.
  Motivation: Notoriety, hacktivism, data dump, website defacement, cryptomining
  Toolset: Metasploit, SQLMap, Nikto, public PoC scripts, automated scanners
  Risk Tolerance: High — noise is acceptable
  ASSIGNED ENTRY (misconfigurations + publicly exploitable CVEs only):
{_fmt_config(s3_config_issues)}
{_fmt_vulns(s3_vulns)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACCURACY RULES — MANDATORY:
1. Only reference dark web/breach findings based on CONFIRMED FINDINGS above.
   If IntelX shows "X records found", say "X intelligence records found" — NOT "credentials confirmed".
   If no breach data exists, do NOT fabricate credential leaks.
2. Each scenario must use ONLY its assigned entry vulnerabilities/context listed above.
3. Attacker stories must be written in FIRST PERSON from that persona's perspective.
4. Attack paths must be technically plausible based on the actual findings.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 1. TOP 3 ATTACK SCENARIOS

---

### Scenario 1: [Name it after the actual exploit method, e.g. "CVE-2023-XXXX Ransomware Double-Extortion Chain"]

**Attacker Profile:** Ransomware Operator (Persona 1)

**Attacker's Story (5-6 sentences, FIRST PERSON as the Ransomware Operator):**
How you discovered {self.domain} (scanning tool / what you found). What specific vulnerability/version
caught your attention and why. Your confidence level and why this target is worth attacking. Your exact
plan — which CVE you exploit first, how you move to high-value data. Expected financial outcome and
timeline. DO NOT mention dark web credentials unless the Dark Web Intelligence section above confirms
actual breach data.

**Entry Point:** [Specific CVE from Persona 1's assigned list above — include CVE ID and tech name]

**Exploitation Chain:**
1. [Discovery: how Persona 1 found and fingerprinted this target]
2. [Initial Access: specific CVE exploit + tool used]
3. [Foothold: how persistence is established]
4. [Privilege Escalation: specific technique]
5. [Lateral Movement: what systems are targeted next]
6. [Impact: ransomware deployment + data exfiltration method]

**Lateral Movement:** [Which internal systems targeted, what credentials stolen, how pivot occurs]

**Business Impact:**
- Data at Risk: [Specific types based on business context — chemical formulas, client data, etc.]
- Estimated Downtime: [Hours or days]
- Ransom Demand Range: [Calibrated to company size from business context]
- Total Financial Exposure: [Including recovery, legal, reputational costs]

**Difficulty Level:** [1-10] — [One sentence explanation]

**MITRE ATT&CK Kill Chain:**
- Initial Access: [T-number: technique name]
- Execution: [T-number: technique name]
- Persistence: [T-number: technique name]
- Privilege Escalation: [T-number: technique name]
- Defense Evasion: [T-number: technique name]
- Credential Access: [T-number: technique name]
- Discovery: [T-number: technique name]
- Lateral Movement: [T-number: technique name]
- Collection: [T-number: technique name]
- Exfiltration: [T-number: technique name]
- Impact: [T-number: technique name]

---

### Scenario 2: [Name it after actual method, e.g. "APT Credential-Led Silent Infiltration for Industrial Espionage"]

**Attacker Profile:** Nation-State APT Operative (Persona 2)

**Attacker's Story (5-6 sentences, FIRST PERSON as the APT Operative):**
How your intelligence unit identified {self.domain} as a target (industry targeting, OSINT).
What intelligence you have from the assigned entry context above (be accurate — report exactly what
the findings show; do NOT say "working credentials found" unless breach data explicitly confirms it).
Your patient, stealthy approach — how you plan to enter without triggering alerts.
Your long-term objective (what data you are stealing and why it matters to your state sponsor).
Your dwell time target and how you maintain access undetected.

**Entry Point:** [Specific method from Persona 2's assigned entry context — credential reuse, dark web
intel, or CVE with custom obfuscation if no breach data exists]

**Exploitation Chain:**
1. [OSINT and target profiling phase]
2. [Initial access method — credential-based or CVE with custom obfuscation]
3. [Establishing persistent, stealthy foothold]
4. [Internal reconnaissance using LOLBins / legitimate tools]
5. [Locating and staging target data (R&D, chemical formulas, client lists)]
6. [Slow, encrypted exfiltration over days/weeks to avoid detection]

**Lateral Movement:** [Stealthy pivoting methods, credential harvesting, target systems]

**Business Impact:**
- Data at Risk: [Specific IP/R&D data based on business context]
- Detection Window: [How long before likely discovery]
- Strategic Damage: [What the stolen IP enables the attacker's sponsor to do]
- Competitive/National Security Impact: [Industry-specific consequence]

**Difficulty Level:** [1-10] — [One sentence explanation]

**MITRE ATT&CK Kill Chain:**
- Initial Access: [T-number: technique name]
- Execution: [T-number: technique name]
- Persistence: [T-number: technique name]
- Privilege Escalation: [T-number: technique name]
- Defense Evasion: [T-number: technique name]
- Credential Access: [T-number: technique name]
- Discovery: [T-number: technique name]
- Lateral Movement: [T-number: technique name]
- Collection: [T-number: technique name]
- Exfiltration: [T-number: technique name]
- Impact: [T-number: technique name]

---

### Scenario 3: [Name it after actual method, e.g. "Misconfiguration Exploitation for Defacement and Data Dump"]

**Attacker Profile:** Opportunistic Script Kiddie / Hacktivist (Persona 3)

**Attacker's Story (5-6 sentences, FIRST PERSON as the Script Kiddie / Hacktivist):**
How you found {self.domain} (Shodan scan, Google dork, or industry targeting for hacktivism).
Which specific misconfiguration or public CVE made this an easy target.
What automated tools you ran (Metasploit module name, SQLMap, Nikto, etc.).
Your goal — defacement, data dump for paste sites, or cryptominer installation.
Why this was low-effort and why you chose this target over others.

**Entry Point:** [Specific misconfiguration or medium-CVSS CVE from Persona 3's assigned list — NOT
the same CVE used in Scenario 1 or 2]

**Exploitation Chain:**
1. [Target discovery via automated scanner or Google dork]
2. [Exploit specific misconfiguration or public CVE PoC]
3. [Gain initial access — what level of access obtained]
4. [Quick data grab, defacement, or cryptominer drop]
5. [Exit — loud and unconcerned about forensics]

**Lateral Movement:** [Whether they attempt deeper access or stay surface-level, and why]

**Business Impact:**
- Immediate Impact: [Defacement / data dump / service disruption]
- Data at Risk: [Surface-level accessible data]
- Reputational Damage: [Public visibility of the attack]
- Recovery Effort: [Time and cost estimate]

**Difficulty Level:** [1-10] — [One sentence explanation]

**MITRE ATT&CK Kill Chain:**
- Initial Access: [T-number: technique name]
- Execution: [T-number: technique name]
- Persistence: [T-number: technique name]
- Privilege Escalation: [T-number: technique name]
- Defense Evasion: [T-number: technique name]
- Credential Access: [T-number: technique name]
- Discovery: [T-number: technique name]
- Lateral Movement: [T-number: technique name]
- Collection: [T-number: technique name]
- Exfiltration: [T-number: technique name]
- Impact: [T-number: technique name]

---

## 2. VULNERABILITY CORRELATION ANALYSIS

Answer in detail:
- Which vulnerabilities can be chained for greater combined impact?
- How do the misconfigurations amplify the CVEs?
- What is the single most critical exploitation path to full system compromise?
- Provide specific attack sequences with CVE IDs

## 3. MITRE ATT&CK DEFENSIVE MAPPING

Map ALL discovered issues to MITRE ATT&CK tactics. For each tactic list the relevant technique IDs
and which specific finding from the target enables it.

**TA0001 - Initial Access**
List applicable techniques (e.g., T1190: Exploit Public-Facing Application)

**TA0002 - Execution**
List applicable techniques

**TA0003 - Persistence**
List applicable techniques

**TA0004 - Privilege Escalation**
List applicable techniques

**TA0005 - Defense Evasion**
List applicable techniques

**TA0006 - Credential Access**
List applicable techniques

**TA0007 - Discovery**
List applicable techniques

**TA0008 - Lateral Movement**
List applicable techniques

**TA0009 - Collection**
List applicable techniques

**TA0010 - Exfiltration**
List applicable techniques

**TA0040 - Impact**
List applicable techniques

For each technique, briefly state which vulnerability or finding enables it.
"""

        if self.use_gemini:
            print(f"{Fore.CYAN}Calling Gemini AI for Attack Vector Analysis...{Style.RESET_ALL}\n")
            print(f"{Fore.YELLOW}Generating comprehensive analysis...{Style.RESET_ALL}\n")
            
            result = self.call_gemini(prompt)
            
            if result:
                print(f"\n{Fore.GREEN}{'='*100}\nATTACK VECTOR CORRELATION COMPLETE\n{'='*100}{Style.RESET_ALL}\n")
                print(result)
                self.attack_vectors = result

                # NEW: Save to Markdown
                safe = (self.domain or "domain").replace(".", "_")
                md = f"Attack_Vector_Correlation_{safe}.md"
                with open(md, "w", encoding="utf-8") as f:
                    f.write(result)
                self.log(f"Saved: {md}", "success")

            else:
                self.log("AI failed - saving prompt", "warning")
                fname = f"Attack_Vectors_Prompt_{self.domain.replace('.', '_')}.txt"
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write(prompt)
                self.log(f"Saved: {fname}", "success")
                print(f"\n{Fore.YELLOW}Use this prompt manually at: https://gemini.google.com{Style.RESET_ALL}\n")
        else:
            fname = f"Attack_Vectors_Prompt_{self.domain.replace('.', '_')}.txt"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(prompt)
            self.log(f"Saved: {fname}", "success")

    def call_gemini(self, prompt, max_tokens=65536):
        """Call Gemini AI — delegates to gemini_config for key rotation"""
        if not self.use_gemini:
            return None
        self.log(f"Calling Gemini ({GEMINI_MODEL})...", "info")
        result = _gemini_call(prompt, max_tokens=max_tokens)
        if result:
            self.log(f"Gemini response received", "success")
        else:
            self.log("Gemini call failed", "error")
        return result

    def executive_summary(self):
        self.header("EXECUTIVE SUMMARY")
        
        total_issues = len(self.cve_results) + len(self.security_issues)
        
        if total_issues == 0:
            print(f"{Fore.GREEN}No vulnerabilities found!{Style.RESET_ALL}")
            return
        
        critical = len([v for v in self.cve_results if v['cvss'] >= 9])
        high = len([v for v in self.cve_results if 7 <= v['cvss'] < 9])
        medium = len([v for v in self.cve_results if 4 <= v['cvss'] < 7])
        
        sec_critical = len([s for s in self.security_issues if s['severity'] == 'CRITICAL'])
        sec_high = len([s for s in self.security_issues if s['severity'] == 'HIGH'])
        sec_medium = len([s for s in self.security_issues if s['severity'] == 'MEDIUM'])
        
        threat_level = 'CRITICAL' if (critical > 0 or sec_critical > 0) else ('HIGH' if (high > 0 or sec_high > 0) else 'MEDIUM')
        
        print(f"\n{Fore.RED}{Style.BRIGHT}THREAT LEVEL: {threat_level}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Domain: {Fore.WHITE}{self.domain}")
        print(f"{Fore.CYAN}Industry: {Fore.WHITE}{self.threat_intel.get('sector', 'Unknown').upper()}")
        print(f"{Fore.CYAN}Technologies Analyzed: {Fore.WHITE}{len(self.technologies)}")
        
        print(f"\n{Fore.YELLOW}CVE/CWE VULNERABILITIES:{Style.RESET_ALL}")
        print(f"  {Fore.RED}Critical (9.0+): {critical}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High (7.0-8.9): {high}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Medium (4.0-6.9): {medium}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total: {len(self.cve_results)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}SECURITY CONFIGURATION ISSUES:{Style.RESET_ALL}")
        print(f"  {Fore.RED}Critical: {sec_critical}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High: {sec_high}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Medium: {sec_medium}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total: {len(self.security_issues)}{Style.RESET_ALL}")

        # Break down by issue type for actionable summary
        type_groups = {}
        for s in self.security_issues:
            t = s.get('type', 'Unknown')
            type_groups[t] = type_groups.get(t, 0) + 1

        # Highlight CRITICAL types first
        critical_types = ['Exposed Client-Side Secret', 'Exposed Database Connection String',
                          'Data Breach - Email Compromised', 'Dark Web Exposure - IntelligenceX',
                          'Cloud Storage Exposure - S3 Bucket', 'Known Vulnerability (InternetDB)']
        high_types = ['SSL Certificate Issue', 'Missing SPF Record', 'Missing DMARC Record',
                      'IP Reputation / Blacklist', 'Exposed Administrative Interface',
                      'APT Threat Association', 'Threat Intelligence Alert']

        print(f"\n{Fore.RED}{Style.BRIGHT}ISSUE BREAKDOWN BY TYPE:{Style.RESET_ALL}")
        for issue_type, count in sorted(type_groups.items(), key=lambda x: x[1], reverse=True):
            if issue_type in critical_types:
                color = Fore.RED
            elif issue_type in high_types:
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
            print(f"  {color}• {issue_type}: {count}{Style.RESET_ALL}")

        print(f"\n{Fore.RED}{Style.BRIGHT}TOP 10 CRITICAL RISKS:{Style.RESET_ALL}")
        
        all_risks = []
        for v in self.cve_results:
            all_risks.append({
                'type': 'CVE/CWE',
                'id': v['cve'],
                'tech': f"{v['tech']} {v.get('version', '')}",
                'cvss': v['cvss'],
                'severity': v['severity'],
                'desc': v['desc'],
                'github': v.get('github_pocs', 0),
                'exploitdb': v.get('exploitdb', 0),
                'metasploit': v.get('metasploit', 0),
                'source': v.get('source', 'NVD/CIRCL')
            })
        
        for s in self.security_issues:
            severity_scores = {'CRITICAL': 10.0, 'HIGH': 8.0, 'MEDIUM': 5.0, 'LOW': 2.0}
            all_risks.append({
                'type': 'CONFIG',
                'id': s['type'],
                'tech': s.get('header', s.get('cookie', 'Unknown')),
                'cvss': severity_scores.get(s['severity'], 5.0),
                'severity': s['severity'],
                'desc': s.get('description', ', '.join(s.get('issues', []))),
                'github': 'N/A',
                'exploitdb': 'N/A',
                'metasploit': 'N/A',
                'source': 'Phase 2/3'
            })
        
        all_risks.sort(key=lambda x: x['cvss'], reverse=True)
        
        for idx, risk in enumerate(all_risks[:10], 1):
            print(f"\n{idx}. {Fore.YELLOW}[{risk['type']}] {risk['id']}{Style.RESET_ALL}")
            print(f"   Technology: {risk['tech']}")
            print(f"   CVSS: {Fore.RED}{risk['cvss']}{Style.RESET_ALL} ({risk['severity']})")
            print(f"   Source: {risk['source']}")
            
            if risk['type'] == 'CVE/CWE':
                print(f"   Description: {risk['desc'][:300]}...")
                if risk['github'] != 'N/A':
                    print(f"   Exploits: GitHub={risk['github']}, ExploitDB={risk['exploitdb']}, MSF={risk['metasploit']}")
            else:
                print(f"   Issue: {risk['desc']}")

    def save_report(self):
        os.makedirs("reports", exist_ok=True)
        fname = os.path.join("reports", f"Phase4_Report_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        # Enhancement 5: Build remediation priority list (top 20 items, sorted by composite score)
        # Uses module-level FIX_MAP (shared with run_correlation Streamlit mode)
        severity_scores = {'CRITICAL': 10.0, 'HIGH': 8.0, 'MEDIUM': 5.0, 'LOW': 2.0}
        remediation_list = []

        for v in self.cve_results:
            has_exploit = v.get('github_pocs', 0) > 0 or v.get('exploitdb', 0) > 0 or v.get('metasploit', 0) > 0
            remediation_list.append({
                'type': 'CVE/CWE',
                'id': v['cve'],
                'affected': f"{v['tech']} {v.get('version', '')}".strip(),
                'score': v.get('composite_score', v.get('cvss', 0)),
                'severity': v['severity'],
                'fix_action': f"Patch/upgrade {v['tech']} to a version that addresses {v['cve']}",
                'has_public_exploit': has_exploit,
                'exploit_note': f"GitHub={v.get('github_pocs',0)}, ExploitDB={v.get('exploitdb',0)}, Metasploit={v.get('metasploit',0)}" if has_exploit else "No public exploit found"
            })

        for s in self.security_issues:
            issue_type = s.get('type', '')
            fix_fn = FIX_MAP.get(issue_type)
            fix = fix_fn(s) if fix_fn else f"Remediate: {issue_type}"
            remediation_list.append({
                'type': 'Security Issue',
                'id': issue_type,
                'affected': s.get('header', s.get('cookie', 'Unknown')),
                'score': severity_scores.get(s.get('severity', 'MEDIUM'), 5.0),
                'severity': s.get('severity', 'MEDIUM'),
                'fix_action': fix,
                'has_public_exploit': False,
                'exploit_note': 'N/A'
            })

        remediation_list.sort(key=lambda x: (x['score'], x['has_public_exploit']), reverse=True)
        for i, item in enumerate(remediation_list[:20], 1):
            item['priority'] = i

        report = {
            'metadata': {
                'domain': self.domain,
                'scan_date': datetime.now().isoformat(),
                'phase': 4,
                'ai_enabled': self.use_gemini
            },
            'technologies': self.technologies,
            'security_issues': self.security_issues,
            'vulnerabilities': self.cve_results,
            'threat_intelligence': self.threat_intel,
            'attack_vectors': self.attack_vectors,
            'remediation_priority': remediation_list[:20],
            'summary': {
                'total_technologies': len(self.technologies),
                'total_cves': len(self.cve_results),
                'total_security_issues': len(self.security_issues),
                'critical_cves': len([v for v in self.cve_results if v.get('cvss', 0) >= 9]),
                'high_cves': len([v for v in self.cve_results if 7 <= v.get('cvss', 0) < 9]),
                'critical_security': len([s for s in self.security_issues if s.get('severity') == 'CRITICAL']),
                'high_security': len([s for s in self.security_issues if s.get('severity') == 'HIGH'])
            }
        }
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        self.log(f"Report saved: {fname}", "success")
        return fname

    def run_correlation(self, phase1_path: str, phase2_path: str, phase3_path: str):
        """
        Headless runner used by the website (Streamlit). Returns a dict with everything the UI needs.
        No prints; no 'AI-Generated' labels; full descriptions; no exploit counters.
        """

        # quiet logs for web
        def _quiet(msg, level="info"):
            pass
        self.log = _quiet

        # Load phases — Phase 1 and Phase 2 are optional, Phase 3 is required
        try:
            if phase1_path and os.path.exists(phase1_path):
                self.load_phase1(phase1_path)  # optional — continue even if fails

            if phase2_path and os.path.exists(phase2_path):
                self.load_phase2(phase2_path)  # optional — continue even if fails

            if not self.load_phase3(phase3_path):
                return {"error": "Failed to load Phase 3 (required)"}
        except Exception as e:
            return {"error": f"Phase loading error: {e}"}

        # Merge infra -> posture before stack extraction (VERY IMPORTANT)
        self.merge_phase2_technologies()
        self.merge_phase2_security_issues(self.phase2_data or {})

        # Build tech stack & posture
        self.extract_tech_stack()

        # Correlate CVEs
        self.correlate_cves()

        # Threat intel & Attack vectors (may return long text; we return raw)
        self.ai_apt_threat_mapping()
        self.ai_attack_vector_correlation()

        # Build payload for UI
        # 1) CVE/CWE mappings (AI + NVD/CIRCL), NO 'source' label, full desc
        cves = []
        for v in self.cve_results:
            cves.append({
                "cve": v.get("cve"),
                "tech": v.get("tech"),
                "version": v.get("version", ""),
                "cvss": v.get("cvss"),
                "severity": v.get("severity"),
                "vector": v.get("vector", ""),
                "cwe": v.get("cwe", ""),
                "published": v.get("published", ""),
                "description": v.get("desc", ""),  # full
            })

        # 2) Technology-only CVEs (optional; handy if you want to show a separate list)
        tech_cves = [
            x for x in cves
            if x.get("tech") not in ("Missing Security Header", "Insecure Cookie Configuration")
            and not (
                x.get("tech","").startswith("Exposed ")
                or x.get("tech") in ("Weak TLS Protocols", "IP Reputation / Blacklist")
            )
        ]

        # 3) Phase 1 summary for UI display
        p1 = self.phase1_data or {}
        ai_overview = p1.get("ai_analysis", {}).get("company_overview", {})
        ai_analysis_full = p1.get("ai_analysis", {})
        phase1_summary = {
            "industry":      ai_overview.get("industry_vertical", self.threat_intel.get("sector", "Unknown")),
            "company_size":  ai_overview.get("company_size", ""),
            "critical_data": ai_overview.get("critical_data", []),
            # Try all known keys Phase 1 may use for compliance
            "compliance": (ai_overview.get("regulatory_compliance")
                           or ai_overview.get("compliance_requirements")
                           or ai_analysis_full.get("regulatory_compliance", {}).get("frameworks", [])
                           or ai_overview.get("compliance", [])),
        }

        # 4) Security issues broken down by category
        issues_by_category = {
            "critical": [s for s in self.security_issues if s.get("severity") == "CRITICAL"],
            "high":     [s for s in self.security_issues if s.get("severity") == "HIGH"],
            "medium":   [s for s in self.security_issues if s.get("severity") == "MEDIUM"],
            "threat_intel": [s for s in self.security_issues if s.get("source") in ("MetaDefender", "AbuseIPDB", "AlienVault OTX", "GreyNoise", "Project Honey Pot")],
            "leaks":    [s for s in self.security_issues if s.get("source") in ("Citadel", "LeakIX", "PasteBin", "IntelligenceX", "GrayHatWarfare")],
        }

        # 5) Build remediation priority for UI (top 15)
        severity_scores = {'CRITICAL': 10.0, 'HIGH': 8.0, 'MEDIUM': 5.0, 'LOW': 2.0}
        remediation_ui = []
        for v in self.cve_results:
            remediation_ui.append({
                'priority': None,
                'type': 'CVE/CWE',
                'id': v['cve'],
                'affected': f"{v['tech']} {v.get('version', '')}".strip(),
                'score': v.get('composite_score', v.get('cvss', 0)),
                'severity': v['severity'],
                'fix_action': f"Patch/upgrade {v['tech']} to a version that addresses {v['cve']}",
                'has_public_exploit': v.get('github_pocs', 0) > 0 or v.get('exploitdb', 0) > 0 or v.get('metasploit', 0) > 0,
            })
        for s in self.security_issues:
            issue_type = s.get('type', '')
            fix_fn = FIX_MAP.get(issue_type)
            fix_action = fix_fn(s) if fix_fn else f"Remediate: {issue_type} — {s.get('description', '')[:100]}"
            remediation_ui.append({
                'priority': None,
                'type': 'Security Issue',
                'id': issue_type,
                'affected': s.get('header', s.get('cookie', 'Unknown')),
                'score': severity_scores.get(s.get('severity', 'MEDIUM'), 5.0),
                'severity': s.get('severity', 'MEDIUM'),
                'fix_action': fix_action,
                'has_public_exploit': False,
            })
        remediation_ui.sort(key=lambda x: (x['score'], x['has_public_exploit']), reverse=True)
        for i, item in enumerate(remediation_ui[:15], 1):
            item['priority'] = i

        # 6) Return full payload for UI
        return {
            "domain": self.domain,
            "phase1_summary": phase1_summary,
            "technologies": self.technologies,
            "security_issues": self.security_issues,
            "issues_by_category": issues_by_category,
            "cves_all": cves,
            "cves_tech_only": tech_cves,
            "apt_mapping_md": self.threat_intel.get("apt_mapping", ""),
            "attack_vectors_md": self.attack_vectors if isinstance(self.attack_vectors, str) else "",
            "remediation_priority": remediation_ui[:15],
            "summary": {
                "total_technologies": len(self.technologies),
                "total_cves": len(self.cve_results),
                "critical_cves": len([v for v in self.cve_results if v.get('cvss', 0) >= 9]),
                "high_cves": len([v for v in self.cve_results if 7 <= v.get('cvss', 0) < 9]),
                "critical_issues": len(issues_by_category["critical"]),
                "high_issues": len(issues_by_category["high"]),
            }
        }


def main():
    print(f"""\n{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║       PHASE 4: REAL-TIME + AI-POWERED THREAT & VULNERABILITY MAPPING       ║
║                                                                            ║
║       • Real-Time CVE Data (NVD, CIRCL, GitHub, Exploit-DB)               ║
║       • AI-Powered CVE Discovery for Security Misconfigurations           ║
║       • AI-Powered APT Threat Mapping (Gemini)                            ║
║       • AI-Powered Attack Vector Correlation with MITRE ATT&CK            ║
║       • NO Rule-Based Fallbacks - Pure Real-Time + AI                     ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n""")
    
    scanner = AIPhase4Scanner()

    def _latest_report(pattern):
        """Return path of the newest file in reports/ matching glob pattern, or None."""
        import glob as _glob
        files = _glob.glob(os.path.join("reports", pattern))
        return max(files, key=os.path.getmtime) if files else None

    # ── Phase 1 (optional — business context) ─────────────────────────────────
    auto1 = _latest_report("*phase1_domain*.json")
    print(f"{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗\n║                    Phase 1 File Input (Business Domain)        ║\n╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    if auto1:
        print(f"{Fore.CYAN}  Auto-detected: {auto1}{Style.RESET_ALL}")
    phase1_path = input(f"{Fore.GREEN}Enter Phase 1 JSON path (Enter to {'use above' if auto1 else 'skip'}): {Style.RESET_ALL}").strip()
    phase1_path = phase1_path or auto1
    if phase1_path:
        scanner.load_phase1(phase1_path)

    # ── Phase 2 (optional — infrastructure) ───────────────────────────────────
    auto2 = _latest_report("*phase2_infra*.json")
    print(f"{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗\n║                    Phase 2 File Input (Infrastructure)         ║\n╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    if auto2:
        print(f"{Fore.CYAN}  Auto-detected: {auto2}{Style.RESET_ALL}")
    phase2_path = input(f"{Fore.GREEN}Enter Phase 2 JSON path (Enter to {'use above' if auto2 else 'skip'}): {Style.RESET_ALL}").strip()
    phase2_path = phase2_path or auto2
    if phase2_path:
        scanner.load_phase2(phase2_path)

    # ── Phase 3 (required — web technology) ───────────────────────────────────
    auto3 = _latest_report("BSI_Phase3_Application_*.json")
    print(f"{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗\n║                    Phase 3 File Input (Web Technology)         ║\n╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    if auto3:
        print(f"{Fore.CYAN}  Auto-detected: {auto3}{Style.RESET_ALL}")
    filepath = input(f"{Fore.GREEN}Enter Phase 3 JSON path (Enter to {'use above' if auto3 else 'skip'}): {Style.RESET_ALL}").strip()
    filepath = filepath or auto3
    if not filepath:
        print(f"\n{Fore.RED}✗ No Phase 3 file found or provided. Exiting.{Style.RESET_ALL}")
        return

    print()
    if not scanner.load_phase3(filepath):
        return

    # Fold Phase 2 into analysis BEFORE extracting Phase 3 tech stack and CVEs
    scanner.merge_phase2_technologies()
    scanner.merge_phase2_security_issues(scanner.phase2_data)

    print(f"\n{Fore.GREEN}{'='*70}\nAll phases loaded!\nStarting Phase 4 analysis for: {scanner.domain}\n{'='*70}{Style.RESET_ALL}\n")
    input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

    scanner.extract_tech_stack()
    if not scanner.technologies:
        print(f"\n{Fore.YELLOW}⚠ No versioned technologies found — CVE search will be skipped, continuing with security issue analysis...{Style.RESET_ALL}")

    input(f"\n{Fore.YELLOW}Press Enter to start CVE correlation...{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}This may take several minutes depending on results...{Style.RESET_ALL}\n")
    time.sleep(2)
    
    scanner.correlate_cves()
    
    if not scanner.cve_results:
        print(f"\n{Fore.YELLOW}⚠ No CVEs found{Style.RESET_ALL}")

    input(f"\n{Fore.YELLOW}Press Enter to start threat intelligence...{Style.RESET_ALL}")
    scanner.ai_apt_threat_mapping()
    
    input(f"\n{Fore.YELLOW}Press Enter to start attack vector correlation...{Style.RESET_ALL}")
    scanner.ai_attack_vector_correlation()
    
    input(f"\n{Fore.YELLOW}Press Enter to view executive summary...{Style.RESET_ALL}")
    scanner.executive_summary()
    
    print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
    scanner.save_report()
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}✓ Phase 4 Complete!{Style.RESET_ALL}\n")
    
    # Final message about saved prompts
    if not scanner.use_gemini or (not scanner.threat_intel.get('apt_mapping') and not scanner.attack_vectors):
        print(f"{Fore.YELLOW}{'='*100}")
        print(f"NOTE: AI analysis prompts have been saved to text files.")
        print(f"You can copy these prompts to https://gemini.google.com")
        print(f"if AI safety filters blocked automated processing.")
        print(f"{'='*100}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}✗ Scan interrupted by user{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}✗ Fatal error: {e}{Style.RESET_ALL}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
