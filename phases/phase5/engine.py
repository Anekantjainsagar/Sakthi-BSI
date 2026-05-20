#!/usr/bin/env python3
"""
Phase 5: Risk Assessment and Categorization
Uses AI to analyze correlation data and generate risk matrices
"""

import json
import os
import re
from typing import Dict, Any, List
from datetime import datetime

from config.gemini_config import call_gemini as _gemini_call, GEMINI_MODEL, GEMINI_API_KEYS

# Fallback to Ollama
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class RiskAssessmentEngine:
    """
    AI-powered risk assessment engine that processes correlation data
    and generates comprehensive risk categorization
    """

    def __init__(self):
        # Keys and model from gemini_config — no hardcoded keys here
        self.use_gemini = len(GEMINI_API_KEYS) > 0
        self.use_ollama = False

        if self.use_gemini:
            print(f"✅ Gemini AI initialized ({GEMINI_MODEL}, {len(GEMINI_API_KEYS)} keys)")
        elif OLLAMA_AVAILABLE:
            self.use_ollama = True
            print("✅ Using Ollama as fallback")
        else:
            print("⚠️ No AI available - using basic analysis")

        self.risk_assessment = {}

    def analyze_with_ai(self, prompt: str, max_tokens: int = 4096) -> str:
        """Call AI — delegates to gemini_config for key rotation"""
        if self.use_gemini:
            result = _gemini_call(prompt, max_tokens=max_tokens)
            if result:
                return result

        if self.use_ollama:
            try:
                response = ollama.chat(
                    model='qwen2.5:3b',
                    messages=[{'role': 'user', 'content': prompt}]
                )
                return response['message']['content']
            except Exception as e:
                print(f"⚠️ Ollama error: {e}")

        # Basic fallback
        return '{"risk_level":"Medium","score":5.0,"categories":["Operational Risk"],"analysis":"Automated assessment — AI unavailable."}'

    # ── FIX Gap 5: reliable JSON-based risk level extraction ────────────────
    def _parse_ai_json(self, raw: str) -> dict:
        """Strip markdown fences and parse JSON from AI response"""
        text = raw.strip()
        # Strip markdown fences
        if '```json' in text:
            text = text.split('```json')[1].split('```')[0].strip()
        elif '```' in text:
            text = text.split('```')[1].split('```')[0].strip()
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try extracting first JSON object from text (handles extra text around JSON)
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        return {}

    def _extract_risk_level(self, data: dict, fallback_text: str = '') -> str:
        """Extract risk level from parsed JSON dict, fallback to text search"""
        # Prefer explicit JSON field
        level = str(data.get('risk_level', '')).strip()
        if level in ('Critical', 'High', 'Medium', 'Low'):
            return level
        # Fallback: look for explicit pattern in text
        match = re.search(r'risk[_\s]?level["\s:]+([Cc]ritical|[Hh]igh|[Mm]edium|[Ll]ow)', fallback_text)
        if match:
            return match.group(1).capitalize()
        return 'Medium'

    def _extract_score(self, data: dict, fallback_text: str = '') -> float:
        """Extract numerical score from JSON dict"""
        try:
            val = data.get('score') or data.get('impact_score') or data.get('vulnerability_density')
            if val is not None:
                return float(val)
            # Fallback regex: match "score": 9.2 or 9.2/10
            match = re.search(r'"score"\s*:\s*(\d+\.?\d*)', fallback_text)
            if match:
                return float(match.group(1))
            match = re.search(r'(\d+\.?\d*)\s*/\s*10', fallback_text)
            if match:
                return float(match.group(1))
        except Exception:
            pass
        return 5.0

    # ── Phase 5.1 ───────────────────────────────────────────────────────────
    def assess_business_risk(self, correlation_data: dict, domain_data: dict) -> dict:
        """Business Risk Categorization — FIX Gap 1: sends real CVE + Phase 1 data"""
        print("\n[Phase 5.1] Assessing Business Risk...")

        if not domain_data or isinstance(domain_data, dict) and 'error' in domain_data:
            domain_data = {}
        if not correlation_data:
            correlation_data = {}

        # ── Extract real Phase 1 fields ──
        ai_analysis    = domain_data.get('ai_analysis', {}) if isinstance(domain_data, dict) else {}
        overview       = ai_analysis.get('company_overview', {}) if isinstance(ai_analysis, dict) else {}
        industry       = overview.get('industry_vertical', 'Unknown')
        business_model = overview.get('business_model', 'Unknown')
        company_size   = overview.get('company_size', 'Unknown')
        revenue        = overview.get('revenue', 'Unknown')
        critical_data  = overview.get('critical_data', [])
        # Phase 1 stores compliance under 'regulatory_compliance' — fall back through all known keys
        compliance     = (overview.get('regulatory_compliance')
                          or overview.get('compliance_requirements')
                          or ai_analysis.get('regulatory_compliance', {}).get('frameworks', [])
                          or overview.get('compliance', []))
        attack_surface = ai_analysis.get('attack_surface', {})

        critical_data_str = ', '.join(critical_data) if isinstance(critical_data, list) else str(critical_data)
        compliance_str    = ', '.join(compliance)    if isinstance(compliance, list)    else str(compliance)

        # ── Extract real CVEs ──
        cves_all = correlation_data.get('cves_all', [])
        if not isinstance(cves_all, list):
            cves_all = []

        critical_cves = [c for c in cves_all if isinstance(c, dict) and c.get('cvss', 0) >= 9.0]
        high_cves     = [c for c in cves_all if isinstance(c, dict) and 7.0 <= c.get('cvss', 0) < 9.0]

        top_cves_text = "\n".join([
            f"  - {c.get('cve','?')}: {c.get('tech','')} {c.get('version','')} | CVSS={c.get('cvss',0)} | {c.get('description','')[:120]}"
            for c in (critical_cves + high_cves)[:10]
        ]) or "  None found"

        # ── Real security issues ──
        security_issues = correlation_data.get('security_issues', [])
        if not isinstance(security_issues, list):
            security_issues = []

        issue_text = "\n".join([
            f"  - [{s.get('severity','?')}] {s.get('type','')}: {s.get('header', s.get('cookie',''))}"
            for s in security_issues[:10]
        ]) or "  None found"

        print(f"   Industry: {industry} | Size: {company_size} | CVEs: {len(cves_all)} ({len(critical_cves)} critical)")

        prompt = f"""You are a senior business risk analyst writing a board-level security risk assessment for a real client.

TARGET COMPANY PROFILE:
- Industry: {industry}
- Business Model: {business_model}
- Company Size: {company_size}
- Revenue Estimate: {revenue}
- Critical Data Assets: {critical_data_str}
- Regulatory Obligations: {compliance_str}
- Attack Surface: {str(attack_surface)[:300]}

CONFIRMED SECURITY VULNERABILITIES:
Critical/High CVEs ({len(critical_cves)} critical, {len(high_cves)} high):
{top_cves_text}

Security Misconfigurations ({len(security_issues)} issues):
{issue_text}

Write a professional, specific risk assessment for THIS company. Do NOT use generic language like "the organization faces risks".
Reference the actual industry, actual CVEs found, and actual compliance obligations.
Consider: What data does this company hold? What happens if it is breached? What regulations apply and what are the fines?

Provide:
1. Business Risk Level (Critical / High / Medium / Low)
2. Business Impact Score (1.0–10.0) — based on industry sensitivity and CVE severity
3. Top 4 risk categories SPECIFIC to this company's industry and data (name them precisely)
4. Detailed analysis (4–6 sentences) — write as if briefing the CEO: what is at risk, why it matters to this specific business, what the regulatory exposure is, and what the financial consequences could be

Return ONLY this JSON (no markdown fences):
{{
  "risk_level": "High",
  "score": 7.5,
  "categories": ["Chemical Formula IP Theft", "Supply Chain Partner Data Breach", "GDPR Non-Compliance Penalty", "Operational Disruption via Ransomware"],
  "analysis": "Your detailed CEO-level briefing here..."
}}"""

        raw = self.analyze_with_ai(prompt, max_tokens=4096)
        data = self._parse_ai_json(raw)

        return {
            "risk_level":            self._extract_risk_level(data, raw),
            "business_impact_score": self._extract_score(data, raw),
            "categories":            data.get('categories', ['Financial', 'Reputational', 'Operational', 'Compliance']),
            "analysis":              data.get('analysis', raw),
        }

    # ── Phase 5.2 ───────────────────────────────────────────────────────────
    def assess_infrastructure_risk(self, infra_data: dict, correlation_data: dict) -> dict:
        """Infrastructure Risk Assessment — FIX Gap 1: sends actual misconfigs & ports"""
        print("\n[Phase 5.2] Assessing Infrastructure Risk...")

        if not infra_data or isinstance(infra_data, dict) and 'error' in infra_data:
            infra_data = {}
        if not correlation_data:
            correlation_data = {}

        # ── Real infra metrics ──
        subdomains    = len(infra_data.get('subdomains', []))
        open_ports_d  = infra_data.get('open_ports', {})
        open_ports    = sum(len(p) for p in open_ports_d.values() if isinstance(p, list)) if isinstance(open_ports_d, dict) else 0
        mail_analysis = infra_data.get('mail_server_analysis', {}) or {}
        ssl_analysis  = infra_data.get('ssl_analysis', {}) or {}

        # Dangerous open ports with IPs
        DANGEROUS = {22: 'SSH', 23: 'Telnet', 3306: 'MySQL', 5432: 'PostgreSQL',
                     1433: 'MSSQL', 3389: 'RDP', 5900: 'VNC', 25: 'SMTP'}
        dangerous_found = []
        for ip, ports in (open_ports_d.items() if isinstance(open_ports_d, dict) else []):
            for p in (ports if isinstance(ports, list) else []):
                if p in DANGEROUS:
                    dangerous_found.append(f"{ip}:{p} ({DANGEROUS[p]})")

        # Blacklisted IPs
        blacklisted = infra_data.get('blacklisted_ips', [])
        bl_text = "\n".join([
            f"  - {b.get('ip','?')} listed on: {', '.join(b.get('blacklists',[]))}"
            for b in blacklisted[:5]
        ]) or "  None"

        # Misconfigurations
        misconfigs = infra_data.get('misconfigurations', [])
        mc_text = "\n".join([
            f"  - [{m.get('severity','?')}] {m.get('type','')}: {m.get('target','')}"
            for m in misconfigs[:10]
        ]) or "  None"

        # Mail / TLS
        spf   = "Present" if mail_analysis.get('spf_record')   else "MISSING"
        dmarc = "Present" if mail_analysis.get('dmarc_record') else "MISSING"
        tls   = ssl_analysis.get('tls_version', 'Unknown')

        # Security issues from Phase 4
        sec_issues = correlation_data.get('security_issues', [])
        infra_issues = [s for s in sec_issues if isinstance(s, dict) and
                        any(x in s.get('type','') for x in ['Exposed', 'TLS', 'Blacklist', 'SPF', 'DMARC', 'DKIM', 'typosquat'])]
        infra_issue_text = "\n".join([
            f"  - [{s.get('severity','?')}] {s.get('type','')}: {s.get('header','')}"
            for s in infra_issues[:10]
        ]) or "  None"

        print(f"   Subdomains: {subdomains} | Open Ports: {open_ports} | Dangerous Ports: {len(dangerous_found)} | Blacklisted IPs: {len(blacklisted)}")

        prompt = f"""You are a senior infrastructure security analyst writing a technical risk narrative for a penetration test report.

LIVE INFRASTRUCTURE SCAN RESULTS:
- Subdomains Discovered: {subdomains} (each subdomain = additional attack surface)
- Total Open Ports: {open_ports}
- Dangerous Exposed Services: {', '.join(dangerous_found) if dangerous_found else 'None'}
- Blacklisted IPs (threat intel hits):
{bl_text}
- Email Security: SPF={spf} | DMARC={dmarc} | TLS={tls}
- Misconfigurations:
{mc_text}
- Correlated Threat Intelligence Issues:
{infra_issue_text}

Write a sharp, technical risk narrative. Reference SPECIFIC ports, IPs, and services found.
Explain exactly HOW each exposure can be exploited — not just that it "poses a risk".
If blacklisted IPs exist, explain what that means (prior compromise, C2 beacon, spam origin).
If dangerous ports are open, name the attack type (brute force, remote code execution, data exfiltration).

Provide:
1. Infrastructure Risk Level (Critical / High / Medium / Low)
2. Attack Surface Score (1.0–10.0)
3. Top 4 risk areas — each must reference a SPECIFIC finding (port number, IP, or service name)
4. Technical analysis (4–5 sentences) — explain the exploit chain an attacker would use given these exact findings

Return ONLY JSON:
{{
  "risk_level": "High",
  "score": 7.0,
  "risk_areas": ["MySQL 3306 on 185.x.x.x exposed — direct database dump without credentials", "Blacklisted IP 195.x.x.x suggests active C2 or prior ransomware infection", "Missing DMARC on primary domain enables CEO phishing campaigns", "23 subdomains expand attack surface with legacy/forgotten services"],
  "analysis": "Your technical exploit-chain narrative here..."
}}"""

        raw = self.analyze_with_ai(prompt, max_tokens=4096)
        data = self._parse_ai_json(raw)

        return {
            "risk_level":       self._extract_risk_level(data, raw),
            "attack_surface_score": self._extract_score(data, raw),
            "risk_areas":       data.get('risk_areas', ['Network Exposure', 'Service Vulnerabilities', 'Configuration', 'Access Control']),
            "analysis":         data.get('analysis', raw),
        }

    # ── Phase 5.3 ───────────────────────────────────────────────────────────
    def assess_application_risk(self, app_data: dict, correlation_data: dict) -> dict:
        """Application Risk Evaluation — FIX Gap 1+3: real tech data, fixed filter"""
        print("\n[Phase 5.3] Assessing Application Risk...")

        if not app_data or isinstance(app_data, dict) and 'error' in app_data:
            app_data = {}
        if not correlation_data:
            correlation_data = {}

        technologies = correlation_data.get('technologies', [])
        if not isinstance(technologies, list):
            technologies = []

        cves_all = correlation_data.get('cves_all', [])
        if not isinstance(cves_all, list):
            cves_all = []

        # FIX Gap 3: use ALL CVEs, categorise by severity — don't filter on 'application' string
        critical_vulns = [v for v in cves_all if isinstance(v, dict) and v.get('cvss', 0) >= 9.0]
        high_vulns     = [v for v in cves_all if isinstance(v, dict) and 7.0 <= v.get('cvss', 0) < 9.0]

        # Tech stack details
        tech_text = "\n".join([
            f"  - {t.get('name','?')} {t.get('version','?')} ({t.get('type','')})"
            for t in technologies[:15]
        ]) or "  None detected"

        # Top CVEs
        top_cves_text = "\n".join([
            f"  - {c.get('cve','?')}: {c.get('tech','')} {c.get('version','')} CVSS={c.get('cvss',0)} — {c.get('description','')[:100]}"
            for c in (critical_vulns + high_vulns)[:10]
        ]) or "  None found"

        # Application-layer posture issues
        sec_issues = correlation_data.get('security_issues', [])
        app_posture = [s for s in sec_issues if isinstance(s, dict) and
                       s.get('type','') in ['Missing Security Header', 'Insecure Cookie Configuration',
                                            'Open Redirect Vulnerability', 'Clickjacking Vulnerability',
                                            'Missing Subresource Integrity (SRI)', 'SSL Certificate Issue',
                                            'Exposed Client-Side Secret', 'Sensitive Path Disclosed (robots.txt)',
                                            'Public Source Code Repository']]
        posture_text = "\n".join([
            f"  - [{s.get('severity','?')}] {s.get('type','')}: {s.get('header', s.get('cookie',''))}"
            for s in app_posture[:10]
        ]) or "  None"

        print(f"   Technologies: {len(technologies)} | Critical CVEs: {len(critical_vulns)} | High CVEs: {len(high_vulns)}")

        prompt = f"""You are an application security analyst.

DETECTED APPLICATION TECHNOLOGY STACK:
{tech_text}

CONFIRMED VULNERABILITIES (CVEs/CWEs mapped to actual tech):
Critical ({len(critical_vulns)}) + High ({len(high_vulns)}):
{top_cves_text}

APPLICATION SECURITY POSTURE GAPS:
{posture_text}

You are writing an application security risk narrative for a penetration test report.
Reference the SPECIFIC technologies found (CMS name, framework versions, libraries).
For each CVE, explain what an attacker can actually DO with it (RCE, data exfil, account takeover, etc.).
Explain how missing headers/insecure cookies create a real exploit path, not just a compliance gap.

Provide:
1. Application Risk Level (Critical / High / Medium / Low)
2. Vulnerability Density Score (1.0–10.0) — higher if critical CVEs exist for detected tech versions
3. Top 4 application risks — each tied to a SPECIFIC technology or CVE found (not generic)
4. Technical analysis (4–5 sentences) — describe the realistic exploit scenario an attacker would execute against this application stack

Return ONLY JSON:
{{
  "risk_level": "High",
  "score": 7.5,
  "risk_categories": ["Drupal 10 RCE via CVE-2024-XXXX allows unauthenticated admin takeover", "jQuery 3.x XSS via missing Content-Security-Policy enables session theft", "Insecure session cookies without HttpOnly allow credential harvesting via XSS", "Public GitHub repo exposes internal API keys and database credentials"],
  "analysis": "Your specific exploit-chain narrative here..."
}}"""

        raw = self.analyze_with_ai(prompt, max_tokens=4096)
        data = self._parse_ai_json(raw)

        return {
            "risk_level":           self._extract_risk_level(data, raw),
            "vulnerability_density": self._extract_score(data, raw),
            "risk_categories":      data.get('risk_categories', ['Web Vulnerabilities', 'Outdated Libraries', 'Insecure Configuration', 'Data Exposure']),
            "analysis":             data.get('analysis', raw),
        }

    # ── Phase 5.4 ───────────────────────────────────────────────────────────
    def correlate_business_impact(self, business_risk: dict, infra_risk: dict,
                                   app_risk: dict, correlation_data: dict) -> dict:
        """Business Impact Correlation — FIX Gap 1: feeds actual analysis text into prompt"""
        print("\n[Phase 5.4] Correlating Business Impact...")

        if not business_risk: business_risk = {'risk_level': 'Unknown', 'analysis': ''}
        if not infra_risk:    infra_risk    = {'risk_level': 'Unknown', 'analysis': ''}
        if not app_risk:      app_risk      = {'risk_level': 'Unknown', 'analysis': ''}
        if not correlation_data: correlation_data = {}

        cves_all = correlation_data.get('cves_all', [])
        if not isinstance(cves_all, list): cves_all = []

        critical_cves = [c for c in cves_all if isinstance(c, dict) and c.get('cvss', 0) >= 9.0]

        # Use actual analysis text from steps 1–3
        biz_analysis  = str(business_risk.get('analysis', ''))[:500]
        infra_analysis = str(infra_risk.get('analysis', ''))[:500]
        app_analysis  = str(app_risk.get('analysis', ''))[:500]

        # Pull in attack scenario context from Phase 4
        attack_vectors = str(correlation_data.get('attack_vectors_md', ''))[:800]
        apt_mapping    = str(correlation_data.get('apt_mapping_md', ''))[:500]

        # Pull company size + revenue from Phase 1 to scale the financial impact estimate
        p1_summary = correlation_data.get('phase1_summary', {}) or {}
        company_size = p1_summary.get('company_size', 'Unknown')
        # Also try to get it from domain_data directly
        if company_size == 'Unknown' and isinstance(correlation_data.get('_domain_data'), dict):
            ai_an = correlation_data['_domain_data'].get('ai_analysis', {})
            company_size = (ai_an.get('company_overview', {}) or {}).get('company_size', 'Unknown')

        # Derive financial scale context based on company size
        if any(k in str(company_size).lower() for k in ['large', 'enterprise', '1000', '5000', '10000']):
            size_context = "Large enterprise (1,000+ employees) — financial exposure in millions; regulatory fines proportional to revenue scale"
        elif any(k in str(company_size).lower() for k in ['medium', '500', '200', '100']):
            size_context = "Mid-size company (100–999 employees) — financial exposure typically $500K–$5M range"
        elif any(k in str(company_size).lower() for k in ['small', 'startup', '50', '10', '20']):
            size_context = "Small company (<100 employees) — financial exposure typically $50K–$500K; existential risk from major breach"
        else:
            size_context = f"Company size: {company_size} — calibrate financial exposure accordingly"

        prompt = f"""You are a CISO writing the business impact section of a board-level security incident report.
You are correlating confirmed technical vulnerabilities with real-world financial and operational consequences.

TECHNICAL RISK SUMMARY:
Business Risk ({business_risk.get('risk_level','?')}): {biz_analysis}

Infrastructure Risk ({infra_risk.get('risk_level','?')}): {infra_analysis}

Application Risk ({app_risk.get('risk_level','?')}): {app_analysis}

CONFIRMED ATTACK VECTORS (Phase 4):
{attack_vectors if attack_vectors else 'Not available'}

THREAT ACTOR CONTEXT:
{apt_mapping if apt_mapping else 'Not available'}

CRITICAL CVEs CONFIRMED: {len(critical_cves)} vulnerabilities with CVSS ≥ 9.0

COMPANY SCALE (scale financial estimates accordingly):
{size_context}

Using the confirmed technical findings above, calculate real business consequences.
- Financial range: scale to the company size above; consider breach response costs, regulatory fines (GDPR up to 4% annual revenue, PCI-DSS up to $500K/month), ransom demands, legal liability
- Recovery time: based on the type of compromise possible (ransomware = weeks, data exfil = months of legal process)
- Be SPECIFIC to the industry and data types at risk, not generic

Provide:
1. Overall Business Impact Level (Critical / High / Medium / Low)
2. Realistic financial impact range with reasoning (include regulatory fine estimates if applicable)
3. Realistic recovery time with explanation
4. Impact rating across 5 dimensions
5. Analysis (4–5 sentences) — connect the specific CVEs and misconfigs to real business consequences for this company

Return ONLY JSON:
{{
  "overall_impact": "High",
  "financial_range": "$250K–$2.5M (includes GDPR fine up to 4% revenue + breach response + legal)",
  "recovery_time": "4–8 weeks (ransomware scenario) to 6+ months (regulatory investigation)",
  "impact_dimensions": {{
    "financial": "High",
    "operational": "Medium",
    "data_breach": "High",
    "customer_trust": "High",
    "regulatory": "High"
  }},
  "analysis": "Your board-level impact narrative here..."
}}"""

        raw = self.analyze_with_ai(prompt, max_tokens=4096)
        data = self._parse_ai_json(raw)

        # Regex fallbacks for truncated JSON responses
        def _extract_field(text, key, default=''):
            m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', text)
            return m.group(1) if m else default

        overall = (data.get('overall_impact')
                   or _extract_field(raw, 'overall_impact')
                   or self._extract_risk_level(data, raw))
        financial = data.get('financial_range') or _extract_field(raw, 'financial_range') or 'Not estimated'
        recovery  = data.get('recovery_time')   or _extract_field(raw, 'recovery_time')   or 'Not estimated'

        dims = data.get('impact_dimensions', {})
        if not dims:
            dims = {
                "financial":      _extract_field(raw, 'financial')      or 'Medium',
                "operational":    _extract_field(raw, 'operational')    or 'Medium',
                "data_breach":    _extract_field(raw, 'data_breach')    or 'Medium',
                "customer_trust": _extract_field(raw, 'customer_trust') or 'Medium',
                "regulatory":     _extract_field(raw, 'regulatory')     or 'Medium',
            }

        # If analysis field itself contains nested JSON or markdown fences, extract narrative from it
        analysis = data.get('analysis', '')
        if not analysis or '```' in str(analysis) or str(analysis).strip().startswith('{'):
            nested = self._parse_ai_json(str(analysis)) if analysis else {}
            analysis = nested.get('analysis', '') if nested else ''
        if not analysis:
            # Last resort: use raw but strip JSON wrapper if possible
            nested = self._parse_ai_json(raw)
            analysis = nested.get('analysis', raw) if nested else raw

        return {
            "overall_impact":    overall,
            "financial_range":   financial,
            "recovery_time":     recovery,
            "impact_dimensions": dims,
            "scenarios":         data.get('scenarios', []),
            "analysis":          analysis,
        }

    # ── Phase 5.5 ───────────────────────────────────────────────────────────
    def generate_risk_matrix(self, business_risk: dict, infra_risk: dict,
                             app_risk: dict, business_impact: dict) -> dict:
        """Risk Matrix Generation"""
        print("\n[Phase 5.5] Generating Risk Matrix...")

        risk_score_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 2}

        try:
            business_score = risk_score_map.get(business_risk.get('risk_level', 'Unknown'), 2)
            infra_score    = risk_score_map.get(infra_risk.get('risk_level', 'Unknown'), 2)
            app_score      = risk_score_map.get(app_risk.get('risk_level', 'Unknown'), 2)
            impact_score   = risk_score_map.get(business_impact.get('overall_impact', 'Unknown'), 2)
        except Exception:
            business_score = infra_score = app_score = impact_score = 2

        composite_score = (business_score * 0.30 + infra_score * 0.25 +
                           app_score * 0.25 + impact_score * 0.20)

        composite_level = self._score_to_level(composite_score)
        labels = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}

        # AI interprets what the scores mean together
        interp_prompt = f"""You are a security analyst interpreting a composite risk matrix for a client report.

RISK MATRIX SCORES (1=Low, 2=Medium, 3=High, 4=Critical):
- Business Risk:      {business_score}/4  ({labels.get(business_score,'Unknown')})  — weight 30%
- Infrastructure:     {infra_score}/4  ({labels.get(infra_score,'Unknown')})  — weight 25%
- Application:        {app_score}/4  ({labels.get(app_score,'Unknown')})  — weight 25%
- Business Impact:    {impact_score}/4  ({labels.get(impact_score,'Unknown')})  — weight 20%
- Composite Score:    {round(composite_score,2)}/4.0  →  Overall: {composite_level}

Write 3–4 sentences interpreting what these scores mean TOGETHER — not individually.
Explain what the pattern of scores reveals about the organization's security posture.
For example: if business and infra are both High but application is Medium, what does that pattern mean?
Be direct and specific. Do not list the scores again — interpret them."""

        try:
            matrix_interpretation = self.analyze_with_ai(interp_prompt, max_tokens=1024)
            if matrix_interpretation and matrix_interpretation.strip().startswith('{'):
                matrix_interpretation = ''
        except Exception:
            matrix_interpretation = ''

        return {
            "composite_risk_score":   round(composite_score, 2),
            "risk_level":             composite_level,
            "interpretation":         matrix_interpretation.strip() if matrix_interpretation else '',
            "dimensions": {
                "business":        {"score": business_score, "level": business_risk.get('risk_level', 'Unknown'), "weight": "30%"},
                "infrastructure":  {"score": infra_score,    "level": infra_risk.get('risk_level', 'Unknown'),    "weight": "25%"},
                "application":     {"score": app_score,      "level": app_risk.get('risk_level', 'Unknown'),      "weight": "25%"},
                "business_impact": {"score": impact_score,   "level": business_impact.get('overall_impact', 'Unknown'), "weight": "20%"},
            },
            "matrix_visualization": self._create_matrix_text(business_score, infra_score, app_score, impact_score),
        }

    # ── Phase 5.6 ───────────────────────────────────────────────────────────
    def calculate_multidimensional_risk_score(self, risk_matrix: dict,
                                              correlation_data: dict) -> dict:
        """Multi-dimensional Risk Scoring"""
        print("\n[Phase 5.6] Calculating Multi-dimensional Risk Score...")

        if not correlation_data: correlation_data = {}
        if not risk_matrix:      risk_matrix = {'dimensions': {'business': {'score': 2}}}

        cves = correlation_data.get('cves_all', [])
        if not isinstance(cves, list): cves = []

        try:
            # Normalize asset_criticality from 1-4 scale to 0-10 to match other dimensions
            raw_asset_score = float(risk_matrix.get('dimensions', {}).get('business', {}).get('score', 2))
            normalized_asset = round((raw_asset_score - 1) / 3 * 10, 2)

            dimensions = {
                "technical_severity": self._calc_technical_severity(cves),
                "exploit_likelihood":  self._calc_exploit_likelihood(cves),
                "asset_criticality":   normalized_asset,
                "threat_intelligence": self._calc_threat_score(correlation_data),
                "compliance_impact":   self._calc_compliance_impact(correlation_data),
            }
        except Exception as e:
            print(f"⚠️ Error calculating dimensions: {e}")
            dimensions = {k: 5.0 for k in ("technical_severity","exploit_likelihood","asset_criticality","threat_intelligence","compliance_impact")}

        weights = {
            "technical_severity": 0.25,
            "exploit_likelihood":  0.20,
            "asset_criticality":   0.25,
            "threat_intelligence": 0.15,
            "compliance_impact":   0.15,
        }

        total_score = sum(dimensions[d] * weights[d] for d in dimensions)
        risk_rating = self._score_to_rating(total_score)

        # AI interprets what the 5-dimension pattern means
        interp_prompt = f"""You are a senior security analyst interpreting a multi-dimensional risk score for a client report.

FIVE-DIMENSION RISK SCORES (0–10 scale):
- Technical Severity:   {dimensions['technical_severity']}/10  (average CVSS of all CVEs — how severe are the vulnerabilities?)
- Exploit Likelihood:   {dimensions['exploit_likelihood']}/10  (% of CVEs with CVSS ≥ 7.0 — how exploitable are they?)
- Asset Criticality:    {dimensions['asset_criticality']}/10   (how critical are the business assets at risk?)
- Threat Intelligence:  {dimensions['threat_intelligence']}/10 (threat intel hits — blacklisted IPs, dark web exposure, APT associations)
- Compliance Impact:    {dimensions['compliance_impact']}/10   (regulatory exposure — missing DMARC, weak TLS, exposed secrets)

OVERALL SCORE: {round(total_score,2)}/10.0  →  {risk_rating}

Write 3–4 sentences interpreting what this PATTERN of scores means for the organization.
Focus on the RELATIONSHIP between dimensions — which combination of scores creates the most dangerous situation?
For example: high threat intelligence + high exploit likelihood = attackers are already watching AND vulnerabilities are easy to exploit.
Be direct, specific, and write as if explaining to a CISO. Do not list the scores again — interpret the pattern."""

        try:
            multi_interpretation = self.analyze_with_ai(interp_prompt, max_tokens=2048)
            if multi_interpretation and multi_interpretation.strip().startswith('{'):
                multi_interpretation = ''
        except Exception:
            multi_interpretation = ''

        return {
            "overall_risk_score":  round(total_score, 2),
            "risk_rating":         risk_rating,
            "interpretation":      multi_interpretation.strip() if multi_interpretation else '',
            "dimensions":          dimensions,
            "weights":             weights,
            "score_breakdown":     self._create_score_breakdown(dimensions, weights),
        }

    # ── Helper: score calculations ──────────────────────────────────────────

    def _calc_technical_severity(self, cves: list) -> float:
        """
        Severity ratio using the same formula as the industry benchmark:
        (Critical + High + Medium) / Grand Total × 10 → 0–10 scale
        Aligns multidimensional scoring with the PPT benchmark metric.
        """
        try:
            if not cves: return 0.0
            total    = len(cves)
            critical = len([c for c in cves if isinstance(c, dict) and c.get('cvss', 0) >= 9.0])
            high     = len([c for c in cves if isinstance(c, dict) and 7.0 <= c.get('cvss', 0) < 9.0])
            medium   = len([c for c in cves if isinstance(c, dict) and 4.0 <= c.get('cvss', 0) < 7.0])
            ratio    = ((critical + high + medium) / total) * 10
            return round(min(ratio, 10.0), 2)
        except Exception:
            return 0.0

    def _calc_exploit_likelihood(self, cves: list) -> float:
        """Ratio of high-severity exploitable (CVSS ≥ 7) CVEs → 0–10"""
        try:
            if not cves: return 0.0
            exploitable = len([c for c in cves if isinstance(c, dict) and c.get('cvss', 0) >= 7.0])
            return round(min((exploitable / max(len(cves), 1)) * 10, 10.0), 2)
        except Exception:
            return 0.0

    # FIX Gap 4: count actual threat intel hits, not text length
    def _calc_threat_score(self, correlation_data: dict) -> float:
        """Calculate threat score from actual threat intel security issues"""
        try:
            security_issues = correlation_data.get('security_issues', [])
            if not isinstance(security_issues, list):
                return 5.0
            threat_types = {
                'Threat Intelligence Alert':     3.0,   # MetaDefender
                'APT Threat Association':        3.0,   # AlienVault OTX
                'Malicious Scanner Activity':    2.0,   # GreyNoise
                'Malicious Activity (Honey Pot)': 2.0,  # Project Honey Pot
                'IP Reputation Risk':            1.5,   # AbuseIPDB
                'IP Reputation / Blacklist':     1.5,   # Phase 2 blacklists
                'Dark Web Exposure - IntelligenceX': 2.0,
                'Data Breach - Email Compromised': 2.0,
                'Known Vulnerability (InternetDB)': 1.0,
            }
            score = 0.0
            for s in security_issues:
                issue_type = s.get('type', '')
                score += threat_types.get(issue_type, 0.0)
            return min(score, 10.0)
        except Exception:
            return 5.0

    def _calc_compliance_impact(self, correlation_data: dict) -> float:
        """Score compliance impact based on issue types that affect regulations"""
        try:
            security_issues = correlation_data.get('security_issues', [])
            if not isinstance(security_issues, list):
                return 5.0
            # Issues that directly affect GDPR / PCI-DSS / HIPAA compliance
            compliance_weights = {
                'Missing DMARC Record':              1.0,
                'Missing SPF Record':                1.0,
                'Missing DKIM Record':               0.5,
                'SSL Certificate Issue':             1.5,
                'Weak TLS Protocols':                1.5,
                'Exposed Client-Side Secret':        2.0,
                'Exposed Database Connection String': 2.0,
                'Data Breach - Email Compromised':   2.0,
                'Dark Web Exposure - IntelligenceX': 2.0,
                'Cloud Storage Exposure - S3 Bucket': 2.0,
                'Missing Security Header':           0.5,
                'Insecure Cookie Configuration':     0.5,
            }
            score = 0.0
            for s in security_issues:
                score += compliance_weights.get(s.get('type', ''), 0.0)
            return min(score, 10.0)
        except Exception:
            return 5.0

    # ── Helper: display ──────────────────────────────────────────────────────

    def _score_to_level(self, score: float) -> str:
        if score >= 3.5: return 'Critical'
        if score >= 2.5: return 'High'
        if score >= 1.5: return 'Medium'
        return 'Low'

    def _score_to_rating(self, score: float) -> str:
        # Aligned with _score_to_level (1-4 scale) so both metrics show consistent severity:
        # 0-10 scale: ≥7.5=Extreme, ≥5.5=High, ≥3.5=Medium, <3.5=Low
        if score >= 7.5: return 'Extreme Risk'
        if score >= 5.5: return 'High Risk'
        if score >= 3.5: return 'Medium Risk'
        return 'Low Risk'

    def _create_matrix_text(self, business: int, infra: int, app: int, impact: int) -> str:
        labels = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        return (
            f"\nRisk Matrix (1=Low → 4=Critical):\n"
            f"┌────────────────────┬─────────────────┐\n"
            f"│ Business Risk      │ {business}/4  {labels[business]:<8} │\n"
            f"│ Infrastructure     │ {infra}/4  {labels[infra]:<8} │\n"
            f"│ Application        │ {app}/4  {labels[app]:<8} │\n"
            f"│ Business Impact    │ {impact}/4  {labels[impact]:<8} │\n"
            f"└────────────────────┴─────────────────┘\n"
        )

    def _create_score_breakdown(self, dimensions: dict, weights: dict) -> str:
        try:
            return "\n".join([
                f"{k.replace('_', ' ').title():<28}: {dimensions[k]:5.2f} × {weights[k]:.0%} = {dimensions[k]*weights[k]:.2f}"
                for k in dimensions
            ])
        except Exception:
            return "Score breakdown unavailable"

    def _generate_executive_summary(self, risk_matrix: dict, multi_score: dict,
                                     correlation_data: dict = None,
                                     domain_data: dict = None,
                                     business_risk: dict = None,
                                     infra_risk: dict = None,
                                     app_risk: dict = None,
                                     business_impact: dict = None) -> str:
        """Generate AI-written C-level executive summary"""
        try:
            rating        = multi_score.get('risk_rating', 'Unknown')
            composite     = risk_matrix.get('composite_risk_score', 0)
            overall_score = multi_score.get('overall_risk_score', 0)
            dims          = risk_matrix.get('dimensions', {})
            domain        = (correlation_data or {}).get('domain', 'the target organization')

            # Company context
            ai_analysis  = (domain_data or {}).get('ai_analysis', {}) if isinstance(domain_data, dict) else {}
            overview     = ai_analysis.get('company_overview', {}) if isinstance(ai_analysis, dict) else {}
            industry     = overview.get('industry_vertical', 'Unknown')
            company_size = overview.get('company_size', 'Unknown')

            # Top remediation items — deduplicated by id so same type doesn't repeat
            remediation_items = []
            if correlation_data:
                seen_ids = {}
                for item in (correlation_data.get('remediation_priority', []) or []):
                    if not isinstance(item, dict):
                        continue
                    rid = item.get('id', '')
                    if rid not in seen_ids:
                        seen_ids[rid] = {'item': item, 'count': 1, 'affected': [item.get('affected', '')]}
                    else:
                        seen_ids[rid]['count'] += 1
                        aff = item.get('affected', '')
                        if aff and aff not in seen_ids[rid]['affected']:
                            seen_ids[rid]['affected'].append(aff)
                priority = 1
                for rid, entry in list(seen_ids.items())[:5]:
                    item = entry['item']
                    count = entry['count']
                    affected = ', '.join(filter(None, entry['affected'][:3]))
                    suffix = f" ({count} instances: {affected})" if count > 1 and affected else (f" ({count} instances)" if count > 1 else (f" — {affected}" if affected else ""))
                    remediation_items.append(
                        f"  {priority}. [{item.get('severity','?')}] {rid}{suffix} — {item.get('fix_action','')[:100]}"
                    )
                    priority += 1
            remediation_text = "\n".join(remediation_items) or "  See Phase 4 report for detailed remediation steps."

            # Key risk findings to summarise
            biz_level    = (business_risk or {}).get('risk_level', 'Unknown')
            infra_level  = (infra_risk    or {}).get('risk_level', 'Unknown')
            app_level    = (app_risk      or {}).get('risk_level', 'Unknown')
            impact_level = (business_impact or {}).get('overall_impact', 'Unknown')
            fin_range    = (business_impact or {}).get('financial_range', 'Not estimated')
            recovery     = (business_impact or {}).get('recovery_time', 'Not estimated')
            biz_analysis = str((business_risk    or {}).get('analysis', ''))[:400]
            infra_analysis = str((infra_risk     or {}).get('analysis', ''))[:400]
            app_analysis = str((app_risk         or {}).get('analysis', ''))[:400]
            impact_analysis = str((business_impact or {}).get('analysis', ''))[:400]

            cves = (correlation_data or {}).get('cves_all', [])
            if not isinstance(cves, list): cves = []
            critical_count = len([c for c in cves if isinstance(c, dict) and c.get('cvss', 0) >= 9.0])
            high_count     = len([c for c in cves if isinstance(c, dict) and 7.0 <= c.get('cvss', 0) < 9.0])

            prompt = f"""You are a Chief Information Security Officer (CISO) writing the Executive Summary section of a formal security assessment report for the board of directors.

TARGET: {domain} | Industry: {industry} | Size: {company_size}
OVERALL RISK RATING: {rating} | Composite Score: {composite}/4.0 | Multi-dimensional Score: {overall_score}/10.0

RISK DIMENSION RESULTS:
- Business Risk: {biz_level}
- Infrastructure Risk: {infra_level}
- Application Risk: {app_level}
- Business Impact: {impact_level}

VULNERABILITY SUMMARY:
- Critical CVEs (CVSS ≥ 9.0): {critical_count}
- High CVEs (CVSS 7.0–8.9): {high_count}
- Estimated Financial Exposure: {fin_range}
- Estimated Recovery Time: {recovery}

DETAILED FINDINGS:
Business: {biz_analysis}
Infrastructure: {infra_analysis}
Application: {app_analysis}
Impact: {impact_analysis}

Write a 3-paragraph professional executive summary for the board:
- Paragraph 1: Overall security posture — what the assessment found, the overall risk rating, and why it matters to this specific company
- Paragraph 2: The 3 most critical findings and their real-world consequences (financial, operational, reputational)
- Paragraph 3: Urgency statement — what happens if nothing is done, and a high-level call to action

Write in the voice of a CISO briefing the CEO and board. Be direct, specific, and professional. No bullet points — pure narrative paragraphs. Reference the domain, industry, and actual risk levels found."""

            ai_text = self.analyze_with_ai(prompt, max_tokens=2048)

            # Clean up any JSON artifacts if AI returns JSON instead of text
            if ai_text.strip().startswith('{'):
                data = self._parse_ai_json(ai_text)
                ai_text = data.get('summary', data.get('executive_summary', ai_text))

            return f"""EXECUTIVE RISK SUMMARY
======================
Domain: {domain}  |  Risk Rating: {rating}  |  Score: {overall_score}/10.0

{ai_text.strip()}

──────────────────────────────────────────────
RISK SCORES AT A GLANCE
  Business Risk:      {biz_level}  ({dims.get('business',{}).get('weight','30%')} weight)
  Infrastructure:     {infra_level}  ({dims.get('infrastructure',{}).get('weight','25%')} weight)
  Application:        {app_level}  ({dims.get('application',{}).get('weight','25%')} weight)
  Business Impact:    {impact_level}  ({dims.get('business_impact',{}).get('weight','20%')} weight)
  Composite Score:    {composite}/4.0  →  Overall: {rating}
  Financial Exposure: {fin_range}
  Recovery Estimate:  {recovery}

TOP PRIORITY ACTIONS (from Phase 4 Correlation):
{remediation_text}
"""
        except Exception as e:
            return f"Executive summary generation error: {e}"

    # ── Phase 5.7: 30/60/90 Day Action Plan ──────────────────────────────────
    def generate_action_plan(self, correlation_data: dict, risk_matrix: dict,
                              business_impact: dict, domain_data: dict) -> dict:
        """Generate prioritized 30/60/90 day remediation action plan"""
        print("\n[Phase 5.8] Generating Action Plan...")

        if not correlation_data: correlation_data = {}

        domain   = correlation_data.get('domain', 'the target')
        ai_analysis = (domain_data or {}).get('ai_analysis', {}) if isinstance(domain_data, dict) else {}
        overview    = ai_analysis.get('company_overview', {}) if isinstance(ai_analysis, dict) else {}
        industry    = overview.get('industry_vertical', 'Unknown')
        fin_range   = (business_impact or {}).get('financial_range', 'Not estimated')
        overall     = (business_impact or {}).get('overall_impact', 'Unknown')

        remediation = correlation_data.get('remediation_priority', [])
        if not isinstance(remediation, list): remediation = []
        remed_text = "\n".join([
            f"  Priority {r.get('priority','?')}: [{r.get('severity','?')}] {r.get('id','')} — {r.get('fix_action','')[:150]}"
            for r in remediation[:10] if isinstance(r, dict)
        ]) or "  No specific remediation items found"

        cves_all = correlation_data.get('cves_all', [])
        if not isinstance(cves_all, list): cves_all = []
        critical_cves = [c for c in cves_all if isinstance(c, dict) and c.get('cvss', 0) >= 9.0]
        high_cves     = [c for c in cves_all if isinstance(c, dict) and 7.0 <= c.get('cvss', 0) < 9.0]

        top_critical = "\n".join([
            f"  - {c.get('cve','?')} | {c.get('tech','')} {c.get('version','')} | CVSS {c.get('cvss',0)}"
            for c in critical_cves[:5]
        ]) or "  None"

        prompt = f"""You are a CISO creating a remediation roadmap for {domain} ({industry}).
Overall Risk: {overall} | Financial Exposure: {fin_range}

PHASE 4 REMEDIATION PRIORITIES:
{remed_text}

CRITICAL CVEs REQUIRING IMMEDIATE PATCHING:
{top_critical}

Create a realistic 30/60/90 day action plan. Each phase must have:
- 3–5 specific, actionable tasks
- Each task references an ACTUAL finding (CVE ID, service name, misconfiguration)
- Owner suggestion (Security Team / IT Ops / Development / Management)
- Expected outcome after completion

Return ONLY JSON (no markdown):
{{
  "day_30": {{
    "theme": "Emergency Triage — Stop Active Bleeding",
    "tasks": [
      {{"action": "Patch CVE-XXXX-YYYY in Drupal 10 — update to version X.X.X", "owner": "Development Team", "outcome": "Eliminates unauthenticated RCE vector"}},
      {{"action": "Close MySQL port 3306 on 185.x.x.x via firewall rule", "owner": "IT Operations", "outcome": "Removes direct database access from internet"}},
      {{"action": "Rotate all API keys found in public GitHub repositories", "owner": "Security Team", "outcome": "Invalidates any credentials already harvested by attackers"}}
    ]
  }},
  "day_60": {{
    "theme": "Hardening — Reduce Attack Surface",
    "tasks": [
      {{"action": "Deploy DMARC policy (p=reject) on primary domain", "owner": "IT Operations", "outcome": "Prevents phishing emails spoofing the company domain"}},
      {{"action": "Implement WAF rules for all public-facing applications", "owner": "Security Team", "outcome": "Blocks exploit attempts against unpatched vulnerabilities"}}
    ]
  }},
  "day_90": {{
    "theme": "Resilience — Build Long-term Defense",
    "tasks": [
      {{"action": "Commission full penetration test after remediation", "owner": "Management", "outcome": "Validates all fixes and identifies any remaining gaps"}},
      {{"action": "Implement vulnerability management program with monthly scanning", "owner": "Security Team", "outcome": "Ensures future vulnerabilities are caught before exploitation"}}
    ]
  }}
}}"""

        try:
            raw  = self.analyze_with_ai(prompt, max_tokens=4096)
            data = self._parse_ai_json(raw)
            if data and ('day_30' in data or 'day30' in data):
                return data
            return {"day_30": {"theme": "Emergency Triage", "tasks": []},
                    "day_60": {"theme": "Hardening", "tasks": []},
                    "day_90": {"theme": "Resilience", "tasks": []},
                    "raw": raw}
        except Exception as e:
            return {"error": str(e)}

    # ── Phase 5.9: Threat Actor Profile ──────────────────────────────────────
    def generate_threat_actor_profile(self, correlation_data: dict, domain_data: dict, infra_data: dict = None) -> dict:
        """Generate threat actor profile — which APTs match, their TTPs, and likelihood"""
        print("\n[Phase 5.9] Generating Threat Actor Profile...")

        if not correlation_data: correlation_data = {}

        domain      = correlation_data.get('domain', 'target')
        ai_analysis = (domain_data or {}).get('ai_analysis', {}) if isinstance(domain_data, dict) else {}
        overview    = ai_analysis.get('company_overview', {}) if isinstance(ai_analysis, dict) else {}
        industry    = overview.get('industry_vertical', 'Unknown')
        company_size = overview.get('company_size', 'Unknown')

        apt_md = str(correlation_data.get('apt_mapping_md', ''))[:800]

        cves_all = correlation_data.get('cves_all', [])
        if not isinstance(cves_all, list): cves_all = []
        top_cves = "\n".join([
            f"  - {c.get('cve','?')} | {c.get('tech','')} | CVSS {c.get('cvss',0)}"
            for c in cves_all if isinstance(c, dict) and c.get('cvss',0) >= 7.0
        ][:6]) or "  None"

        sec_issues = correlation_data.get('security_issues', [])
        if not isinstance(sec_issues, list): sec_issues = []
        threat_intel_issues = [s for s in sec_issues if any(x in s.get('type','') for x in
                        ['Threat Intelligence', 'APT', 'Malicious', 'Dark Web', 'Data Breach', 'Blacklist',
                         'IP Reputation', 'Credential Leak', 'Data Exposure', 'Cloud Storage'])]
        intel_text = "\n".join([
            f"  - {s.get('type','')}: {s.get('header', s.get('url',''))} — {s.get('description','')[:80]}"
            for s in threat_intel_issues[:8]
        ]) or "  No threat intel hits"

        # Pull Phase 3 dark web + threat intel signals directly from app_data
        p3_leak = {}
        p3_threat = {}
        if isinstance(domain_data, dict):
            p3_leak   = domain_data.get('11_leak_detection', {}) or {}
            p3_threat = domain_data.get('10_threat_intelligence', {}) or {}

        # Dark web exposure summary
        intelx     = p3_leak.get('intelx', {}) or {}
        darknet_c  = intelx.get('darknet_count', 0) or len([r for r in intelx.get('all_results', []) if r.get('type') == 'darknet'])
        total_rec  = intelx.get('total_records', intelx.get('total_results', 0))
        dark_web_text = f"IntelligenceX: {total_rec} breach record(s), {darknet_c} darknet mention(s)" if total_rec else "No dark web records found"

        # IP reputation signals from Phase 2 infra
        ip_rep_text = "Not available"
        if isinstance(infra_data, dict):
            rep_dict = infra_data.get('ip_reputation', {})
            if isinstance(rep_dict, dict):
                high_rep = [(ip, d.get('abuseipdb', {}).get('abuse_score', 0))
                            for ip, d in rep_dict.items()
                            if isinstance(d, dict) and d.get('abuseipdb', {}).get('abuse_score', 0) > 25]
                if high_rep:
                    ip_rep_text = "; ".join([f"{ip} (abuse score {sc}%)" for ip, sc in high_rep[:4]])

        prompt = f"""You are a cyber threat intelligence analyst profiling threat actors that would target {domain}.

TARGET PROFILE:
- Domain: {domain}
- Industry: {industry}
- Company Size: {company_size}

PHASE 4 APT CONTEXT:
{apt_md if apt_md else 'Not available'}

CONFIRMED THREAT INTELLIGENCE HITS (from Phase 2 + Phase 3 scanning):
{intel_text}

DARK WEB EXPOSURE (Phase 3):
  {dark_web_text}

IP REPUTATION (Phase 2):
  {ip_rep_text}

HIGH-SEVERITY CVEs THAT APTs EXPLOIT:
{top_cves}

Based on the industry, company profile, and actual threat intelligence findings, profile the most likely threat actors.

Return ONLY JSON:
{{
  "primary_threat_actors": [
    {{
      "name": "APT Group Name (e.g. APT41, FIN7, Lazarus Group)",
      "origin": "Country/Region",
      "motivation": "Financial / Espionage / Disruption",
      "likelihood": "High / Medium / Low",
      "why_this_company": "Specific reason this group targets this industry/company type",
      "known_ttps": ["Spear phishing", "Supply chain attacks", "Living off the land"],
      "matching_findings": "Which specific findings from this scan match their known attack patterns"
    }}
  ],
  "opportunistic_threats": "Description of opportunistic attackers (ransomware gangs, script kiddies) who would exploit the exposed services",
  "overall_threat_level": "High / Medium / Low",
  "analyst_note": "2–3 sentence assessment of the overall threat landscape for this specific company"
}}"""

        try:
            raw  = self.analyze_with_ai(prompt, max_tokens=4096)
            data = self._parse_ai_json(raw)
            return data if data else {"raw": raw, "overall_threat_level": "Unknown"}
        except Exception as e:
            return {"error": str(e)}

    # ── Main runner ──────────────────────────────────────────────────────────
    def run_full_assessment(self, correlation_data: dict, infra_data: dict,
                            domain_data: dict, app_data: dict) -> dict:
        """Run complete Phase 5 risk assessment"""
        print("\n" + "="*60)
        print("PHASE 5: RISK ASSESSMENT AND CATEGORIZATION")
        print("="*60)

        # Normalize Phase 4 JSON structure — save_report() uses different keys than run_correlation()
        # save_report()    → metadata.domain, vulnerabilities
        # run_correlation() → domain, cves_all
        if correlation_data:
            if 'domain' not in correlation_data and 'metadata' in correlation_data:
                correlation_data['domain'] = correlation_data['metadata'].get('domain', 'unknown')
            if 'cves_all' not in correlation_data and 'vulnerabilities' in correlation_data:
                correlation_data['cves_all'] = correlation_data['vulnerabilities']

        try:
            business_risk     = self.assess_business_risk(correlation_data, domain_data)
            infra_risk        = self.assess_infrastructure_risk(infra_data, correlation_data)
            app_risk          = self.assess_application_risk(app_data, correlation_data)
            business_impact   = self.correlate_business_impact(business_risk, infra_risk, app_risk, correlation_data)
            risk_matrix       = self.generate_risk_matrix(business_risk, infra_risk, app_risk, business_impact)
            multidim_score    = self.calculate_multidimensional_risk_score(risk_matrix, correlation_data)

            # ── New high-value sections ──
            action_plan          = self.generate_action_plan(correlation_data, risk_matrix, business_impact, domain_data)
            threat_actor_profile = self.generate_threat_actor_profile(correlation_data, domain_data, infra_data)

            final_assessment = {
                "assessment_date":        datetime.now().isoformat(),
                "business_risk":          business_risk,
                "infrastructure_risk":    infra_risk,
                "application_risk":       app_risk,
                "business_impact":        business_impact,
                "risk_matrix":            risk_matrix,
                "multidimensional_score": multidim_score,
                "action_plan":            action_plan,
                "threat_actor_profile":   threat_actor_profile,
                "executive_summary":      self._generate_executive_summary(
                    risk_matrix, multidim_score, correlation_data,
                    domain_data, business_risk, infra_risk, app_risk, business_impact
                ),
            }

            # Auto-save report to reports/ folder
            os.makedirs("reports", exist_ok=True)
            domain = (correlation_data or {}).get('domain', 'unknown').replace('.', '_')
            filename = os.path.join("reports", f"Phase5_RiskAssessment_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            save_risk_assessment(final_assessment, filename)

            print("\n✅ Phase 5 Complete!")
            return final_assessment

        except Exception as e:
            print(f"\n❌ Phase 5 Error: {e}")
            import traceback
            traceback.print_exc()
            return {
                "assessment_date": datetime.now().isoformat(),
                "error": str(e),
                "status": "partial_failure",
                "message": "Risk assessment incomplete. Manual review required.",
            }


def save_risk_assessment(assessment: dict, filename: str):
    """Save risk assessment to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(assessment, f, indent=2, default=str)
        print(f"\n💾 Risk assessment saved: {filename}")
    except Exception as e:
        print(f"\n⚠️ Error saving assessment: {e}")


if __name__ == "__main__":
    import glob as _glob

    def _latest(pattern):
        files = _glob.glob(os.path.join("reports", pattern))
        return max(files, key=os.path.getmtime) if files else None

    def _load(path, label):
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            print(f"  ✅ {label}: {path}")
            return data
        except Exception as e:
            print(f"  ⚠️  Could not load {label}: {e}")
            return None

    print("\n" + "="*70)
    print("PHASE 5: RISK ASSESSMENT & CATEGORIZATION")
    print("="*70 + "\n")

    # ── Auto-detect latest outputs from reports/ ──────────────────────────────
    auto4 = _latest("Phase4_Report_*.json")
    auto2 = _latest("*phase2_infra*.json")
    auto1 = _latest("*phase1_domain*.json")
    auto3 = _latest("BSI_Phase3_Application_*.json")

    print("Auto-detected report files from reports/:")
    for lbl, p in [("Phase 1", auto1), ("Phase 2", auto2), ("Phase 3", auto3), ("Phase 4", auto4)]:
        print(f"  {'✅' if p else '❌'} {lbl}: {p or 'not found'}")

    print()

    p4 = input(f"Phase 4 JSON path (Enter to {'use above' if auto4 else 'skip'}): ").strip() or auto4
    p2 = input(f"Phase 2 JSON path (Enter to {'use above' if auto2 else 'skip'}): ").strip() or auto2
    p1 = input(f"Phase 1 JSON path (Enter to {'use above' if auto1 else 'skip'}): ").strip() or auto1
    p3 = input(f"Phase 3 JSON path (Enter to {'use above' if auto3 else 'skip'}): ").strip() or auto3

    if not p4:
        print("\n❌ Phase 4 output is required to run Phase 5. Exiting.")
        raise SystemExit(1)

    print("\nLoading files...")
    correlation_data = _load(p4, "Phase 4 (Correlation)")
    infra_data       = _load(p2, "Phase 2 (Infrastructure)")
    domain_data      = _load(p1, "Phase 1 (Business Domain)")
    app_data         = _load(p3, "Phase 3 (Application)")

    engine = RiskAssessmentEngine()
    result = engine.run_full_assessment(
        correlation_data=correlation_data,
        infra_data=infra_data,
        domain_data=domain_data,
        app_data=app_data,
    )
    print("\n✅ Phase 5 Complete!")
