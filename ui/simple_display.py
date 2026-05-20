#!/usr/bin/env python3
"""
Simple Display - Human-readable rendering of phase data.
Each phase uses expanders/dropdowns. Data is rendered as readable text,
not raw JSON. Matches the exact data structures each phase produces.
"""

import streamlit as st
from typing import Dict, Any, List


# ── Shared helpers ────────────────────────────────────────────────────────────

def _kv(label: str, value: Any, fallback: str = "N/A"):
    """Render a key-value line. Skips if value is empty."""
    if value is None or value == "" or value == [] or value == {}:
        return
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    st.markdown(f"**{label}:** {value}")


def _severity_icon(sev: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")


def _risk_icon(level: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Minimal": "🟢"}.get(level, "⚪")


def _render_list(items: List, bullet: str = "•"):
    for item in items:
        if isinstance(item, dict):
            st.markdown(f"{bullet} " + "  |  ".join(f"**{k.replace('_',' ').title()}:** {v}" for k, v in item.items() if v))
        else:
            st.markdown(f"{bullet} {item}")


# ── Phase 1: Business Domain ──────────────────────────────────────────────────

def display_business_domain_simple(data: Dict[str, Any]):
    st.header("🏢 Business Domain Understanding")
    if not data:
        st.warning("No data available for Phase 1.")
        return
    if "error" in data:
        st.error(f"Phase 1 failed: {data['error']}")
        return

    # Top metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Company", data.get("company_name", "N/A"))
    c2.metric("Domain",  data.get("domain", "N/A"))
    c3.metric("Analysed", str(data.get("analysis_timestamp", ""))[:10] or "N/A")
    st.divider()

    # WHOIS
    whois = data.get("whois_data", {})
    if whois and not whois.get("error"):
        with st.expander("📋 WHOIS Registration", expanded=True):
            c1, c2 = st.columns(2)
            with c1:
                _kv("Registrar",    whois.get("registrar"))
                _kv("Organisation", whois.get("organization"))
                _kv("Country",      whois.get("country"))
            with c2:
                _kv("Domain Age",   f"{whois.get('domain_age_years')} years" if whois.get('domain_age_years') else None)
                _kv("Created",      str(whois.get("creation_date", ""))[:10] or None)
                _kv("Expires",      str(whois.get("expiration_date", ""))[:10] or None)
                _kv("Name Servers", whois.get("name_servers"))

    # AbstractAPI company profile
    api = data.get("abstractapi_company", {})
    if api and not api.get("error") and not api.get("status") == "no_key":
        with st.expander("🏢 Company Profile", expanded=True):
            c1, c2, c3 = st.columns(3)
            c1.metric("Industry",  api.get("industry", "N/A"))
            c2.metric("Employees", str(api.get("employees_count", "N/A")))
            c3.metric("Founded",   str(api.get("year_founded", "N/A")))
            _kv("Country",   api.get("country"))
            _kv("Locality",  api.get("locality"))
            _kv("LinkedIn",  api.get("linkedin_url"))

    # Hunter.io emails
    hunter = data.get("hunter_io", {})
    emails = hunter.get("emails", []) if isinstance(hunter, dict) else []
    if emails:
        with st.expander(f"📧 Email Intelligence ({len(emails)} found)", expanded=False):
            for e in emails[:20]:
                if isinstance(e, dict):
                    addr = e.get("value") or e.get("email", "")
                    parts = [addr]
                    if e.get("position"):   parts.append(e["position"])
                    if e.get("department"): parts.append(e["department"])
                    conf = e.get("confidence")
                    if conf: parts.append(f"{conf}% confidence")
                    st.markdown("• " + "  —  ".join(parts))
                else:
                    st.markdown(f"• {e}")
            if len(emails) > 20:
                st.caption(f"… and {len(emails)-20} more")

    # Host.io
    hostio = data.get("host_io", {})
    if hostio and not hostio.get("error") and hostio.get("status") == "success":
        with st.expander("🌐 Hosting Intelligence", expanded=False):
            web = hostio.get("web", {})
            dns = hostio.get("dns", {})
            c1, c2 = st.columns(2)
            with c1:
                _kv("IP",           web.get("ip"))
                _kv("Global Rank",  web.get("rank"))
                _kv("Contact",      web.get("email"))
            with c2:
                if dns.get("a"):  _kv("A Records",  ", ".join(dns["a"]))
                if dns.get("mx"): _kv("MX Records",  ", ".join(dns["mx"]))
                if dns.get("ns"): _kv("Nameservers", ", ".join(dns["ns"]))

    # AI Analysis — each section as its own expander
    ai = data.get("ai_analysis", {})
    if ai and ai.get("analysis_method") != "error":
        section_icons = {
            "company_overview":       "🏢",
            "financial_intelligence": "💰",
            "leadership":             "👤",
            "services_and_products":  "📦",
            "customer_base":          "👥",
            "threat_intelligence":    "⚠️",
            "regulatory_compliance":  "⚖️",
            "data_quality":           "📊",
        }
        for key, content in ai.items():
            if key in ("analysis_method", "raw_analysis") or not content:
                continue
            icon  = section_icons.get(key, "📌")
            title = key.replace("_", " ").title()
            with st.expander(f"{icon} {title}", expanded=False):
                if isinstance(content, dict):
                    for k, v in content.items():
                        if v:
                            _kv(k.replace("_", " ").title(), v)
                elif isinstance(content, list):
                    _render_list(content)
                else:
                    st.write(content)


# ── Phase 2: Infrastructure ───────────────────────────────────────────────────

def display_infrastructure_simple(data: Dict[str, Any]):
    st.header("🌐 Infrastructure Discovery")
    if not data:
        st.warning("No data available for Phase 2.")
        return
    if "error" in data:
        st.error(f"Phase 2 failed: {data['error']}")
        return

    subdomains  = data.get("subdomains", [])
    ips         = data.get("ip_addresses", [])
    ssl         = data.get("ssl_analysis", {})
    asn         = data.get("asn_info", {})
    bl_ips      = data.get("blacklisted_ips", [])
    ssl_weak    = data.get("ssl_weaknesses", {})
    dns         = data.get("dns_records", {})
    mail        = data.get("mail_server_analysis", {})
    misconfigs  = data.get("security_misconfigs", {})
    cloud       = data.get("cloud_provider", "")

    # Summary metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Subdomains",    len(subdomains))
    c2.metric("IP Addresses",  len(ips))
    c3.metric("Blacklisted",   len(bl_ips))
    c4.metric("SSL Issues",    ssl_weak.get("issue_count", len(ssl_weak.get("issues", []))))
    st.divider()

    # IP Addresses + reputation
    if ips:
        with st.expander(f"🌍 IP Addresses ({len(ips)})", expanded=True):
            for ip in ips:
                bl = next((b for b in bl_ips if b.get("ip") == ip), None)
                suffix = f"  🚫 Blacklisted — {bl.get('reason','')}" if bl else ""
                asn_entry = asn.get(ip, {})
                org = asn_entry.get("organization") or asn_entry.get("asn", "")
                country = asn_entry.get("country", "")
                detail = "  |  ".join(filter(None, [org, country]))
                st.markdown(f"• `{ip}`" + (f"  —  {detail}" if detail else "") + suffix)

    # SSL / TLS
    if ssl:
        with st.expander("🔒 SSL / TLS Analysis", expanded=True):
            cert = ssl.get("certificate_info", {})
            c1, c2 = st.columns(2)
            with c1:
                supported = ssl.get("tls_versions_supported", [])
                st.markdown(f"**Supported TLS:** {', '.join(supported) if supported else 'N/A'}")
                _kv("Issuer",     cert.get("issuer"))
                _kv("Valid From", str(cert.get("not_before") or cert.get("notBefore", ""))[:16])
                _kv("Days Left",  cert.get("days_until_expiry"))
            with c2:
                rejected = ssl.get("tls_versions_rejected", [])
                st.markdown(f"**Rejected TLS:** {', '.join(rejected) if rejected else 'None'}")
                _kv("Subject",   cert.get("subject"))
                _kv("Valid To",  str(cert.get("not_after") or cert.get("notAfter", ""))[:16])
                _kv("Self-Signed", "Yes ⚠️" if cert.get("self_signed") else None)
            if ssl_weak.get("issues"):
                st.markdown("**Weaknesses:**")
                for issue in ssl_weak["issues"]:
                    icon = _severity_icon(issue.get("severity", ""))
                    st.markdown(f"  {icon} {issue.get('title')} — {issue.get('description','')}")

    # DNS Records
    if dns:
        with st.expander("🗂️ DNS Records", expanded=False):
            for rtype, records in dns.items():
                if records:
                    st.markdown(f"**{rtype}**")
                    items = records if isinstance(records, list) else [records]
                    for r in items:
                        st.markdown(f"  • {r}")

    # Mail server analysis
    if mail:
        with st.expander("📬 Mail Server Analysis", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                _kv("SPF",   "✅ Configured" if mail.get("spf_configured") else "❌ Missing")
                _kv("DMARC", "✅ Configured" if mail.get("dmarc_configured") else "❌ Missing")
                _kv("DKIM",  "✅ Configured" if mail.get("dkim_configured") else "❌ Missing")
            with c2:
                _kv("Email Security Score", mail.get("email_security_score"))
                _kv("Primary Provider",     mail.get("primary_provider"))
                _kv("SPF Record",           mail.get("spf_record"))

    # Blacklisted IPs
    if bl_ips:
        with st.expander(f"🚫 Blacklisted IPs ({len(bl_ips)})", expanded=True):
            for entry in bl_ips:
                if isinstance(entry, dict):
                    st.markdown(f"• **{entry.get('ip')}** — {entry.get('reason','Flagged by reputation service')}")
                else:
                    st.markdown(f"• {entry}")

    # Security misconfigurations
    if misconfigs and misconfigs.get("summary", {}).get("total", 0) > 0:
        total = misconfigs["summary"].get("total", 0)
        with st.expander(f"⚠️ Security Misconfigurations ({total} found)", expanded=True):
            for section, items in misconfigs.items():
                if section == "summary" or not items:
                    continue
                label = section.replace("_", " ").title()
                if isinstance(items, list) and items:
                    st.markdown(f"**{label}**")
                    for item in items:
                        if isinstance(item, dict):
                            url  = item.get("url") or item.get("service") or ""
                            sev  = item.get("severity", "")
                            desc = item.get("desc") or item.get("detail") or ""
                            icon = _severity_icon(sev)
                            st.markdown(f"  {icon} `{url}` — {desc}")
                        else:
                            st.markdown(f"  • {item}")

    # Subdomains (paginated)
    if subdomains:
        with st.expander(f"🔗 Subdomains ({len(subdomains)} discovered)", expanded=False):
            show = min(100, len(subdomains))
            cols = st.columns(2)
            for i, s in enumerate(subdomains[:show]):
                cols[i % 2].code(s, language="text")
            if len(subdomains) > show:
                st.caption(f"… and {len(subdomains)-show} more")


# ── Phase 3: Application Landscape ───────────────────────────────────────────

def display_application_simple(data: Dict[str, Any]):
    st.header("🖥️ Application Landscape Assessment")
    if not data:
        st.warning("No data available for Phase 3.")
        return
    if "error" in data:
        st.error(f"Phase 3 failed: {data['error']}")
        return

    app   = data.get("1_application_discovery", {})
    tech  = data.get("2_web_server_stack", {})
    third = data.get("4_third_party_software", {})
    repos = data.get("5_code_repositories", {})
    old   = data.get("6_outdated_software", {})
    sec   = data.get("7_security_posture", {})
    apis  = data.get("8_api_discovery", {})
    db    = data.get("9_database_detection", {})
    ti    = data.get("10_threat_intelligence", {})
    leak  = data.get("11_data_leak_detection", {})
    s3    = data.get("12_s3_bucket_exposure", {})

    # Summary metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Status",       app.get("status", "Unknown"))
    c2.metric("CMS",          ", ".join(tech.get("cms", [])) or "None")
    c3.metric("API Endpoints", len(apis.get("api_endpoints", [])))
    c4.metric("Admin Panels",  len(sec.get("admin_panels", [])))
    st.divider()

    # Application discovery
    if app:
        with st.expander("🔍 Application Discovery", expanded=True):
            c1, c2, c3 = st.columns(3)
            c1.metric("HTTP Status",    app.get("http_status", "N/A"))
            c2.metric("Response Time",  f"{app.get('response_time_ms', 0)} ms")
            c3.metric("Server",         str(app.get("server", "Not disclosed"))[:30])
            _kv("Powered By",    app.get("powered_by"))
            _kv("Final URL",     app.get("final_url"))
            _kv("Redirects",     app.get("redirect_count"))

    # Technology stack
    with st.expander("⚙️ Technology Stack", expanded=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            cms = tech.get("cms", [])
            st.markdown(f"**CMS:** {', '.join(cms) if cms else 'None detected'}")
            _kv("CMS Version", tech.get("cms_version"))
        with c2:
            fw = tech.get("frameworks", [])
            st.markdown(f"**Frameworks:** {', '.join(fw) if fw else 'None detected'}")
        with c3:
            js = tech.get("javascript_libraries", [])
            st.markdown(f"**JS Libraries:** {', '.join(js) if js else 'None detected'}")
        _kv("Language", tech.get("programming_language"))
        _kv("CDN",      tech.get("cdn"))

    # Security posture
    with st.expander("🔐 Security Posture", expanded=True):
        headers = sec.get("security_headers", {})
        if headers:
            st.markdown("**HTTP Security Headers**")
            for h, v in headers.items():
                icon = "✅" if v else "❌"
                st.markdown(f"  {icon} **{h}:** {v if v else 'Not set'}")
        score = sec.get("header_score")
        if score is not None:
            st.progress(score / 100)
            st.caption(f"Header security score: {score}/100")

        panels = sec.get("admin_panels", [])
        if panels:
            st.markdown(f"**Admin Panels ({len(panels)} found)**")
            for p in panels:
                icon = "🔓" if p.get("access") == "OPEN" else "🔒"
                st.markdown(f"  {icon} `{p.get('path')}` — HTTP {p.get('status')} — {p.get('access','')}")

        cookies = sec.get("cookie_security", [])
        if cookies:
            st.markdown("**Cookie Security**")
            for c in cookies:
                name = c.get("name") or c.get("cookie", "?")
                issues = c.get("issues", [])
                if issues:
                    st.markdown(f"  ⚠️ `{name}`: {'; '.join(issues)}")
                else:
                    st.markdown(f"  ✅ `{name}`: Secure")

    # API Discovery
    rest = apis.get("api_endpoints", [])
    gql  = apis.get("graphql_endpoints", [])
    swagger = apis.get("swagger_docs", [])
    if rest or gql or swagger:
        with st.expander(f"🔌 API Discovery ({len(rest)} REST, {len(gql)} GraphQL)", expanded=False):
            if rest:
                st.markdown("**REST Endpoints**")
                for ep in rest:
                    acc = "✅" if ep.get("accessible") else "🔒"
                    st.markdown(f"  {acc} `{ep.get('path')}` — HTTP {ep.get('status')}")
            if gql:
                st.markdown("**GraphQL Endpoints**")
                for ep in gql:
                    intro = " (introspection enabled ⚠️)" if ep.get("introspection_enabled") else ""
                    st.markdown(f"  • `{ep.get('path')}` — HTTP {ep.get('status')}{intro}")
            if swagger:
                st.markdown("**API Documentation**")
                for doc in swagger:
                    st.markdown(f"  📄 `{doc.get('path')}`")

    # Third-party software
    has_third = any(v for v in third.values() if isinstance(v, list) and v)
    if has_third:
        with st.expander("🧩 Third-Party Software", expanded=False):
            for category, items in third.items():
                if items and isinstance(items, list):
                    st.markdown(f"**{category.replace('_',' ').title()}:** {', '.join(items)}")

    # Exposed files / repos
    exposed = repos.get("exposed_paths", [])
    if exposed:
        with st.expander(f"🚨 Exposed Sensitive Files ({len(exposed)})", expanded=True):
            for e in exposed:
                icon = _severity_icon(e.get("severity", "Critical"))
                st.markdown(f"  {icon} `{e.get('path')}` — {e.get('issue','')}")

    # Outdated software
    vuln_libs = old.get("vulnerable", [])
    if vuln_libs:
        with st.expander(f"⚠️ Outdated / Vulnerable Software ({len(vuln_libs)})", expanded=True):
            for lib in vuln_libs:
                icon = _severity_icon(lib.get("severity", "Medium"))
                name = lib.get("library") or lib.get("name", "Unknown")
                ver  = lib.get("version", "")
                desc = lib.get("description", "")
                st.markdown(f"  {icon} **{name}** {ver} — {desc}")

    # Database detection
    db_ifaces = db.get("database_interfaces", [])
    if db_ifaces:
        with st.expander(f"🗄️ Database Interfaces ({len(db_ifaces)} found)", expanded=True):
            for d in db_ifaces:
                icon = "🔓" if d.get("exposed") else "🔒"
                st.markdown(f"  {icon} **{d.get('name')}** at `{d.get('path')}` — HTTP {d.get('status')}")

    # Threat intelligence
    if ti and ti.get("status") == "success":
        with st.expander("🕵️ Threat Intelligence (VirusTotal)", expanded=False):
            c1, c2, c3 = st.columns(3)
            c1.metric("Malicious",  ti.get("malicious", 0))
            c2.metric("Suspicious", ti.get("suspicious", 0))
            c3.metric("Harmless",   ti.get("harmless", 0))
            _kv("Reputation Score", ti.get("reputation"))

    # Data leaks
    leaks = leak.get("leaks", [])
    if leaks:
        with st.expander(f"💧 Data Leaks ({len(leaks)} records)", expanded=True):
            for l in leaks[:10]:
                if isinstance(l, dict):
                    st.markdown("• " + "  |  ".join(f"**{k}:** {v}" for k, v in l.items() if v))
                else:
                    st.markdown(f"• {l}")

    # S3 buckets
    buckets = s3.get("buckets", []) or s3.get("exposed_buckets", [])
    if buckets:
        with st.expander(f"🪣 Exposed S3 Buckets ({len(buckets)})", expanded=True):
            for b in buckets:
                name = b.get("bucket") or b.get("name") or str(b) if isinstance(b, dict) else str(b)
                st.markdown(f"  • {name}")


# ── Phase 4: Vulnerability Correlation ───────────────────────────────────────

def _build_attack_chains_from_data(vulns: List[Dict], security_issues: List[Dict]) -> List[Dict]:
    """
    Build attack chains from vulnerability and security issue data.
    Groups related findings into realistic attack scenarios showing HOW
    the agent discovered and correlated each vulnerability.
    """
    chains = []

    # ── Chain 1: Remote Code Execution via exposed services + CVEs ──
    rce_vulns = [v for v in vulns if isinstance(v, dict) and
                 (v.get("attack_type") == "Remote Code Execution" or
                  (v.get("cvss", 0) >= 9.0 and "RCE" in str(v.get("desc", ""))))]
    exposed_services = [s for s in security_issues if isinstance(s, dict) and
                        "Exposed Service" in s.get("type", "")]
    if rce_vulns or exposed_services:
        steps = []
        # Reconnaissance step
        steps.append("Reconnaissance: Agent scanned all subdomains and IP addresses, identifying open ports and running services via Shodan/Censys correlation")
        # Service exposure
        for svc in exposed_services[:3]:
            steps.append(f"Service Discovery: {svc.get('header', svc.get('type', ''))} found exposed — {svc.get('description', '')}")
        # CVE correlation
        for v in rce_vulns[:2]:
            steps.append(f"CVE Correlation: {v.get('cve', v.get('cwe', 'N/A'))} matched to {v.get('tech', 'detected technology')} {v.get('version', '')} (CVSS {v.get('cvss', 'N/A')}) — {v.get('desc', '')[:120]}")
        steps.append("Exploit Path: Attacker can leverage exposed service + unpatched CVE to achieve unauthenticated remote code execution")
        steps.append("Impact: Full server compromise, lateral movement to internal network, data exfiltration")
        chains.append({"name": "Remote Code Execution via Exposed Services", "severity": "Critical", "steps": steps})

    # ── Chain 2: Credential theft via exposed files ──
    cred_issues = [s for s in security_issues if isinstance(s, dict) and
                   any(x in s.get("type", "") for x in ["Exposed Sensitive File", "Exposed File"])]
    cred_vulns = [v for v in vulns if isinstance(v, dict) and
                  v.get("attack_type") in ("Credential Theft", "Data Theft")]
    if cred_issues or cred_vulns:
        steps = []
        steps.append("Reconnaissance: Agent crawled all discovered subdomains for sensitive file paths (backup archives, config files, .git directories)")
        for issue in cred_issues[:3]:
            steps.append(f"File Discovery: {issue.get('header', '')} — {issue.get('description', '')} (Severity: {issue.get('severity', 'N/A')})")
        for v in cred_vulns[:2]:
            steps.append(f"Vulnerability Mapping: {v.get('cve', v.get('cwe', 'N/A'))} — {v.get('desc', '')[:120]}")
        steps.append("Exploit Path: Attacker downloads exposed backup/config files to extract database credentials, API keys, or source code")
        steps.append("Impact: Database access, credential reuse across services, source code analysis for further vulnerabilities")
        chains.append({"name": "Credential Theft via Exposed Sensitive Files", "severity": "Critical", "steps": steps})

    # ── Chain 3: Phishing / Email-based attack via missing email security ──
    email_issues = [s for s in security_issues if isinstance(s, dict) and
                    any(x in s.get("type", "") for x in ["DMARC", "DKIM", "SPF", "Phishing"])]
    if email_issues:
        steps = []
        steps.append("Reconnaissance: Agent queried DNS records for SPF, DMARC, and DKIM configurations")
        for issue in email_issues[:3]:
            steps.append(f"Email Security Gap: {issue.get('type', '')} — {issue.get('description', '')} (Severity: {issue.get('severity', 'N/A')})")
        steps.append("Exploit Path: Attacker spoofs legitimate company email addresses to send phishing emails to employees or customers — no email authentication to block it")
        steps.append("Impact: Credential harvesting, business email compromise (BEC), financial fraud via fake invoice attacks")
        chains.append({"name": "Phishing via Missing Email Authentication", "severity": "High", "steps": steps})

    # ── Chain 4: Dark web / threat intelligence chain ──
    darkweb_issues = [s for s in security_issues if isinstance(s, dict) and
                      any(x in s.get("type", "") for x in ["Dark Web", "APT Threat", "Threat Intelligence", "Data Breach"])]
    if darkweb_issues:
        steps = []
        steps.append("Threat Intelligence: Agent queried AlienVault OTX, IntelligenceX, and dark web databases for domain/IP reputation")
        for issue in darkweb_issues[:3]:
            steps.append(f"Intel Hit: {issue.get('type', '')} — {issue.get('header', issue.get('description', ''))} (Source: {issue.get('source', 'Threat Intel')})")
        steps.append("Correlation: Threat intelligence hits indicate prior compromise, active targeting, or leaked credentials already in attacker hands")
        steps.append("Impact: Attackers may already have valid credentials or internal knowledge — breach may be ongoing or imminent")
        chains.append({"name": "Active Threat Intelligence Indicators", "severity": "Critical", "steps": steps})

    # ── Chain 5: Database exposure chain ──
    db_issues = [s for s in security_issues if isinstance(s, dict) and
                 any(x in s.get("type", "") for x in ["MSSQL", "MySQL", "PostgreSQL", "Database"])]
    db_vulns = [v for v in vulns if isinstance(v, dict) and
                any(x in str(v.get("tech", "")) for x in ["SQL", "MySQL", "MSSQL", "PostgreSQL", "Database"])]
    if db_issues or db_vulns:
        steps = []
        steps.append("Port Scanning: Agent identified database ports exposed directly to the internet via Shodan/Censys data")
        for issue in db_issues[:2]:
            steps.append(f"Exposed Database: {issue.get('header', '')} — {issue.get('description', '')} (Severity: {issue.get('severity', 'N/A')})")
        for v in db_vulns[:2]:
            steps.append(f"CVE Match: {v.get('cve', v.get('cwe', 'N/A'))} — {v.get('desc', '')[:100]}")
        steps.append("Exploit Path: Attacker connects directly to exposed database port, attempts brute-force or exploits known CVE for unauthenticated access")
        steps.append("Impact: Full database dump, PII exfiltration, ransomware deployment, regulatory violations (GDPR/HIPAA)")
        chains.append({"name": "Direct Database Exposure & Exploitation", "severity": "Critical", "steps": steps})

    return chains


def display_correlation_simple(data: Dict[str, Any]):
    st.header("🔗 Vulnerability Correlation & Threat Intelligence")
    if not data:
        st.warning("No data available for Phase 4.")
        return
    if "error" in data:
        st.error(f"Phase 4 failed: {data['error']}")
        return

    # ── Normalize data: handle both AIPhase4Scanner schema and VulnerabilityCorrelation schema ──
    # AIPhase4Scanner produces: security_issues, vulnerabilities, threat_intelligence.apt_groups,
    #                           attack_vectors (markdown string), cves_all
    # VulnerabilityCorrelation produces: summary, vulnerabilities, mitre_mapping, threat_actors,
    #                                    attack_chains, overall_risk_score, risk_factors

    security_issues = data.get("security_issues", [])
    if not isinstance(security_issues, list):
        security_issues = []

    cves_all = data.get("cves_all", data.get("vulnerabilities", []))
    if not isinstance(cves_all, list):
        cves_all = []

    # Build summary from actual data if not present
    summary = data.get("summary", {})
    if not summary or not isinstance(summary, dict):
        all_issues = security_issues + cves_all
        sev_norm = lambda s: str(s).upper()
        summary = {
            "critical_count": sum(1 for s in all_issues if isinstance(s, dict) and sev_norm(s.get("severity", "")) == "CRITICAL"),
            "high_count":     sum(1 for s in all_issues if isinstance(s, dict) and sev_norm(s.get("severity", "")) == "HIGH"),
            "medium_count":   sum(1 for s in all_issues if isinstance(s, dict) and sev_norm(s.get("severity", "")) == "MEDIUM"),
            "low_count":      sum(1 for s in all_issues if isinstance(s, dict) and sev_norm(s.get("severity", "")) == "LOW"),
            "total":          len(all_issues),
        }
    else:
        # Normalize scanner summary keys (critical_cves/high_cves) to display keys (critical_count/high_count)
        if "critical_count" not in summary and "critical_cves" in summary:
            summary["critical_count"] = summary["critical_cves"] + summary.get("critical_issues", 0)
        if "high_count" not in summary and "high_cves" in summary:
            summary["high_count"] = summary["high_cves"] + summary.get("high_issues", 0)
        if "medium_count" not in summary:
            # Compute from issues if not present
            all_issues = security_issues + cves_all
            sev_norm = lambda s: str(s).upper()
            summary["medium_count"] = sum(1 for s in all_issues if isinstance(s, dict) and sev_norm(s.get("severity", "")) == "MEDIUM")
        if "total" not in summary:
            summary["total"] = len(security_issues) + len(cves_all)

    # Compute risk score from CVEs if not present
    score = data.get("overall_risk_score", 0)
    if not score and cves_all:
        top_cvss = sorted([v.get("cvss", 0) for v in cves_all if isinstance(v, dict)], reverse=True)
        score = round(min(sum(top_cvss[:5]) / 5 * 10, 100), 1) if top_cvss else 0

    # Threat actors: try top-level first, then nested under threat_intelligence
    actors = data.get("threat_actors", [])
    if not actors or not isinstance(actors, list):
        threat_intel = data.get("threat_intelligence", {})
        if isinstance(threat_intel, dict):
            actors = threat_intel.get("apt_groups", [])
        if not actors:
            actors = []

    # Risk factors: build from summary if not present
    factors = data.get("risk_factors", [])
    if not factors or not isinstance(factors, list):
        factors = []
        if summary.get("critical_count", 0):
            factors.append(f"{summary['critical_count']} critical severity findings require immediate remediation")
        if summary.get("high_count", 0):
            factors.append(f"{summary['high_count']} high severity issues identified across infrastructure and application layers")
        if summary.get("medium_count", 0):
            factors.append(f"{summary['medium_count']} medium severity issues contribute to overall attack surface")
        darkweb = [s for s in security_issues if isinstance(s, dict) and "Dark Web" in s.get("type", "")]
        if darkweb:
            factors.append(f"Dark web exposure detected — {darkweb[0].get('description', 'breach records found')}")
        apt_hits = [s for s in security_issues if isinstance(s, dict) and "APT" in s.get("type", "")]
        if apt_hits:
            factors.append(f"APT threat intelligence hits — {apt_hits[0].get('header', 'IP flagged in threat feeds')}")

    # Attack chains: build from actual vulnerability data
    chains = data.get("attack_chains", [])
    if not chains or not isinstance(chains, list) or (isinstance(chains, str)):
        chains = _build_attack_chains_from_data(cves_all, security_issues)

    # MITRE mapping: try existing, or build from apt_mapping_md / threat_intelligence
    mitre = data.get("mitre_mapping", {})
    if not mitre or not isinstance(mitre, dict):
        # Try to extract from threat_intelligence sector context
        threat_intel = data.get("threat_intelligence", {})
        if isinstance(threat_intel, dict) and threat_intel.get("sector"):
            mitre = {}  # Will be shown via APT groups instead

    # Attack vectors markdown — scanner stores as attack_vectors_md
    attack_vectors_md = data.get("attack_vectors_md", "")
    if not attack_vectors_md:
        # Fallback: check attack_vectors if it's a string
        av = data.get("attack_vectors", "")
        if isinstance(av, str) and av.strip():
            attack_vectors_md = av

    # APT mapping markdown — scanner stores as apt_mapping_md
    apt_md = data.get("apt_mapping_md", "")

    # ── Summary metrics ──
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Risk Score",  f"{score}/100")
    c2.metric("Total Issues", summary.get("total", len(security_issues)))
    c3.metric("🔴 Critical", summary.get("critical_count", 0))
    c4.metric("🟠 High",     summary.get("high_count", 0))
    c5.metric("🟡 Medium",   summary.get("medium_count", 0))
    st.progress(min(float(score), 100) / 100)
    st.divider()

    # Risk factors narrative
    if factors:
        with st.expander("📋 Risk Factors", expanded=True):
            for f in factors:
                st.markdown(f"• {f}")

    # CVEs / Vulnerabilities (from cves_all — the correlated CVE list)
    if cves_all:
        with st.expander(f"🔬 Correlated CVEs ({len(cves_all)} found)", expanded=True):
            for v in cves_all:
                if not isinstance(v, dict):
                    continue
                sev   = v.get("severity", "Low")
                icon  = _severity_icon(sev)
                cve   = v.get("cve", v.get("cwe", "N/A"))
                tech  = v.get("tech", "")
                ver   = v.get("version", "")
                cvss  = v.get("cvss", "")
                desc  = v.get("desc", v.get("description", ""))
                src   = v.get("source", "")
                label = f"{tech} {ver}".strip() if tech else ""
                cvss_str = f"CVSS {cvss}" if cvss else ""
                meta = "  |  ".join(filter(None, [label, cvss_str, src]))
                st.markdown(f"{icon} **{cve}** — {sev}" + (f"  *({meta})*" if meta else ""))
                if desc:
                    st.caption(f"  {desc[:200]}")

    # Security issues (misconfigurations, exposed services, etc.)
    if security_issues:
        with st.expander(f"🚨 Security Issues ({len(security_issues)} found)", expanded=True):
            for v in security_issues:
                if not isinstance(v, dict):
                    continue
                sev   = v.get("severity", "Low")
                icon  = _severity_icon(sev.title())
                itype = v.get("type", "Unknown")
                hdr   = v.get("header", "")
                desc  = v.get("description", "")
                src   = v.get("source", "")
                st.markdown(f"{icon} **{itype}**" + (f" — `{hdr}`" if hdr else "") + (f"  *(source: {src})*" if src else ""))
                if desc:
                    st.caption(f"  {desc}")

    # Attack chains — built from actual vulnerability data showing the reasoning
    if chains:
        with st.expander(f"⛓️ Attack Chains ({len(chains)} identified)", expanded=True):
            for chain in chains:
                if isinstance(chain, dict):
                    name  = chain.get("name", "Unknown")
                    sev   = chain.get("severity", "")
                    steps = chain.get("steps", [])
                    icon  = _severity_icon(sev)
                    st.markdown(f"#### {icon} {name}")
                    for i, step in enumerate(steps, 1):
                        st.markdown(f"  **{i}.** {step}")
                    st.markdown("---")
                elif isinstance(chain, str):
                    st.markdown(chain)

    # Threat actors (APT groups)
    if actors:
        with st.expander(f"👾 Threat Actors ({len(actors)} identified)", expanded=False):
            for actor in actors:
                if isinstance(actor, dict):
                    name  = actor.get("name", "Unknown")
                    desc  = actor.get("description", "")
                    aliases = actor.get("aliases", [])
                    alias_str = f"  *(aliases: {', '.join(aliases[:3])})*" if aliases else ""
                    st.markdown(f"• **{name}**{alias_str}")
                    if desc:
                        # Strip markdown links for cleaner display
                        import re as _re
                        clean_desc = _re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', str(desc))
                        st.caption(f"  {clean_desc[:300]}")
                else:
                    st.markdown(f"• {actor}")

    # MITRE ATT&CK mapping (if available)
    if mitre and isinstance(mitre, dict):
        with st.expander(f"🎯 MITRE ATT&CK Mapping ({len(mitre)} techniques)", expanded=False):
            for tid, info in mitre.items():
                if isinstance(info, dict):
                    name = info.get("name", "")
                    linked_vulns = info.get("vulnerabilities", [])
                    st.markdown(f"**{tid} — {name}**")
                    for lv in linked_vulns:
                        st.markdown(f"  • {lv}")
                else:
                    st.markdown(f"• **{tid}:** {info}")

    # APT mapping markdown (if present from scanner)
    if apt_md and isinstance(apt_md, str) and apt_md.strip():
        with st.expander("🗺️ APT Threat Mapping", expanded=False):
            st.markdown(apt_md)

    # Attack vectors markdown (if present from scanner)
    if attack_vectors_md and isinstance(attack_vectors_md, str) and attack_vectors_md.strip():
        with st.expander("🎯 Attack Vector Analysis", expanded=False):
            st.markdown(attack_vectors_md)


# ── Phase 5: Risk Assessment ──────────────────────────────────────────────────

def display_risk_simple(data: Dict[str, Any]):
    st.header("📊 Risk Assessment & Recommendations")
    if not data:
        st.warning("No data available for Phase 5.")
        return
    if "error" in data:
        st.error(f"Phase 5 failed: {data['error']}")
        return

    # ── Normalize: handle both RiskAssessmentEngine schema (new) and RiskAssessment schema (old) ──
    # New engine produces: risk_matrix, multidimensional_score, business_risk, infrastructure_risk,
    #                      application_risk, business_impact, action_plan, threat_actor_profile, executive_summary
    # Old class produces:  risk_overview, asset_risks, threat_landscape, compliance_status,
    #                      business_impact, recommendations

    # Determine which schema we have
    has_new_schema = "risk_matrix" in data or "multidimensional_score" in data
    has_old_schema = "risk_overview" in data

    # ── Extract risk level and score ──
    if has_new_schema:
        risk_matrix  = data.get("risk_matrix", {})
        multi_score  = data.get("multidimensional_score", {})
        level        = risk_matrix.get("risk_level", "Unknown")
        raw_score    = multi_score.get("overall_risk_score", 0)
        # Convert 0-10 scale to 0-100 for display
        score        = round(float(raw_score) * 10, 1) if raw_score else 0
        exposure     = risk_matrix.get("risk_level", "Unknown")
    elif has_old_schema:
        overview = data.get("risk_overview", {})
        level    = overview.get("overall_risk_level", "Unknown")
        score    = overview.get("risk_score", 0)
        exposure = overview.get("exposure_level", "Unknown")
    else:
        level = "Unknown"
        score = 0
        exposure = "Unknown"

    icon = _risk_icon(level)

    # ── Build key findings from available data ──
    findings = []
    if has_new_schema:
        biz_risk   = data.get("business_risk", {})
        infra_risk = data.get("infrastructure_risk", {})
        app_risk   = data.get("application_risk", {})
        if biz_risk.get("analysis"):
            findings.append(f"Business Risk ({biz_risk.get('risk_level','?')}): {str(biz_risk['analysis'])[:200]}")
        if infra_risk.get("analysis"):
            findings.append(f"Infrastructure Risk ({infra_risk.get('risk_level','?')}): {str(infra_risk['analysis'])[:200]}")
        if app_risk.get("analysis"):
            findings.append(f"Application Risk ({app_risk.get('risk_level','?')}): {str(app_risk['analysis'])[:200]}")
    elif has_old_schema:
        findings = data.get("risk_overview", {}).get("key_findings", [])

    # ── Top metrics ──
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Level",  f"{icon} {level}")
    c2.metric("Risk Score",  f"{round(score)}/100")
    c3.metric("Exposure",    exposure)
    c4.metric("Findings",    len(findings))
    st.progress(min(float(score), 100) / 100)
    st.divider()

    # ── Executive Summary (new schema) ──
    exec_summary = data.get("executive_summary", "")
    if exec_summary and isinstance(exec_summary, str) and exec_summary.strip():
        with st.expander("📋 Executive Summary", expanded=True):
            st.text(exec_summary)

    # ── Key Findings ──
    if findings:
        with st.expander("🔍 Key Findings", expanded=True):
            for f in findings:
                st.markdown(f"• {f}")

    # ── Risk Dimensions (new schema) ──
    if has_new_schema:
        risk_matrix = data.get("risk_matrix", {})
        dims = risk_matrix.get("dimensions", {})
        if dims:
            with st.expander("📊 Risk Matrix Dimensions", expanded=True):
                for dim_name, dim_data in dims.items():
                    if isinstance(dim_data, dict):
                        dl    = dim_data.get("level", "Unknown")
                        ds    = dim_data.get("score", 0)
                        dw    = dim_data.get("weight", "")
                        dicon = _risk_icon(dl)
                        st.markdown(f"{dicon} **{dim_name.replace('_',' ').title()}** — {dl}  (score: {ds}/4, weight: {dw})")
                interp = risk_matrix.get("interpretation", "")
                if interp:
                    st.info(interp)

        # Multi-dimensional score breakdown
        multi = data.get("multidimensional_score", {})
        if multi:
            with st.expander("🎯 Multi-Dimensional Risk Score", expanded=False):
                c1, c2 = st.columns(2)
                with c1:
                    st.metric("Overall Score", f"{multi.get('overall_risk_score', 0)}/10")
                    st.metric("Risk Rating",   multi.get("risk_rating", "Unknown"))
                with c2:
                    breakdown = multi.get("score_breakdown", "")
                    if breakdown:
                        st.code(breakdown, language="text")
                interp = multi.get("interpretation", "")
                if interp:
                    st.info(interp)

    # ── Business Risk Detail (new schema) ──
    biz_risk = data.get("business_risk", {})
    if biz_risk and isinstance(biz_risk, dict) and biz_risk.get("analysis"):
        with st.expander(f"💼 Business Risk — {biz_risk.get('risk_level','?')}", expanded=False):
            cats = biz_risk.get("categories", [])
            if cats:
                st.markdown("**Risk Categories:**")
                for c in cats:
                    st.markdown(f"  • {c}")
            analysis = biz_risk.get("analysis", "")
            if analysis:
                st.write(analysis)

    # ── Infrastructure Risk Detail (new schema) ──
    infra_risk = data.get("infrastructure_risk", {})
    if infra_risk and isinstance(infra_risk, dict) and infra_risk.get("analysis"):
        with st.expander(f"🌐 Infrastructure Risk — {infra_risk.get('risk_level','?')}", expanded=False):
            areas = infra_risk.get("risk_areas", [])
            if areas:
                st.markdown("**Risk Areas:**")
                for a in areas:
                    st.markdown(f"  • {a}")
            analysis = infra_risk.get("analysis", "")
            if analysis:
                st.write(analysis)

    # ── Application Risk Detail (new schema) ──
    app_risk = data.get("application_risk", {})
    if app_risk and isinstance(app_risk, dict) and app_risk.get("analysis"):
        with st.expander(f"🖥️ Application Risk — {app_risk.get('risk_level','?')}", expanded=False):
            cats = app_risk.get("risk_categories", [])
            if cats:
                st.markdown("**Risk Categories:**")
                for c in cats:
                    st.markdown(f"  • {c}")
            analysis = app_risk.get("analysis", "")
            if analysis:
                st.write(analysis)

    # ── Business Impact ──
    impact = data.get("business_impact", {})
    if impact and isinstance(impact, dict):
        with st.expander("💼 Business Impact", expanded=True):
            if has_new_schema:
                c1, c2 = st.columns(2)
                with c1:
                    _kv("Overall Impact",   impact.get("overall_impact"))
                    _kv("Financial Range",  impact.get("financial_range"))
                    _kv("Recovery Time",    impact.get("recovery_time"))
                with c2:
                    dims = impact.get("impact_dimensions", {})
                    if dims:
                        for k, v in dims.items():
                            icon_d = _risk_icon(str(v))
                            st.markdown(f"  {icon_d} **{k.replace('_',' ').title()}:** {v}")
                analysis = impact.get("analysis", "")
                if analysis:
                    st.info(analysis)
            else:
                c1, c2 = st.columns(2)
                with c1:
                    _kv("Potential Impact",   impact.get("potential_impact"))
                    _kv("Financial Risk",     impact.get("financial_risk"))
                    _kv("Operational Impact", impact.get("operational_impact"))
                with c2:
                    _kv("Reputational Risk",  impact.get("reputational_risk"))
                    _kv("Industry",           impact.get("industry"))
                    _kv("Company Size",       impact.get("company_size"))
                desc = impact.get("description")
                if desc:
                    st.info(desc)

    # ── 30/60/90 Day Action Plan (new schema) ──
    action_plan = data.get("action_plan", {})
    if action_plan and isinstance(action_plan, dict) and not action_plan.get("error"):
        with st.expander("🗓️ 30/60/90 Day Remediation Plan", expanded=True):
            for day_key in ("day_30", "day_60", "day_90"):
                day_data = action_plan.get(day_key, {})
                if not day_data or not isinstance(day_data, dict):
                    continue
                theme = day_data.get("theme", day_key.replace("_", " ").title())
                label = day_key.replace("_", " ").replace("day", "Day").title()
                st.markdown(f"**{label}: {theme}**")
                tasks = day_data.get("tasks", [])
                for task in tasks:
                    if isinstance(task, dict):
                        action  = task.get("action", "")
                        owner   = task.get("owner", "")
                        outcome = task.get("outcome", "")
                        st.markdown(f"  • {action}" + (f"  *(Owner: {owner})*" if owner else ""))
                        if outcome:
                            st.caption(f"    → {outcome}")
                    else:
                        st.markdown(f"  • {task}")
                st.markdown("")

    # ── Threat Actor Profile (new schema) ──
    tap = data.get("threat_actor_profile", {})
    if tap and isinstance(tap, dict) and not tap.get("error"):
        primary = tap.get("primary_threat_actors", [])
        if primary:
            with st.expander(f"👾 Threat Actor Profile ({len(primary)} actors)", expanded=False):
                overall_tl = tap.get("overall_threat_level", "")
                if overall_tl:
                    st.markdown(f"**Overall Threat Level:** {_risk_icon(overall_tl)} {overall_tl}")
                analyst_note = tap.get("analyst_note", "")
                if analyst_note:
                    st.info(analyst_note)
                for actor in primary:
                    if isinstance(actor, dict):
                        name    = actor.get("name", "Unknown")
                        origin  = actor.get("origin", "")
                        mot     = actor.get("motivation", "")
                        like    = actor.get("likelihood", "")
                        why     = actor.get("why_this_company", "")
                        ttps    = actor.get("known_ttps", [])
                        matches = actor.get("matching_findings", "")
                        like_icon = _risk_icon(like)
                        st.markdown(f"**{name}**" + (f"  ({origin})" if origin else "") + (f"  — Likelihood: {like_icon} {like}" if like else ""))
                        if mot:     st.caption(f"  Motivation: {mot}")
                        if why:     st.caption(f"  Why this target: {why}")
                        if matches: st.caption(f"  Matching findings: {matches}")
                        if ttps:    st.caption(f"  Known TTPs: {', '.join(ttps[:5])}")
                        st.markdown("---")
                opp = tap.get("opportunistic_threats", "")
                if opp:
                    st.markdown("**Opportunistic Threats:**")
                    st.write(opp)

    # ── Recommendations (old schema) ──
    recs = data.get("recommendations", [])
    if recs and isinstance(recs, list):
        with st.expander(f"💡 Recommendations ({len(recs)})", expanded=True):
            for rec in recs:
                if not isinstance(rec, dict):
                    st.markdown(f"• {rec}")
                    continue
                prio   = rec.get("priority", "Low")
                r_icon = _severity_icon(prio)
                title  = rec.get("title", "")
                tl     = rec.get("timeline", "")
                desc   = rec.get("description", "")
                action = rec.get("action", "")
                imp    = rec.get("impact", "")
                st.markdown(f"{r_icon} **{title}**" + (f"  *(Timeline: {tl})*" if tl else ""))
                if desc:   st.caption(f"  Issue: {desc}")
                if action: st.caption(f"  Action: {action}")
                if imp:    st.caption(f"  Impact: {imp}")
                st.markdown("---")

    # ── Old schema: Asset risks ──
    assets = data.get("asset_risks", [])
    if assets and isinstance(assets, list):
        with st.expander(f"🏗️ Asset Risks ({len(assets)} assets)", expanded=False):
            for asset in assets:
                if not isinstance(asset, dict):
                    continue
                rl    = asset.get("risk_level", "Low")
                a_icon = _risk_icon(rl)
                name  = asset.get("name", "Unknown")
                atype = asset.get("type", "")
                st.markdown(f"{a_icon} **{name}**" + (f"  ({atype})" if atype else ""))
                vulns = asset.get("vulnerabilities", [])
                for v in vulns:
                    st.markdown(f"  ⚠️ {v}")

    # ── Old schema: Compliance status ──
    compliance = data.get("compliance_status", {})
    if compliance and isinstance(compliance, dict):
        with st.expander("⚖️ Compliance Status", expanded=False):
            for framework, info in compliance.items():
                if not isinstance(info, dict):
                    continue
                status = info.get("status", "Unknown")
                gaps   = info.get("gaps", [])
                s_icon = "✅" if status == "Compliant" else "⚠️" if status == "Partial" else "❌"
                st.markdown(f"**{framework}:** {s_icon} {status}")
                for gap in gaps:
                    st.markdown(f"  • {gap}")

    # ── Old schema: Threat landscape ──
    threat_land = data.get("threat_landscape", {})
    if threat_land and isinstance(threat_land, dict):
        ta = threat_land.get("threat_actors", [])
        av = threat_land.get("attack_vectors", [])
        mt = threat_land.get("mitre_techniques", [])
        if ta or av or mt:
            with st.expander("🌍 Threat Landscape", expanded=False):
                if ta:
                    st.markdown("**Threat Actors:**")
                    for actor in ta:
                        if isinstance(actor, dict):
                            st.markdown(f"  • **{actor.get('name')}** — {actor.get('motivation','')} (likelihood: {actor.get('likelihood','')})")
                        else:
                            st.markdown(f"  • {actor}")
                if mt:
                    st.markdown(f"**MITRE Techniques:** {', '.join(mt)}")
                if av:
                    st.markdown("**Attack Vectors:**")
                    for v in av:
                        if isinstance(v, dict):
                            st.markdown(f"  • **{v.get('name','')}** — {v.get('severity','')}")
                        else:
                            st.markdown(f"  • {v}")
