#!/usr/bin/env python3
"""
Report Display - Reads directly from raw phase data keys.
No transformation layer. Each function knows the actual stored structure.
"""

import streamlit as st
from typing import Dict, Any, List


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _badge(label: str, color: str = "blue") -> str:
    colors = {"red": "#c0392b", "orange": "#e67e22", "yellow": "#f39c12",
              "green": "#27ae60", "blue": "#2980b9", "grey": "#7f8c8d"}
    bg = colors.get(color, colors["blue"])
    return f'<span style="background:{bg};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em">{label}</span>'


def _severity_color(severity: str) -> str:
    return {"Critical": "red", "High": "orange", "Medium": "yellow",
            "Low": "green"}.get(severity, "grey")


def _safe(val, fallback: str = "N/A") -> str:
    if val is None or val == "" or val == [] or val == {}:
        return fallback
    return str(val)


def _kv(label: str, value: Any):
    """Render a single key-value row."""
    if value is None or value == "" or value == [] or value == {}:
        return
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    st.markdown(f"**{label}:** {value}")


# ─── Phase 1: Business Domain ─────────────────────────────────────────────────

def display_phase1(data: Dict[str, Any]):
    st.header("🏢 Business Domain Understanding")
    # ✅ FIX: Check for error first, then empty data
    if not data:
        st.warning("No data available for this phase.")
        return
    if 'error' in data:
        st.error(f"❌ Phase 1 Analysis Failed: {data['error']}")
        return

    # ── Company identity ──────────────────────────────────────────────────────
    company = data.get("name") or data.get("company_name", "Unknown")
    domain  = data.get("domain", "")
    ts      = str(data.get("analysis_timestamp", ""))[:10]

    col1, col2, col3 = st.columns(3)
    col1.metric("Company", company)
    col2.metric("Domain",  domain)
    col3.metric("Analysed", ts)
    st.divider()

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    whois = data.get("whois_data", {})
    if whois and not whois.get("error"):
        st.subheader("📋 WHOIS Registration")
        c1, c2 = st.columns(2)
        with c1:
            _kv("Registrar",        whois.get("registrar"))
            _kv("Organisation",     whois.get("org") or whois.get("organization"))
            _kv("Country",          whois.get("country"))
        with c2:
            _kv("Created",          whois.get("creation_date"))
            _kv("Expires",          whois.get("expiration_date"))
            _kv("Name Servers",     whois.get("name_servers"))
        st.divider()

    # ── AbstractAPI company enrichment ────────────────────────────────────────
    api = data.get("abstractapi_company", {})
    if api and not api.get("error"):
        st.subheader("🏢 Company Profile")
        c1, c2, c3 = st.columns(3)
        c1.metric("Industry",    _safe(api.get("industry")))
        c2.metric("Employees",   _safe(api.get("employees_count") or api.get("size")))
        c3.metric("Founded",     _safe(api.get("year_founded") or api.get("founded")))
        _kv("Description", api.get("long_description") or api.get("description"))
        _kv("LinkedIn",    api.get("linkedin_url"))
        _kv("Type",        api.get("type"))
        st.divider()

    # ── Hunter.io emails ──────────────────────────────────────────────────────
    hunter = data.get("hunter_io", {})
    if hunter and not hunter.get("error"):
        emails = hunter.get("emails", [])
        st.subheader(f"📧 Email Intelligence ({len(emails)} found)")
        if emails:
            for e in emails[:15]:
                if isinstance(e, dict):
                    addr = e.get("value") or e.get("email", "")
                    dept = e.get("department", "")
                    pos  = e.get("position", "")
                    line = f"• **{addr}**"
                    if dept: line += f"  —  {dept}"
                    if pos:  line += f"  ({pos})"
                    st.markdown(line)
                else:
                    st.markdown(f"• {e}")
            if len(emails) > 15:
                st.caption(f"… and {len(emails)-15} more addresses")
        st.divider()

    # ── Host.io ───────────────────────────────────────────────────────────────
    hostio = data.get("host_io", {})
    if hostio and not hostio.get("error"):
        st.subheader("🌐 Hosting Intelligence")
        c1, c2 = st.columns(2)
        with c1:
            _kv("Hosting Provider", hostio.get("hosting") or hostio.get("isp"))
            _kv("IP",               hostio.get("ip"))
            _kv("Country",          hostio.get("country"))
        with c2:
            _kv("Domains on IP",    hostio.get("domains"))
            _kv("Rank",             hostio.get("rank"))
        st.divider()

    # ── AI Analysis ───────────────────────────────────────────────────────────
    ai = data.get("ai_analysis", {})
    if ai and not ai.get("error"):
        st.subheader("🤖 AI-Generated Intelligence")
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
            if key == "analysis_method" or not content:
                continue
            icon  = section_icons.get(key, "📌")
            title = key.replace("_", " ").title()
            with st.expander(f"{icon} {title}", expanded=False):
                if isinstance(content, dict):
                    for k, v in content.items():
                        if v:
                            _kv(k.replace("_", " ").title(), v)
                elif isinstance(content, list):
                    for item in content:
                        st.markdown(f"• {item}")
                else:
                    st.write(content)


# ─── Phase 2: Infrastructure ───────────────────────────────────────────────────

def display_phase2(data: Dict[str, Any]):
    st.header("🌐 Infrastructure Discovery")
    # ✅ FIX: Check for error first, then empty data
    if not data:
        st.warning("No data available for this phase.")
        return
    if 'error' in data:
        st.error(f"❌ Phase 2 Analysis Failed: {data['error']}")
        return

    subdomains = data.get("subdomains", [])
    ips        = data.get("ip_addresses", []) or data.get("ipv6_addresses", [])
    open_ports = data.get("open_ports", {})
    dns        = data.get("dns_records", {})
    ssl        = data.get("ssl_analysis", {})
    asn        = data.get("asn_info", {})
    waf        = data.get("waf_detection", {})
    cloud      = data.get("cloud_provider", "")
    bl_ips     = data.get("blacklisted_ips", [])
    misconfigs = data.get("security_misconfigs", {})
    mail       = data.get("mail_server_analysis", {})

    # ── Summary metrics ───────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Subdomains",  len(subdomains))
    c2.metric("IP Addresses", len(data.get("ip_addresses", [])))
    c3.metric("Open Ports",  sum(len(v) if isinstance(v, list) else 1 for v in open_ports.values()) if open_ports else 0)
    c4.metric("DNS Records", sum(len(v) if isinstance(v, list) else 1 for v in dns.values()) if dns else 0)
    st.divider()

    # ── Cloud / WAF ───────────────────────────────────────────────────────────
    if cloud or waf:
        st.subheader("☁️ Hosting & Protection")
        c1, c2 = st.columns(2)
        with c1:
            _kv("Cloud Provider", cloud)
            _kv("Cloud Services", data.get("cloud_services"))
        with c2:
            if waf:
                detected = waf.get("detected") or waf.get("waf_name") or waf.get("provider")
                _kv("WAF Detected", detected)
                _kv("WAF Confidence", waf.get("confidence"))
        st.divider()

    # ── IP Addresses ──────────────────────────────────────────────────────────
    ipv4 = data.get("ip_addresses", [])
    if ipv4:
        st.subheader("🌍 IP Addresses")
        for ip in ipv4:
            st.code(ip, language="text")
        st.divider()

    # ── Open Ports ────────────────────────────────────────────────────────────
    if open_ports:
        st.subheader("🔌 Open Ports & Services")
        for ip, ports in open_ports.items():
            st.markdown(f"**{ip}**")
            services = data.get("port_services", {}).get(ip, {})
            if isinstance(ports, list):
                for p in ports:
                    svc = services.get(str(p), "")
                    st.markdown(f"  • Port **{p}**" + (f" — {svc}" if svc else ""))
            else:
                st.write(ports)
        st.divider()

    # ── DNS Records ───────────────────────────────────────────────────────────
    if dns:
        st.subheader("🗂️ DNS Records")
        for rtype, records in dns.items():
            if records:
                st.markdown(f"**{rtype}**")
                if isinstance(records, list):
                    for r in records:
                        st.markdown(f"  • {r}")
                else:
                    st.markdown(f"  {records}")
        st.divider()

    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    if ssl:
        st.subheader("🔒 SSL / TLS")
        cert = ssl.get("certificate_info") or ssl.get("cert_info") or {}
        c1, c2 = st.columns(2)
        with c1:
            supported = ssl.get("tls_versions_supported", [])
            st.markdown(f"**Supported:** {', '.join(supported) if supported else 'N/A'}")
            _kv("Issuer",    cert.get("issuer"))
            _kv("Valid From", cert.get("notBefore") or cert.get("valid_from"))
        with c2:
            rejected = ssl.get("tls_versions_rejected", [])
            st.markdown(f"**Rejected:** {', '.join(rejected) if rejected else 'None'}")
            _kv("Subject",   cert.get("subject"))
            _kv("Valid To",  cert.get("notAfter") or cert.get("valid_to"))
        weaknesses = data.get("ssl_weaknesses", {})
        if weaknesses:
            with st.expander("⚠️ SSL Weaknesses", expanded=False):
                for k, v in weaknesses.items():
                    if v:
                        st.markdown(f"• **{k.replace('_',' ').title()}:** {v}")
        st.divider()

    # ── Mail Servers ──────────────────────────────────────────────────────────
    if mail:
        st.subheader("📬 Mail Server Analysis")
        for k, v in mail.items():
            if v:
                _kv(k.replace("_", " ").title(), v)
        st.divider()

    # ── Blacklisted IPs ───────────────────────────────────────────────────────
    if bl_ips:
        st.subheader("🚫 Blacklisted IPs")
        for entry in bl_ips:
            if isinstance(entry, dict):
                st.markdown(f"• **{entry.get('ip')}** — {entry.get('reason','')}")
            else:
                st.markdown(f"• {entry}")
        st.divider()

    # ── Security Misconfigurations ────────────────────────────────────────────
    if misconfigs:
        st.subheader("⚠️ Security Misconfigurations")
        for k, v in misconfigs.items():
            if v:
                _kv(k.replace("_", " ").title(), v)
        st.divider()

    # ── Subdomains (paginated) ────────────────────────────────────────────────
    if subdomains:
        st.subheader(f"🔗 Subdomains ({len(subdomains)} discovered)")
        show = st.slider("Show top N subdomains", 10, min(500, len(subdomains)), 50, key="sub_slider")
        cols = st.columns(2)
        for i, s in enumerate(subdomains[:show]):
            cols[i % 2].code(s, language="text")


# ─── Phase 3: Application Landscape ───────────────────────────────────────────

def display_phase3(data: Dict[str, Any]):
    st.header("🖥️ Application Landscape Assessment")
    # ✅ FIX: Check for error first, then empty data
    if not data:
        st.warning("No data available for this phase.")
        return
    if 'error' in data:
        st.error(f"❌ Phase 3 Analysis Failed: {data['error']}")
        return

    app   = data.get("1_application_discovery", {})
    tech  = data.get("2_web_server_stack", {})
    erp   = data.get("3_erp_sap_detection", {})
    third = data.get("4_third_party_software", {})
    repos = data.get("5_code_repositories", {})
    old   = data.get("6_outdated_software", {})
    sec   = data.get("7_security_posture", {})
    apis  = data.get("8_api_discovery", {})
    db    = data.get("9_database_detection", {})
    ti    = data.get("10_threat_intelligence", {})
    leak  = data.get("11_leak_detection", {})
    s3    = data.get("12_s3_exposure", {})

    # ── Application overview ──────────────────────────────────────────────────
    if app:
        st.subheader("🔍 Application Discovery")
        c1, c2, c3 = st.columns(3)
        c1.metric("Status",        app.get("status", "Unknown"))
        c2.metric("Server",        str(app.get("server") or app.get("server_full", "Not disclosed"))[:30])
        c3.metric("Response Time", f"{app.get('response_time_ms', 0)} ms")
        _kv("Content Length", app.get("content_length"))
        _kv("Redirect",       app.get("redirect_url"))
        st.divider()

    # ── Technology stack ──────────────────────────────────────────────────────
    if tech:
        st.subheader("⚙️ Technology Stack")
        c1, c2, c3 = st.columns(3)
        with c1:
            cms = tech.get("cms", [])
            st.markdown(f"**CMS:** {', '.join(cms) if cms else 'None detected'}")
            _kv("CMS Version", tech.get("cms_version"))
        with c2:
            fw = tech.get("frameworks", [])
            st.markdown(f"**Frameworks:** {', '.join(fw) if fw else 'None detected'}")
        with c3:
            js = tech.get("javascript_libraries", []) or list(tech.get("javascript_versions", {}).keys())
            st.markdown(f"**JS Libraries:** {', '.join(js) if js else 'None detected'}")
        _kv("Programming Language", tech.get("programming_language") or tech.get("language"))
        _kv("CDN",                  tech.get("cdn"))
        st.divider()

    # ── Security posture ──────────────────────────────────────────────────────
    if sec:
        st.subheader("🔐 Security Posture")
        headers = sec.get("security_headers", {})
        if headers:
            st.markdown("**HTTP Security Headers**")
            for h, v in headers.items():
                icon = "✅" if v else "❌"
                st.markdown(f"{icon} **{h}:** {v if v else 'Not set'}")

        panels = sec.get("admin_panels", [])
        if panels:
            st.markdown(f"**Admin Panels ({len(panels)} found)**")
            for p in panels:
                icon = "🔓" if p.get("access") == "OPEN" else "🔒"
                st.markdown(f"{icon} `{p.get('path')}` — HTTP {p.get('status')} — {p.get('access','')}")

        cookies = sec.get("cookie_security", [])
        if cookies:
            st.markdown("**Cookie Security**")
            for c in cookies:
                flags = []
                if c.get("httponly"): flags.append("HttpOnly ✅")
                else: flags.append("HttpOnly ❌")
                if c.get("secure"):   flags.append("Secure ✅")
                else: flags.append("Secure ❌")
                st.markdown(f"• `{c.get('cookie')}` — {' | '.join(flags)}")
        st.divider()

    # ── API Discovery ─────────────────────────────────────────────────────────
    if apis:
        st.subheader("🔌 API Discovery")
        rest = apis.get("api_endpoints", [])
        gql  = apis.get("graphql_endpoints", [])
        if rest:
            st.markdown(f"**REST Endpoints ({len(rest)})**")
            for ep in rest:
                st.markdown(f"• `{ep.get('path')}` — HTTP {ep.get('status')}")
        if gql:
            st.markdown(f"**GraphQL Endpoints ({len(gql)})**")
            for ep in gql:
                st.markdown(f"• `{ep.get('path')}` — HTTP {ep.get('status')}")
        st.divider()

    # ── Third-party software ──────────────────────────────────────────────────
    if third:
        st.subheader("🧩 Third-Party Software")
        for category, items in third.items():
            if items:
                label = category.replace("_", " ").title()
                if isinstance(items, list):
                    st.markdown(f"**{label}:** {', '.join(str(i) for i in items)}")
                else:
                    _kv(label, items)
        st.divider()

    # ── Outdated software ─────────────────────────────────────────────────────
    if old:
        vuln_libs = old.get("vulnerable", []) or old.get("outdated", [])
        if vuln_libs:
            st.subheader("⚠️ Outdated / Vulnerable Software")
            for lib in vuln_libs:
                if isinstance(lib, dict):
                    st.markdown(f"• **{lib.get('library') or lib.get('name')}** {lib.get('version','')} — {lib.get('severity','')}")
                else:
                    st.markdown(f"• {lib}")
            st.divider()

    # ── Database detection ────────────────────────────────────────────────────
    if db:
        db_types = db.get("database_type", []) or db.get("detected", [])
        if db_types:
            st.subheader("🗄️ Database Detection")
            st.markdown(f"**Detected:** {', '.join(db_types) if isinstance(db_types, list) else db_types}")
            _kv("Exposed Ports", db.get("exposed_ports"))
            st.divider()

    # ── Threat intelligence ───────────────────────────────────────────────────
    if ti:
        st.subheader("🕵️ Threat Intelligence")
        for k, v in ti.items():
            if v:
                _kv(k.replace("_", " ").title(), v)
        st.divider()

    # ── Data leak detection ───────────────────────────────────────────────────
    if leak:
        st.subheader("💧 Data Leak Detection")
        for k, v in leak.items():
            if v:
                _kv(k.replace("_", " ").title(), v)
        st.divider()

    # ── S3 / Cloud storage exposure ───────────────────────────────────────────
    if s3:
        exposed = s3.get("exposed_buckets", []) or s3.get("buckets", [])
        if exposed:
            st.subheader("🪣 Cloud Storage Exposure")
            for b in exposed:
                st.markdown(f"• {b}")


# ─── Phase 4: Vulnerability Correlation ───────────────────────────────────────

def display_phase4(data: Dict[str, Any]):
    st.header("🔗 Vulnerability Correlation & Threat Intelligence")
    # ✅ FIX: Check for error first, then empty data
    if not data:
        st.warning("No data available for this phase.")
        return
    if 'error' in data:
        st.error(f"❌ Phase 4 Analysis Failed: {data['error']}")
        return

    summary   = data.get("summary", {})
    issues    = data.get("security_issues", [])
    cves      = data.get("cves_all", [])
    by_cat    = data.get("issues_by_category", {})
    apt_md    = data.get("apt_mapping_md", "")
    atk_md    = data.get("attack_vectors_md", "")
    remed     = data.get("remediation_priority", [])

    # ── Risk summary metrics ──────────────────────────────────────────────────
    st.subheader("📊 Risk Summary")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Issues",  summary.get("total_issues") or len(issues))
    c2.metric("Critical",      summary.get("critical", 0))
    c3.metric("High",          summary.get("high", 0))
    c4.metric("Medium",        summary.get("medium", 0))
    c5.metric("CVEs Found",    len(cves))
    st.divider()

    # ── Security issues by category ───────────────────────────────────────────
    if by_cat:
        st.subheader("🗂️ Issues by Category")
        for cat, items in by_cat.items():
            if not items:
                continue
            label = cat.replace("_", " ").title()
            count = len(items) if isinstance(items, list) else 1
            with st.expander(f"📁 {label} ({count})", expanded=False):
                if isinstance(items, list):
                    for issue in items:
                        if isinstance(issue, dict):
                            sev   = issue.get("severity", "")
                            title = issue.get("title") or issue.get("name", "")
                            desc  = issue.get("description") or issue.get("detail", "")
                            icon  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(sev, "⚪")
                            st.markdown(f"{icon} **{title}**" + (f" — {sev}" if sev else ""))
                            if desc:
                                st.caption(desc)
                        else:
                            st.markdown(f"• {issue}")
        st.divider()

    # ── CVEs ──────────────────────────────────────────────────────────────────
    if cves:
        st.subheader(f"🛡️ CVEs ({len(cves)} found)")
        for cve in cves[:30]:
            if isinstance(cve, dict):
                cid   = cve.get("cve_id") or cve.get("id", "")
                cvss  = cve.get("cvss") or cve.get("score", "")
                desc  = cve.get("description", "")
                tech  = cve.get("technology") or cve.get("affected", "")
                score = float(cvss) if cvss else 0
                sev   = "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
                icon  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(sev, "⚪")
                with st.expander(f"{icon} {cid}  (CVSS {cvss})" + (f" — {tech}" if tech else ""), expanded=False):
                    if desc:
                        st.write(desc)
            else:
                st.markdown(f"• {cve}")
        if len(cves) > 30:
            st.caption(f"… and {len(cves)-30} more CVEs")
        st.divider()

    # ── APT / Threat actor mapping ────────────────────────────────────────────
    if apt_md and apt_md.strip():
        st.subheader("👾 APT & Threat Actor Mapping")
        st.markdown(apt_md)
        st.divider()

    # ── Attack vectors ────────────────────────────────────────────────────────
    if atk_md and atk_md.strip():
        st.subheader("⚔️ Attack Vectors")
        st.markdown(atk_md)
        st.divider()

    # ── Remediation priority ──────────────────────────────────────────────────
    if remed:
        st.subheader("🛠️ Remediation Priority List")
        for i, item in enumerate(remed, 1):
            if isinstance(item, dict):
                title = item.get("title") or item.get("name", f"Item {i}")
                sev   = item.get("severity") or item.get("priority", "")
                desc  = item.get("description") or item.get("action", "")
                icon  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(sev, "⚪")
                with st.expander(f"{i}. {icon} {title}", expanded=False):
                    if sev:  st.markdown(f"**Priority:** {sev}")
                    if desc: st.write(desc)
            else:
                st.markdown(f"{i}. {item}")


# ─── Phase 5: Risk Assessment ─────────────────────────────────────────────────

def display_phase5(data: Dict[str, Any]):
    st.header("📊 Risk Assessment & Categorization")
    # ✅ FIX: Check for error first, then empty data
    if not data:
        st.warning("No data available for this phase.")
        return
    if 'error' in data:
        st.error(f"❌ Phase 5 Analysis Failed: {data['error']}")
        return

    biz_risk  = data.get("business_risk", {})
    inf_risk  = data.get("infrastructure_risk", {})
    app_risk  = data.get("application_risk", {})
    impact    = data.get("business_impact", {})
    matrix    = data.get("risk_matrix", {})
    multi     = data.get("multidimensional_score", {})
    action    = data.get("action_plan", {})
    threat    = data.get("threat_actor_profile", {})
    exec_sum  = data.get("executive_summary", "")

    # ── Executive summary ─────────────────────────────────────────────────────
    if exec_sum:
        st.subheader("📝 Executive Summary")
        st.markdown(exec_sum)
        st.divider()

    # ── Overall risk score ────────────────────────────────────────────────────
    st.subheader("🎯 Overall Risk Score")
    score = multi.get("overall_risk_score") or matrix.get("composite_risk_score", 0)
    level = multi.get("risk_rating") or matrix.get("risk_level", "Unknown")
    icon  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(level, "⚪")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk Score",  f"{score}/100")
    c2.metric("Risk Level",  f"{icon} {level}")
    c3.metric("Assessed",    str(data.get("assessment_date",""))[:10])
    st.progress(min(int(score), 100) / 100)
    st.divider()

    # ── Risk by domain ────────────────────────────────────────────────────────
    st.subheader("📋 Risk by Domain")
    c1, c2, c3 = st.columns(3)
    for col, (label, risk) in zip([c1, c2, c3], [
        ("Business",       biz_risk),
        ("Infrastructure", inf_risk),
        ("Application",    app_risk),
    ]):
        rl   = risk.get("risk_level", "Unknown")
        rs   = risk.get("risk_score", "")
        icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(rl, "⚪")
        col.metric(label, f"{icon} {rl}", delta=f"Score: {rs}" if rs else None, delta_color="off")
    st.divider()

    # ── Risk detail per domain ────────────────────────────────────────────────
    for label, risk in [("Business Risk", biz_risk), ("Infrastructure Risk", inf_risk), ("Application Risk", app_risk)]:
        if not risk:
            continue
        with st.expander(f"📂 {label} — Details", expanded=False):
            for k, v in risk.items():
                if v and k != "risk_level":
                    _kv(k.replace("_", " ").title(), v)
    st.divider()

    # ── Business impact ───────────────────────────────────────────────────────
    if impact:
        st.subheader("💼 Business Impact")
        c1, c2 = st.columns(2)
        with c1:
            _kv("Financial Risk",      impact.get("financial_risk"))
            _kv("Operational Impact",  impact.get("operational_impact"))
            _kv("Reputational Risk",   impact.get("reputational_risk"))
        with c2:
            _kv("Data Breach Risk",    impact.get("data_breach_risk"))
            _kv("Regulatory Risk",     impact.get("regulatory_risk"))
            _kv("Potential Impact",    impact.get("potential_impact"))
        st.divider()

    # ── Threat actor profile ──────────────────────────────────────────────────
    if threat:
        st.subheader("👾 Threat Actor Profile")
        for k, v in threat.items():
            if v:
                _kv(k.replace("_", " ").title(), v)
        st.divider()

    # ── Action plan ───────────────────────────────────────────────────────────
    if action:
        st.subheader("🛠️ Action Plan")
        for phase_label, items in action.items():
            if not items:
                continue
            st.markdown(f"**{phase_label.replace('_', ' ').title()}**")
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        title = item.get("title") or item.get("action") or item.get("name", "")
                        desc  = item.get("description") or item.get("detail", "")
                        prio  = item.get("priority") or item.get("severity", "")
                        icon  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(prio, "•")
                        st.markdown(f"{icon} **{title}**")
                        if desc:
                            st.caption(desc)
                    else:
                        st.markdown(f"• {item}")
            elif isinstance(items, str):
                st.write(items)
        st.divider()

    # ── Risk matrix dimensions ────────────────────────────────────────────────
    dims = matrix.get("dimensions", {})
    if dims:
        st.subheader("📐 Risk Matrix Dimensions")
        for dim, val in dims.items():
            _kv(dim.replace("_", " ").title(), val)
