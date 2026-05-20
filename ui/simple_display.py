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

def display_correlation_simple(data: Dict[str, Any]):
    st.header("🔗 Vulnerability Correlation & Threat Intelligence")
    if not data:
        st.warning("No data available for Phase 4.")
        return
    if "error" in data:
        st.error(f"Phase 4 failed: {data['error']}")
        return

    summary = data.get("summary", {})
    vulns   = data.get("vulnerabilities", data.get("security_issues", []))
    mitre   = data.get("mitre_mapping", {})
    actors  = data.get("threat_actors", [])
    chains  = data.get("attack_chains", data.get("attack_vectors", []))
    score   = data.get("overall_risk_score", 0)
    factors = data.get("risk_factors", [])

    # Summary metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Risk Score",  f"{score}/100")
    c2.metric("Total",       summary.get("total", len(vulns)))
    c3.metric("🔴 Critical", summary.get("critical_count", 0))
    c4.metric("🟠 High",     summary.get("high_count", 0))
    c5.metric("🟡 Medium",   summary.get("medium_count", 0))
    st.progress(min(score, 100) / 100)
    st.divider()

    # Risk factors narrative
    if factors:
        with st.expander("📋 Risk Factors", expanded=True):
            for f in factors:
                st.markdown(f"• {f}")

    # Vulnerabilities
    if vulns:
        with st.expander(f"🚨 Vulnerabilities ({len(vulns)} found)", expanded=True):
            for v in vulns:
                sev  = v.get("severity", "Low")
                icon = _severity_icon(sev)
                title = v.get("title", "Unknown")
                src   = v.get("source", "")
                desc  = v.get("description", "")
                with st.container():
                    st.markdown(f"{icon} **{title}** — {sev}" + (f"  *(source: {src})*" if src else ""))
                    if desc:
                        st.caption(f"  {desc}")

    # MITRE ATT&CK mapping
    if mitre:
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

    # Threat actors
    if actors:
        with st.expander(f"👾 Threat Actors ({len(actors)} identified)", expanded=False):
            for actor in actors:
                if isinstance(actor, dict):
                    name = actor.get("name", "Unknown")
                    mot  = actor.get("motivation", "")
                    like = actor.get("likelihood", "")
                    st.markdown(f"• **{name}**" + (f" — {mot}" if mot else "") + (f"  (likelihood: {like})" if like else ""))
                else:
                    st.markdown(f"• {actor}")

    # Attack chains
    if chains:
        with st.expander(f"⛓️ Attack Chains ({len(chains)} identified)", expanded=False):
            for chain in chains:
                if isinstance(chain, dict):
                    name  = chain.get("name", "Unknown")
                    sev   = chain.get("severity", "")
                    steps = chain.get("steps", [])
                    icon  = _severity_icon(sev)
                    st.markdown(f"{icon} **{name}**")
                    for i, step in enumerate(steps, 1):
                        st.markdown(f"  {i}. {step}")
                else:
                    st.markdown(f"• {chain}")


# ── Phase 5: Risk Assessment ──────────────────────────────────────────────────

def display_risk_simple(data: Dict[str, Any]):
    st.header("📊 Risk Assessment & Recommendations")
    if not data:
        st.warning("No data available for Phase 5.")
        return
    if "error" in data:
        st.error(f"Phase 5 failed: {data['error']}")
        return

    overview    = data.get("risk_overview", {})
    assets      = data.get("asset_risks", [])
    threat_land = data.get("threat_landscape", {})
    compliance  = data.get("compliance_status", {})
    impact      = data.get("business_impact", {})
    recs        = data.get("recommendations", [])

    # Top-level risk metrics
    level = overview.get("overall_risk_level", "Unknown")
    score = overview.get("risk_score", 0)
    icon  = _risk_icon(level)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Level",   f"{icon} {level}")
    c2.metric("Risk Score",   f"{score}/100")
    c3.metric("Exposure",     overview.get("exposure_level", "Unknown"))
    c4.metric("Findings",     len(overview.get("key_findings", [])))
    st.progress(min(score, 100) / 100)
    st.divider()

    # Key findings
    findings = overview.get("key_findings", [])
    if findings:
        with st.expander("🔍 Key Findings", expanded=True):
            for f in findings:
                st.markdown(f"• {f}")

    # Recommendations (most important — expanded by default)
    if recs:
        with st.expander(f"💡 Recommendations ({len(recs)})", expanded=True):
            for rec in recs:
                prio  = rec.get("priority", "Low")
                icon  = _severity_icon(prio)
                title = rec.get("title", "")
                tl    = rec.get("timeline", "")
                desc  = rec.get("description", "")
                action = rec.get("action", "")
                imp   = rec.get("impact", "")
                st.markdown(f"{icon} **{title}**" + (f"  *(Timeline: {tl})*" if tl else ""))
                if desc:   st.caption(f"  Issue: {desc}")
                if action: st.caption(f"  Action: {action}")
                if imp:    st.caption(f"  Impact: {imp}")
                st.markdown("---")

    # Business impact
    if impact:
        with st.expander("💼 Business Impact", expanded=False):
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

    # Compliance status
    if compliance:
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

    # Asset risks
    if assets:
        with st.expander(f"🏗️ Asset Risks ({len(assets)} assets)", expanded=False):
            for asset in assets:
                rl   = asset.get("risk_level", "Low")
                icon = _risk_icon(rl)
                name = asset.get("name", "Unknown")
                atype = asset.get("type", "")
                st.markdown(f"{icon} **{name}**" + (f"  ({atype})" if atype else ""))
                vulns = asset.get("vulnerabilities", [])
                if vulns:
                    for v in vulns:
                        st.markdown(f"  ⚠️ {v}")

    # Threat landscape
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
