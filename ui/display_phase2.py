"""
Display functions for Phase 2: Infrastructure Discovery
"""

import streamlit as st
from typing import Dict, Any


def display_infrastructure_results(data: Dict[str, Any]):
    """Display infrastructure discovery results"""
    st.header("🌐 Infrastructure Discovery")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    tabs = st.tabs([
        "Network Infrastructure",
        "SSL/TLS Analysis", 
        "Mail Servers",
        "Cloud & ASN",
        "Security Findings",
        "Port Analysis",
        "DNS Information",
        "⚠️ Look-alike Domains"
    ])
    
    with tabs[0]:
        _display_network_infrastructure(data)
    
    with tabs[1]:
        _display_ssl_tls_analysis(data)
    
    with tabs[2]:
        _display_mail_servers(data)
    
    with tabs[3]:
        _display_cloud_asn(data)
    
    with tabs[4]:
        _display_security_findings(data)
    
    with tabs[5]:
        _display_port_analysis(data)
    
    with tabs[6]:
        _display_dns_information(data)
    
    with tabs[7]:
        _display_lookalike_domains(data)


def _display_network_infrastructure(data: Dict[str, Any]):
    """Display network infrastructure section"""
    st.subheader("🔌 Network Infrastructure")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**IPv4 Addresses**")
        ip_count = len(data.get('ip_addresses', []))
        st.text(f"Total: {ip_count}")
        for ip in data.get('ip_addresses', []):
            st.code(ip, language=None)
    
    with col2:
        st.markdown("**IPv6 Addresses**")
        ipv6_count = len(data.get('ipv6_addresses', []))
        st.text(f"Total: {ipv6_count}")
        for ip in data.get('ipv6_addresses', []):
            st.code(ip, language=None)
    
    st.markdown("---")
    
    # Subdomains Section
    st.markdown("**🔍 Discovered Subdomains**")
    subdomains_raw = data.get('subdomains', [])
    if isinstance(subdomains_raw, dict):
        subdomain_list = subdomains_raw.get('subdomains', [])
    elif isinstance(subdomains_raw, list):
        subdomain_list = subdomains_raw
    else:
        subdomain_list = []

    subdomain_list = [s for s in subdomain_list if s and str(s).strip() and s != '']
    subdomain_count = len(subdomain_list)

    if subdomain_count > 0:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Subdomains", subdomain_count)
        with col2:
            unique_subs = len(set(subdomain_list))
            st.metric("Unique Domains", unique_subs)
        with col3:
            mapping_count = len(data.get('subdomain_mapping', {}))
            st.metric("Mapped Subdomains", mapping_count)
        
        st.markdown("---")
        
        with st.expander(f"📋 View All {subdomain_count} Subdomains", expanded=subdomain_count <= 20):
            sorted_subs = sorted(subdomain_list)
            subdomain_cols = st.columns(2)
            for idx, subdomain in enumerate(sorted_subs):
                with subdomain_cols[idx % 2]:
                    if data.get('subdomain_mapping', {}).get(subdomain):
                        ips = data.get('subdomain_mapping', {}).get(subdomain, [])
                        st.success(f"✅ {subdomain} → {', '.join(ips[:2])}")
                    else:
                        st.text(f"• {subdomain}")
    else:
        st.info("No subdomains discovered")
    
    # Subdomain to IP Mapping
    if data.get('subdomain_mapping'):
        st.markdown("---")
        st.markdown("**🗺️ Subdomain → IP Address Mapping**")
        mapping_data = data.get('subdomain_mapping', {})
        if mapping_data:
            shown_count = 0
            for subdomain, ips in list(mapping_data.items())[:10]:
                if ips:
                    st.text(f"• {subdomain} → {', '.join(ips)}")
                    shown_count += 1
            
            if len(mapping_data) > 10:
                st.info(f"+ {len(mapping_data) - 10} more subdomain mappings")


def _display_ssl_tls_analysis(data: Dict[str, Any]):
    """Display SSL/TLS analysis"""
    st.subheader("🔒 SSL/TLS Analysis")
    ssl_analysis = data.get('ssl_analysis', {})
    
    if ssl_analysis:
        cert_info = ssl_analysis.get('certificate_info', {})
        if cert_info:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Certificate Details**")
                if 'subject' in cert_info and isinstance(cert_info['subject'], dict):
                    st.text(f"Common Name: {cert_info['subject'].get('commonName', 'N/A')}")
                elif 'common_name' in cert_info:
                    st.text(f"Common Name: {cert_info.get('common_name', 'N/A')}")

                if 'issuer' in cert_info:
                    if isinstance(cert_info['issuer'], dict):
                        issuer_cn = cert_info['issuer'].get('commonName', cert_info['issuer'].get('organizationName', 'Unknown'))
                        st.text(f"Issuer: {issuer_cn}")
                    else:
                        st.text(f"Issuer: {cert_info['issuer']}")

                not_before = cert_info.get('notBefore') or cert_info.get('not_before', 'N/A')
                not_after = cert_info.get('notAfter') or cert_info.get('not_after', 'N/A')
                st.text(f"Valid From: {not_before}")
                st.text(f"Valid Until: {not_after}")

                days = cert_info.get('days_until_expiry')
                if days is not None:
                    if days < 0:
                        st.error(f"🚨 EXPIRED ({abs(days)} days ago)")
                    elif days < 30:
                        st.warning(f"⚠️ Expiring in {days} days!")
                    else:
                        st.success(f"✅ Valid for {days} more days")

                if cert_info.get('is_wildcard'):
                    st.info("🌐 Wildcard Certificate")

            with col2:
                st.markdown("**Security Features**")
                st.text(f"TLS Version: {ssl_analysis.get('tls_version', 'N/A')}")
                cipher = ssl_analysis.get('cipher_suite', 'N/A')
                if cipher and len(str(cipher)) > 50:
                    cipher = str(cipher)[:50] + "..."
                st.text(f"Cipher Suite: {cipher}")
                if 'key_size' in cert_info:
                    st.text(f"Key Size: {cert_info['key_size']}")
                if 'signature_algorithm' in cert_info:
                    st.text(f"Signature: {cert_info['signature_algorithm']}")

            # SAN domains
            san_list = cert_info.get('san_domains', [])
            if san_list:
                st.markdown(f"**Subject Alternative Names ({len(san_list)} domains)**")
                with st.expander("View all SAN domains"):
                    for san in san_list:
                        st.text(f"• {san}")
        
        # TLS Versions
        if 'tls_versions_supported' in ssl_analysis:
            st.markdown("**Supported TLS Versions**")
            for version in ssl_analysis.get('tls_versions_supported', []):
                st.success(f"✅ {version}")
        
        if 'tls_versions_rejected' in ssl_analysis:
            st.markdown("**Rejected TLS Versions**")
            for version in ssl_analysis.get('tls_versions_rejected', []):
                st.info(f"❌ {version}")
        
        # Vulnerabilities
        if 'vulnerabilities' in ssl_analysis and ssl_analysis['vulnerabilities']:
            st.markdown("**⚠️ SSL/TLS Vulnerabilities**")
            for vuln in ssl_analysis['vulnerabilities']:
                st.warning(f"• {vuln}")
    else:
        st.info("SSL/TLS analysis not available")
    
    st.markdown("---")
    st.subheader("🔒 CertSpotter - SSL Certificate History")
    
    ssl_analysis = data.get('ssl_analysis', {})
    certspotter_data = ssl_analysis.get('certspotter', {})
    
    if certspotter_data and certspotter_data.get('status') == 'success':
        total = certspotter_data.get('total_certificates', 0)
        certs = certspotter_data.get('certificates', [])
        
        st.success(f"✅ Found {total} SSL certificates")
        
        if certs:
            st.markdown(f"**Showing first {len(certs)} certificates:**")
            for idx, cert in enumerate(certs, 1):
                with st.expander(f"🔐 Certificate {idx} - ID: {cert.get('id', 'N/A')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Certificate SHA256:**")
                        st.code(cert.get('cert_sha256', 'N/A'), language="text")
                        st.markdown("**TBS SHA256:**")
                        st.code(cert.get('tbs_sha256', 'N/A'), language="text")
                        st.markdown(f"**Not Before:** {cert.get('not_before', 'N/A')}")
                        st.markdown(f"**Not After:** {cert.get('not_after', 'N/A')}")
                    with col2:
                        st.markdown("**Public Key SHA256:**")
                        st.code(cert.get('pubkey_sha256', 'N/A'), language="text")
                        revoked = cert.get('revoked', False)
                        if revoked:
                            st.error("⚠️ Certificate is REVOKED")
                        else:
                            st.success("✅ Certificate is Valid")
    elif certspotter_data and certspotter_data.get('status') == 'error':
        error_msg = certspotter_data.get('error', 'Unknown error')
        st.warning(f"⚠️ CertSpotter API Error: {error_msg}")
    else:
        st.info("No SSL certificate data available")
    
    st.markdown("---")
    st.subheader("🔍 SSL/TLS Weakness Analysis")
    ssl_weaknesses = data.get('ssl_weaknesses', {})
    if ssl_weaknesses:
        hsts = ssl_weaknesses.get('hsts_missing', False)
        self_signed = ssl_weaknesses.get('self_signed', False)
        weak_tls = ssl_weaknesses.get('weak_tls_versions', [])
        weak_ciphers = ssl_weaknesses.get('weak_ciphers', [])

        if not weak_tls and not weak_ciphers and not hsts and not self_signed:
            st.success("✅ No SSL/TLS weaknesses detected")
        else:
            col1, col2 = st.columns(2)
            with col1:
                if hsts:
                    st.error("🔴 HSTS Not Configured")
                else:
                    st.success("✅ HSTS Enabled")
                if self_signed:
                    st.warning("⚠️ Self-Signed Certificate")
            with col2:
                if weak_tls:
                    for ver in weak_tls:
                        st.error(f"🔴 {ver} supported — deprecated")
                if weak_ciphers:
                    for cipher in weak_ciphers:
                        st.warning(f"⚠️ Weak cipher: {cipher}")
    else:
        st.info("SSL weakness analysis not available")


def _display_mail_servers(data: Dict[str, Any]):
    """Display mail server infrastructure"""
    st.subheader("📧 Mail Server Infrastructure")
    
    mail_servers = data.get('mail_servers', [])
    if mail_servers:
        st.markdown("**MX Records**")
        for server in mail_servers:
            st.text(f"• Priority {server.get('priority')}: {server.get('server')}")
    
    mail_analysis = data.get('mail_server_analysis', {})
    if mail_analysis:
        st.markdown("---")
        st.markdown("**🔐 Email Security (SPF / DMARC / DKIM)**")

        score = mail_analysis.get('email_security_score', 0)
        score_color = "🟢" if score == 3 else ("🟡" if score == 2 else ("🟠" if score == 1 else "🔴"))
        st.metric("Email Security Score", f"{score_color} {score}/3")

        col1, col2, col3 = st.columns(3)
        with col1:
            if mail_analysis.get('spf_configured'):
                st.success("✅ SPF Configured")
                spf = mail_analysis.get('spf_record', '')
                if spf and spf != 'Not configured':
                    st.caption(spf[:80])
            else:
                st.error("❌ SPF Not Found")

        with col2:
            if mail_analysis.get('dmarc_configured'):
                st.success("✅ DMARC Configured")
                dmarc = mail_analysis.get('dmarc_record', '')
                if dmarc and dmarc != 'Not configured':
                    st.caption(dmarc[:80])
            else:
                st.error("❌ DMARC Not Found")

        with col3:
            if mail_analysis.get('dkim_configured'):
                selectors = mail_analysis.get('dkim_selectors_found', [])
                st.success(f"✅ DKIM Found ({', '.join(selectors)})")
            else:
                st.error("❌ DKIM Not Found")

        st.markdown("**Primary Provider:** " + mail_analysis.get('primary_provider', 'Unknown'))


def _display_cloud_asn(data: Dict[str, Any]):
    """Display cloud infrastructure and ASN information"""
    st.subheader("☁️ Cloud Infrastructure & ASN")
    
    cloud_providers = set()
    single_provider = data.get('cloud_provider')
    if single_provider and single_provider != 'Not Detected':
        cloud_providers.add(single_provider)
    
    asn_info = data.get('asn_info', {})
    for ip, info in asn_info.items():
        asn = info.get('asn', '')
        org = info.get('org', '')
        isp = info.get('isp', '')
        
        if 'AS15169' in asn or 'google' in org.lower() or 'google' in isp.lower():
            cloud_providers.add('Google Cloud')
        elif 'AS16509' in asn or 'AS14618' in asn or 'amazon' in org.lower() or 'aws' in org.lower():
            cloud_providers.add('Amazon Web Services')
        elif 'AS8075' in asn or 'microsoft' in org.lower() or 'azure' in org.lower():
            cloud_providers.add('Microsoft Azure')
        elif 'AS13335' in asn or 'cloudflare' in org.lower():
            cloud_providers.add('Cloudflare')
        elif 'AS14061' in asn or 'digitalocean' in org.lower():
            cloud_providers.add('Digital Ocean')
    
    if cloud_providers:
        providers_list = sorted(list(cloud_providers))
        if len(providers_list) == 1:
            st.success(f"**Cloud Provider:** {providers_list[0]}")
        else:
            st.success(f"**Cloud Providers ({len(providers_list)}):** {', '.join(providers_list)}")
    else:
        st.info("**Cloud Provider:** Not Detected")
    
    if asn_info:
        st.markdown("**ASN Information**")
        for ip, info in list(asn_info.items())[:10]:
            with st.expander(f"📍 {ip}", expanded=False):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.text(f"Country: {info.get('country', 'Unknown')}")
                    st.text(f"City: {info.get('city', 'Unknown')}")
                    st.text(f"ASN: {info.get('asn', 'Unknown')}")
                with col2:
                    isp = str(info.get('isp', 'Unknown'))[:40]
                    org = str(info.get('organization', 'Unknown'))[:40]
                    st.text(f"ISP: {isp}")
                    st.text(f"Org: {org}")
                with col3:
                    if info.get('hosting'):
                        st.info("🏢 Hosting Provider")
                    if info.get('proxy'):
                        st.warning("⚠️ Proxy Detected")


def _display_security_findings(data: Dict[str, Any]):
    """Display security findings"""
    st.subheader("⚠️ Security Findings")
    
    blacklisted = data.get('blacklisted_ips', [])
    st.markdown("**🚫 Blacklisted IPs**")
    if blacklisted:
        for item in blacklisted:
            bl = item.get('blacklist', item.get('blacklists', 'Unknown'))
            st.error(f"🚫 {item.get('ip', 'Unknown')} — listed on: {bl}")
    else:
        st.success(f"No blacklisted IPs found")
    
    st.markdown("---")
    mc = data.get('security_misconfigs', {})
    summary = mc.get('summary', {})
    
    if summary.get('total', 0) > 0:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Findings", summary.get('total', 0))
        c2.metric("Critical", summary.get('critical', 0))
        c3.metric("High", summary.get('high', 0))
        c4.metric("Medium", summary.get('medium', 0))
    else:
        st.success("✅ No security misconfigurations detected")


def _display_port_analysis(data: Dict[str, Any]):
    """Display port analysis"""
    st.subheader("🔌 Port Analysis")
    ports = data.get('open_ports', [])
    
    if ports:
        st.markdown(f"**Open Ports Found: {len(ports)}**")
        for port in ports[:20]:
            st.text(f"• Port {port.get('port')}: {port.get('service')} ({port.get('state')})")
        if len(ports) > 20:
            st.info(f"+ {len(ports) - 20} more ports")
    else:
        st.info("No open ports detected")


def _display_dns_information(data: Dict[str, Any]):
    """Display DNS information"""
    st.subheader("📡 DNS Information")
    dns_records = data.get('dns_records', {})
    
    if dns_records:
        for record_type, records in dns_records.items():
            if records:
                st.markdown(f"**{record_type} Records:**")
                for record in records:
                    st.text(f"• {record}")
    else:
        st.info("No DNS records available")


def _display_lookalike_domains(data: Dict[str, Any]):
    """Display look-alike domains"""
    st.subheader("⚠️ Look-alike Domains")
    lookalikes = data.get('lookalike_domains', [])
    
    if lookalikes:
        st.warning(f"Found {len(lookalikes)} potential look-alike domains")
        for domain in lookalikes[:20]:
            st.text(f"• {domain}")
        if len(lookalikes) > 20:
            st.info(f"+ {len(lookalikes) - 20} more domains")
    else:
        st.success("No suspicious look-alike domains detected")
