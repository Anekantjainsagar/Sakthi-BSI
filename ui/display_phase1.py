"""
Display functions for Phase 1: Business Domain Understanding
"""

import streamlit as st
from typing import Dict, Any


def display_business_domain_results(data: Dict[str, Any]):
    """Enhanced display for Phase 1 business domain analysis"""
    st.header("🏢 Business Domain Understanding")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Display API Results
    st.subheader("📊 API Collected Data")
    
    api_tabs = st.tabs(["Hunter.io Emails", "Host.io Domain Info", "AbstractAPI Company"])
    
    # TAB 1: Hunter.io
    with api_tabs[0]:
        _display_hunter_io_tab(data)
    
    # TAB 2: Host.io
    with api_tabs[1]:
        _display_hostio_tab(data)
    
    # TAB 3: AbstractAPI Company
    with api_tabs[2]:
        _display_abstractapi_tab(data)
    
    st.markdown("---")
    
    # Data Collection Summary
    _display_data_collection_summary(data)
    
    st.markdown("---")
    
    # WHOIS Information
    _display_whois_information(data)
    
    st.markdown("---")
    
    # AI Analysis
    _display_ai_analysis(data)


def _display_hunter_io_tab(data: Dict[str, Any]):
    """Display Hunter.io email discovery results"""
    st.markdown("### 📧 Hunter.io - Email Discovery")
    hunter_data = data.get('hunter_io', {})
    
    if hunter_data and hunter_data.get('emails'):
        emails = hunter_data.get('emails', [])
        st.success(f"✅ Found {len(emails)} email addresses")
        
        for email_obj in emails[:10]:
            with st.expander(f"📧 {email_obj.get('value', 'N/A')}", expanded=False):
                col1, col2 = st.columns(2)
                with col1:
                    st.text(f"Type: {email_obj.get('type', 'Unknown')}")
                    st.text(f"First Name: {email_obj.get('first_name', 'N/A')}")
                    st.text(f"Last Name: {email_obj.get('last_name', 'N/A')}")
                with col2:
                    st.text(f"Position: {email_obj.get('position', 'N/A')}")
                    st.text(f"Department: {email_obj.get('department', 'N/A')}")
                    confidence = email_obj.get('confidence', 0)
                    st.progress(confidence / 100)
                    st.caption(f"Confidence: {confidence}%")
    else:
        st.info("No email data available from Hunter.io")


def _display_hostio_tab(data: Dict[str, Any]):
    """Display Host.io domain information"""
    st.markdown("### 🌐 Host.io - Domain Information")
    hostio_data = data.get('host_io', {})

    if hostio_data and hostio_data.get('status') == 'success':
        web = hostio_data.get('web', {})
        dns = hostio_data.get('dns', {})
        ipinfo = hostio_data.get('ipinfo', {})
        related = hostio_data.get('related', {})

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**🌍 Web Info**")
            st.text(f"Domain: {web.get('domain', 'N/A')}")
            st.text(f"IP Address: {web.get('ip', 'N/A')}")
            st.text(f"Global Rank: {web.get('rank', 'N/A')}")
            st.text(f"Contact Email: {web.get('email', 'N/A')}")

            for ip, info in ipinfo.items():
                asn = info.get('asn', {})
                st.markdown("**☁️ Hosting Provider**")
                st.text(f"Provider: {asn.get('name', 'N/A')}")
                st.text(f"ASN: {asn.get('asn', 'N/A')}")
                st.text(f"Type: {asn.get('type', 'N/A')}")

        with col2:
            st.markdown("**📡 DNS Records**")
            a_records = dns.get('a', [])
            if a_records:
                st.text(f"A Records: {', '.join(a_records)}")
            mx_records = dns.get('mx', [])
            if mx_records:
                st.markdown("**MX (Mail Servers):**")
                for mx in mx_records:
                    st.text(f"  {mx}")
            ns_records = dns.get('ns', [])
            if ns_records:
                st.markdown("**NS (Nameservers):**")
                for ns in ns_records:
                    st.text(f"  {ns}")

        # Brand/subsidiary domains
        links = web.get('links', [])
        skip_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
                       'instagram.com', 'google.com', 'pinterest.com']
        brand_domains = [l for l in links if not any(s in l for s in skip_domains)]
        if brand_domains:
            st.markdown("**🏷️ Brand / Subsidiary Domains:**")
            cols = st.columns(3)
            for i, domain_link in enumerate(brand_domains):
                with cols[i % 3]:
                    st.markdown(f"🔗 `{domain_link}`")

        # Related stats
        st.markdown("**📊 Domain Stats**")
        col1, col2, col3 = st.columns(3)
        with col1:
            backlinks = related.get('backlinks', [{}])
            st.metric("Backlinks", backlinks[0].get('count', 0) if backlinks else 0)
        with col2:
            redirects = related.get('redirects', [{}])
            st.metric("Redirects", redirects[0].get('count', 0) if redirects else 0)
        with col3:
            ip_count = related.get('ip', [{}])
            st.metric("IP Co-hosts", ip_count[0].get('count', 0) if ip_count else 0)
    else:
        st.info("No Host.io data available")


def _display_abstractapi_tab(data: Dict[str, Any]):
    """Display AbstractAPI company enrichment"""
    st.markdown("### 🏢 AbstractAPI - Company Enrichment")
    st.caption("⭐ Primary source for Industry, Employee Count, and Founded Year")
    abstract_data = data.get('abstractapi_company', {})
    
    if abstract_data:
        col1, col2 = st.columns(2)
        
        with col1:
            st.text(f"Company Name: {abstract_data.get('name', 'N/A')}")
            st.text(f"Domain: {abstract_data.get('domain', 'N/A')}")
            st.text(f"Country: {abstract_data.get('country', 'N/A')}")
            st.text(f"Locality: {abstract_data.get('locality', 'N/A')}")
        
        with col2:
            industry = abstract_data.get('industry', 'N/A')
            st.markdown(f"**🏭 Industry:** {industry}")
            st.caption("(Primary source)")
            
            employees = abstract_data.get('employees_count', 'N/A')
            st.markdown(f"**👥 Employees:** {employees}")
            st.caption("(Only location for employee data)")
            
            founded = abstract_data.get('year_founded', 'N/A')
            st.markdown(f"**📅 Founded:** {founded}")
            st.caption("(Primary source)")
        
        linkedin = abstract_data.get('linkedin_url', '')
        if linkedin:
            if not linkedin.startswith('http'):
                linkedin = 'https://' + linkedin
            st.markdown(f"**🔗 LinkedIn:** [View Profile]({linkedin})")
    else:
        st.info("No company data available from AbstractAPI")


def _display_data_collection_summary(data: Dict[str, Any]):
    """Display data collection summary"""
    with st.expander("🔍 Data Collection Summary"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            whois_status = "✅" if data.get('whois_data', {}).get('domain_age_years') else "❌"
            st.metric("WHOIS Data", whois_status)
        
        with col2:
            scrape_status = "✅" if data.get('scraped_data', {}).get('success') else "❌"
            st.metric("Web Scraping", scrape_status)
        
        with col3:
            search_status = "✅" if data.get('search_data', {}).get('revenue') or data.get('search_data', {}).get('market_cap') else "⚠️"
            st.metric("Google Search", search_status)
        
        search_data = data.get('search_data', {})
        if search_data:
            st.markdown("**Google Search Results:**")
            if search_data.get('revenue'):
                st.success(f"💰 Revenue: {search_data.get('revenue')}")
            if search_data.get('revenue_growth'):
                st.success(f"📈 Growth: {search_data.get('revenue_growth')}")
            if search_data.get('market_cap'):
                st.success(f"💵 Market Cap: {search_data.get('market_cap')}")
            if search_data.get('ticker'):
                st.success(f"📊 Ticker: {search_data.get('ticker')}")
            if search_data.get('headquarters'):
                st.success(f"🏢 HQ: {search_data.get('headquarters')}")
            compliance_found = search_data.get('compliance_found', [])
            if compliance_found:
                st.success(f"✅ Compliance Found: {', '.join(compliance_found)}")


def _display_whois_information(data: Dict[str, Any]):
    """Display WHOIS domain intelligence"""
    st.subheader("📋 Domain Intelligence")
    whois_data = data.get('whois_data', {})
    
    if whois_data and not whois_data.get('error'):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Domain Age**")
            st.metric("Years", f"{whois_data.get('domain_age_years', 'Unknown')} years")
            st.markdown("**Registrar**")
            st.write(whois_data.get('registrar', 'Unknown'))
        
        with col2:
            st.markdown("**Created**")
            st.write(whois_data.get('creation_date', 'Unknown')[:10])
            st.markdown("**Country**")
            st.write(whois_data.get('country', 'Unknown'))
        
        with col3:
            st.markdown("**Organization**")
            st.write(whois_data.get('organization', 'None'))
            st.markdown("**Expires**")
            st.write(whois_data.get('expiration_date', 'Unknown')[:10])


def _display_ai_analysis(data: Dict[str, Any]):
    """Display AI analysis results"""
    ai_analysis = data.get('ai_analysis', {})
    
    if ai_analysis.get('analysis_method') == 'error':
        st.error("❌ AI Analysis Failed")
        st.warning(f"**Error:** {ai_analysis.get('error_message', 'Unknown error')}")
        return
    
    # Company Overview
    st.subheader("🏢 Company Profile")
    overview = ai_analysis.get('company_overview', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"**Primary Business**")
        st.info(overview.get('primary_business', 'Unknown'))
        st.markdown(f"**Industry:** {overview.get('industry_vertical', 'Unknown')}")
        st.markdown(f"**Business Model:** {overview.get('business_model', 'Unknown')}")
    
    with col2:
        st.markdown(f"**Founded:** {overview.get('founded_year', 'Unknown')}")
        hq = overview.get('headquarters', '')
        hq_display = hq if hq and 'not specified' not in hq.lower() and 'not found' not in hq.lower() else 'Not found publicly'
        st.markdown(f"**Headquarters:** {hq_display}")
        st.markdown(f"**Maturity:** {overview.get('company_maturity', 'Unknown')}")
        st.markdown(f"**Size:** {overview.get('company_size', 'Unknown')}")
    
    st.markdown("---")
    
    # Financial Intelligence
    _display_financial_intelligence(ai_analysis)
    
    st.markdown("---")
    
    # Leadership
    _display_leadership(ai_analysis)
    
    # Products & Services
    _display_products_services(ai_analysis)
    
    st.markdown("---")
    
    # Customer Base
    _display_customer_base(ai_analysis)
    
    st.markdown("---")
    
    # Threat Intelligence
    _display_threat_intelligence(ai_analysis)
    
    st.markdown("---")
    
    # Regulatory Compliance
    _display_regulatory_compliance(ai_analysis)
    
    st.markdown("---")
    
    # Data Quality Summary
    with st.expander("📊 Analysis Metadata"):
        quality = ai_analysis.get('data_quality', {})
        st.json({
            "Revenue Source": quality.get('revenue_source', 'Unknown'),
            "Confidence Score": f"{quality.get('confidence_score', 0)}/10",
            "Analysis Timestamp": data.get('analysis_timestamp', 'Unknown')
        })


def _display_financial_intelligence(ai_analysis: Dict[str, Any]):
    """Display financial intelligence section"""
    st.subheader("💰 Financial Intelligence")
    financial = ai_analysis.get('financial_intelligence', {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        revenue = financial.get('annual_revenue') or 'Unknown'
        revenue_year = financial.get('revenue_year', '')

        if not revenue or any(x in str(revenue).lower() for x in ['not available', 'unknown', 'not found', 'n/a']):
            st.metric("Annual Revenue", "📊 N/A")
        else:
            st.metric("Annual Revenue", revenue)
            if revenue_year:
                st.caption(f"Year: {revenue_year}")
        
        source = ai_analysis.get('data_quality', {}).get('revenue_source', 'Unknown').lower()
        if 'search' in source or 'google' in source:
            st.success("✅ From Google")
        elif 'ai' in source or 'knowledge' in source:
            st.info("🤖 From AI")
        else:
            st.warning("⚠️ Estimated")
    
    with col2:
        quarterly = financial.get('quarterly_revenue', 'N/A')
        if quarterly and quarterly != 'N/A':
            st.metric("Quarterly Revenue", quarterly)
        else:
            st.metric("Quarterly Revenue", "📊 N/A")
    
    with col3:
        company_type = financial.get('company_type', 'Unknown')
        is_public = financial.get('is_public', False)
        
        if is_public:
            ticker = financial.get('ticker_symbol', 'N/A')
            st.metric("Company Type", "📈 Public")
            st.caption(f"Ticker: {ticker}")
        else:
            st.metric("Company Type", "🔒 Private")
    
    with st.expander("📊 Additional Financial Details"):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown(f"**Revenue Growth:** {financial.get('revenue_growth', 'N/A')}")
            st.markdown(f"**Profitability:** {financial.get('profitability', 'Unknown')}")

        with col2:
            st.markdown(f"**Market Cap:** {financial.get('market_cap', 'N/A')}")
            st.markdown(f"**Funding Raised:** {financial.get('funding_raised', 'N/A')}")


def _display_leadership(ai_analysis: Dict[str, Any]):
    """Display leadership information"""
    st.subheader("👔 Leadership")
    leadership = ai_analysis.get('leadership', {})
    if leadership and leadership.get('ceo') != 'Unknown':
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**CEO:** {leadership.get('ceo', 'Unknown')}")
        with col2:
            st.markdown(f"**Founder:** {leadership.get('founder', 'Unknown')}")


def _display_products_services(ai_analysis: Dict[str, Any]):
    """Display products and services"""
    st.subheader("🛍️ Products & Services")
    services = ai_analysis.get('services_and_products', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        products = services.get('primary_products', [])
        if products:
            st.markdown("**Primary Products:**")
            for product in products:
                st.write(f"• {product}")
        else:
            st.info("No product information available")
    
    with col2:
        categories = services.get('service_categories', [])
        if categories:
            st.markdown("**Service Categories:**")
            for cat in categories:
                st.write(f"• {cat}")
        
        offerings = services.get('key_offerings', [])
        if offerings:
            st.markdown("**Key Offerings:**")
            for offer in offerings:
                st.write(f"• {offer}")


def _display_customer_base(ai_analysis: Dict[str, Any]):
    """Display customer base information"""
    st.subheader("👥 Customer Base")
    customers = ai_analysis.get('customer_base', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        target = customers.get('target_customers', [])
        if target:
            st.markdown("**Target Customers:**")
            for t in target:
                st.write(f"• {t}")
        
        segments = customers.get('customer_segments', [])
        if segments:
            st.markdown("**Segments:**")
            st.write(", ".join(segments))
    
    with col2:
        markets = customers.get('geographic_markets', [])
        if markets:
            st.markdown("**Geographic Markets:**")
            for market in markets:
                st.write(f"• {market}")
        
        clients = customers.get('notable_clients', [])
        if isinstance(clients, str):
            clients = [] if clients.lower() in ['none', 'n/a', ''] else [clients]
        real_clients = [c for c in clients if c and 'none' not in str(c).lower() and 'not' not in str(c).lower()]
        if real_clients:
            st.markdown("**Notable Clients:**")
            for client in real_clients:
                st.write(f"• {client}")


def _display_threat_intelligence(ai_analysis: Dict[str, Any]):
    """Display threat intelligence"""
    st.subheader("⚠️ Threat Intelligence")
    threat = ai_analysis.get('threat_intelligence', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        apt_groups = threat.get('industry_apt_groups', [])
        if apt_groups:
            st.markdown("**APT Groups Targeting Industry:**")
            st.caption("🤖 AI-suggested based on industry — not verified threat intelligence")
            for apt in apt_groups:
                apt_name = apt.get('name', str(apt)) if isinstance(apt, dict) else str(apt)
                st.error(f"🎯 {apt_name}")
        else:
            st.info("No specific APT groups identified")
    
    with col2:
        assets = threat.get('critical_assets', [])
        if assets:
            st.markdown("**Critical Assets:**")
            for asset in assets:
                st.write(f"• {asset}")
        else:
            st.info("No critical assets identified")


def _display_regulatory_compliance(ai_analysis: Dict[str, Any]):
    """Display regulatory compliance"""
    st.subheader("📋 Regulatory Compliance")
    compliance = ai_analysis.get('regulatory_compliance', {})
    
    rationale = compliance.get('compliance_rationale', '')
    if rationale:
        st.info(f"**Context:** {rationale}")
        st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        confirmed = compliance.get('confirmed_public', [])
        if confirmed:
            st.markdown("**✅ Publicly Confirmed Certifications:**")
            st.caption("Found via public sources / company website")
            for item in confirmed:
                name = item.get('name', item) if isinstance(item, dict) else item
                st.success(f"✔ {name}")
        else:
            st.info("No publicly confirmed certifications found")

        data_protection = compliance.get('data_protection_requirements', [])
        if data_protection:
            st.markdown("**🔒 Data Protection Requirements:**")
            for dp in data_protection:
                st.write(f"• {dp}")

    with col2:
        ai_suggested = compliance.get('ai_suggested', [])
        if ai_suggested:
            st.markdown("**🤖 AI-Suggested Compliance:**")
            st.caption("Based on industry/country — not verified")
            for item in ai_suggested:
                name = item.get('name', item) if isinstance(item, dict) else item
                rationale = item.get('rationale', '') if isinstance(item, dict) else ''
                st.warning(f"⚠️ {name}" + (f" — {rationale}" if rationale else ""))
        else:
            st.info("No AI suggestions available")
