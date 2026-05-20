#!/usr/bin/env python3
"""
Dynamic Display Templates - Real-time rendering of phase data
Provides instant display of data as it arrives from phases
"""

import streamlit as st
from typing import Dict, Any, List, Optional
import pandas as pd
from datetime import datetime


class DynamicDisplayTemplate:
    """Base template for dynamic data display"""
    
    @staticmethod
    def render_metric_card(label: str, value: Any, icon: str = "📊", color: str = "blue"):
        """Render a metric card"""
        col1, col2 = st.columns([1, 3])
        with col1:
            st.markdown(f"## {icon}")
        with col2:
            st.metric(label, value)
    
    @staticmethod
    def render_section(title: str, data: Dict[str, Any], icon: str = "📋"):
        """Render a data section with expander"""
        with st.expander(f"{icon} {title}", expanded=True):
            if isinstance(data, dict):
                if data:
                    st.json(data)
                else:
                    st.info("No data available")
            elif isinstance(data, list):
                if data:
                    st.write(data)
                else:
                    st.info("No data available")
            else:
                st.write(data)
    
    @staticmethod
    def render_table(title: str, data: List[Dict], icon: str = "📊"):
        """Render data as table"""
        st.subheader(f"{icon} {title}")
        if data and isinstance(data, list) and len(data) > 0:
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No data available")
    
    @staticmethod
    def render_status_badge(status: str, label: str = "Status"):
        """Render status badge"""
        status_colors = {
            'completed': '🟢',
            'in_progress': '🟡',
            'pending': '⚪',
            'error': '🔴',
            'success': '✅',
            'warning': '⚠️',
            'critical': '🚨'
        }
        icon = status_colors.get(status.lower(), '❓')
        st.markdown(f"**{label}:** {icon} {status}")


class Phase1Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 1: Business Intelligence"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 1 data"""
        st.header("🏢 Phase 1: Business Domain Understanding")
        
        if not data or 'error' in data:
            st.error(f"Phase 1 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            company_name = data.get('company_name', 'N/A')
            st.metric("Company", company_name[:20] + "..." if len(str(company_name)) > 20 else company_name)
        
        with col2:
            domain = data.get('domain', 'N/A')
            st.metric("Domain", domain)
        
        with col3:
            emails = len(data.get('hunter_io', {}).get('emails', []))
            st.metric("Emails Found", emails)
        
        with col4:
            timestamp = data.get('analysis_timestamp', 'N/A')
            st.metric("Timestamp", str(timestamp)[:10])
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Hunter.io", "Host.io", "AbstractAPI", "WHOIS", "Scraped Data", "AI Analysis"])
        
        with tabs[0]:
            Phase1Display.render_section("Hunter.io Results", data.get('hunter_io', {}), "🎯")
        
        with tabs[1]:
            Phase1Display.render_section("Host.io Results", data.get('host_io', {}), "🌐")
        
        with tabs[2]:
            Phase1Display.render_section("AbstractAPI Results", data.get('abstractapi_company', {}), "🏢")
        
        with tabs[3]:
            Phase1Display.render_section("WHOIS Information", data.get('whois_data', {}), "📋")
        
        with tabs[4]:
            Phase1Display.render_section("Scraped Data", data.get('scraped_data', {}), "🕷️")
        
        with tabs[5]:
            ai_analysis = data.get('ai_analysis', {})
            if ai_analysis:
                for key, value in ai_analysis.items():
                    Phase1Display.render_section(key.replace('_', ' ').title(), value, "🤖")
            else:
                st.info("No AI analysis available")


class Phase2Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 2: Infrastructure Discovery"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 2 data"""
        st.header("🌐 Phase 2: Infrastructure Discovery")
        
        if not data or 'error' in data:
            st.error(f"Phase 2 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            subdomains = len(data.get('subdomains', []))
            st.metric("Subdomains", subdomains)
        
        with col2:
            ips = len(data.get('ip_addresses', []))
            st.metric("IP Addresses", ips)
        
        with col3:
            ssl_info = data.get('ssl_analysis', {})
            tls_versions = len(ssl_info.get('tls_versions_supported', []))
            st.metric("TLS Versions", tls_versions)
        
        with col4:
            asn_info = len(data.get('asn_info', {}))
            st.metric("ASN Records", asn_info)
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Subdomains", "IP Addresses", "SSL/TLS", "ASN Info"])
        
        with tabs[0]:
            subdomains = data.get('subdomains', [])
            if subdomains:
                st.write(f"**Found {len(subdomains)} subdomains:**")
                for subdomain in subdomains[:20]:
                    st.code(subdomain)
                if len(subdomains) > 20:
                    st.info(f"... and {len(subdomains) - 20} more")
            else:
                st.info("No subdomains found")
        
        with tabs[1]:
            ips = data.get('ip_addresses', [])
            if ips:
                st.write(f"**Found {len(ips)} IP addresses:**")
                for ip in ips:
                    st.code(ip)
            else:
                st.info("No IP addresses found")
        
        with tabs[2]:
            Phase2Display.render_section("SSL/TLS Analysis", data.get('ssl_analysis', {}), "🔒")
        
        with tabs[3]:
            Phase2Display.render_section("ASN Information", data.get('asn_info', {}), "🌍")


class Phase3Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 3: Application Landscape"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 3 data"""
        st.header("🖥️ Phase 3: Application Landscape Assessment")
        
        if not data or 'error' in data:
            st.error(f"Phase 3 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            app_discovery = data.get('1_application_discovery', {})
            status = app_discovery.get('status', 'Unknown')
            st.metric("App Status", status)
        
        with col2:
            tech_stack = data.get('2_web_server_stack', {})
            cms = tech_stack.get('cms', [])
            st.metric("CMS Detected", len(cms))
        
        with col3:
            frameworks = tech_stack.get('frameworks', [])
            st.metric("Frameworks", len(frameworks))
        
        with col4:
            api_discovery = data.get('8_api_discovery', {})
            apis = api_discovery.get('api_endpoints', [])
            st.metric("API Endpoints", len(apis))
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Application", "Tech Stack", "Security", "APIs", "Admin Panels"])
        
        with tabs[0]:
            Phase3Display.render_section("Application Discovery", data.get('1_application_discovery', {}), "🔍")
        
        with tabs[1]:
            Phase3Display.render_section("Web Server Stack", data.get('2_web_server_stack', {}), "⚙️")
        
        with tabs[2]:
            security = data.get('7_security_posture', {})
            col1, col2 = st.columns(2)
            with col1:
                Phase3Display.render_section("Security Headers", security.get('security_headers', {}), "🔐")
            with col2:
                Phase3Display.render_section("Cookies", security.get('cookie_security', []), "🍪")
        
        with tabs[3]:
            Phase3Display.render_section("API Discovery", data.get('8_api_discovery', {}), "🔌")
        
        with tabs[4]:
            admin_panels = data.get('7_security_posture', {}).get('admin_panels', [])
            if admin_panels:
                st.warning(f"⚠️ Found {len(admin_panels)} admin panels")
                for panel in admin_panels:
                    status_icon = "🔓" if panel.get('access') == 'OPEN' else "🔒"
                    st.write(f"{status_icon} {panel.get('path')} - {panel.get('status')}")
            else:
                st.success("✅ No exposed admin panels found")


class Phase4Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 4: Vulnerability Correlation"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 4 data"""
        st.header("🔗 Phase 4: Vulnerability Correlation & Threat Intelligence")
        
        if not data or 'error' in data:
            st.error(f"Phase 4 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Risk score and summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            risk_score = data.get('overall_risk_score', 0)
            st.metric("Risk Score", f"{risk_score}/100")
        
        with col2:
            summary = data.get('summary', {})
            total_vulns = summary.get('total', 0)
            st.metric("Total Vulnerabilities", total_vulns)
        
        with col3:
            critical = summary.get('critical_count', 0)
            st.metric("Critical", critical, delta=None, delta_color="off")
        
        with col4:
            high = summary.get('high_count', 0)
            st.metric("High", high, delta=None, delta_color="off")
        
        st.divider()
        
        # Vulnerability breakdown
        col1, col2, col3 = st.columns(3)
        with col1:
            medium = summary.get('medium_count', 0)
            st.metric("Medium", medium)
        with col2:
            low = summary.get('low_count', 0)
            st.metric("Low", low)
        with col3:
            st.metric("Risk Level", "🔴 Critical" if risk_score >= 80 else "🟠 High" if risk_score >= 60 else "🟡 Medium" if risk_score >= 40 else "🟢 Low")
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Vulnerabilities", "MITRE Mapping", "Threat Actors", "Attack Chains"])
        
        with tabs[0]:
            vulns = data.get('vulnerabilities', [])
            if vulns:
                st.write(f"**Found {len(vulns)} vulnerabilities:**")
                for vuln in vulns[:10]:
                    severity = vuln.get('severity', 'Unknown')
                    severity_icon = "🔴" if severity == "Critical" else "🟠" if severity == "High" else "🟡" if severity == "Medium" else "🟢"
                    st.write(f"{severity_icon} **{vuln.get('title', 'Unknown')}** - {severity}")
                if len(vulns) > 10:
                    st.info(f"... and {len(vulns) - 10} more vulnerabilities")
            else:
                st.info("No vulnerabilities found")
        
        with tabs[1]:
            Phase4Display.render_section("MITRE Mapping", data.get('mitre_mapping', {}), "🎯")
        
        with tabs[2]:
            threat_actors = data.get('threat_actors', [])
            if threat_actors:
                st.write(f"**Identified {len(threat_actors)} threat actors:**")
                for actor in threat_actors:
                    st.write(f"• {actor}")
            else:
                st.info("No threat actors identified")
        
        with tabs[3]:
            attack_chains = data.get('attack_chains', [])
            if attack_chains:
                st.write(f"**Found {len(attack_chains)} attack chains:**")
                for chain in attack_chains:
                    st.write(f"• {chain}")
            else:
                st.info("No attack chains identified")


class Phase5Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 5: Risk Assessment"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 5 data"""
        st.header("📊 Phase 5: Risk Assessment & Categorization")
        
        if not data or 'error' in data:
            st.error(f"Phase 5 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Risk overview
        risk_overview = data.get('risk_overview', {})
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            risk_level = risk_overview.get('overall_risk_level', 'Unknown')
            risk_icon = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢"
            st.metric("Risk Level", f"{risk_icon} {risk_level}")
        
        with col2:
            risk_score = risk_overview.get('risk_score', 0)
            st.metric("Risk Score", f"{risk_score}/100")
        
        with col3:
            exposure = risk_overview.get('exposure_level', 'Unknown')
            st.metric("Exposure", exposure)
        
        with col4:
            findings = len(risk_overview.get('key_findings', []))
            st.metric("Key Findings", findings)
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Overview", "Assets", "Threats", "Compliance", "Business Impact", "Recommendations"])
        
        with tabs[0]:
            st.subheader("Risk Overview")
            for finding in risk_overview.get('key_findings', []):
                st.write(f"• {finding}")
        
        with tabs[1]:
            Phase5Display.render_section("Asset Risks", data.get('asset_risks', []), "🏗️")
        
        with tabs[2]:
            Phase5Display.render_section("Threat Landscape", data.get('threat_landscape', {}), "⚔️")
        
        with tabs[3]:
            Phase5Display.render_section("Compliance Status", data.get('compliance_status', {}), "✅")
        
        with tabs[4]:
            business_impact = data.get('business_impact', {})
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Financial Risk", business_impact.get('financial_risk', 'Unknown'))
                st.metric("Operational Impact", business_impact.get('operational_impact', 'Unknown'))
            with col2:
                st.metric("Reputational Risk", business_impact.get('reputational_risk', 'Unknown'))
                st.write(f"**Potential Impact:** {business_impact.get('potential_impact', 'Unknown')}")
        
        with tabs[5]:
            recommendations = data.get('recommendations', [])
            if recommendations:
                st.write(f"**{len(recommendations)} Recommendations:**")
                for rec in recommendations:
                    priority = rec.get('priority', 'Unknown')
                    priority_icon = "🚨" if priority == "Critical" else "🔴" if priority == "High" else "🟡" if priority == "Medium" else "🟢"
                    st.write(f"{priority_icon} **{rec.get('title', 'Unknown')}** ({rec.get('timeline', 'N/A')})")
                    st.write(f"   {rec.get('description', '')}")
            else:
                st.info("No recommendations available")


def render_phase_data(phase_num: int, data: Dict[str, Any]):
    """Render phase data based on phase number"""
    if phase_num == 1:
        Phase1Display.render(data)
    elif phase_num == 2:
        Phase2Display.render(data)
    elif phase_num == 3:
        Phase3Display.render(data)
    elif phase_num == 4:
        Phase4Display.render(data)
    elif phase_num == 5:
        Phase5Display.render(data)
    else:
        st.error(f"Unknown phase: {phase_num}")
