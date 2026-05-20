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
        
        # Extract CVEs and calculate severity counts
        cves = data.get('cves', [])
        critical_count = sum(1 for c in cves if c.get('severity') == 'CRITICAL')
        high_count = sum(1 for c in cves if c.get('severity') == 'HIGH')
        medium_count = sum(1 for c in cves if c.get('severity') == 'MEDIUM')
        low_count = sum(1 for c in cves if c.get('severity') == 'LOW')
        total_vulns = len(cves)
        
        # Calculate risk score based on CVE severity distribution
        risk_score = min(100, (critical_count * 25 + high_count * 15 + medium_count * 5 + low_count * 1) / max(1, total_vulns))
        
        # Risk score and summary
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Risk Score", f"{int(risk_score)}/100")
        
        with col2:
            st.metric("Total Vulns", total_vulns)
        
        with col3:
            st.metric("🔴 Critical", critical_count)
        
        with col4:
            st.metric("🟠 High", high_count)
        
        with col5:
            st.metric("Risk Level", "🔴 CRITICAL" if risk_score >= 80 else "🟠 HIGH" if risk_score >= 60 else "🟡 MEDIUM" if risk_score >= 40 else "🟢 LOW")
        
        st.divider()
        
        # Vulnerability breakdown
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🟡 Medium", medium_count)
        with col2:
            st.metric("🟢 Low", low_count)
        with col3:
            security_issues = data.get('security_issues', [])
            st.metric("Security Issues", len(security_issues))
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["CVE Details", "Security Issues", "Threat Intelligence", "Attack Vectors"])
        
        with tabs[0]:
            st.subheader("📋 Vulnerability Details")
            if cves:
                st.write(f"**Found {len(cves)} CVEs:**")
                
                # Group by severity
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    severity_cves = [c for c in cves if c.get('severity') == severity]
                    if severity_cves:
                        severity_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
                        with st.expander(f"{severity_icon} {severity} ({len(severity_cves)})"):
                            for cve in severity_cves:
                                col1, col2 = st.columns([1, 4])
                                with col1:
                                    st.write(f"**{cve.get('cve', 'N/A')}**")
                                with col2:
                                    st.write(f"CVSS: {cve.get('cvss', 'N/A')}")
                                    st.write(f"**{cve.get('tech', 'Unknown')}** {cve.get('version', '')}")
                                    st.write(f"CWE: {cve.get('cwe', 'N/A')}")
                                    st.write(cve.get('description', 'No description'))
                                st.divider()
            else:
                st.info("No CVEs found")
        
        with tabs[1]:
            st.subheader("🔍 Security Issues & Misconfigurations")
            security_issues = data.get('security_issues', [])
            if security_issues:
                st.write(f"**Found {len(security_issues)} security issues:**")
                for issue in security_issues:
                    if isinstance(issue, dict):
                        st.write(f"• **{issue.get('title', 'Unknown')}** - {issue.get('severity', 'Unknown')}")
                        st.write(f"  {issue.get('description', '')}")
                    else:
                        st.write(f"• {issue}")
            else:
                st.info("No security issues found")
        
        with tabs[2]:
            st.subheader("🎯 Threat Intelligence")
            threat_intel = data.get('threat_intel', {})
            if threat_intel:
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Sector:** {threat_intel.get('sector', 'Unknown')}")
                    st.write(f"**Company Size:** {threat_intel.get('company_size', 'Unknown')}")
                with col2:
                    st.write(f"**Industry:** {threat_intel.get('industry', 'Unknown')}")
                    st.write(f"**Compliance:** {', '.join(threat_intel.get('compliance', []))}")
                
                st.write("**Threat Actors:**")
                threat_actors = threat_intel.get('threat_actors', [])
                if threat_actors:
                    for actor in threat_actors:
                        st.write(f"• {actor}")
                else:
                    st.write("No specific threat actors identified")
            else:
                st.info("No threat intelligence available")
        
        with tabs[3]:
            st.subheader("⚔️ Attack Vectors & Exploitation Chains")
            attack_vectors = data.get('attack_vectors', [])
            if attack_vectors:
                st.write(f"**Identified {len(attack_vectors)} attack vectors:**")
                for i, vector in enumerate(attack_vectors, 1):
                    if isinstance(vector, dict):
                        with st.expander(f"Attack Vector {i}: {vector.get('name', 'Unknown')}"):
                            st.write(f"**Entry Point:** {vector.get('entry_point', 'N/A')}")
                            st.write(f"**Difficulty:** {vector.get('difficulty', 'N/A')}/10")
                            st.write(f"**Impact:** {vector.get('impact', 'N/A')}")
                            
                            chain = vector.get('exploitation_chain', [])
                            if chain:
                                st.write("**Exploitation Chain:**")
                                for step in chain:
                                    st.write(f"  {step}")
                    else:
                        st.write(f"• {vector}")
            else:
                st.info("No attack vectors identified")


class Phase5Display(DynamicDisplayTemplate):
    """Dynamic display for Phase 5: Risk Assessment"""
    
    @staticmethod
    def render(data: Dict[str, Any]):
        """Render Phase 5 data"""
        st.header("📊 Phase 5: Risk Assessment & Categorization")
        
        if not data or 'error' in data:
            st.error(f"Phase 5 failed: {data.get('error', 'Unknown error')}")
            return
        
        # Extract risk data from proper structure
        multidim_score = data.get('multidimensional_score', {})
        risk_matrix = data.get('risk_matrix', {})
        business_risk = data.get('business_risk', {})
        infra_risk = data.get('infrastructure_risk', {})
        app_risk = data.get('application_risk', {})
        business_impact = data.get('business_impact', {})
        
        # Calculate overall risk level
        overall_score = multidim_score.get('overall_score', 0)
        risk_level = "🔴 CRITICAL" if overall_score >= 80 else "🟠 HIGH" if overall_score >= 60 else "🟡 MEDIUM" if overall_score >= 40 else "🟢 LOW"
        
        # Risk overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Overall Risk", f"{int(overall_score)}/100")
        
        with col2:
            st.metric("Risk Level", risk_level)
        
        with col3:
            exposure = business_impact.get('exposure_level', 'Unknown')
            st.metric("Exposure", exposure)
        
        with col4:
            findings = len(data.get('cves', [])) if 'cves' in data else 0
            st.metric("Findings", findings)
        
        st.divider()
        
        # Detailed sections
        tabs = st.tabs(["Executive Summary", "Risk Breakdown", "Business Impact", "Action Plan", "Threat Actors"])
        
        with tabs[0]:
            st.subheader("📋 Executive Summary")
            executive_summary = data.get('executive_summary', {})
            if executive_summary:
                st.write(f"**Overall Assessment:** {executive_summary.get('overall_assessment', 'N/A')}")
                st.write(f"**Key Risks:** {executive_summary.get('key_risks', 'N/A')}")
                st.write(f"**Immediate Actions:** {executive_summary.get('immediate_actions', 'N/A')}")
            else:
                st.info("No executive summary available")
        
        with tabs[1]:
            st.subheader("🎯 Risk Breakdown by Dimension")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write("**Business Risk**")
                business_score = business_risk.get('risk_score', 0)
                business_level = business_risk.get('risk_level', 'Unknown')
                st.metric("Score", f"{int(business_score)}/100")
                st.write(f"Level: {business_level}")
                st.write(f"**Factors:**")
                for factor in business_risk.get('risk_factors', [])[:3]:
                    st.write(f"• {factor}")
            
            with col2:
                st.write("**Infrastructure Risk**")
                infra_score = infra_risk.get('risk_score', 0)
                infra_level = infra_risk.get('risk_level', 'Unknown')
                st.metric("Score", f"{int(infra_score)}/100")
                st.write(f"Level: {infra_level}")
                st.write(f"**Factors:**")
                for factor in infra_risk.get('risk_factors', [])[:3]:
                    st.write(f"• {factor}")
            
            with col3:
                st.write("**Application Risk**")
                app_score = app_risk.get('risk_score', 0)
                app_level = app_risk.get('risk_level', 'Unknown')
                st.metric("Score", f"{int(app_score)}/100")
                st.write(f"Level: {app_level}")
                st.write(f"**Factors:**")
                for factor in app_risk.get('risk_factors', [])[:3]:
                    st.write(f"• {factor}")
            
            st.divider()
            
            # Risk Matrix
            st.write("**Risk Matrix:**")
            risk_matrix_text = risk_matrix.get('matrix_text', 'N/A')
            st.code(risk_matrix_text, language="text")
        
        with tabs[2]:
            st.subheader("💼 Business Impact Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Financial Impact**")
                st.write(f"Risk: {business_impact.get('financial_risk', 'Unknown')}")
                st.write(f"Estimated Loss: {business_impact.get('estimated_financial_loss', 'Unknown')}")
                
                st.write("**Operational Impact**")
                st.write(f"Risk: {business_impact.get('operational_impact', 'Unknown')}")
                st.write(f"Downtime: {business_impact.get('estimated_downtime', 'Unknown')}")
            
            with col2:
                st.write("**Reputational Impact**")
                st.write(f"Risk: {business_impact.get('reputational_risk', 'Unknown')}")
                st.write(f"Severity: {business_impact.get('reputational_severity', 'Unknown')}")
                
                st.write("**Compliance Impact**")
                st.write(f"Risk: {business_impact.get('compliance_risk', 'Unknown')}")
                st.write(f"Frameworks: {', '.join(business_impact.get('affected_frameworks', []))}")
            
            st.divider()
            
            st.write("**Potential Impact Scenarios:**")
            scenarios = business_impact.get('impact_scenarios', [])
            if scenarios:
                for scenario in scenarios:
                    st.write(f"• {scenario}")
            else:
                st.write("No specific scenarios identified")
        
        with tabs[3]:
            st.subheader("🛠️ Action Plan & Remediation")
            action_plan = data.get('action_plan', {})
            
            if action_plan:
                # Immediate actions
                immediate = action_plan.get('immediate_actions', [])
                if immediate:
                    st.write("**🚨 Immediate Actions (0-7 days):**")
                    for action in immediate:
                        if isinstance(action, dict):
                            st.write(f"• **{action.get('action', 'N/A')}**")
                            st.write(f"  Priority: {action.get('priority', 'N/A')}")
                            st.write(f"  Effort: {action.get('effort', 'N/A')}")
                        else:
                            st.write(f"• {action}")
                
                # Short-term actions
                short_term = action_plan.get('short_term_actions', [])
                if short_term:
                    st.write("**📅 Short-term Actions (1-4 weeks):**")
                    for action in short_term:
                        if isinstance(action, dict):
                            st.write(f"• **{action.get('action', 'N/A')}**")
                            st.write(f"  Priority: {action.get('priority', 'N/A')}")
                        else:
                            st.write(f"• {action}")
                
                # Long-term actions
                long_term = action_plan.get('long_term_actions', [])
                if long_term:
                    st.write("**🎯 Long-term Actions (1-6 months):**")
                    for action in long_term:
                        if isinstance(action, dict):
                            st.write(f"• **{action.get('action', 'N/A')}**")
                            st.write(f"  Priority: {action.get('priority', 'N/A')}")
                        else:
                            st.write(f"• {action}")
            else:
                st.info("No action plan available")
        
        with tabs[4]:
            st.subheader("🎭 Threat Actor Profile")
            threat_profile = data.get('threat_actor_profile', {})
            
            if threat_profile:
                threat_actors = threat_profile.get('threat_actors', [])
                if threat_actors:
                    st.write(f"**Identified {len(threat_actors)} Threat Actors:**")
                    for i, actor in enumerate(threat_actors, 1):
                        with st.expander(f"{i}. {actor.get('name', 'Unknown')} (Risk: {actor.get('risk_score', 'N/A')}/10)"):
                            st.write(f"**Type:** {actor.get('type', 'Unknown')}")
                            st.write(f"**Motivation:** {actor.get('motivation', 'Unknown')}")
                            st.write(f"**Capabilities:** {actor.get('capabilities', 'Unknown')}")
                            st.write(f"**Why They Target This Organization:**")
                            st.write(actor.get('targeting_rationale', 'N/A'))
                            
                            st.write(f"**Technical Alignment:**")
                            st.write(actor.get('technical_alignment', 'N/A'))
                            
                            st.write(f"**Historical Context:**")
                            st.write(actor.get('historical_context', 'N/A'))
                else:
                    st.info("No threat actors identified")
            else:
                st.info("No threat actor profile available")


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
