"""
Display functions for Phase 3: Application Landscape Assessment
"""

import streamlit as st
from typing import Dict, Any


def display_application_landscape_results(data: Dict[str, Any]):
    """Display application landscape assessment results"""
    st.header("🖥️ Application Landscape Assessment")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    tabs = st.tabs([
        "Application Discovery",
        "Web Technology Stack",
        "ERP/SAP Detection",
        "Third-Party Software",
        "Code Repositories",
        "Outdated Software",
        "Security Posture",
        "API Discovery",
        "Database Detection",
        "Threat Intelligence",
        "Data Leak Detection",
        "S3 Bucket Exposure"
    ])
    
    with tabs[0]:
        _display_application_discovery(data)
    
    with tabs[1]:
        _display_web_technology_stack(data)
    
    with tabs[2]:
        _display_erp_sap_detection(data)
    
    with tabs[3]:
        _display_third_party_software(data)
    
    with tabs[4]:
        _display_code_repositories(data)
    
    with tabs[5]:
        _display_outdated_software(data)
    
    with tabs[6]:
        _display_security_posture(data)
    
    with tabs[7]:
        _display_api_discovery(data)
    
    with tabs[8]:
        _display_database_detection(data)
    
    with tabs[9]:
        _display_threat_intelligence(data)
    
    with tabs[10]:
        _display_data_leak_detection(data)
    
    with tabs[11]:
        _display_s3_bucket_exposure(data)


def _display_application_discovery(data: Dict[str, Any]):
    """Display application discovery results"""
    st.subheader("🌐 Application Discovery")
    app_data = data.get('1_application_discovery', {})
    
    if app_data:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Status**")
            status = app_data.get('status', 'Unknown')
            if status == 'Active':
                st.success(f"✅ {status}")
            else:
                st.error(f"❌ {status}")
            
            st.markdown("**Web Server**")
            server = app_data.get('server', 'Not disclosed')
            st.info(server)
        
        with col2:
            st.markdown("**Response Time**")
            st.text(f"{app_data.get('response_time_ms', 0)} ms")
            
            st.markdown("**Content Length**")
            st.text(f"{app_data.get('content_length', 0):,} bytes")
    else:
        st.info("No application discovery data available")


def _display_web_technology_stack(data: Dict[str, Any]):
    """Display web technology stack"""
    st.subheader("🛠️ Web Technology Stack")
    tech_stack = data.get('2_web_server_stack', {})
    
    if tech_stack:
        st.markdown("**Content Management System**")
        cms_list = tech_stack.get('cms', [])
        if cms_list:
            for cms in cms_list:
                st.success(f"✅ {cms}")
        else:
            st.info("No CMS detected")
        
        st.markdown("---")
        
        st.markdown("**JavaScript Libraries**")
        js_libs = tech_stack.get('javascript_libraries', [])
        if js_libs:
            for lib in js_libs:
                st.text(f"• {lib}")
        else:
            st.info("No JavaScript libraries detected")
    else:
        st.info("No technology stack data available")


def _display_erp_sap_detection(data: Dict[str, Any]):
    """Display ERP/SAP detection"""
    st.subheader("🏢 ERP/SAP System Detection")
    erp_data = data.get('3_erp_sap_detection', {})
    
    detected = erp_data.get('detected_systems', [])
    if detected:
        for system in detected:
            st.success(f"✅ {system}")
    else:
        st.info("❌ No ERP/SAP systems detected")


def _display_third_party_software(data: Dict[str, Any]):
    """Display third-party software inventory"""
    st.subheader("📦 Third-Party Software Inventory")
    third_party = data.get('4_third_party_software', {})
    
    if third_party:
        categories = ['analytics', 'payment', 'chat', 'cdn', 'social', 'video', 'captcha']
        
        for category in categories:
            services = third_party.get(category, [])
            if services:
                st.markdown(f"**{category.title()}**")
                for service in services:
                    st.text(f"• {service}")
                st.markdown("---")
    else:
        st.info("No third-party software data available")


def _display_code_repositories(data: Dict[str, Any]):
    """Display code repository analysis"""
    st.subheader("📁 Code Repository Analysis")
    repo_data = data.get('5_code_repositories', {})
    
    if repo_data:
        st.markdown("**robots.txt — Disallow Paths**")
        disallow = repo_data.get('robots_disallow', [])
        if disallow:
            for path in disallow:
                st.text(f"  {path}")
        else:
            st.info("No Disallow paths in robots.txt")
        
        st.markdown("---")
        
        st.markdown("**GitHub Repositories**")
        repos = repo_data.get('github_repos', [])
        if repos:
            for repo in repos:
                st.text(f"• {repo.get('name')} ({repo.get('stars')} stars)")
        else:
            st.info("No GitHub repositories found")
    else:
        st.info("No code repository data available")


def _display_outdated_software(data: Dict[str, Any]):
    """Display outdated software and vulnerabilities"""
    st.subheader("⚠️ Outdated Software & Vulnerabilities")
    vuln_data = data.get('6_outdated_software', {})
    
    if vuln_data:
        vulnerable = vuln_data.get('vulnerable', [])
        
        if vulnerable:
            for vuln in vulnerable:
                severity = vuln.get('severity', 'Unknown')
                lib = vuln.get('library', 'Unknown')
                current = vuln.get('current_version', 'Unknown')
                recommended = vuln.get('recommended_version', 'Unknown')
                
                if severity == 'Critical':
                    st.error(f"🔴 CRITICAL: {lib} {current} → {recommended}")
                elif severity == 'High':
                    st.error(f"🟠 HIGH: {lib} {current} → {recommended}")
                else:
                    st.warning(f"🟡 {severity}: {lib} {current} → {recommended}")
        else:
            st.success("✅ No vulnerable software detected")
    else:
        st.info("No outdated software analysis available")


def _display_security_posture(data: Dict[str, Any]):
    """Display security posture analysis"""
    st.subheader("🔒 Security Posture Analysis")
    security = data.get('7_security_posture', {})
    
    if security:
        st.markdown("**Security Headers**")
        headers = security.get('security_headers', {})
        if headers:
            for header_name, header_info in headers.items():
                if header_info.get('present'):
                    st.success(f"✅ {header_name}")
                else:
                    st.error(f"❌ {header_name}: Missing")
        else:
            st.info("No security headers data available")
        
        st.markdown("---")
        
        st.markdown("**Admin Panel Discovery**")
        admin_panels = security.get('admin_panels', [])
        if admin_panels:
            for panel in admin_panels:
                status = panel.get('status')
                path = panel.get('path')
                if status == 200:
                    st.error(f"🚨 EXPOSED: {path}")
                elif status in [401, 403]:
                    st.warning(f"🔐 Protected: {path}")
        else:
            st.success("✅ No exposed admin panels found")
    else:
        st.info("No security posture data available")


def _display_api_discovery(data: Dict[str, Any]):
    """Display API endpoint discovery"""
    st.subheader("🔌 API Endpoint Discovery")
    api_data = data.get('8_api_discovery', {})
    
    if api_data:
        endpoints = api_data.get('api_endpoints', [])
        if endpoints:
            st.markdown("**REST API Endpoints**")
            for endpoint in endpoints:
                st.text(f"• {endpoint.get('path')} [{endpoint.get('status')}]")
        else:
            st.info("No API endpoints discovered")
    else:
        st.info("No API discovery data available")


def _display_database_detection(data: Dict[str, Any]):
    """Display database and backend detection"""
    st.subheader("🗄️ Database & Backend Detection")
    db_data = data.get('9_database_detection', {})
    
    if db_data:
        db_types = db_data.get('database_type', [])
        if db_types:
            st.markdown("**Detected Databases**")
            for db in db_types:
                st.warning(f"⚠️ {db}")
        else:
            st.info("No databases detected")
    else:
        st.info("No database detection data available")


def _display_threat_intelligence(data: Dict[str, Any]):
    """Display threat intelligence"""
    st.subheader("🛡️ Threat Intelligence")
    threat_data = data.get('10_threat_intelligence', {})
    
    if threat_data:
        st.json(threat_data)
    else:
        st.info("No threat intelligence data available")


def _display_data_leak_detection(data: Dict[str, Any]):
    """Display data leak detection"""
    st.subheader("🔍 Data Leak Detection")
    leak_data = data.get('11_data_leak_detection', {})
    
    if leak_data:
        st.json(leak_data)
    else:
        st.info("No data leak detection data available")


def _display_s3_bucket_exposure(data: Dict[str, Any]):
    """Display S3 bucket exposure"""
    st.subheader("🪣 S3 Bucket Exposure")
    s3_data = data.get('12_s3_bucket_exposure', {})
    
    if s3_data:
        st.json(s3_data)
    else:
        st.info("No S3 bucket exposure data available")
