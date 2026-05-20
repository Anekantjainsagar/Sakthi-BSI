"""
Display functions for Phase 5: Risk Assessment & Categorization
"""

import streamlit as st
from typing import Dict, Any


def display_risk_assessment_results(data: Dict[str, Any]):
    """Display Phase 5: Risk Assessment and Categorization"""
    st.header("📊 Phase 5: Risk Assessment & Categorization")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    tabs = st.tabs([
        "Risk Overview",
        "Asset Risk",
        "Threat Landscape",
        "Compliance Status",
        "Business Impact",
        "Recommendations"
    ])
    
    with tabs[0]:
        _display_risk_overview(data)
    
    with tabs[1]:
        _display_asset_risk(data)
    
    with tabs[2]:
        _display_threat_landscape(data)
    
    with tabs[3]:
        _display_compliance_status(data)
    
    with tabs[4]:
        _display_business_impact(data)
    
    with tabs[5]:
        _display_recommendations(data)


def _display_risk_overview(data: Dict[str, Any]):
    """Display risk overview"""
    st.subheader("📈 Risk Overview")
    
    overview = data.get('risk_overview', {})
    
    if overview:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            overall_risk = overview.get('overall_risk_level', 'Unknown')
            st.metric("Overall Risk Level", overall_risk)
            
            if overall_risk == 'Critical':
                st.error("🔴 CRITICAL RISK")
            elif overall_risk == 'High':
                st.warning("🟠 HIGH RISK")
            elif overall_risk == 'Medium':
                st.warning("🟡 MEDIUM RISK")
            else:
                st.success("🟢 LOW RISK")
        
        with col2:
            risk_score = overview.get('risk_score', 0)
            st.metric("Risk Score", f"{risk_score}/100")
        
        with col3:
            exposure_level = overview.get('exposure_level', 'Unknown')
            st.metric("Exposure Level", exposure_level)
        
        st.markdown("---")
        
        # Key findings
        st.markdown("**Key Findings**")
        findings = overview.get('key_findings', [])
        for finding in findings:
            st.text(f"• {finding}")
    else:
        st.info("No risk overview data available")


def _display_asset_risk(data: Dict[str, Any]):
    """Display asset risk assessment"""
    st.subheader("🎯 Asset Risk Assessment")
    
    asset_risks = data.get('asset_risks', [])
    
    if asset_risks:
        for asset in asset_risks:
            asset_name = asset.get('name', 'Unknown')
            risk_level = asset.get('risk_level', 'Unknown')
            
            with st.expander(f"{asset_name} — {risk_level}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Vulnerabilities**")
                    vulns = asset.get('vulnerabilities', [])
                    for vuln in vulns:
                        st.text(f"• {vuln}")
                
                with col2:
                    st.markdown("**Threats**")
                    threats = asset.get('threats', [])
                    for threat in threats:
                        st.text(f"• {threat}")
    else:
        st.info("No asset risk data available")


def _display_threat_landscape(data: Dict[str, Any]):
    """Display threat landscape"""
    st.subheader("🌍 Threat Landscape")
    
    threat_landscape = data.get('threat_landscape', {})
    
    if threat_landscape:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Threat Actors**")
            actors = threat_landscape.get('threat_actors', [])
            for actor in actors:
                st.text(f"• {actor}")
        
        with col2:
            st.markdown("**Attack Vectors**")
            vectors = threat_landscape.get('attack_vectors', [])
            for vector in vectors:
                st.text(f"• {vector}")
        
        st.markdown("---")
        
        st.markdown("**Industry Threats**")
        industry_threats = threat_landscape.get('industry_threats', [])
        for threat in industry_threats:
            st.text(f"• {threat}")
    else:
        st.info("No threat landscape data available")


def _display_compliance_status(data: Dict[str, Any]):
    """Display compliance status"""
    st.subheader("📋 Compliance Status")
    
    compliance = data.get('compliance_status', {})
    
    if compliance:
        st.markdown("**Compliance Frameworks**")
        frameworks = compliance.get('frameworks', {})
        
        for framework, status in frameworks.items():
            if status == 'Compliant':
                st.success(f"✅ {framework}: Compliant")
            elif status == 'Partial':
                st.warning(f"⚠️ {framework}: Partially Compliant")
            else:
                st.error(f"❌ {framework}: Non-Compliant")
        
        st.markdown("---")
        
        st.markdown("**Compliance Gaps**")
        gaps = compliance.get('gaps', [])
        for gap in gaps:
            st.error(f"🔴 {gap}")
    else:
        st.info("No compliance status data available")


def _display_business_impact(data: Dict[str, Any]):
    """Display business impact assessment"""
    st.subheader("💼 Business Impact Assessment")
    
    business_impact = data.get('business_impact', {})
    
    if business_impact:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Potential Impact**")
            impact = business_impact.get('potential_impact', 'Unknown')
            st.info(impact)
            
            st.markdown("**Financial Risk**")
            financial = business_impact.get('financial_risk', 'Unknown')
            st.warning(financial)
        
        with col2:
            st.markdown("**Operational Impact**")
            operational = business_impact.get('operational_impact', 'Unknown')
            st.warning(operational)
            
            st.markdown("**Reputational Risk**")
            reputational = business_impact.get('reputational_risk', 'Unknown')
            st.error(reputational)
    else:
        st.info("No business impact data available")


def _display_recommendations(data: Dict[str, Any]):
    """Display recommendations"""
    st.subheader("🔧 Recommendations")
    
    recommendations = data.get('recommendations', [])
    
    if recommendations:
        st.markdown("**Priority Actions**")
        
        for idx, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'Medium')
            title = rec.get('title', 'Unknown')
            description = rec.get('description', '')
            timeline = rec.get('timeline', 'Unknown')
            
            if priority == 'Critical':
                st.error(f"🔴 [{priority}] {title}")
            elif priority == 'High':
                st.warning(f"🟠 [{priority}] {title}")
            elif priority == 'Medium':
                st.warning(f"🟡 [{priority}] {title}")
            else:
                st.info(f"🔵 [{priority}] {title}")
            
            if description:
                st.caption(description)
            
            st.caption(f"Timeline: {timeline}")
            st.markdown("---")
    else:
        st.info("No recommendations available")
