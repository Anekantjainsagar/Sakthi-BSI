"""
Display functions for Phase 4: Vulnerability Correlation & Threat Intelligence
"""

import streamlit as st
from typing import Dict, Any


def display_correlation_results(data: Dict[str, Any]):
    """Display Phase 4 correlation analysis results"""
    st.header("🔗 Phase 4: Vulnerability Correlation & Threat Intelligence")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    tabs = st.tabs([
        "Vulnerability Summary",
        "MITRE ATT&CK Mapping",
        "Threat Actors",
        "Attack Chains",
        "Risk Scoring",
        "Remediation"
    ])
    
    with tabs[0]:
        _display_vulnerability_summary(data)
    
    with tabs[1]:
        _display_mitre_mapping(data)
    
    with tabs[2]:
        _display_threat_actors(data)
    
    with tabs[3]:
        _display_attack_chains(data)
    
    with tabs[4]:
        _display_risk_scoring(data)
    
    with tabs[5]:
        _display_remediation(data)


def _display_vulnerability_summary(data: Dict[str, Any]):
    """Display vulnerability summary"""
    st.subheader("📊 Vulnerability Summary")
    
    summary = data.get('summary', {})
    
    if summary:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            critical = summary.get('critical_count', 0)
            st.metric("Critical", critical, delta=None)
            if critical > 0:
                st.error(f"🔴 {critical} critical vulnerabilities")
        
        with col2:
            high = summary.get('high_count', 0)
            st.metric("High", high, delta=None)
            if high > 0:
                st.warning(f"🟠 {high} high severity")
        
        with col3:
            medium = summary.get('medium_count', 0)
            st.metric("Medium", medium, delta=None)
        
        with col4:
            low = summary.get('low_count', 0)
            st.metric("Low", low, delta=None)
        
        st.markdown("---")
        
        # Vulnerability list
        vulnerabilities = data.get('vulnerabilities', [])
        if vulnerabilities:
            st.markdown("**Detected Vulnerabilities**")
            for vuln in vulnerabilities[:20]:
                severity = vuln.get('severity', 'Unknown')
                title = vuln.get('title', 'Unknown')
                
                if severity == 'Critical':
                    st.error(f"🔴 [{severity}] {title}")
                elif severity == 'High':
                    st.warning(f"🟠 [{severity}] {title}")
                elif severity == 'Medium':
                    st.warning(f"🟡 [{severity}] {title}")
                else:
                    st.info(f"🔵 [{severity}] {title}")
            
            if len(vulnerabilities) > 20:
                st.info(f"+ {len(vulnerabilities) - 20} more vulnerabilities")
    else:
        st.info("No vulnerability summary available")


def _display_mitre_mapping(data: Dict[str, Any]):
    """Display MITRE ATT&CK mapping"""
    st.subheader("🎯 MITRE ATT&CK Framework Mapping")
    
    mitre_data = data.get('mitre_mapping', {})
    
    if mitre_data:
        tactics = mitre_data.get('tactics', {})
        
        if tactics:
            st.markdown("**Tactics Identified**")
            for tactic, techniques in tactics.items():
                with st.expander(f"📍 {tactic} ({len(techniques)} techniques)"):
                    for technique in techniques:
                        st.text(f"• {technique}")
        else:
            st.info("No MITRE tactics mapped")
    else:
        st.info("No MITRE mapping data available")


def _display_threat_actors(data: Dict[str, Any]):
    """Display threat actors"""
    st.subheader("👥 Threat Actors & APT Groups")
    
    threat_actors = data.get('threat_actors', [])
    
    if threat_actors:
        for actor in threat_actors:
            with st.expander(f"🎯 {actor.get('name', 'Unknown')}"):
                st.text(f"Aliases: {actor.get('aliases', 'N/A')}")
                st.text(f"Country: {actor.get('country', 'N/A')}")
                st.text(f"Active Since: {actor.get('active_since', 'N/A')}")
                
                targets = actor.get('targets', [])
                if targets:
                    st.markdown("**Target Industries:**")
                    for target in targets:
                        st.text(f"• {target}")
    else:
        st.info("No threat actors identified")


def _display_attack_chains(data: Dict[str, Any]):
    """Display attack chains"""
    st.subheader("⛓️ Attack Chains")
    
    attack_chains = data.get('attack_chains', [])
    
    if attack_chains:
        for idx, chain in enumerate(attack_chains, 1):
            with st.expander(f"Chain {idx}: {chain.get('name', 'Unknown')}"):
                steps = chain.get('steps', [])
                for step_idx, step in enumerate(steps, 1):
                    st.text(f"{step_idx}. {step}")
    else:
        st.info("No attack chains identified")


def _display_risk_scoring(data: Dict[str, Any]):
    """Display risk scoring"""
    st.subheader("📈 Risk Scoring")
    
    risk_score = data.get('overall_risk_score', 0)
    
    if risk_score:
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Overall Risk Score", f"{risk_score}/100")
            
            if risk_score >= 80:
                st.error("🔴 CRITICAL RISK")
            elif risk_score >= 60:
                st.warning("🟠 HIGH RISK")
            elif risk_score >= 40:
                st.warning("🟡 MEDIUM RISK")
            else:
                st.success("🟢 LOW RISK")
        
        with col2:
            st.markdown("**Risk Factors**")
            risk_factors = data.get('risk_factors', [])
            for factor in risk_factors:
                st.text(f"• {factor}")
    else:
        st.info("No risk scoring data available")


def _display_remediation(data: Dict[str, Any]):
    """Display remediation recommendations"""
    st.subheader("🔧 Remediation Recommendations")
    
    recommendations = data.get('recommendations', [])
    
    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'Medium')
            title = rec.get('title', 'Unknown')
            
            if priority == 'Critical':
                st.error(f"🔴 [{priority}] {title}")
            elif priority == 'High':
                st.warning(f"🟠 [{priority}] {title}")
            else:
                st.info(f"🟡 [{priority}] {title}")
            
            description = rec.get('description', '')
            if description:
                st.caption(description)
            
            st.markdown("---")
    else:
        st.info("No remediation recommendations available")
