#!/usr/bin/env python3
"""
Dark Web Intelligence Display Component
Displays dark web coverage gaps, recommendations, and security signals
"""

import streamlit as st
from typing import Dict, Any


def display_dark_web_results(data: Dict[str, Any]):
    """Display dark web intelligence results"""
    
    if not data or 'error' in data:
        st.error(f"Dark Web Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("🌐 Dark Web Intelligence & Exposure Monitoring")
    
    # Status
    status = data.get('status', 'unknown')
    if status == 'not_executed':
        st.warning("⚠️ Dark Web Scanning Not Executed (Placeholder Implementation)")
        st.info("This phase is currently a placeholder. Integration with actual dark web monitoring services is pending.")
    
    # Coverage Gaps
    coverage_gaps = data.get('coverage_gaps', [])
    if coverage_gaps:
        st.subheader("📊 Coverage Gaps Identified")
        st.markdown(f"**{len(coverage_gaps)} major gaps detected:**")
        
        for i, gap in enumerate(coverage_gaps, 1):
            with st.expander(f"Gap {i}: {gap.get('gap', 'Unknown')} - {gap.get('severity', 'UNKNOWN').upper()}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Description:**")
                    st.write(gap.get('description', 'N/A'))
                    
                    st.markdown("**Impact:**")
                    st.write(gap.get('impact', 'N/A'))
                
                with col2:
                    severity = gap.get('severity', 'medium').upper()
                    if severity == 'HIGH':
                        st.error(f"🔴 Severity: {severity}")
                    elif severity == 'MEDIUM':
                        st.warning(f"🟡 Severity: {severity}")
                    else:
                        st.info(f"🟢 Severity: {severity}")
                    
                    priority = gap.get('priority', 'N/A')
                    st.metric("Priority", priority)
    
    # Recommendations
    recommendations = data.get('recommendations', [])
    if recommendations:
        st.subheader("💡 Integration Recommendations")
        st.markdown(f"**{len(recommendations)} recommendations for improvement:**")
        
        for i, rec in enumerate(recommendations, 1):
            with st.expander(f"Recommendation {i}: {rec.get('recommendation', 'Unknown')}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Description:**")
                    st.write(rec.get('description', 'N/A'))
                    
                    st.markdown("**Effort:**")
                    effort = rec.get('effort', 'unknown').lower()
                    if effort == 'low':
                        st.success(f"✅ {effort.title()}")
                    elif effort == 'medium':
                        st.warning(f"⚠️ {effort.title()}")
                    else:
                        st.error(f"❌ {effort.title()}")
                
                with col2:
                    st.markdown("**Cost:**")
                    st.write(rec.get('cost', 'N/A'))
                    
                    priority = rec.get('priority', 'N/A')
                    st.metric("Priority", priority)
    
    # Security Signals
    security_signals = data.get('security_signals', [])
    if security_signals:
        st.subheader("🚨 Security Signals")
        st.markdown(f"**{len(security_signals)} security signals generated:**")
        
        for i, signal in enumerate(security_signals, 1):
            signal_type = signal.get('signal_type', 'unknown')
            severity = signal.get('severity', 'medium').upper()
            confidence = signal.get('confidence', 0)
            
            with st.expander(f"Signal {i}: {signal_type.replace('_', ' ').title()} ({severity})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Description:**")
                    st.write(signal.get('description', 'N/A'))
                    
                    st.markdown("**Remediation:**")
                    st.write(signal.get('remediation', 'N/A'))
                
                with col2:
                    if severity == 'HIGH':
                        st.error(f"🔴 Severity: {severity}")
                    elif severity == 'MEDIUM':
                        st.warning(f"🟡 Severity: {severity}")
                    else:
                        st.info(f"🟢 Severity: {severity}")
                    
                    st.metric("Confidence", f"{confidence * 100:.0f}%")
    
    # Metadata
    metadata = data.get('metadata', {})
    if metadata:
        st.markdown("---")
        st.subheader("📋 Metadata")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Phase", metadata.get('phase', 'N/A').replace('_', ' ').title())
        
        with col2:
            st.metric("Status", metadata.get('status', 'N/A').title())
        
        with col3:
            st.metric("Execution Time", f"{metadata.get('execution_time_seconds', 0):.2f}s")
        
        with col4:
            st.metric("Coverage", f"{metadata.get('coverage_percentage', 0):.0f}%")


def display_dark_web_summary(data: Dict[str, Any]):
    """Display a compact summary of dark web results"""
    
    if not data or 'error' in data:
        return
    
    status = data.get('status', 'unknown')
    coverage_gaps = data.get('coverage_gaps', [])
    security_signals = data.get('security_signals', [])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Status", status.replace('_', ' ').title())
    
    with col2:
        st.metric("Coverage Gaps", len(coverage_gaps))
    
    with col3:
        st.metric("Security Signals", len(security_signals))


def display_dark_web_warnings(data: Dict[str, Any]):
    """Display warnings about missing dark web coverage"""
    
    if not data or 'error' in data:
        return
    
    status = data.get('status', 'unknown')
    
    if status == 'not_executed':
        st.warning(
            "⚠️ **Dark Web Scanning Not Executed**\n\n"
            "This analysis does not include dark web intelligence. "
            "The following capabilities are missing:\n\n"
            "• Breach database monitoring (HaveIBeenPwned, Breach.com)\n"
            "• Credential dump detection\n"
            "• Dark web forum monitoring\n"
            "• Paste site monitoring\n"
            "• Ransomware leak site monitoring\n"
            "• Threat actor tracking\n\n"
            "This may result in an incomplete threat assessment."
        )


def display_dark_web_comparison(current_data: Dict[str, Any], previous_data: Dict[str, Any] = None):
    """Display comparison of dark web results over time"""
    
    if not current_data:
        return
    
    st.subheader("📈 Dark Web Coverage Trend")
    
    current_gaps = len(current_data.get('coverage_gaps', []))
    current_signals = len(current_data.get('security_signals', []))
    
    if previous_data:
        previous_gaps = len(previous_data.get('coverage_gaps', []))
        previous_signals = len(previous_data.get('security_signals', []))
        
        col1, col2 = st.columns(2)
        
        with col1:
            gap_change = current_gaps - previous_gaps
            if gap_change > 0:
                st.metric("Coverage Gaps", current_gaps, delta=f"+{gap_change}")
            elif gap_change < 0:
                st.metric("Coverage Gaps", current_gaps, delta=f"{gap_change}")
            else:
                st.metric("Coverage Gaps", current_gaps, delta="No change")
        
        with col2:
            signal_change = current_signals - previous_signals
            if signal_change > 0:
                st.metric("Security Signals", current_signals, delta=f"+{signal_change}")
            elif signal_change < 0:
                st.metric("Security Signals", current_signals, delta=f"{signal_change}")
            else:
                st.metric("Security Signals", current_signals, delta="No change")
    else:
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Coverage Gaps", current_gaps)
        
        with col2:
            st.metric("Security Signals", current_signals)
