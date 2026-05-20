#!/usr/bin/env python3
"""
Formatted Display Functions - Display phase results in Streamlit UI
Provides display functions for all 5 phases of BSI analysis
"""

import streamlit as st
from typing import Dict, Any


def display_business_domain_formatted(data: Dict[str, Any]):
    """Display Phase 1: Business Domain Understanding results"""
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("🏢 Business Domain Understanding")
    st.info("Phase 1 analysis complete - Business intelligence gathered")


def display_infrastructure_formatted(data: Dict[str, Any]):
    """Display Phase 2: Infrastructure Discovery results"""
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("🌐 Infrastructure Discovery")
    st.info("Phase 2 analysis complete - Infrastructure mapped")


def display_application_formatted(data: Dict[str, Any]):
    """Display Phase 3: Application Landscape results"""
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("� Application Landscape")
    st.info("Phase 3 analysis complete - Applications identified")


def display_correlation_formatted(data: Dict[str, Any]):
    """Display Phase 4: Correlation Analysis results"""
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("🔗 Correlation Analysis")
    st.info("Phase 4 analysis complete - Correlations identified")


def display_risk_formatted(data: Dict[str, Any]):
    """Display Phase 5: Risk Assessment results"""
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    st.header("📊 Risk Assessment")
    st.info("Phase 5 analysis complete - Risk assessment generated")
