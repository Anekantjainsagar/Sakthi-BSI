#!/usr/bin/env python3
"""
Simple Display Functions - Robust rendering that works with actual data
"""

import streamlit as st
from typing import Dict, Any
import json


def display_phase_data_simple(phase_num: int, data: Dict[str, Any]):
    """Simple, robust display for any phase data"""
    
    if not data or 'error' in data:
        st.error(f"Phase {phase_num} analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Display raw data structure for debugging
    st.markdown("### 📊 Data Overview")
    
    # Show top-level keys
    keys = list(data.keys())
    st.markdown(f"**Available data keys ({len(keys)}):**")
    
    cols = st.columns(3)
    for i, key in enumerate(keys):
        with cols[i % 3]:
            value = data[key]
            if isinstance(value, dict):
                st.markdown(f"📦 `{key}` (dict: {len(value)} items)")
            elif isinstance(value, list):
                st.markdown(f"📋 `{key}` (list: {len(value)} items)")
            elif isinstance(value, str):
                preview = value[:30] + "..." if len(value) > 30 else value
                st.markdown(f"📝 `{key}`: {preview}")
            else:
                st.markdown(f"🔢 `{key}`: {type(value).__name__}")
    
    st.markdown("---")
    
    # Display each key's content
    st.markdown("### 📋 Detailed Data")
    
    for key in keys:
        value = data[key]
        
        with st.expander(f"🔍 {key}", expanded=False):
            if isinstance(value, dict):
                if value:
                    st.json(value)
                else:
                    st.info("Empty dictionary")
            elif isinstance(value, list):
                if value:
                    if len(value) > 0 and isinstance(value[0], dict):
                        st.markdown(f"**List with {len(value)} items:**")
                        for i, item in enumerate(value[:5]):
                            st.json(item)
                        if len(value) > 5:
                            st.info(f"... and {len(value) - 5} more items")
                    else:
                        st.json(value)
                else:
                    st.info("Empty list")
            elif isinstance(value, str):
                st.text(value)
            else:
                st.write(value)


def display_business_domain_simple(data: Dict[str, Any]):
    """Simple display for Phase 1"""
    st.header("🏢 Business Domain Understanding")
    display_phase_data_simple(1, data)


def display_infrastructure_simple(data: Dict[str, Any]):
    """Simple display for Phase 2"""
    st.header("🌐 Infrastructure Discovery")
    display_phase_data_simple(2, data)


def display_application_simple(data: Dict[str, Any]):
    """Simple display for Phase 3"""
    st.header("🖥️ Application Landscape Assessment")
    display_phase_data_simple(3, data)


def display_correlation_simple(data: Dict[str, Any]):
    """Simple display for Phase 4"""
    st.header("🔗 Vulnerability Correlation & Threat Intelligence")
    display_phase_data_simple(4, data)


def display_risk_simple(data: Dict[str, Any]):
    """Simple display for Phase 5"""
    st.header("📊 Risk Assessment & Categorization")
    display_phase_data_simple(5, data)
