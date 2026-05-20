#!/usr/bin/env python3
"""
Business Security Intelligence (BSI) - Main Streamlit Application (Refactored)
Runs multiple analysis phases in parallel for comprehensive domain assessment
"""

import streamlit as st
import sys
import os
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import orchestrator and display modules
try:
    from core.orchestrator_bsi import BSIOrchestrator
    from ui.display_phase1 import display_business_domain_results
    from ui.display_phase2 import display_infrastructure_results
    from ui.display_phase3 import display_application_landscape_results
    from ui.display_phase4 import display_correlation_results
    from ui.display_phase5 import display_risk_assessment_results
    from ui.search_history import SearchHistoryUI
except ImportError as e:
    st.error(f"Required modules not found: {e}")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Business Security Intelligence",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main { padding: 0rem 1rem; }
    </style>
    """, unsafe_allow_html=True)


def main():
    """Main Streamlit application"""
    
    # Sidebar
    st.sidebar.title("🔐 Business Security Intelligence")
    st.sidebar.markdown("---")
    
    # Navigation
    page = st.sidebar.radio(
        "Navigation",
        ["🏠 Home", "🔍 Analyze", "📊 Search History"]
    )
    
    if page == "🏠 Home":
        _display_home()
    
    elif page == "🔍 Analyze":
        _display_analyze()
    
    elif page == "📊 Search History":
        _display_search_history()


def _display_home():
    """Display home page"""
    st.title("🔐 Business Security Intelligence")
    
    st.markdown("""
    ### Welcome to BSI
    
    Business Security Intelligence (BSI) is a comprehensive security analysis platform that performs
    deep reconnaissance and threat assessment across 5 integrated phases:
    
    **Phase 1: 🏢 Business Domain Understanding**
    - Company intelligence gathering
    - Financial analysis
    - Leadership identification
    - Compliance assessment
    
    **Phase 2: 🌐 Infrastructure Discovery**
    - Network reconnaissance
    - SSL/TLS analysis
    - Mail server configuration
    - Cloud infrastructure detection
    
    **Phase 3: 🖥️ Application Landscape**
    - Technology stack detection
    - API discovery
    - Database identification
    - Security posture assessment
    
    **Phase 4: 🔗 Vulnerability Correlation**
    - Cross-phase vulnerability mapping
    - MITRE ATT&CK framework alignment
    - Threat actor identification
    - Attack chain analysis
    
    **Phase 5: 📊 Risk Assessment**
    - Comprehensive risk scoring
    - Business impact analysis
    - Compliance gap identification
    - Remediation recommendations
    
    ---
    
    ### Getting Started
    
    1. Navigate to **Analyze** in the sidebar
    2. Enter a domain name
    3. Click **Start Analysis**
    4. View results across all 5 phases
    5. Check **Search History** to revisit previous analyses
    """)


def _display_analyze():
    """Display analysis page"""
    st.title("🔍 Domain Analysis")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        domain = st.text_input(
            "Enter domain to analyze",
            placeholder="example.com",
            key="domain_input"
        )
    
    with col2:
        analyze_button = st.button("🚀 Start Analysis", use_container_width=True)
    
    if analyze_button and domain:
        _run_analysis(domain)
    elif analyze_button:
        st.error("Please enter a domain name")


def _run_analysis(domain: str):
    """Run the full analysis pipeline"""
    
    st.markdown("---")
    st.info(f"🔄 Starting analysis for **{domain}**...")
    
    # Initialize orchestrator
    orchestrator = BSIOrchestrator()
    
    # Run parallel analysis
    with st.spinner("Running analysis phases..."):
        orchestrator.analyze_domain_parallel(domain)
    
    st.markdown("---")
    
    # Display results
    st.success("✅ Analysis Complete!")
    
    # Create tabs for each phase
    phase_tabs = st.tabs([
        "Phase 1: Business",
        "Phase 2: Infrastructure",
        "Phase 3: Application",
        "Phase 4: Correlation",
        "Phase 5: Risk"
    ])
    
    # Phase 1: Business Domain
    with phase_tabs[0]:
        if orchestrator.results['business_domain']:
            display_business_domain_results(orchestrator.results['business_domain'])
        else:
            st.warning("Phase 1 analysis not completed")
    
    # Phase 2: Infrastructure
    with phase_tabs[1]:
        if orchestrator.results['infrastructure']:
            display_infrastructure_results(orchestrator.results['infrastructure'])
        else:
            st.warning("Phase 2 analysis not completed")
    
    # Phase 3: Application
    with phase_tabs[2]:
        if orchestrator.results['application_landscape']:
            display_application_landscape_results(orchestrator.results['application_landscape'])
        else:
            st.warning("Phase 3 analysis not completed")
    
    # Phase 4: Correlation
    with phase_tabs[3]:
        if orchestrator.results['correlation_analysis']:
            display_correlation_results(orchestrator.results['correlation_analysis'])
        else:
            st.warning("Phase 4 analysis not completed")
    
    # Phase 5: Risk Assessment
    with phase_tabs[4]:
        if orchestrator.results['risk_assessment']:
            display_risk_assessment_results(orchestrator.results['risk_assessment'])
        else:
            st.warning("Phase 5 analysis not completed")


def _display_search_history():
    """Display search history page"""
    st.title("📊 Search History")
    
    try:
        search_ui = SearchHistoryUI()
        search_ui.render()
    except Exception as e:
        st.error(f"Error loading search history: {str(e)}")


if __name__ == "__main__":
    main()
