#!/usr/bin/env python3
"""
Streamlit UI components for database features
Displays analysis history, resume options, and database statistics
"""

import streamlit as st
from datetime import datetime
from core.database import get_db_manager
from core.orchestrator import DatabaseIntegrationHelper


def display_analysis_history_sidebar():
    """Display analysis history in sidebar"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("📚 Analysis History")
    
    db = get_db_manager()
    analyses = db.list_recent_analyses(limit=5)
    
    if analyses:
        for analysis in analyses:
            domain = analysis['domain']
            status = analysis['status']
            completion = analysis['completion_percentage']
            
            # Status indicator
            if status == 'completed':
                status_icon = "✅"
            elif status == 'completed_with_errors':
                status_icon = "⚠️"
            elif status == 'in_progress':
                status_icon = "⏳"
            else:
                status_icon = "❓"
            
            # Display as clickable button
            col1, col2 = st.sidebar.columns([3, 1])
            with col1:
                st.caption(f"{status_icon} {domain}")
            with col2:
                st.caption(f"{completion}%")
    else:
        st.sidebar.info("No analyses yet")


def display_resume_option(domain: str) -> bool:
    """Display resume option if analysis exists"""
    db = get_db_manager()
    existing = db.get_analysis(domain)
    
    if not existing:
        return False
    
    st.warning(f"⏸️ **Previous analysis found for {domain}**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Resume Analysis", key="resume_btn"):
            st.session_state.resume_analysis = True
            return True
    
    with col2:
        if st.button("🆕 Start Fresh", key="fresh_btn"):
            st.session_state.resume_analysis = False
            return False
    
    return False


def display_analysis_progress(analysis_id: int):
    """Display analysis progress"""
    db = get_db_manager()
    progress = db.get_analysis_progress(analysis_id)
    
    st.subheader("📊 Analysis Progress")
    
    # Overall progress bar
    st.progress(progress['completion_percentage'] / 100)
    st.caption(f"{progress['completion_percentage']}% Complete")
    
    # Phase breakdown
    st.markdown("**Phase Status:**")
    
    phase_names = {
        1: "🏢 Business Domain",
        2: "🌐 Infrastructure",
        3: "📱 Application Landscape",
        4: "🔗 Correlation Analysis",
        5: "📊 Risk Assessment"
    }
    
    for phase in progress['phases']:
        phase_num = phase['phase_number']
        status = phase['status']
        duration = phase['duration_seconds'] or 0
        
        phase_name = phase_names.get(phase_num, f"Phase {phase_num}")
        
        if status == 'completed':
            st.success(f"✅ {phase_name} - {duration:.2f}s")
        elif status == 'failed':
            st.error(f"❌ {phase_name} - Failed")
        else:
            st.info(f"⏳ {phase_name} - Pending")
    
    # Total duration
    st.markdown(f"**Total Duration:** {progress['total_duration_seconds']:.2f}s")


def display_database_stats():
    """Display database statistics"""
    db = get_db_manager()
    stats = db.get_database_stats()
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("📈 Database Stats")
    
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        st.metric("Total Analyses", stats['total_analyses'])
        st.metric("Cache Hits", stats['total_cache_hits'])
    
    with col2:
        st.metric("Completed Phases", stats['completed_phases'])
        st.metric("Active Cache", stats['active_cache_entries'])


def display_search_history():
    """Display search/filter for analysis history"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔍 Search History")
    
    search_term = st.sidebar.text_input("Search domain:", placeholder="example.com")
    
    if search_term:
        db = get_db_manager()
        results = db.search_analyses(search_term)
        
        if results:
            st.sidebar.success(f"Found {len(results)} result(s)")
            for result in results:
                st.sidebar.caption(f"• {result['domain']} ({result['status']})")
        else:
            st.sidebar.info("No results found")


def display_analysis_details(analysis_id: int):
    """Display detailed analysis information"""
    db = get_db_manager()
    analysis = db.get_analysis_by_id(analysis_id)
    summary = db.get_analysis_summary(analysis_id)
    
    if not analysis:
        st.error("Analysis not found")
        return
    
    st.subheader(f"📋 Analysis Details: {analysis['domain']}")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Status", analysis['status'])
    with col2:
        st.metric("Completion", f"{analysis['completion_percentage']}%")
    with col3:
        st.metric("Duration", f"{analysis['total_duration_seconds']:.2f}s")
    
    st.caption(f"Created: {analysis['created_at']}")
    st.caption(f"Updated: {analysis['updated_at']}")
    
    if summary:
        st.markdown("---")
        st.subheader("📝 Summary")
        
        if summary['business_domain_summary']:
            with st.expander("🏢 Business Domain"):
                st.write(summary['business_domain_summary'])
        
        if summary['infrastructure_summary']:
            with st.expander("🌐 Infrastructure"):
                st.write(summary['infrastructure_summary'])
        
        if summary['application_summary']:
            with st.expander("📱 Application Landscape"):
                st.write(summary['application_summary'])
        
        if summary['correlation_summary']:
            with st.expander("🔗 Correlation Analysis"):
                st.write(summary['correlation_summary'])
        
        if summary['risk_assessment_summary']:
            with st.expander("📊 Risk Assessment"):
                st.write(summary['risk_assessment_summary'])


def display_cache_management():
    """Display cache management options"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("💾 Cache Management")
    
    db = get_db_manager()
    stats = db.get_database_stats()
    
    st.sidebar.info(f"Active cache entries: {stats['active_cache_entries']}")
    
    if st.sidebar.button("🗑️ Clear Expired Cache"):
        db.clear_expired_cache()
        st.sidebar.success("Cache cleared!")
        st.rerun()


def create_analysis_comparison_view(domain1: str, domain2: str):
    """Compare two analyses side by side"""
    db = get_db_manager()
    
    analysis1 = db.get_analysis(domain1)
    analysis2 = db.get_analysis(domain2)
    
    if not analysis1 or not analysis2:
        st.error("One or both analyses not found")
        return
    
    st.subheader(f"📊 Comparison: {domain1} vs {domain2}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"### {domain1}")
        st.metric("Status", analysis1['status'])
        st.metric("Completion", f"{analysis1['completion_percentage']}%")
        st.metric("Duration", f"{analysis1['total_duration_seconds']:.2f}s")
    
    with col2:
        st.markdown(f"### {domain2}")
        st.metric("Status", analysis2['status'])
        st.metric("Completion", f"{analysis2['completion_percentage']}%")
        st.metric("Duration", f"{analysis2['total_duration_seconds']:.2f}s")
    
    # Phase comparison
    st.markdown("---")
    st.subheader("Phase Comparison")
    
    progress1 = db.get_analysis_progress(analysis1['id'])
    progress2 = db.get_analysis_progress(analysis2['id'])
    
    comparison_data = []
    for p1, p2 in zip(progress1['phases'], progress2['phases']):
        comparison_data.append({
            'Phase': p1['phase_name'],
            f'{domain1} Status': p1['status'],
            f'{domain1} Duration': f"{p1['duration_seconds']:.2f}s" if p1['duration_seconds'] else "N/A",
            f'{domain2} Status': p2['status'],
            f'{domain2} Duration': f"{p2['duration_seconds']:.2f}s" if p2['duration_seconds'] else "N/A"
        })
    
    import pandas as pd
    df = pd.DataFrame(comparison_data)
    st.dataframe(df, use_container_width=True)
