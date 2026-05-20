#!/usr/bin/env python3
"""
Search History Page - Streamlit multi-page app
Displays recent searches and search functionality
"""

import streamlit as st
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.database import get_db_manager

st.set_page_config(
    page_title="Search History - BSI",
    page_icon="📋",
    layout="wide"
)

st.title("📋 Search History")
st.markdown("View and manage your domain analysis history")

db = get_db_manager()

# Tabs for different views
tab1, tab2, tab3 = st.tabs(["Recent Searches", "Search", "Statistics"])

with tab1:
    st.markdown("### 📋 Recent Searches")
    
    history = db.get_search_history(limit=20)
    
    if not history:
        st.info("No search history yet. Start by analyzing a domain!")
    else:
        # Create a table view
        for idx, record in enumerate(history):
            domain = record['domain']
            last_searched = record['last_searched_at']
            search_count = record['search_count']
            status = record['status']
            completion = record['completion_percentage']
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(last_searched)
                time_str = dt.strftime("%b %d, %H:%M")
            except:
                time_str = last_searched
            
            # Status indicator
            if status == 'completed':
                status_icon = "✅"
                status_color = "green"
            elif status == 'in_progress':
                status_icon = "⏳"
                status_color = "blue"
            elif status == 'failed':
                status_icon = "❌"
                status_color = "red"
            else:
                status_icon = "⭕"
                status_color = "gray"
            
            # Create clickable card
            col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 1, 1])
            
            with col1:
                if st.button(f"🔗 {domain}", key=f"history_{idx}", use_container_width=True):
                    st.session_state['navigate_to_domain'] = domain
                    st.switch_page("pages/0_Analyze.py")
            
            with col2:
                st.caption(f"{status_icon} {status}")
            
            with col3:
                st.caption(f"🔄 {search_count}x")
            
            with col4:
                st.caption(f"📅 {time_str}")
            
            with col5:
                if st.button("🗑️", key=f"delete_{idx}", help="Delete this search"):
                    # Delete from database
                    if record['analysis_id']:
                        db.delete_analysis(record['analysis_id'])
                    st.rerun()
            
            # Show progress bar if in progress
            if status == 'in_progress' and completion > 0:
                st.progress(completion / 100, text=f"{completion}%")

with tab2:
    st.markdown("### 🔎 Search Domains")
    
    search_query = st.text_input(
        "Search in history",
        placeholder="Enter domain name (e.g., example.com)",
        key="search_history_input"
    )
    
    if search_query:
        results = db.search_history(search_query)
        
        if not results:
            st.warning(f"No domains found matching '{search_query}'")
        else:
            st.success(f"Found {len(results)} matching domain(s)")
            
            for idx, record in enumerate(results):
                domain = record['domain']
                last_searched = record['last_searched_at']
                search_count = record['search_count']
                status = record['status']
                completion = record['completion_percentage']
                
                # Format timestamp
                try:
                    dt = datetime.fromisoformat(last_searched)
                    time_str = dt.strftime("%b %d, %H:%M")
                except:
                    time_str = last_searched
                
                # Status indicator
                if status == 'completed':
                    status_icon = "✅"
                elif status == 'in_progress':
                    status_icon = "⏳"
                elif status == 'failed':
                    status_icon = "❌"
                else:
                    status_icon = "⭕"
                
                col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 1, 1])
                
                with col1:
                    if st.button(f"🔗 {domain}", key=f"search_result_{idx}", use_container_width=True):
                        st.session_state['navigate_to_domain'] = domain
                        st.switch_page("pages/0_Analyze.py")
                
                with col2:
                    st.caption(f"{status_icon} {status}")
                
                with col3:
                    st.caption(f"🔄 {search_count}x")
                
                with col4:
                    st.caption(f"📅 {time_str}")
                
                with col5:
                    if st.button("🗑️", key=f"delete_search_{idx}", help="Delete this search"):
                        if record['analysis_id']:
                            db.delete_analysis(record['analysis_id'])
                        st.rerun()
                
                if status == 'in_progress' and completion > 0:
                    st.progress(completion / 100, text=f"{completion}%")

with tab3:
    st.markdown("### 📊 Search Statistics")
    
    stats = db.get_search_history_stats()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Unique Domains", stats['total_unique_domains'])
    
    with col2:
        st.metric("Total Searches", stats['total_searches'])
    
    with col3:
        st.metric("Completed Analyses", stats['completed_analyses'])
    
    st.markdown("---")
    
    # Database stats
    db_stats = db.get_database_stats()
    
    st.markdown("### 💾 Database Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Analyses", db_stats['total_analyses'])
    
    with col2:
        st.metric("Completed Phases", db_stats['completed_phases'])
    
    with col3:
        st.metric("Active Cache", db_stats['active_cache_entries'])
    
    with col4:
        st.metric("Cache Hits", db_stats['total_cache_hits'])
