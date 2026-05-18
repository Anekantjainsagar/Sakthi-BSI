#!/usr/bin/env python3
"""
Search History UI Component - Streamlit UI for search history and domain lookup
"""

import streamlit as st
from typing import Dict, Any, Optional, List
from services.search_history_manager import SearchHistoryManager


class SearchHistoryUI:
    """Streamlit UI component for search history management"""
    
    def __init__(self, db_path: str = "bsi_analysis.db"):
        """Initialize search history UI"""
        self.manager = SearchHistoryManager(db_path)
    
    def render_sidebar(self) -> Optional[str]:
        """Render search history sidebar with recent searches and search bar"""
        with st.sidebar:
            st.markdown("---")
            st.subheader("📚 Search History")
            
            # Search bar
            search_term = st.text_input(
                "🔍 Search domains",
                placeholder="example.com",
                key="search_history_input"
            )
            
            # Tabs for recent vs search results
            tab1, tab2 = st.tabs(["Recent", "Search"])
            
            selected_domain = None
            
            with tab1:
                st.markdown("### Recent Searches")
                recent = self.manager.get_recent_searches(limit=15)
                
                if recent:
                    stats = self.manager.get_search_stats()
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Domains", stats['total_unique_domains'])
                    with col2:
                        st.metric("Total Searches", stats['total_searches'])
                    with col3:
                        st.metric("Completed", stats['completed_analyses'])
                    
                    st.markdown("---")
                    
                    for result in recent:
                        formatted = self.manager.format_search_result(result)
                        if st.button(formatted, key=f"recent_{result['domain']}", use_container_width=True):
                            selected_domain = result['domain']
                            st.session_state.selected_domain = selected_domain
                else:
                    st.info("No search history yet. Start by analyzing a domain!")
            
            with tab2:
                st.markdown("### Search Results")
                if search_term and len(search_term.strip()) > 0:
                    results = self.manager.search_domains(search_term)
                    
                    if results:
                        st.success(f"Found {len(results)} result(s)")
                        st.markdown("---")
                        
                        for result in results:
                            formatted = self.manager.format_search_result(result)
                            if st.button(formatted, key=f"search_{result['domain']}", use_container_width=True):
                                selected_domain = result['domain']
                                st.session_state.selected_domain = selected_domain
                    else:
                        st.warning(f"No results found for '{search_term}'")
                else:
                    st.info("Enter a domain name to search")
            
            st.markdown("---")
        
        return selected_domain
    
    def render_history_modal(self):
        """Render a modal/expander for viewing full search history"""
        with st.expander("📊 Search History Statistics"):
            stats = self.manager.get_search_stats()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Unique Domains", stats['total_unique_domains'])
            with col2:
                st.metric("Total Searches", stats['total_searches'])
            with col3:
                st.metric("Completed", stats['completed_analyses'])
            
            st.markdown("---")
            
            # Show all recent searches
            st.markdown("### All Recent Searches")
            recent = self.manager.get_recent_searches(limit=50)
            
            if recent:
                # Create a table view
                import pandas as pd
                
                df_data = []
                for item in recent:
                    df_data.append({
                        'Domain': item['domain'],
                        'Status': item['status'],
                        'Completion': f"{item['completion_percentage']}%",
                        'Searches': item['search_count'],
                        'Last Searched': item['last_searched_at'][:10] if item['last_searched_at'] else 'N/A'
                    })
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No search history available")
    
    def record_domain_search(self, domain: str, analysis_id: int = None):
        """Record a domain search"""
        self.manager.record_search(domain, analysis_id, 'in_progress', 0)
    
    def update_domain_status(self, domain: str, status: str, completion_percentage: int = 0):
        """Update domain analysis status"""
        self.manager.update_search_status(domain, status, completion_percentage)
    
    def get_domain_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get analysis data for a domain"""
        return self.manager.get_domain_analysis(domain)
    
    def get_recent_searches(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent searches (wrapper for manager method)"""
        return self.manager.get_recent_searches(limit)
    
    def search_domains(self, search_term: str) -> List[Dict[str, Any]]:
        """Search domains (wrapper for manager method)"""
        return self.manager.search_domains(search_term)
