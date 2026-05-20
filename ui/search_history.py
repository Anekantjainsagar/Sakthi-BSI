#!/usr/bin/env python3
"""
Search History UI Component - Streamlit UI for search history and domain lookup
"""

import streamlit as st
from typing import Dict, Any, Optional, List
from services.search_history_manager import SearchHistoryManager


class SearchHistoryUI:
    """Streamlit UI component for search history management"""

    def __init__(self, db_path: str = "data/bsi_analysis.db"):
        self.manager = SearchHistoryManager(db_path)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _status_icon(self, status: str) -> str:
        return {'completed': '✅', 'in_progress': '⏳', 'pending': '⏱️', 'failed': '❌'}.get(status, '❓')

    def _render_domain_row(self, result: Dict[str, Any], key_prefix: str) -> Optional[str]:
        """
        Render one domain row with a load button and a delete button.
        Returns the domain string if the load button was clicked, else None.
        """
        domain = result['domain']
        status = result.get('status', 'pending')
        pct = result.get('completion_percentage', 0)
        icon = self._status_icon(status)

        col_btn, col_del = st.columns([5, 1])

        selected = None
        with col_btn:
            label = f"{icon} {domain}  ({pct}%)"
            if st.button(label, key=f"{key_prefix}_load_{domain}", use_container_width=True):
                selected = domain
                st.session_state.selected_domain = domain

        with col_del:
            if st.button("🗑️", key=f"{key_prefix}_del_{domain}", help=f"Delete {domain}"):
                # Two-step confirm via session state
                st.session_state[f"confirm_delete_{domain}"] = True

        # Confirmation row (appears below the domain row)
        if st.session_state.get(f"confirm_delete_{domain}"):
            st.warning(f"Delete **{domain}** and all its analysis data?")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Yes, delete", key=f"{key_prefix}_confirm_{domain}",
                             type="primary", use_container_width=True):
                    ok = self.manager.delete_domain(domain)
                    if ok:
                        st.success(f"Deleted {domain}")
                    else:
                        st.error(f"Could not delete {domain}")
                    del st.session_state[f"confirm_delete_{domain}"]
                    st.rerun()
            with c2:
                if st.button("Cancel", key=f"{key_prefix}_cancel_{domain}",
                             use_container_width=True):
                    del st.session_state[f"confirm_delete_{domain}"]
                    st.rerun()

        return selected

    # ── sidebar ──────────────────────────────────────────────────────────────

    def render_sidebar(self) -> Optional[str]:
        """Render search history sidebar. Returns selected domain or None."""
        with st.sidebar:
            st.markdown("---")
            st.subheader("📚 Search History")

            search_term = st.text_input(
                "🔍 Search domains",
                placeholder="example.com",
                key="search_history_input"
            )

            tab1, tab2 = st.tabs(["Recent", "Search"])
            selected_domain = None

            with tab1:
                st.markdown("### Recent Searches")
                recent = self.manager.get_recent_searches(limit=15)

                if recent:
                    stats = self.manager.get_search_stats()
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Domains", stats['total_unique_domains'])
                    c2.metric("Searches", stats['total_searches'])
                    c3.metric("Done", stats['completed_analyses'])
                    st.markdown("---")

                    for result in recent:
                        hit = self._render_domain_row(result, "recent")
                        if hit:
                            selected_domain = hit
                else:
                    st.info("No search history yet. Start by analyzing a domain!")

            with tab2:
                st.markdown("### Search Results")
                if search_term and search_term.strip():
                    results = self.manager.search_domains(search_term)
                    if results:
                        st.success(f"Found {len(results)} result(s)")
                        st.markdown("---")
                        for result in results:
                            hit = self._render_domain_row(result, "search")
                            if hit:
                                selected_domain = hit
                    else:
                        st.warning(f"No results for '{search_term}'")
                else:
                    st.info("Enter a domain name to search")

            st.markdown("---")

        return selected_domain

    # ── history modal / expander ─────────────────────────────────────────────

    def render_history_modal(self):
        """Render full search history with delete buttons in an expander."""
        with st.expander("📊 Search History", expanded=False):
            stats = self.manager.get_search_stats()
            c1, c2, c3 = st.columns(3)
            c1.metric("Unique Domains", stats['total_unique_domains'])
            c2.metric("Total Searches", stats['total_searches'])
            c3.metric("Completed", stats['completed_analyses'])

            st.markdown("---")

            recent = self.manager.get_recent_searches(limit=50)
            if not recent:
                st.info("No search history available")
                return

            # Table header
            hc1, hc2, hc3, hc4, hc5 = st.columns([3, 1, 1, 1, 1])
            hc1.markdown("**Domain**")
            hc2.markdown("**Status**")
            hc3.markdown("**Done %**")
            hc4.markdown("**Searches**")
            hc5.markdown("**Delete**")
            st.markdown("---")

            for item in recent:
                domain = item['domain']
                status = item.get('status', 'pending')
                pct = item.get('completion_percentage', 0)
                count = item.get('search_count', 1)
                icon = self._status_icon(status)

                rc1, rc2, rc3, rc4, rc5 = st.columns([3, 1, 1, 1, 1])
                rc1.write(domain)
                rc2.write(f"{icon} {status}")
                rc3.write(f"{pct}%")
                rc4.write(str(count))

                with rc5:
                    if st.button("🗑️", key=f"modal_del_{domain}", help=f"Delete {domain}"):
                        st.session_state[f"modal_confirm_{domain}"] = True

                if st.session_state.get(f"modal_confirm_{domain}"):
                    st.warning(f"Delete **{domain}** and all its data?")
                    mc1, mc2 = st.columns(2)
                    with mc1:
                        if st.button("Yes, delete", key=f"modal_confirm_yes_{domain}",
                                     type="primary", use_container_width=True):
                            ok = self.manager.delete_domain(domain)
                            st.success(f"Deleted {domain}") if ok else st.error("Delete failed")
                            del st.session_state[f"modal_confirm_{domain}"]
                            st.rerun()
                    with mc2:
                        if st.button("Cancel", key=f"modal_confirm_no_{domain}",
                                     use_container_width=True):
                            del st.session_state[f"modal_confirm_{domain}"]
                            st.rerun()

    # ── thin wrappers ─────────────────────────────────────────────────────────

    def record_domain_search(self, domain: str, analysis_id: int = None):
        self.manager.record_search(domain, analysis_id, 'in_progress', 0)

    def update_domain_status(self, domain: str, status: str, completion_percentage: int = 0):
        self.manager.update_search_status(domain, status, completion_percentage)

    def get_domain_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        return self.manager.get_domain_analysis(domain)

    def get_recent_searches(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.manager.get_recent_searches(limit)

    def search_domains(self, search_term: str) -> List[Dict[str, Any]]:
        return self.manager.search_domains(search_term)
