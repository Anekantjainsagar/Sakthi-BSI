#!/usr/bin/env python3
"""
Search History Manager - Manages domain search history and quick access
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from data.database import get_db_manager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SearchHistoryManager:
    """Manages search history for quick domain access and retrieval"""
    
    def __init__(self, db_path: str = "data/bsi_analysis.db"):
        """Initialize search history manager"""
        self.db = get_db_manager(db_path)
    
    def record_search(self, domain: str, analysis_id: int = None, status: str = 'pending', completion_percentage: int = 0):
        """Record a domain search in history"""
        try:
            self.db.add_to_search_history(domain, analysis_id, status, completion_percentage)
            logger.info(f"✅ Recorded search for {domain}")
        except Exception as e:
            logger.error(f"❌ Failed to record search: {e}")
    
    def get_recent_searches(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent domain searches"""
        try:
            searches = self.db.get_search_history(limit)
            return searches
        except Exception as e:
            logger.error(f"❌ Failed to get recent searches: {e}")
            return []
    
    def search_domains(self, search_term: str) -> List[Dict[str, Any]]:
        """Search for domains in history"""
        try:
            if not search_term or len(search_term.strip()) == 0:
                return []
            
            results = self.db.search_history(search_term.strip())
            logger.info(f"🔍 Found {len(results)} results for '{search_term}'")
            return results
        except Exception as e:
            logger.error(f"❌ Failed to search domains: {e}")
            return []
    
    def get_domain_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get analysis data for a domain"""
        try:
            analysis = self.db.get_analysis(domain)
            if analysis:
                # Get all phase results
                phases = self.db.get_all_phase_results(analysis['id'])
                analysis['phases'] = phases
                return analysis
            return None
        except Exception as e:
            logger.error(f"❌ Failed to get domain analysis: {e}")
            return None
    
    def get_search_stats(self) -> Dict[str, Any]:
        """Get search history statistics"""
        try:
            stats = self.db.get_search_history_stats()
            return stats
        except Exception as e:
            logger.error(f"❌ Failed to get search stats: {e}")
            return {
                'total_unique_domains': 0,
                'total_searches': 0,
                'completed_analyses': 0
            }
    
    def format_search_result(self, result: Dict[str, Any]) -> str:
        """Format search result for display"""
        domain = result.get('domain', 'Unknown')
        status = result.get('status', 'pending')
        completion = result.get('completion_percentage', 0)
        search_count = result.get('search_count', 1)
        
        status_icon = {
            'completed': '✅',
            'in_progress': '⏳',
            'pending': '⏱️',
            'failed': '❌'
        }.get(status, '❓')
        
        return f"{status_icon} {domain} ({completion}%) - Searched {search_count}x"
    
    def get_formatted_recent_searches(self, limit: int = 10) -> List[str]:
        """Get formatted recent searches for display"""
        searches = self.get_recent_searches(limit)
        return [self.format_search_result(s) for s in searches]
    
    def get_formatted_search_results(self, search_term: str) -> List[str]:
        """Get formatted search results for display"""
        results = self.search_domains(search_term)
        return [self.format_search_result(r) for r in results]
    
    def get_domain_from_formatted(self, formatted_str: str) -> str:
        """Extract domain from formatted string"""
        # Format: "✅ domain.com (100%) - Searched 5x"
        parts = formatted_str.split(' ')
        if len(parts) > 1:
            return parts[1]
        return formatted_str
    
    def update_search_status(self, domain: str, status: str, completion_percentage: int = 0):
        """Update search status in history"""
        try:
            analysis = self.db.get_analysis(domain)
            if analysis:
                self.db.add_to_search_history(domain, analysis['id'], status, completion_percentage)
                logger.info(f"✅ Updated {domain} status to {status}")
        except Exception as e:
            logger.error(f"❌ Failed to update search status: {e}")

    def delete_domain(self, domain: str) -> bool:
        """Delete all data for a domain (analysis, phases, cache, search history)"""
        try:
            result = self.db.delete_domain_data(domain)
            if result:
                logger.info(f"🗑️ Deleted all data for {domain}")
            else:
                logger.warning(f"⚠️ No data found for {domain}")
            return result
        except Exception as e:
            logger.error(f"❌ Failed to delete domain {domain}: {e}")
            return False
