#!/usr/bin/env python3
"""
BSI Database Manager - SQLite integration for analysis history and resume capability
Handles domain analysis history, phase tracking, and result caching
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
import threading

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BSIDatabaseManager:
    """Manages SQLite database for BSI analysis history and caching"""
    
    def __init__(self, db_path: str = "data/bsi_analysis.db"):
        """Initialize database connection and create tables if needed"""
        self.db_path = db_path
        self.lock = threading.Lock()  # Thread-safe operations
        self._init_database()
    
    def _get_connection(self):
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        """Create tables if they don't exist"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Main analysis history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    completion_percentage INTEGER DEFAULT 0,
                    total_duration_seconds REAL DEFAULT 0,
                    notes TEXT
                )
            ''')
            
            # Phase tracking table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phase_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    phase_number INTEGER NOT NULL,
                    phase_name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    result_data TEXT,
                    error_message TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    duration_seconds REAL,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id),
                    UNIQUE(analysis_id, phase_number)
                )
            ''')
            
            # API response cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT NOT NULL UNIQUE,
                    api_name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    response_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    hit_count INTEGER DEFAULT 0
                )
            ''')
            
            # Analysis summary table (for quick lookups)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL UNIQUE,
                    domain TEXT NOT NULL,
                    business_domain_summary TEXT,
                    infrastructure_summary TEXT,
                    application_summary TEXT,
                    correlation_summary TEXT,
                    risk_assessment_summary TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
                )
            ''')
            
            # Search history table for UI display
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    analysis_id INTEGER,
                    first_searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    search_count INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'pending',
                    completion_percentage INTEGER DEFAULT 0,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
                )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON analysis_history(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_status ON phase_results(analysis_id, status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_key ON api_cache(cache_key)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_expires ON api_cache(expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_search_history_domain ON search_history(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_search_history_last_searched ON search_history(last_searched_at DESC)')
            
            conn.commit()
            logger.info(f"✅ Database initialized at {self.db_path}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
        finally:
            conn.close()
    
    # ==================== ANALYSIS HISTORY ====================
    
    def create_analysis(self, domain: str, notes: str = "") -> int:
        """Create new analysis record or return existing one"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                # Check if domain already exists
                cursor.execute('SELECT id FROM analysis_history WHERE domain = ?', (domain,))
                existing = cursor.fetchone()
                
                if existing:
                    logger.info(f"📋 Found existing analysis for {domain}")
                    return existing['id']
                
                # Create new analysis
                cursor.execute('''
                    INSERT INTO analysis_history (domain, status, notes)
                    VALUES (?, ?, ?)
                ''', (domain, 'in_progress', notes))
                
                conn.commit()
                analysis_id = cursor.lastrowid
                logger.info(f"✅ Created new analysis record for {domain} (ID: {analysis_id})")
                return analysis_id
                
            except Exception as e:
                logger.error(f"❌ Failed to create analysis: {e}")
                raise
            finally:
                conn.close()
    
    def get_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get analysis record by domain"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT * FROM analysis_history WHERE domain = ?', (domain,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()
    
    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Get analysis record by ID"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT * FROM analysis_history WHERE id = ?', (analysis_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()
    
    def update_analysis_status(self, analysis_id: int, status: str, completion_percentage: int = None):
        """Update analysis status and completion percentage"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                if completion_percentage is not None:
                    cursor.execute('''
                        UPDATE analysis_history 
                        SET status = ?, completion_percentage = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (status, completion_percentage, analysis_id))
                else:
                    cursor.execute('''
                        UPDATE analysis_history 
                        SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (status, analysis_id))
                
                conn.commit()
                logger.info(f"✅ Updated analysis {analysis_id} status to {status}")
            finally:
                conn.close()
    
    def list_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analyses"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM analysis_history 
                    ORDER BY updated_at DESC 
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
    
    # ==================== PHASE RESULTS ====================
    
    def save_phase_result(self, analysis_id: int, phase_number: int, phase_name: str, 
                         result_data: Dict[str, Any], duration_seconds: float = 0):
        """Save phase result"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                result_json = json.dumps(result_data, default=str)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO phase_results 
                    (analysis_id, phase_number, phase_name, status, result_data, 
                     completed_at, duration_seconds)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                ''', (analysis_id, phase_number, phase_name, 'completed', result_json, duration_seconds))
                
                conn.commit()
                logger.info(f"✅ Saved Phase {phase_number} ({phase_name}) for analysis {analysis_id}")
            except Exception as e:
                logger.error(f"❌ Failed to save phase result: {e}")
                raise
            finally:
                conn.close()
    
    def save_phase_error(self, analysis_id: int, phase_number: int, phase_name: str, error_message: str):
        """Save phase error"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO phase_results 
                    (analysis_id, phase_number, phase_name, status, error_message, completed_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (analysis_id, phase_number, phase_name, 'failed', error_message))
                
                conn.commit()
                logger.warning(f"⚠️ Saved error for Phase {phase_number} ({phase_name}): {error_message}")
            finally:
                conn.close()
    
    def get_phase_result(self, analysis_id: int, phase_number: int) -> Optional[Dict[str, Any]]:
        """Get phase result"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM phase_results 
                    WHERE analysis_id = ? AND phase_number = ?
                ''', (analysis_id, phase_number))
                
                row = cursor.fetchone()
                if row:
                    result = dict(row)
                    if result['result_data']:
                        result['result_data'] = json.loads(result['result_data'])
                    return result
                return None
            finally:
                conn.close()
    
    def get_all_phase_results(self, analysis_id: int) -> List[Dict[str, Any]]:
        """Get all phase results for an analysis"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM phase_results 
                    WHERE analysis_id = ?
                    ORDER BY phase_number
                ''', (analysis_id,))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if result['result_data']:
                        result['result_data'] = json.loads(result['result_data'])
                    results.append(result)
                return results
            finally:
                conn.close()
    
    def get_analysis_progress(self, analysis_id: int) -> Dict[str, Any]:
        """Get analysis progress across all phases"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT phase_number, phase_name, status, duration_seconds
                    FROM phase_results 
                    WHERE analysis_id = ?
                    ORDER BY phase_number
                ''', (analysis_id,))
                
                phases = [dict(row) for row in cursor.fetchall()]
                
                completed = sum(1 for p in phases if p['status'] == 'completed')
                failed = sum(1 for p in phases if p['status'] == 'failed')
                total_duration = sum(p['duration_seconds'] or 0 for p in phases)
                
                return {
                    'phases': phases,
                    'completed_count': completed,
                    'failed_count': failed,
                    'total_phases': len(phases),
                    'total_duration_seconds': total_duration,
                    'completion_percentage': int((completed / 5) * 100) if phases else 0
                }
            finally:
                conn.close()
    
    # ==================== API CACHING ====================
    
    def cache_api_response(self, cache_key: str, api_name: str, domain: str, 
                          response_data: Dict[str, Any], ttl_hours: int = 24):
        """Cache API response"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                response_json = json.dumps(response_data, default=str)
                expires_at = datetime.now() + timedelta(hours=ttl_hours)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO api_cache 
                    (cache_key, api_name, domain, response_data, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (cache_key, api_name, domain, response_json, expires_at))
                
                conn.commit()
                logger.info(f"💾 Cached {api_name} response for {domain}")
            except Exception as e:
                logger.error(f"❌ Failed to cache API response: {e}")
            finally:
                conn.close()
    
    def get_cached_response(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached API response if not expired"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT response_data, hit_count FROM api_cache 
                    WHERE cache_key = ? AND expires_at > CURRENT_TIMESTAMP
                ''', (cache_key,))
                
                row = cursor.fetchone()
                if row:
                    # Increment hit count
                    cursor.execute('UPDATE api_cache SET hit_count = hit_count + 1 WHERE cache_key = ?', (cache_key,))
                    conn.commit()
                    
                    logger.info(f"✅ Cache hit for {cache_key}")
                    return json.loads(row['response_data'])
                
                logger.info(f"❌ Cache miss for {cache_key}")
                return None
            finally:
                conn.close()
    
    def clear_expired_cache(self):
        """Remove expired cache entries"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('DELETE FROM api_cache WHERE expires_at <= CURRENT_TIMESTAMP')
                deleted = cursor.rowcount
                conn.commit()
                logger.info(f"🗑️ Cleared {deleted} expired cache entries")
            finally:
                conn.close()
    
    # ==================== ANALYSIS SUMMARY ====================
    
    def save_analysis_summary(self, analysis_id: int, domain: str, 
                             business_summary: str = "", infrastructure_summary: str = "",
                             application_summary: str = "", correlation_summary: str = "",
                             risk_summary: str = ""):
        """Save analysis summary for quick lookups"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO analysis_summary 
                    (analysis_id, domain, business_domain_summary, infrastructure_summary,
                     application_summary, correlation_summary, risk_assessment_summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (analysis_id, domain, business_summary, infrastructure_summary,
                      application_summary, correlation_summary, risk_summary))
                
                conn.commit()
                logger.info(f"✅ Saved analysis summary for {domain}")
            finally:
                conn.close()
    
    def get_analysis_summary(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Get analysis summary"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT * FROM analysis_summary WHERE analysis_id = ?', (analysis_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()
    
    # ==================== UTILITY ====================
    
    def add_to_search_history(self, domain: str, analysis_id: int = None, status: str = 'pending', completion_percentage: int = 0):
        """Add or update domain in search history"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT INTO search_history (domain, analysis_id, status, completion_percentage)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        last_searched_at = CURRENT_TIMESTAMP,
                        search_count = search_count + 1,
                        analysis_id = COALESCE(?, analysis_id),
                        status = ?,
                        completion_percentage = ?
                ''', (domain, analysis_id, status, completion_percentage, analysis_id, status, completion_percentage))
                
                conn.commit()
                logger.info(f"✅ Added {domain} to search history")
            except Exception as e:
                logger.error(f"❌ Failed to add to search history: {e}")
            finally:
                conn.close()
    
    def get_search_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent search history ordered by last searched"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM search_history 
                    ORDER BY last_searched_at DESC 
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
    
    def search_history(self, search_term: str) -> List[Dict[str, Any]]:
        """Search in search history by domain"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM search_history 
                    WHERE domain LIKE ? 
                    ORDER BY last_searched_at DESC
                ''', (f'%{search_term}%',))
                
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
    
    def get_search_history_stats(self) -> Dict[str, Any]:
        """Get search history statistics"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT COUNT(*) as count FROM search_history')
                total_searches = cursor.fetchone()['count']
                
                cursor.execute('SELECT SUM(search_count) as total FROM search_history')
                total_search_count = cursor.fetchone()['total'] or 0
                
                cursor.execute('SELECT COUNT(*) as count FROM search_history WHERE status = "completed"')
                completed_analyses = cursor.fetchone()['count']
                
                return {
                    'total_unique_domains': total_searches,
                    'total_searches': total_search_count,
                    'completed_analyses': completed_analyses
                }
            finally:
                conn.close()
    
    def search_analyses(self, search_term: str) -> List[Dict[str, Any]]:
        """Search analyses by domain"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    SELECT * FROM analysis_history 
                    WHERE domain LIKE ? 
                    ORDER BY updated_at DESC
                ''', (f'%{search_term}%',))
                
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT COUNT(*) as count FROM analysis_history')
                total_analyses = cursor.fetchone()['count']
                
                cursor.execute('SELECT COUNT(*) as count FROM phase_results WHERE status = "completed"')
                completed_phases = cursor.fetchone()['count']
                
                cursor.execute('SELECT COUNT(*) as count FROM api_cache WHERE expires_at > CURRENT_TIMESTAMP')
                active_cache = cursor.fetchone()['count']
                
                cursor.execute('SELECT SUM(hit_count) as total FROM api_cache')
                cache_hits = cursor.fetchone()['total'] or 0
                
                return {
                    'total_analyses': total_analyses,
                    'completed_phases': completed_phases,
                    'active_cache_entries': active_cache,
                    'total_cache_hits': cache_hits,
                    'database_file': self.db_path
                }
            finally:
                conn.close()
    
    def delete_analysis(self, analysis_id: int):
        """Delete analysis and related data"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute('DELETE FROM phase_results WHERE analysis_id = ?', (analysis_id,))
                cursor.execute('DELETE FROM analysis_summary WHERE analysis_id = ?', (analysis_id,))
                cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
                conn.commit()
                logger.info(f"🗑️ Deleted analysis {analysis_id}")
            finally:
                conn.close()
    
    def delete_domain_data(self, domain: str) -> bool:
        """Delete all data for a domain (analysis, phases, cache, search history)"""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            try:
                # Get analysis ID
                cursor.execute('SELECT id FROM analysis_history WHERE domain = ?', (domain,))
                result = cursor.fetchone()
                
                if not result:
                    logger.warning(f"⚠️ No analysis found for domain {domain}")
                    return False
                
                analysis_id = result['id']
                
                # Delete all related data
                cursor.execute('DELETE FROM phase_results WHERE analysis_id = ?', (analysis_id,))
                cursor.execute('DELETE FROM analysis_summary WHERE analysis_id = ?', (analysis_id,))
                cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
                cursor.execute('DELETE FROM api_cache WHERE domain = ?', (domain,))
                cursor.execute('DELETE FROM search_history WHERE domain = ?', (domain,))
                
                conn.commit()
                logger.info(f"🗑️ Deleted all data for domain {domain}")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to delete domain data: {e}")
                return False
            finally:
                conn.close()


# Singleton instance
_db_instance = None

def get_db_manager(db_path: str = "data/bsi_analysis.db") -> BSIDatabaseManager:
    """Get or create database manager singleton"""
    global _db_instance
    if _db_instance is None:
        _db_instance = BSIDatabaseManager(db_path)
    return _db_instance
