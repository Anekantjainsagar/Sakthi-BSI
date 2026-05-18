#!/usr/bin/env python3
"""
Enhanced BSI Orchestrator with Database Integration
Adds history tracking, resume capability, and phase checkpointing
"""

import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional
import logging

from core.database import get_db_manager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BSIOrchestratorWithDB:
    """Enhanced orchestrator with database integration"""
    
    def __init__(self, db_path: str = "bsi_analysis.db"):
        """Initialize orchestrator with database"""
        self.db = get_db_manager(db_path)
        self.domain = None
        self.analysis_id = None
        self.results = {
            'business_domain': None,
            'infrastructure': None,
            'application_landscape': None,
            'correlation_analysis': None,
            'risk_assessment': None,
            'timestamp': None,
            'status': {
                'business_domain': 'pending',
                'infrastructure': 'pending',
                'application_landscape': 'pending',
                'correlation_analysis': 'pending',
                'risk_assessment': 'pending'
            }
        }
    
    def check_existing_analysis(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if domain was already analyzed"""
        existing = self.db.get_analysis(domain)
        
        if existing:
            logger.info(f"📋 Found existing analysis for {domain}")
            logger.info(f"   Status: {existing['status']}")
            logger.info(f"   Completion: {existing['completion_percentage']}%")
            logger.info(f"   Last updated: {existing['updated_at']}")
            return existing
        
        return None
    
    def resume_analysis(self, domain: str) -> bool:
        """Resume interrupted analysis from last checkpoint"""
        existing = self.db.get_analysis(domain)
        
        if not existing:
            logger.info(f"ℹ️ No previous analysis found for {domain}")
            return False
        
        self.analysis_id = existing['id']
        self.domain = domain
        
        # Load completed phases
        phases = self.db.get_all_phase_results(self.analysis_id)
        
        logger.info(f"🔄 Resuming analysis for {domain}")
        logger.info(f"   Analysis ID: {self.analysis_id}")
        
        for phase in phases:
            phase_num = phase['phase_number']
            phase_name = phase['phase_name']
            status = phase['status']
            
            if status == 'completed':
                logger.info(f"   ✅ Phase {phase_num} ({phase_name}): COMPLETED")
                self.results[self._get_phase_key(phase_num)] = phase['result_data']
                self.results['status'][self._get_phase_key(phase_num)] = 'completed'
            elif status == 'failed':
                logger.warning(f"   ❌ Phase {phase_num} ({phase_name}): FAILED - {phase['error_message']}")
                self.results['status'][self._get_phase_key(phase_num)] = 'failed'
            else:
                logger.info(f"   ⏳ Phase {phase_num} ({phase_name}): PENDING")
        
        return True
    
    def _get_phase_key(self, phase_number: int) -> str:
        """Map phase number to result key"""
        phase_map = {
            1: 'business_domain',
            2: 'infrastructure',
            3: 'application_landscape',
            4: 'correlation_analysis',
            5: 'risk_assessment'
        }
        return phase_map.get(phase_number, '')
    
    def _get_phase_name(self, phase_number: int) -> str:
        """Get phase name"""
        phase_names = {
            1: 'Business Domain Understanding',
            2: 'Infrastructure Discovery',
            3: 'Application Landscape',
            4: 'Correlation Analysis',
            5: 'Risk Assessment'
        }
        return phase_names.get(phase_number, f'Phase {phase_number}')
    
    def start_analysis(self, domain: str, force_new: bool = False) -> int:
        """Start new analysis or resume existing"""
        self.domain = domain
        
        if not force_new:
            # Try to resume
            if self.resume_analysis(domain):
                return self.analysis_id
        
        # Create new analysis
        self.analysis_id = self.db.create_analysis(domain)
        self.results['timestamp'] = datetime.now().isoformat()
        
        logger.info(f"🚀 Starting new analysis for {domain}")
        logger.info(f"   Analysis ID: {self.analysis_id}")
        
        return self.analysis_id
    
    def run_phase(self, phase_number: int, phase_func, *args, **kwargs) -> Dict[str, Any]:
        """Run a phase with database tracking"""
        phase_name = self._get_phase_name(phase_number)
        phase_key = self._get_phase_key(phase_number)
        
        # Check if already completed
        existing_result = self.db.get_phase_result(self.analysis_id, phase_number)
        if existing_result and existing_result['status'] == 'completed':
            logger.info(f"⏭️  Phase {phase_number} ({phase_name}): Already completed, skipping")
            self.results[phase_key] = existing_result['result_data']
            self.results['status'][phase_key] = 'completed'
            return existing_result['result_data']
        
        logger.info(f"▶️  Starting Phase {phase_number}: {phase_name}")
        start_time = time.time()
        
        try:
            # Run the phase function
            result = phase_func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Save to database
            self.db.save_phase_result(
                self.analysis_id,
                phase_number,
                phase_name,
                result,
                duration
            )
            
            # Update results
            self.results[phase_key] = result
            self.results['status'][phase_key] = 'completed'
            
            # Update analysis progress
            progress = self.db.get_analysis_progress(self.analysis_id)
            self.db.update_analysis_status(
                self.analysis_id,
                'in_progress',
                progress['completion_percentage']
            )
            
            logger.info(f"✅ Phase {phase_number} completed in {duration:.2f}s")
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            
            # Save error to database
            self.db.save_phase_error(
                self.analysis_id,
                phase_number,
                phase_name,
                error_msg
            )
            
            self.results['status'][phase_key] = 'failed'
            
            logger.error(f"❌ Phase {phase_number} failed: {error_msg}")
            raise
    
    def finalize_analysis(self):
        """Mark analysis as completed"""
        progress = self.db.get_analysis_progress(self.analysis_id)
        
        # Check if all phases completed
        if progress['failed_count'] == 0 and progress['completed_count'] == 5:
            status = 'completed'
        elif progress['failed_count'] > 0:
            status = 'completed_with_errors'
        else:
            status = 'in_progress'
        
        self.db.update_analysis_status(
            self.analysis_id,
            status,
            progress['completion_percentage']
        )
        
        logger.info(f"📊 Analysis finalized: {status}")
        logger.info(f"   Completed phases: {progress['completed_count']}/5")
        logger.info(f"   Failed phases: {progress['failed_count']}")
        logger.info(f"   Total duration: {progress['total_duration_seconds']:.2f}s")
    
    def get_analysis_status(self) -> Dict[str, Any]:
        """Get current analysis status"""
        if not self.analysis_id:
            return {'error': 'No analysis in progress'}
        
        progress = self.db.get_analysis_progress(self.analysis_id)
        analysis = self.db.get_analysis_by_id(self.analysis_id)
        
        return {
            'domain': self.domain,
            'analysis_id': self.analysis_id,
            'status': analysis['status'],
            'completion_percentage': progress['completion_percentage'],
            'phases': progress['phases'],
            'total_duration_seconds': progress['total_duration_seconds']
        }


class DatabaseIntegrationHelper:
    """Helper class for database operations in Streamlit context"""
    
    @staticmethod
    def display_analysis_history(limit: int = 10):
        """Display recent analyses (for Streamlit UI)"""
        db = get_db_manager()
        analyses = db.list_recent_analyses(limit)
        
        if not analyses:
            return None
        
        return analyses
    
    @staticmethod
    def display_database_stats():
        """Display database statistics (for Streamlit UI)"""
        db = get_db_manager()
        return db.get_database_stats()
    
    @staticmethod
    def search_domain_history(search_term: str):
        """Search domain analysis history"""
        db = get_db_manager()
        return db.search_analyses(search_term)
    
    @staticmethod
    def get_cached_api_response(cache_key: str):
        """Get cached API response"""
        db = get_db_manager()
        return db.get_cached_response(cache_key)
    
    @staticmethod
    def cache_api_response(cache_key: str, api_name: str, domain: str, 
                          response_data: Dict[str, Any], ttl_hours: int = 24):
        """Cache API response"""
        db = get_db_manager()
        db.cache_api_response(cache_key, api_name, domain, response_data, ttl_hours)
