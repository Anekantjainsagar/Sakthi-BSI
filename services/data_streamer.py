#!/usr/bin/env python3
"""
Data Streamer - Real-time data extraction and storage layer
Captures phase outputs immediately and stores them in database
"""

import json
import logging
from typing import Dict, Any, Callable, Optional
from datetime import datetime
from core.database import get_db_manager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataStreamer:
    """Streams and stores phase data in real-time"""
    
    def __init__(self, analysis_id: int, domain: str, db_path: str = "bsi_analysis.db"):
        """Initialize data streamer"""
        self.analysis_id = analysis_id
        self.domain = domain
        self.db = get_db_manager(db_path)
        self.phase_data = {}
        self.callbacks = {}
    
    def register_callback(self, phase_num: int, callback: Callable):
        """Register callback for phase data updates"""
        if phase_num not in self.callbacks:
            self.callbacks[phase_num] = []
        self.callbacks[phase_num].append(callback)
        logger.info(f"✅ Registered callback for Phase {phase_num}")
    
    def trigger_callbacks(self, phase_num: int, data: Dict[str, Any]):
        """Trigger all callbacks for a phase"""
        if phase_num in self.callbacks:
            for callback in self.callbacks[phase_num]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"❌ Callback error for Phase {phase_num}: {e}")
    
    def stream_phase_data(self, phase_num: int, phase_name: str, data: Dict[str, Any], 
                         duration_seconds: float = 0) -> bool:
        """
        Stream phase data: extract, validate, store, and trigger callbacks
        
        Args:
            phase_num: Phase number (1-5)
            phase_name: Phase name
            data: Phase output data
            duration_seconds: Phase execution duration
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"📥 Streaming Phase {phase_num}: {phase_name}")
            
            # Validate data
            if not data:
                logger.warning(f"⚠️ Phase {phase_num} returned empty data")
                return False
            
            if 'error' in data:
                logger.error(f"❌ Phase {phase_num} error: {data['error']}")
                self.db.save_phase_error(self.analysis_id, phase_num, phase_name, data['error'])
                return False
            
            # Extract key metrics
            metrics = self._extract_metrics(phase_num, data)
            logger.info(f"✅ Extracted metrics for Phase {phase_num}: {metrics}")
            
            # Store in database immediately
            logger.info(f"💾 Storing Phase {phase_num} data to database...")
            self.db.save_phase_result(self.analysis_id, phase_num, phase_name, data, duration_seconds)
            logger.info(f"✅ Phase {phase_num} data stored successfully")
            
            # Cache for quick access
            self.phase_data[phase_num] = {
                'data': data,
                'metrics': metrics,
                'stored_at': datetime.now().isoformat()
            }
            
            # Trigger callbacks for real-time display
            self.trigger_callbacks(phase_num, data)
            
            # Update analysis status
            completion = int((phase_num / 5) * 100)
            self.db.update_analysis_status(self.analysis_id, 'in_progress', completion)
            self.db.add_to_search_history(self.domain, self.analysis_id, 'in_progress', completion)
            
            logger.info(f"✅ Phase {phase_num} streaming complete ({completion}% overall)")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error streaming Phase {phase_num}: {e}")
            self.db.save_phase_error(self.analysis_id, phase_num, phase_name, str(e))
            return False
    
    def _extract_metrics(self, phase_num: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics from phase data"""
        metrics = {
            'phase': phase_num,
            'timestamp': datetime.now().isoformat(),
            'data_size': len(json.dumps(data, default=str))
        }
        
        try:
            if phase_num == 1:  # Business Domain
                metrics['emails_found'] = len(data.get('hunter_io', {}).get('emails', []))
                metrics['company_name'] = data.get('abstractapi_company', {}).get('name', 'N/A')
                metrics['industry'] = data.get('abstractapi_company', {}).get('industry', 'N/A')
            
            elif phase_num == 2:  # Infrastructure
                metrics['subdomains'] = len(data.get('subdomains', []))
                metrics['open_ports'] = sum(len(p) for p in data.get('open_ports', {}).values())
                metrics['dns_records'] = len(data.get('dns_records', {}))
            
            elif phase_num == 3:  # Application
                metrics['technologies'] = len(data.get('2_web_server_stack', {}).get('technologies', []))
                metrics['cms'] = data.get('2_web_server_stack', {}).get('cms', 'N/A')
                metrics['server'] = data.get('1_application_discovery', {}).get('server', 'N/A')
            
            elif phase_num == 4:  # Correlation
                metrics['cves_found'] = len(data.get('cves_all', []))
                metrics['security_issues'] = len(data.get('security_issues', []))
                metrics['attack_vectors'] = len(data.get('attack_vectors', []))
            
            elif phase_num == 5:  # Risk Assessment
                metrics['business_risk'] = data.get('business_risk', {}).get('risk_level', 'N/A')
                metrics['infra_risk'] = data.get('infrastructure_risk', {}).get('risk_level', 'N/A')
                metrics['app_risk'] = data.get('application_risk', {}).get('risk_level', 'N/A')
        
        except Exception as e:
            logger.warning(f"⚠️ Error extracting metrics for Phase {phase_num}: {e}")
        
        return metrics
    
    def get_phase_data(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Get cached phase data"""
        return self.phase_data.get(phase_num, {}).get('data')
    
    def get_phase_metrics(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Get cached phase metrics"""
        return self.phase_data.get(phase_num, {}).get('metrics')
    
    def get_all_phases(self) -> Dict[int, Dict[str, Any]]:
        """Get all cached phase data"""
        return self.phase_data
    
    def finalize(self):
        """Finalize streaming and mark analysis as complete"""
        try:
            logger.info("🏁 Finalizing analysis...")
            self.db.update_analysis_status(self.analysis_id, 'completed', 100)
            self.db.add_to_search_history(self.domain, self.analysis_id, 'completed', 100)
            logger.info("✅ Analysis finalized and marked as complete")
        except Exception as e:
            logger.error(f"❌ Error finalizing analysis: {e}")


class StreamingProgressTracker:
    """Tracks streaming progress for UI display"""
    
    def __init__(self):
        """Initialize progress tracker"""
        self.phases = {
            1: {'name': 'Business Domain', 'status': 'pending', 'progress': 0},
            2: {'name': 'Infrastructure', 'status': 'pending', 'progress': 0},
            3: {'name': 'Application', 'status': 'pending', 'progress': 0},
            4: {'name': 'Correlation', 'status': 'pending', 'progress': 0},
            5: {'name': 'Risk Assessment', 'status': 'pending', 'progress': 0}
        }
        self.metrics = {}
    
    def update_phase(self, phase_num: int, status: str, progress: int = 0, metrics: Dict = None):
        """Update phase status"""
        if phase_num in self.phases:
            self.phases[phase_num]['status'] = status
            self.phases[phase_num]['progress'] = progress
            if metrics:
                self.metrics[phase_num] = metrics
            logger.info(f"📊 Phase {phase_num} updated: {status} ({progress}%)")
    
    def get_phase_status(self, phase_num: int) -> Dict[str, Any]:
        """Get phase status"""
        return self.phases.get(phase_num, {})
    
    def get_all_status(self) -> Dict[int, Dict[str, Any]]:
        """Get all phases status"""
        return self.phases
    
    def get_overall_progress(self) -> int:
        """Calculate overall progress"""
        total = sum(p['progress'] for p in self.phases.values())
        return int(total / len(self.phases))
