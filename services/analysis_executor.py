#!/usr/bin/env python3
"""
Analysis Executor Service
Orchestrates analysis execution with dummy data fallback and parallel processing
Integrates database, parallel execution, and dummy data generation
"""

import sys
import os
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.dummy_data_generator import DummyDataGenerator
from services.parallel_executor import ParallelExecutor
from services.api_optimizer import APIOptimizer, DNSOptimizer
from data.database import get_db_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("analysis-executor")


class AnalysisExecutor:
    """
    Main analysis executor with fallback to dummy data
    Supports both real API calls and dummy data generation
    """
    
    def __init__(self, db_path: str = "bsi.db", use_dummy_data: bool = False, 
                 use_parallel: bool = True, max_workers: int = 5):
        """
        Initialize analysis executor
        
        Args:
            db_path: Path to database file
            use_dummy_data: Use dummy data instead of real APIs
            use_parallel: Enable parallel execution
            max_workers: Maximum parallel workers
        """
        self.db_path = db_path
        self.use_dummy_data = use_dummy_data
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        
        self.db = get_db_manager(db_path)
        self.parallel_executor = ParallelExecutor(max_workers=max_workers, timeout=60)
        self.api_optimizer = APIOptimizer()
        self.dns_optimizer = DNSOptimizer()
        
        logger.info(f"Analysis Executor initialized")
        logger.info(f"  Database: {db_path}")
        logger.info(f"  Dummy Data: {'ENABLED' if use_dummy_data else 'DISABLED'}")
        logger.info(f"  Parallel: {'ENABLED' if use_parallel else 'DISABLED'}")
    
    def execute_analysis(self, domain: str, force_new: bool = False, 
                        use_dummy: Optional[bool] = None) -> Dict[str, Any]:
        """
        Execute complete analysis for a domain
        
        Args:
            domain: Domain to analyze
            force_new: Force new analysis even if exists
            use_dummy: Override default dummy data setting
        
        Returns:
            Analysis results
        """
        use_dummy_data = use_dummy if use_dummy is not None else self.use_dummy_data
        
        logger.info(f"\n{'='*70}")
        logger.info(f"ANALYSIS EXECUTION: {domain}")
        logger.info(f"{'='*70}")
        logger.info(f"Mode: {'DUMMY DATA' if use_dummy_data else 'REAL APIs'}")
        logger.info(f"Parallel: {'ENABLED' if self.use_parallel else 'DISABLED'}")
        
        start_time = time.time()
        
        # Check if analysis exists
        if not force_new:
            existing = self.db.get_analysis(domain)
            if existing and existing['status'] != 'failed':
                logger.info(f"Analysis already exists for {domain}, resuming...")
                return self._resume_analysis(domain)
        
        # Create new analysis
        analysis_id = self.db.create_analysis(domain, notes=f"Analysis mode: {'Dummy Data' if use_dummy_data else 'Real APIs'}")
        logger.info(f"Created analysis ID: {analysis_id}")
        
        try:
            if use_dummy_data:
                # Use dummy data generator
                result = self._execute_with_dummy_data(analysis_id, domain)
            else:
                # Use real APIs with fallback to dummy data on error
                result = self._execute_with_real_apis(analysis_id, domain)
            
            elapsed = time.time() - start_time
            result['elapsed_time'] = elapsed
            
            # Update analysis status
            self.db.update_analysis_status(analysis_id, 'completed', completion_percentage=100)
            
            logger.info(f"\n{'='*70}")
            logger.info(f"ANALYSIS COMPLETED: {domain}")
            logger.info(f"Total Time: {elapsed:.2f}s")
            logger.info(f"{'='*70}\n")
            
            return result
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.db.update_analysis_status(analysis_id, 'failed', completion_percentage=0)
            raise
    
    def _execute_with_dummy_data(self, analysis_id: int, domain: str) -> Dict[str, Any]:
        """
        Execute analysis using dummy data
        
        Args:
            analysis_id: Analysis ID
            domain: Domain to analyze
        
        Returns:
            Analysis results
        """
        logger.info(f"\nGenerating dummy data for {domain}...")
        
        generator = DummyDataGenerator(domain)
        all_data = generator.generate_all_phases()
        
        # Run phases in parallel (1-3) then sequential (4-5)
        logger.info("Running phases 1-3 in parallel...")
        phase_results = self._run_phases_parallel(analysis_id, all_data)
        
        # Run phases 4-5 sequentially
        logger.info("Running phases 4-5 sequentially...")
        phase_results.update(self._run_phases_sequential(analysis_id, all_data))
        
        return {
            'analysis_id': analysis_id,
            'domain': domain,
            'status': 'completed',
            'mode': 'dummy_data',
            'phases': phase_results,
            'results': all_data
        }
    
    def _execute_with_real_apis(self, analysis_id: int, domain: str) -> Dict[str, Any]:
        """
        Execute analysis using real APIs with fallback to dummy data
        
        Args:
            analysis_id: Analysis ID
            domain: Domain to analyze
        
        Returns:
            Analysis results
        """
        logger.info(f"\nExecuting analysis with real APIs for {domain}...")
        
        try:
            # Try to import and run real phases
            from phases.phase1 import CompanyIntelligenceAnalyzer
            from phases.phase2 import BSIInfrastructureDiscovery
            from phases.phase3 import CompleteBSIScanner
            from phases.phase4 import AIPhase4Scanner
            from phases.phase5 import RiskAssessmentEngine
            
            # Phase 1: Business Domain
            logger.info("Running Phase 1: Business Domain Intelligence...")
            phase1_start = time.time()
            analyzer1 = CompanyIntelligenceAnalyzer()
            phase1_data = analyzer1.analyze_business_domain(domain)
            phase1_duration = time.time() - phase1_start
            self.db.save_phase_result(analysis_id, 1, "Business Domain", phase1_data, phase1_duration)
            
            # Phase 2: Infrastructure
            logger.info("Running Phase 2: Infrastructure Discovery...")
            phase2_start = time.time()
            analyzer2 = InfrastructureAnalyzer()
            phase2_data = analyzer2.analyze_infrastructure(domain)
            phase2_duration = time.time() - phase2_start
            self.db.save_phase_result(analysis_id, 2, "Infrastructure", phase2_data, phase2_duration)
            
            # Phase 3: Application
            logger.info("Running Phase 3: Application Landscape...")
            phase3_start = time.time()
            analyzer3 = ApplicationAnalyzer()
            phase3_data = analyzer3.analyze_application(domain)
            phase3_duration = time.time() - phase3_start
            self.db.save_phase_result(analysis_id, 3, "Application", phase3_data, phase3_duration)
            
            # Phase 4: Correlation
            logger.info("Running Phase 4: Threat Correlation...")
            phase4_start = time.time()
            analyzer4 = ThreatCorrelationAnalyzer()
            phase4_data = analyzer4.analyze_correlation(phase1_data, phase2_data, phase3_data)
            phase4_duration = time.time() - phase4_start
            self.db.save_phase_result(analysis_id, 4, "Correlation", phase4_data, phase4_duration)
            
            # Phase 5: Risk Assessment
            logger.info("Running Phase 5: Risk Assessment...")
            phase5_start = time.time()
            analyzer5 = RiskAssessmentAnalyzer()
            phase5_data = analyzer5.analyze_risk(phase1_data, phase2_data, phase3_data, phase4_data)
            phase5_duration = time.time() - phase5_start
            self.db.save_phase_result(analysis_id, 5, "Risk Assessment", phase5_data, phase5_duration)
            
            return {
                'analysis_id': analysis_id,
                'domain': domain,
                'status': 'completed',
                'mode': 'real_apis',
                'phases': {
                    'Phase 1': {'duration': phase1_duration, 'status': 'completed'},
                    'Phase 2': {'duration': phase2_duration, 'status': 'completed'},
                    'Phase 3': {'duration': phase3_duration, 'status': 'completed'},
                    'Phase 4': {'duration': phase4_duration, 'status': 'completed'},
                    'Phase 5': {'duration': phase5_duration, 'status': 'completed'}
                },
                'results': {
                    'phase1': phase1_data,
                    'phase2': phase2_data,
                    'phase3': phase3_data,
                    'phase4': phase4_data,
                    'phase5': phase5_data
                }
            }
        
        except Exception as e:
            logger.warning(f"Real API execution failed: {e}")
            logger.info("Falling back to dummy data...")
            return self._execute_with_dummy_data(analysis_id, domain)
    
    def _run_phases_parallel(self, analysis_id: int, all_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run phases 1-3 in parallel
        
        Args:
            analysis_id: Analysis ID
            all_data: All phase data
        
        Returns:
            Phase results
        """
        tasks = [
            {
                'name': 'Phase 1',
                'func': self._save_phase,
                'args': (analysis_id, 1, 'Business Domain', all_data['phase1'], 2.5)
            },
            {
                'name': 'Phase 2',
                'func': self._save_phase,
                'args': (analysis_id, 2, 'Infrastructure', all_data['phase2'], 3.0)
            },
            {
                'name': 'Phase 3',
                'func': self._save_phase,
                'args': (analysis_id, 3, 'Application', all_data['phase3'], 2.0)
            }
        ]
        
        result = self.parallel_executor.execute_parallel(tasks)
        
        phase_results = {}
        for phase_name, phase_data in result['results'].items():
            phase_results[phase_name] = phase_data
        
        for phase_name, error in result['errors'].items():
            logger.error(f"{phase_name} failed: {error}")
        
        return phase_results
    
    def _run_phases_sequential(self, analysis_id: int, all_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run phases 4-5 sequentially (they depend on previous phases)
        
        Args:
            analysis_id: Analysis ID
            all_data: All phase data
        
        Returns:
            Phase results
        """
        phase_results = {}
        
        # Phase 4
        logger.info("Running Phase 4: Correlation...")
        result4 = self._save_phase(analysis_id, 4, 'Correlation', all_data['phase4'], 2.5)
        phase_results['Phase 4'] = result4
        
        # Phase 5
        logger.info("Running Phase 5: Risk Assessment...")
        result5 = self._save_phase(analysis_id, 5, 'Risk Assessment', all_data['phase5'], 1.5)
        phase_results['Phase 5'] = result5
        
        return phase_results
    
    def _save_phase(self, analysis_id: int, phase_num: int, phase_name: str, 
                   phase_data: Dict[str, Any], duration: float) -> Dict[str, Any]:
        """
        Save phase result to database
        
        Args:
            analysis_id: Analysis ID
            phase_num: Phase number
            phase_name: Phase name
            phase_data: Phase data
            duration: Simulated duration in seconds
        
        Returns:
            Phase result
        """
        # Simulate phase execution
        time.sleep(duration)
        
        # Save to database
        self.db.save_phase_result(
            analysis_id,
            phase_num,
            phase_name,
            phase_data,
            duration_seconds=duration
        )
        
        logger.info(f"✓ Phase {phase_num} ({phase_name}) saved - {duration:.1f}s")
        
        return {
            'phase': phase_num,
            'name': phase_name,
            'status': 'completed',
            'duration': duration
        }
    
    def _resume_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Resume an existing analysis
        
        Args:
            domain: Domain to resume
        
        Returns:
            Resumed analysis results
        """
        analysis = self.db.get_analysis(domain)
        logger.info(f"Resuming analysis for {domain}")
        logger.info(f"Current status: {analysis['status']}")
        logger.info(f"Completion: {analysis['completion_percentage']}%")
        
        phases = self.db.get_all_phase_results(analysis['id'])
        
        return {
            'analysis_id': analysis['id'],
            'domain': domain,
            'status': analysis['status'],
            'completion_percentage': analysis['completion_percentage'],
            'phases': phases,
            'resumed': True
        }
    
    def get_analysis_history(self, limit: int = 10) -> list:
        """Get recent analyses"""
        return self.db.list_recent_analyses(limit)
    
    def get_analysis_details(self, domain: str) -> Dict[str, Any]:
        """Get detailed analysis information"""
        analysis = self.db.get_analysis(domain)
        if not analysis:
            return None
        
        phases = self.db.get_all_phase_results(analysis['id'])
        summary = self.db.get_analysis_summary(analysis['id'])
        
        return {
            'analysis': analysis,
            'phases': phases,
            'summary': summary
        }
    
    def shutdown(self):
        """Shutdown the executor"""
        self.parallel_executor.shutdown()
        logger.info("Analysis executor shutdown complete")


# Example usage
if __name__ == "__main__":
    # Test with dummy data
    executor = AnalysisExecutor(db_path="test_executor.db", use_dummy_data=True)
    
    try:
        # Run analysis
        result = executor.execute_analysis("example.com", force_new=True)
        
        print(f"\n{'='*70}")
        print("ANALYSIS RESULT")
        print(f"{'='*70}")
        print(f"Domain: {result['domain']}")
        print(f"Status: {result['status']}")
        print(f"Mode: {result['mode']}")
        print(f"Time: {result['elapsed_time']:.2f}s")
        print(f"Phases: {len(result['phases'])}")
        
        # Get history
        history = executor.get_analysis_history()
        print(f"\nRecent Analyses: {len(history)}")
        for analysis in history:
            print(f"  - {analysis['domain']}: {analysis['status']} ({analysis['completion_percentage']}%)")
    
    finally:
        executor.shutdown()
