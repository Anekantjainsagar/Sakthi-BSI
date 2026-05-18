#!/usr/bin/env python3
"""
Test Orchestrator
Tests database integration using dummy data
Allows testing without external API dependencies
"""

import time
import logging
import sys
import os
from typing import Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.dummy_data_generator import DummyDataGenerator
from services.parallel_executor import ParallelExecutor
from core.database import get_db_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test-orchestrator")


class TestOrchestrator:
    """
    Test orchestrator that uses dummy data to test database integration
    """
    
    def __init__(self, db_path: str = "bsi.db", use_dummy_data: bool = True):
        """
        Initialize test orchestrator
        
        Args:
            db_path: Path to database file
            use_dummy_data: Whether to use dummy data (True) or real APIs (False)
        """
        self.db_path = db_path
        self.use_dummy_data = use_dummy_data
        self.db = get_db_manager(db_path)
        self.parallel_executor = ParallelExecutor(max_workers=5, timeout=30)
        self.results = {}
        self.errors = {}
    
    def run_test_analysis(self, domain: str, force_new: bool = False) -> Dict[str, Any]:
        """
        Run a complete test analysis using dummy data
        
        Args:
            domain: Domain to analyze
            force_new: Force new analysis even if exists
        
        Returns:
            Analysis results
        """
        logger.info(f"Starting test analysis for {domain}")
        start_time = time.time()
        
        # Check if analysis exists
        if not force_new:
            existing = self.db.get_analysis(domain)
            if existing and existing['status'] != 'failed':
                logger.info(f"Analysis already exists for {domain}, resuming...")
                return self._resume_analysis(domain)
        
        # Create new analysis
        analysis_id = self.db.create_analysis(domain, notes="Test analysis with dummy data")
        logger.info(f"Created analysis ID: {analysis_id}")
        
        # Generate dummy data for all phases
        generator = DummyDataGenerator(domain)
        all_data = generator.generate_all_phases()
        
        # Run phases in parallel (1-3) then sequential (4-5)
        logger.info("Running phases 1-3 in parallel...")
        phase_results = self._run_phases_parallel(analysis_id, all_data)
        
        # Run phases 4-5 sequentially
        logger.info("Running phases 4-5 sequentially...")
        phase_results.update(self._run_phases_sequential(analysis_id, all_data))
        
        # Update analysis status
        self.db.update_analysis_status(analysis_id, 'completed', completion_percentage=100)
        
        elapsed = time.time() - start_time
        logger.info(f"Test analysis completed in {elapsed:.2f}s")
        
        return {
            'analysis_id': analysis_id,
            'domain': domain,
            'status': 'completed',
            'elapsed_time': elapsed,
            'phases': phase_results,
            'results': all_data
        }
    
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
        
        return {
            'analysis_id': analysis['id'],
            'domain': domain,
            'status': analysis['status'],
            'completion_percentage': analysis['completion_percentage'],
            'phases': self.db.get_all_phase_results(analysis['id'])
        }
    
    def test_database_operations(self) -> Dict[str, Any]:
        """
        Test all database operations
        
        Returns:
            Test results
        """
        logger.info("Testing database operations...")
        test_results = {}
        
        # Test 1: Create analysis
        logger.info("Test 1: Creating analysis...")
        analysis_id = self.db.create_analysis("test.com", notes="Database test")
        test_results['create_analysis'] = analysis_id > 0
        logger.info(f"✓ Created analysis ID: {analysis_id}")
        
        # Test 2: Get analysis
        logger.info("Test 2: Getting analysis...")
        analysis = self.db.get_analysis("test.com")
        test_results['get_analysis'] = analysis is not None
        logger.info(f"✓ Retrieved analysis: {analysis['domain']}")
        
        # Test 3: Save phase result
        logger.info("Test 3: Saving phase result...")
        phase_data = {'test': 'data', 'timestamp': datetime.now().isoformat()}
        self.db.save_phase_result(analysis_id, 1, "Test Phase", phase_data, 10.5)
        test_results['save_phase_result'] = True
        logger.info("✓ Saved phase result")
        
        # Test 4: Get phase result
        logger.info("Test 4: Getting phase result...")
        phase_result = self.db.get_phase_result(analysis_id, 1)
        test_results['get_phase_result'] = phase_result is not None
        logger.info(f"✓ Retrieved phase result: {phase_result['phase_name']}")
        
        # Test 5: Cache API response
        logger.info("Test 5: Caching API response...")
        cache_data = {'emails': ['test@test.com'], 'confidence': 95}
        self.db.cache_api_response('test_key', 'test_api', 'test.com', cache_data, ttl_hours=24)
        test_results['cache_api_response'] = True
        logger.info("✓ Cached API response")
        
        # Test 6: Get cached response
        logger.info("Test 6: Getting cached response...")
        cached = self.db.get_cached_response('test_key')
        test_results['get_cached_response'] = cached is not None
        logger.info(f"✓ Retrieved cached response: {cached}")
        
        # Test 7: Update analysis status
        logger.info("Test 7: Updating analysis status...")
        self.db.update_analysis_status(analysis_id, 'in_progress', completion_percentage=50)
        test_results['update_analysis_status'] = True
        logger.info("✓ Updated analysis status")
        
        # Test 8: Get analysis progress
        logger.info("Test 8: Getting analysis progress...")
        progress = self.db.get_analysis_progress(analysis_id)
        test_results['get_analysis_progress'] = progress is not None
        logger.info(f"✓ Retrieved progress: {progress['completion_percentage']}%")
        
        # Test 9: Search analyses
        logger.info("Test 9: Searching analyses...")
        results = self.db.search_analyses('test')
        test_results['search_analyses'] = len(results) > 0
        logger.info(f"✓ Found {len(results)} analyses")
        
        # Test 10: Database statistics
        logger.info("Test 10: Getting database statistics...")
        stats = self.db.get_database_stats()
        test_results['get_database_stats'] = stats is not None
        logger.info(f"✓ Database stats: {stats['total_analyses']} analyses")
        
        # Summary
        passed = sum(1 for v in test_results.values() if v)
        total = len(test_results)
        logger.info(f"\n{'='*50}")
        logger.info(f"Database Tests: {passed}/{total} passed")
        logger.info(f"{'='*50}")
        
        return test_results
    
    def test_full_workflow(self, domain: str = "example.com") -> Dict[str, Any]:
        """
        Test full workflow: create analysis, run phases, save results
        
        Args:
            domain: Domain to test
        
        Returns:
            Workflow test results
        """
        logger.info(f"\n{'='*60}")
        logger.info("FULL WORKFLOW TEST")
        logger.info(f"{'='*60}\n")
        
        # Run test analysis
        result = self.run_test_analysis(domain, force_new=True)
        
        # Verify results
        logger.info(f"\n{'='*60}")
        logger.info("WORKFLOW TEST RESULTS")
        logger.info(f"{'='*60}")
        logger.info(f"Domain: {result['domain']}")
        logger.info(f"Status: {result['status']}")
        logger.info(f"Total Time: {result['elapsed_time']:.2f}s")
        logger.info(f"Phases Completed: {len(result['phases'])}")
        
        for phase_name, phase_result in result['phases'].items():
            logger.info(f"  ✓ {phase_name}: {phase_result['duration']:.1f}s")
        
        logger.info(f"{'='*60}\n")
        
        return result
    
    def shutdown(self):
        """Shutdown the orchestrator"""
        self.parallel_executor.shutdown()
        logger.info("Test orchestrator shutdown complete")


# Example usage
if __name__ == "__main__":
    # Initialize test orchestrator
    orchestrator = TestOrchestrator(db_path="test_bsi.db", use_dummy_data=True)
    
    # Test 1: Database operations
    logger.info("\n" + "="*60)
    logger.info("TEST 1: DATABASE OPERATIONS")
    logger.info("="*60)
    db_tests = orchestrator.test_database_operations()
    
    # Test 2: Full workflow
    logger.info("\n" + "="*60)
    logger.info("TEST 2: FULL WORKFLOW")
    logger.info("="*60)
    workflow_result = orchestrator.test_full_workflow("example.com")
    
    # Test 3: Resume analysis
    logger.info("\n" + "="*60)
    logger.info("TEST 3: RESUME ANALYSIS")
    logger.info("="*60)
    resume_result = orchestrator.run_test_analysis("example.com", force_new=False)
    logger.info(f"Resume Status: {resume_result['status']}")
    
    # Cleanup
    orchestrator.shutdown()
    
    logger.info("\n" + "="*60)
    logger.info("ALL TESTS COMPLETED")
    logger.info("="*60)
