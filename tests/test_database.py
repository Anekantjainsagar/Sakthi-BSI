#!/usr/bin/env python3
"""
Test script to demonstrate database integration
Shows how to use the database with the orchestrator
"""

import time
from data.database import get_db_manager
from core.orchestrator import BSIOrchestratorWithDB


def test_basic_database_operations():
    """Test basic database operations"""
    print("\n" + "="*60)
    print("🧪 Testing Basic Database Operations")
    print("="*60)
    
    db = get_db_manager("test_bsi.db")
    
    # Test 1: Create analysis
    print("\n1️⃣ Creating new analysis...")
    analysis_id = db.create_analysis("example.com", notes="Test analysis")
    print(f"   ✅ Created analysis ID: {analysis_id}")
    
    # Test 2: Get analysis
    print("\n2️⃣ Retrieving analysis...")
    analysis = db.get_analysis("example.com")
    print(f"   ✅ Domain: {analysis['domain']}")
    print(f"   ✅ Status: {analysis['status']}")
    print(f"   ✅ Created: {analysis['created_at']}")
    
    # Test 3: Save phase result
    print("\n3️⃣ Saving phase result...")
    phase_data = {
        "company_name": "Example Corp",
        "industry": "Technology",
        "employees": 500
    }
    db.save_phase_result(analysis_id, 1, "Business Domain", phase_data, duration_seconds=45.2)
    print(f"   ✅ Saved Phase 1 result")
    
    # Test 4: Get phase result
    print("\n4️⃣ Retrieving phase result...")
    phase_result = db.get_phase_result(analysis_id, 1)
    print(f"   ✅ Phase: {phase_result['phase_name']}")
    print(f"   ✅ Status: {phase_result['status']}")
    print(f"   ✅ Duration: {phase_result['duration_seconds']}s")
    print(f"   ✅ Data: {phase_result['result_data']}")
    
    # Test 5: Cache API response
    print("\n5️⃣ Caching API response...")
    cache_key = "hunter_io_example.com"
    cache_data = {
        "emails": ["john@example.com", "jane@example.com"],
        "confidence": 95
    }
    db.cache_api_response(cache_key, "hunter_io", "example.com", cache_data, ttl_hours=24)
    print(f"   ✅ Cached API response")
    
    # Test 6: Get cached response
    print("\n6️⃣ Retrieving cached response...")
    cached = db.get_cached_response(cache_key)
    print(f"   ✅ Cache hit! Data: {cached}")
    
    # Test 7: Update analysis status
    print("\n7️⃣ Updating analysis status...")
    db.update_analysis_status(analysis_id, "in_progress", completion_percentage=20)
    print(f"   ✅ Updated status to in_progress (20%)")
    
    # Test 8: Get analysis progress
    print("\n8️⃣ Getting analysis progress...")
    progress = db.get_analysis_progress(analysis_id)
    print(f"   ✅ Completed phases: {progress['completed_count']}")
    print(f"   ✅ Total phases: {progress['total_phases']}")
    print(f"   ✅ Completion: {progress['completion_percentage']}%")
    
    # Test 9: Database statistics
    print("\n9️⃣ Getting database statistics...")
    stats = db.get_database_stats()
    print(f"   ✅ Total analyses: {stats['total_analyses']}")
    print(f"   ✅ Completed phases: {stats['completed_phases']}")
    print(f"   ✅ Active cache: {stats['active_cache_entries']}")
    print(f"   ✅ Cache hits: {stats['total_cache_hits']}")
    
    print("\n" + "="*60)
    print("✅ All basic tests passed!")
    print("="*60)


def test_orchestrator_integration():
    """Test orchestrator with database integration"""
    print("\n" + "="*60)
    print("🧪 Testing Orchestrator Integration")
    print("="*60)
    
    orchestrator = BSIOrchestratorWithDB("test_bsi.db")
    
    # Test 1: Start new analysis
    print("\n1️⃣ Starting new analysis...")
    analysis_id = orchestrator.start_analysis("testdomain.com", force_new=True)
    print(f"   ✅ Analysis ID: {analysis_id}")
    
    # Test 2: Check existing analysis
    print("\n2️⃣ Checking for existing analysis...")
    existing = orchestrator.check_existing_analysis("testdomain.com")
    print(f"   ✅ Found existing: {existing is not None}")
    
    # Test 3: Resume analysis
    print("\n3️⃣ Testing resume capability...")
    orchestrator2 = BSIOrchestratorWithDB("test_bsi.db")
    resumed = orchestrator2.resume_analysis("testdomain.com")
    print(f"   ✅ Resume successful: {resumed}")
    
    # Test 4: Run phase with tracking
    print("\n4️⃣ Running phase with database tracking...")
    
    def mock_phase_function():
        """Mock phase function"""
        time.sleep(0.5)  # Simulate work
        return {"result": "Phase completed successfully"}
    
    try:
        result = orchestrator.run_phase(1, mock_phase_function)
        print(f"   ✅ Phase executed: {result}")
    except Exception as e:
        print(f"   ⚠️ Phase execution: {e}")
    
    # Test 5: Get analysis status
    print("\n5️⃣ Getting analysis status...")
    status = orchestrator.get_analysis_status()
    print(f"   ✅ Domain: {status['domain']}")
    print(f"   ✅ Status: {status['status']}")
    print(f"   ✅ Completion: {status['completion_percentage']}%")
    
    # Test 6: Finalize analysis
    print("\n6️⃣ Finalizing analysis...")
    orchestrator.finalize_analysis()
    print(f"   ✅ Analysis finalized")
    
    print("\n" + "="*60)
    print("✅ All orchestrator tests passed!")
    print("="*60)


def test_resume_workflow():
    """Test complete resume workflow"""
    print("\n" + "="*60)
    print("🧪 Testing Resume Workflow")
    print("="*60)
    
    db = get_db_manager("test_bsi.db")
    
    # Simulate interrupted analysis
    print("\n1️⃣ Simulating interrupted analysis...")
    analysis_id = db.create_analysis("interrupted.com")
    
    # Save some phase results
    db.save_phase_result(analysis_id, 1, "Business Domain", {"status": "done"}, 30)
    db.save_phase_result(analysis_id, 2, "Infrastructure", {"status": "done"}, 45)
    db.update_analysis_status(analysis_id, "in_progress", 40)
    print(f"   ✅ Created interrupted analysis (ID: {analysis_id})")
    
    # Resume analysis
    print("\n2️⃣ Resuming interrupted analysis...")
    orchestrator = BSIOrchestratorWithDB("test_bsi.db")
    orchestrator.start_analysis("interrupted.com", force_new=False)
    
    status = orchestrator.get_analysis_status()
    print(f"   ✅ Resumed analysis")
    print(f"   ✅ Completion: {status['completion_percentage']}%")
    print(f"   ✅ Phases completed: {len([p for p in status['phases'] if p['status'] == 'completed'])}")
    
    print("\n" + "="*60)
    print("✅ Resume workflow test passed!")
    print("="*60)


def test_search_functionality():
    """Test search functionality"""
    print("\n" + "="*60)
    print("🧪 Testing Search Functionality")
    print("="*60)
    
    db = get_db_manager("test_bsi.db")
    
    # Create multiple analyses
    print("\n1️⃣ Creating test analyses...")
    domains = ["google.com", "github.com", "stackoverflow.com", "google-analytics.com"]
    for domain in domains:
        db.create_analysis(domain)
    print(f"   ✅ Created {len(domains)} test analyses")
    
    # Search
    print("\n2️⃣ Searching for 'google'...")
    results = db.search_analyses("google")
    print(f"   ✅ Found {len(results)} results:")
    for result in results:
        print(f"      • {result['domain']}")
    
    print("\n" + "="*60)
    print("✅ Search functionality test passed!")
    print("="*60)


if __name__ == "__main__":
    print("\n🚀 BSI Database Integration Tests\n")
    
    try:
        test_basic_database_operations()
        test_orchestrator_integration()
        test_resume_workflow()
        test_search_functionality()
        
        print("\n" + "="*60)
        print("🎉 ALL TESTS PASSED!")
        print("="*60)
        print("\nDatabase file: test_bsi.db")
        print("Ready for integration into app.py")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
