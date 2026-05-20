#!/usr/bin/env python3
"""
Example: Integrating Observability Framework into BSI Pipeline
Shows how to use the observability system in practice
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.observability import get_observability_manager, ObservabilityDecorator
from core.logging_framework import (
    Observation, SecuritySignal, SeverityLevel, get_execution_logger
)
from core.resilience_framework import (
    retry_with_backoff, RetryConfig, RetryStrategy, get_adaptive_scanner
)
from core.output_sync import get_output_synchronizer
from phases.phase_dark_web import DarkWebIntelligencePhase
import json
import time


def example_1_basic_step_tracking():
    """Example 1: Basic step tracking"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Step Tracking")
    print("="*60)
    
    logger = get_execution_logger()
    
    # Start a step
    step = logger.start_step(
        phase="phase1_business",
        tool="hunter_io",
        action="query",
        inputs={"domain": "example.com"},
        timeout_seconds=30
    )
    
    print(f"Started step: {step.step_id}")
    
    # Simulate work
    time.sleep(1)
    
    # End step
    result = {"emails": ["admin@example.com", "info@example.com"]}
    logger.end_step(step, result)
    
    print(f"Completed step in {step.duration_seconds}s")
    print(f"Result: {result}")


def example_2_observations_and_signals():
    """Example 2: Adding observations and security signals"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Observations & Security Signals")
    print("="*60)
    
    logger = get_execution_logger()
    
    # Start step
    step = logger.start_step(
        phase="phase2_infrastructure",
        tool="ssl_analysis",
        action="scan",
        inputs={"domain": "example.com"},
        timeout_seconds=30
    )
    
    # Simulate finding weak cipher
    result = {
        "ssl_version": "TLS 1.0",
        "ciphers": ["DES-CBC3-SHA", "RC4-SHA"]
    }
    
    # Create observation
    obs = Observation(
        observation_id="obs_weak_ssl",
        category="vulnerability",
        description="Weak SSL/TLS configuration detected",
        evidence={"ssl_version": "TLS 1.0", "weak_ciphers": 2},
        confidence=0.95,
        security_signals=[
            SecuritySignal(
                signal_type="weak_cipher",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                description="SSL/TLS using weak cipher suite",
                affected_asset="example.com:443",
                remediation="Update to TLS 1.3 with strong ciphers",
                tags=["ssl", "cryptography", "compliance"]
            )
        ]
    )
    
    # Add observation to step
    logger.add_observation(step, obs)
    
    # End step
    logger.end_step(step, result, observations=[obs])
    
    print(f"Added observation: {obs.observation_id}")
    print(f"Security signal: {obs.security_signals[0].signal_type}")
    print(f"Severity: {obs.security_signals[0].severity.value}")


def example_3_retry_with_backoff():
    """Example 3: Retry with exponential backoff"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Retry with Exponential Backoff")
    print("="*60)
    
    config = RetryConfig(
        max_retries=3,
        initial_delay=0.5,
        strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        backoff_multiplier=2.0
    )
    
    attempt_count = 0
    
    def on_retry(attempt, error):
        print(f"Retry attempt {attempt}: {str(error)}")
    
    @retry_with_backoff(config=config, on_retry=on_retry)
    def flaky_api_call():
        nonlocal attempt_count
        attempt_count += 1
        
        if attempt_count < 3:
            raise ConnectionError(f"Connection failed (attempt {attempt_count})")
        
        return {"status": "success", "data": "result"}
    
    try:
        result = flaky_api_call()
        print(f"Success after {attempt_count} attempts: {result}")
    except Exception as e:
        print(f"Failed after all retries: {str(e)}")


def example_4_adaptive_scanning():
    """Example 4: Adaptive scanning based on performance"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Adaptive Scanning")
    print("="*60)
    
    scanner = get_adaptive_scanner()
    
    print(f"Initial config: {scanner.get_scan_config()}")
    
    # Simulate slow performance
    for i in range(5):
        scanner.record_performance(35.0)  # Slow
    
    print(f"After slow steps: {scanner.get_scan_config()}")
    
    # Simulate fast performance
    for i in range(5):
        scanner.record_performance(2.0)  # Fast
    
    print(f"After fast steps: {scanner.get_scan_config()}")


def example_5_output_synchronization():
    """Example 5: Output synchronization"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Output Synchronization")
    print("="*60)
    
    sync = get_output_synchronizer()
    
    # Register outputs
    record1 = sync.register_output(
        output_type="vulnerability",
        source="phase3_application",
        domain="example.com",
        data={"cve": "CVE-2024-1234", "severity": "high"}
    )
    
    record2 = sync.register_output(
        output_type="correlation",
        source="phase4_correlation",
        domain="example.com",
        data={"threat_level": "high", "affected_systems": 3}
    )
    
    print(f"Registered {len(sync.pending_outputs)} outputs")
    
    # Check sync status
    status = sync.get_sync_status()
    print(f"Sync status: {status}")
    
    # Detect desync (will show missing_in_db since we have no DB)
    desync = sync.detect_desync()
    print(f"Desync detected: {desync['desync_detected']}")
    if desync['missing_in_db']:
        print(f"Missing in DB: {len(desync['missing_in_db'])} records")


def example_6_dark_web_coverage():
    """Example 6: Dark web coverage checking"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Dark Web Coverage Checking")
    print("="*60)
    
    dark_web = DarkWebIntelligencePhase()
    result = dark_web.run_dark_web_scan("example.com")
    
    print(f"Status: {result['status']}")
    print(f"Coverage gaps: {len(result['coverage_gaps'])}")
    
    for gap in result['coverage_gaps'][:3]:
        print(f"\n  Gap: {gap['gap']}")
        print(f"  Impact: {gap['impact']}")
        print(f"  Severity: {gap['severity']}")
    
    print(f"\nSecurity signals: {len(result['security_signals'])}")
    for signal in result['security_signals'][:2]:
        print(f"  - {signal['signal_type']}: {signal['description']}")


def example_7_observability_manager():
    """Example 7: Using ObservabilityManager"""
    print("\n" + "="*60)
    print("EXAMPLE 7: ObservabilityManager")
    print("="*60)
    
    obs = get_observability_manager()
    obs.start_analysis("example.com", "analysis_001")
    
    print(f"Started analysis for example.com")
    
    # Check dark web coverage
    coverage = obs.check_dark_web_coverage()
    print(f"Dark web coverage gaps: {len(coverage['coverage_gaps'])}")
    
    # Generate report
    report = obs.generate_observability_report()
    print(f"\nObservability Report:")
    print(f"  Execution ID: {report['execution_id']}")
    print(f"  Domain: {report['domain']}")
    print(f"  Total steps: {report['execution']['total_steps']}")
    print(f"  Observations: {report['execution']['observations_count']}")
    print(f"  Security signals: {report['execution']['security_signals_count']}")


def example_8_hierarchical_tracking():
    """Example 8: Hierarchical step tracking"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Hierarchical Step Tracking")
    print("="*60)
    
    logger = get_execution_logger()
    
    # Parent step
    parent = logger.start_step(
        phase="phase2_infrastructure",
        tool="dns_discovery",
        action="full_scan",
        inputs={"domain": "example.com"},
        timeout_seconds=60
    )
    
    print(f"Started parent step: {parent.step_id}")
    
    # Child steps
    for record_type in ["A", "MX", "NS"]:
        child = logger.start_step(
            phase="phase2_infrastructure",
            tool="dns_lookup",
            action=f"query_{record_type}",
            inputs={"domain": "example.com", "type": record_type},
            timeout_seconds=10
        )
        
        time.sleep(0.5)
        
        result = {f"{record_type}_records": ["192.0.2.1"]}
        logger.end_step(child, result)
        
        print(f"  Completed child step: {record_type} records")
    
    # End parent
    logger.end_step(parent, {"all_records": "collected"})
    
    print(f"Completed parent step")
    
    # Export tree
    tree = logger.export_execution_tree()
    print(f"\nExecution tree depth: {len(tree['tree'])}")


def example_9_comprehensive_workflow():
    """Example 9: Comprehensive workflow with all features"""
    print("\n" + "="*60)
    print("EXAMPLE 9: Comprehensive Workflow")
    print("="*60)
    
    obs = get_observability_manager()
    obs.start_analysis("example.com", "analysis_comprehensive")
    
    # Phase 1: Business Intelligence
    print("\n[Phase 1] Business Intelligence")
    step1 = obs.execution_logger.start_step(
        phase="phase1_business",
        tool="hunter_io",
        action="query",
        inputs={"domain": "example.com"},
        timeout_seconds=30
    )
    
    result1 = {"emails": ["admin@example.com"]}
    obs.execution_logger.end_step(step1, result1)
    obs.output_synchronizer.register_output(
        "phase_result", "phase1_business", "example.com", result1
    )
    print("✓ Phase 1 completed")
    
    # Phase 2: Infrastructure
    print("\n[Phase 2] Infrastructure Discovery")
    step2 = obs.execution_logger.start_step(
        phase="phase2_infrastructure",
        tool="dns_lookup",
        action="query",
        inputs={"domain": "example.com"},
        timeout_seconds=30
    )
    
    result2 = {"subdomains": ["www.example.com", "mail.example.com"]}
    obs.execution_logger.end_step(step2, result2)
    obs.output_synchronizer.register_output(
        "phase_result", "phase2_infrastructure", "example.com", result2
    )
    print("✓ Phase 2 completed")
    
    # Check dark web coverage
    print("\n[Coverage Check] Dark Web Intelligence")
    coverage = obs.check_dark_web_coverage()
    print(f"✓ Coverage gaps identified: {len(coverage['coverage_gaps'])}")
    
    # Synchronize outputs
    print("\n[Sync] Output Synchronization")
    sync_result = obs.synchronize_outputs()
    print(f"✓ Synced: {sync_result['sync_result']['synced']}")
    print(f"✓ Failed: {sync_result['sync_result']['failed']}")
    
    # Generate report
    print("\n[Report] Observability Report")
    report = obs.generate_observability_report()
    print(f"✓ Report generated")
    print(f"  - Total steps: {report['execution']['total_steps']}")
    print(f"  - Duration: {report['execution']['total_duration_seconds']:.2f}s")
    print(f"  - Observations: {report['execution']['observations_count']}")
    print(f"  - Security signals: {report['execution']['security_signals_count']}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("BSI OBSERVABILITY FRAMEWORK - EXAMPLES")
    print("="*60)
    
    example_1_basic_step_tracking()
    example_2_observations_and_signals()
    example_3_retry_with_backoff()
    example_4_adaptive_scanning()
    example_5_output_synchronization()
    example_6_dark_web_coverage()
    example_7_observability_manager()
    example_8_hierarchical_tracking()
    example_9_comprehensive_workflow()
    
    print("\n" + "="*60)
    print("ALL EXAMPLES COMPLETED")
    print("="*60)
    
    # Export execution data
    logger = get_execution_logger()
    summary = logger.get_execution_summary()
    print(f"\nExecution Summary:")
    print(f"  ID: {summary['execution_id']}")
    print(f"  Total steps: {summary['total_steps']}")
    print(f"  Completed: {summary['completed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Duration: {summary['total_duration_seconds']:.2f}s")
    print(f"  Log file: {summary['log_file']}")
