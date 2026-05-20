#!/usr/bin/env python3
"""
BSI Observability Integration
Ties together logging, resilience, output sync, and dark web coverage
Provides unified observability across the entire pipeline
"""

import logging
import json
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from functools import wraps
import traceback

from core.logging_framework import (
    ExecutionLogger, ExecutionStep, Observation, SecuritySignal,
    SeverityLevel, get_execution_logger
)
from core.resilience_framework import (
    RetryConfig, RetryStrategy, get_circuit_breaker,
    get_adaptive_scanner, get_failure_recovery
)
from core.output_sync import (
    OutputSynchronizer, OutputValidator, OutputConsistencyChecker,
    get_output_synchronizer, get_consistency_checker
)
from phases.phase_dark_web import DarkWebIntelligencePhase

logger = logging.getLogger(__name__)


class ObservabilityManager:
    """
    Central observability manager for the BSI pipeline
    Coordinates logging, resilience, output sync, and coverage tracking
    """
    
    def __init__(self, db_manager=None):
        """Initialize observability manager"""
        self.db_manager = db_manager
        self.execution_logger = get_execution_logger()
        self.output_synchronizer = get_output_synchronizer(db_manager)
        self.consistency_checker = get_consistency_checker(db_manager)
        self.dark_web_phase = DarkWebIntelligencePhase()
        
        self.circuit_breaker = get_circuit_breaker()
        self.adaptive_scanner = get_adaptive_scanner()
        self.failure_recovery = get_failure_recovery()
        
        self.domain = None
        self.analysis_id = None
        self.coverage_report = {}

    def start_analysis(self, domain: str, analysis_id: str):
        """Start a new analysis"""
        self.domain = domain
        self.analysis_id = analysis_id
        
        logger.info(f"Starting analysis for {domain} (ID: {analysis_id})")

    def track_phase_execution(
        self,
        phase_name: str,
        phase_func: Callable,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Track execution of a phase with full observability
        """
        # Start execution step
        step = self.execution_logger.start_step(
            phase=phase_name,
            tool=phase_name,
            action="execute",
            inputs={"args": str(args), "kwargs": str(kwargs)},
            timeout_seconds=600,
            metadata={"domain": self.domain, "analysis_id": self.analysis_id}
        )
        
        try:
            # Execute phase with circuit breaker
            result = self.circuit_breaker.call(phase_func, *args, **kwargs)
            
            # Record performance
            if step.duration_seconds:
                self.adaptive_scanner.record_performance(step.duration_seconds)
            
            # End step
            self.execution_logger.end_step(step, result)
            
            # Register output for synchronization
            self.output_synchronizer.register_output(
                output_type="phase_result",
                source=phase_name,
                domain=self.domain,
                data=result
            )
            
            return result
        
        except Exception as e:
            # Record failure
            self.execution_logger.fail_step(
                step,
                str(e),
                error_type=type(e).__name__
            )
            
            # Try fallback strategies
            try:
                logger.info(f"Attempting fallback for {phase_name}")
                result = self.failure_recovery.execute_with_fallback(
                    phase_name,
                    phase_func,
                    *args,
                    **kwargs
                )
                
                # Mark as partial
                result["_partial"] = True
                result["_partial_reason"] = f"Fallback execution after {type(e).__name__}"
                
                self.execution_logger.end_step(step, result)
                return result
            
            except Exception as fallback_error:
                logger.error(f"All fallback strategies failed for {phase_name}")
                raise

    def track_api_call(
        self,
        api_name: str,
        endpoint: str,
        method: str = "GET",
        timeout_seconds: float = 30.0
    ) -> Callable:
        """
        Decorator for tracking API calls
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                # Start step
                step = self.execution_logger.start_step(
                    phase="api_integration",
                    tool=api_name,
                    action=method,
                    inputs={"endpoint": endpoint, "args": str(args)},
                    timeout_seconds=timeout_seconds,
                    metadata={"domain": self.domain}
                )
                
                try:
                    # Execute API call
                    result = func(*args, **kwargs)
                    
                    # Extract observations
                    observations = self._extract_observations(api_name, result)
                    
                    # End step
                    self.execution_logger.end_step(step, result, observations)
                    
                    return result
                
                except TimeoutError as e:
                    self.execution_logger.timeout_step(step)
                    raise
                
                except Exception as e:
                    self.execution_logger.fail_step(step, str(e), type(e).__name__)
                    raise
            
            return wrapper
        
        return decorator

    def check_dark_web_coverage(self) -> Dict[str, Any]:
        """
        Check and report dark web intelligence coverage
        """
        logger.warning("Checking dark web intelligence coverage...")
        
        # Run dark web phase (placeholder)
        dark_web_result = self.dark_web_phase.run_dark_web_scan(self.domain)
        
        # Extract coverage gaps
        coverage_gaps = dark_web_result.get("coverage_gaps", [])
        security_signals = dark_web_result.get("security_signals", [])
        
        # Create observations for each gap
        observations = []
        for gap in coverage_gaps:
            obs = Observation(
                observation_id=f"dark_web_gap_{gap['priority']}",
                category="coverage_gap",
                description=gap["description"],
                evidence={"gap": gap["gap"], "impact": gap["impact"]},
                confidence=1.0,
                security_signals=[
                    SecuritySignal(
                        signal_type="missing_intelligence",
                        severity=SeverityLevel.HIGH if gap["severity"] == "high" else SeverityLevel.MEDIUM,
                        confidence=1.0,
                        description=gap["description"],
                        remediation=f"Integrate {gap['gap']}"
                    )
                ]
            )
            observations.append(obs)
        
        # Log observations
        step = self.execution_logger.start_step(
            phase="dark_web_intelligence",
            tool="dark_web_monitor",
            action="coverage_check",
            inputs={"domain": self.domain},
            timeout_seconds=10
        )
        
        self.execution_logger.end_step(
            step,
            dark_web_result,
            observations=observations
        )
        
        self.coverage_report = {
            "dark_web_coverage": dark_web_result,
            "observations": [o.to_dict() for o in observations],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return self.coverage_report

    def synchronize_outputs(self) -> Dict[str, Any]:
        """
        Synchronize all outputs between CLI and Web UI
        """
        logger.info("Synchronizing outputs...")
        
        # Sync all pending outputs
        sync_result = self.output_synchronizer.sync_all_outputs()
        
        # Detect desynchronization
        desync_report = self.output_synchronizer.detect_desync()
        
        # Log desync if detected
        if desync_report["desync_detected"]:
            logger.error("Output desynchronization detected!")
            
            step = self.execution_logger.start_step(
                phase="output_sync",
                tool="output_synchronizer",
                action="detect_desync",
                inputs={"domain": self.domain},
                timeout_seconds=10
            )
            
            # Create security signal for desync
            signal = SecuritySignal(
                signal_type="output_desynchronization",
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                description="CLI outputs not reflected in Web UI",
                remediation="Check database persistence and UI layer"
            )
            
            self.execution_logger.add_security_signal(step, signal)
            self.execution_logger.end_step(step, desync_report)
        
        return {
            "sync_result": sync_result,
            "desync_report": desync_report,
            "sync_status": self.output_synchronizer.get_sync_status()
        }

    def generate_observability_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive observability report
        """
        execution_summary = self.execution_logger.get_execution_summary()
        sync_status = self.output_synchronizer.get_sync_status()
        
        report = {
            "analysis_id": self.analysis_id,
            "domain": self.domain,
            "timestamp": datetime.utcnow().isoformat(),
            
            # Execution metrics
            "execution": execution_summary,
            
            # Output synchronization
            "output_sync": sync_status,
            
            # Coverage report
            "coverage": self.coverage_report,
            
            # Adaptive scanning metrics
            "adaptive_scanning": self.adaptive_scanner.get_scan_config(),
            
            # Consistency check
            "consistency": self.consistency_checker.get_inconsistency_report()
        }
        
        return report

    def _extract_observations(self, api_name: str, result: Dict[str, Any]) -> List[Observation]:
        """
        Extract observations from API results
        """
        observations = []
        
        # Check for errors
        if isinstance(result, dict) and "error" in result:
            obs = Observation(
                observation_id=f"api_error_{api_name}",
                category="anomaly",
                description=f"API error from {api_name}",
                evidence={"error": result["error"]},
                confidence=1.0
            )
            observations.append(obs)
        
        # Check for sensitive data
        sensitive_patterns = ["password", "token", "key", "secret", "credential"]
        result_str = json.dumps(result, default=str).lower()
        
        for pattern in sensitive_patterns:
            if pattern in result_str:
                obs = Observation(
                    observation_id=f"sensitive_data_{api_name}",
                    category="sensitive_data",
                    description=f"Potential sensitive data detected in {api_name} response",
                    evidence={"pattern": pattern},
                    confidence=0.8
                )
                observations.append(obs)
                break
        
        return observations


class ObservabilityDecorator:
    """
    Provides decorators for easy observability integration
    """
    
    def __init__(self, observability_manager: ObservabilityManager):
        self.obs_manager = observability_manager

    def track_step(
        self,
        phase: str,
        tool: str,
        action: str,
        timeout_seconds: float = 30.0
    ):
        """Decorator for tracking execution steps"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                step = self.obs_manager.execution_logger.start_step(
                    phase=phase,
                    tool=tool,
                    action=action,
                    inputs={"args": str(args)[:100]},
                    timeout_seconds=timeout_seconds
                )
                
                try:
                    result = func(*args, **kwargs)
                    self.obs_manager.execution_logger.end_step(step, result)
                    return result
                except Exception as e:
                    self.obs_manager.execution_logger.fail_step(
                        step,
                        str(e),
                        type(e).__name__
                    )
                    raise
            
            return wrapper
        
        return decorator

    def track_api(self, api_name: str, timeout_seconds: float = 30.0):
        """Decorator for tracking API calls"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                step = self.obs_manager.execution_logger.start_step(
                    phase="api_integration",
                    tool=api_name,
                    action="call",
                    inputs={"args": str(args)[:100]},
                    timeout_seconds=timeout_seconds
                )
                
                try:
                    result = func(*args, **kwargs)
                    self.obs_manager.execution_logger.end_step(step, result)
                    return result
                except Exception as e:
                    self.obs_manager.execution_logger.fail_step(
                        step,
                        str(e),
                        type(e).__name__
                    )
                    raise
            
            return wrapper
        
        return decorator


# Global observability manager
_observability_manager: Optional[ObservabilityManager] = None


def get_observability_manager(db_manager=None) -> ObservabilityManager:
    """Get or create global observability manager"""
    global _observability_manager
    if _observability_manager is None:
        _observability_manager = ObservabilityManager(db_manager)
    return _observability_manager


def reset_observability():
    """Reset observability manager"""
    global _observability_manager
    _observability_manager = None
