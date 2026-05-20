#!/usr/bin/env python3
"""
BSI Structured Logging Framework
Provides hierarchical step tracking, observation extraction, and security signal tagging
"""

import json
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict, field
from enum import Enum
import threading
from pathlib import Path

# Configure base logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class StepStatus(Enum):
    """Step execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class SeverityLevel(Enum):
    """Security signal severity"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecuritySignal:
    """Represents a security finding or anomaly"""
    signal_type: str  # e.g., "missing_intelligence", "exposed_credential", "weak_cipher"
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    description: str
    affected_asset: Optional[str] = None
    remediation: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


@dataclass
class Observation:
    """Represents an observation extracted from execution"""
    observation_id: str
    category: str  # e.g., "anomaly", "pattern", "sensitive_data", "vulnerability"
    description: str
    evidence: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    security_signals: List[SecuritySignal] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['security_signals'] = [s.to_dict() for s in self.security_signals]
        return data


@dataclass
class ExecutionStep:
    """Represents a single execution step in the pipeline"""
    step_id: str
    parent_step_id: Optional[str]
    phase: str  # e.g., "phase1_business", "phase2_infrastructure"
    tool: str  # e.g., "hunter_io", "dns_lookup", "port_scan"
    action: str  # e.g., "query", "scan", "parse"
    status: StepStatus
    
    # Timing
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    # Inputs and outputs
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    
    # Error tracking
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    retry_count: int = 0
    retry_reasons: List[str] = field(default_factory=list)
    
    # Observations and signals
    observations: List[Observation] = field(default_factory=list)
    security_signals: List[SecuritySignal] = field(default_factory=list)
    
    # Performance metrics
    timeout_seconds: Optional[float] = None
    performance_notes: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['observations'] = [o.to_dict() for o in self.observations]
        data['security_signals'] = [s.to_dict() for s in self.security_signals]
        return data

    def mark_completed(self):
        """Mark step as completed"""
        self.end_time = datetime.utcnow().isoformat()
        self.status = StepStatus.COMPLETED
        if self.start_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def mark_failed(self, error_msg: str, error_type: str = "unknown"):
        """Mark step as failed"""
        self.end_time = datetime.utcnow().isoformat()
        self.status = StepStatus.FAILED
        self.error_message = error_msg
        self.error_type = error_type
        if self.start_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def mark_timeout(self):
        """Mark step as timed out"""
        self.end_time = datetime.utcnow().isoformat()
        self.status = StepStatus.TIMEOUT
        self.error_message = f"Step exceeded timeout of {self.timeout_seconds}s"
        if self.start_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            self.duration_seconds = (end - start).total_seconds()

    def add_observation(self, observation: Observation):
        """Add an observation"""
        self.observations.append(observation)

    def add_security_signal(self, signal: SecuritySignal):
        """Add a security signal"""
        self.security_signals.append(signal)

    def record_retry(self, reason: str):
        """Record a retry attempt"""
        self.retry_count += 1
        self.retry_reasons.append(reason)


class ExecutionLogger:
    """Thread-safe execution logger for the BSI pipeline"""

    def __init__(self, log_dir: str = "logs"):
        """Initialize the execution logger"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.execution_id = str(uuid.uuid4())
        self.steps: Dict[str, ExecutionStep] = {}
        self.step_stack: List[str] = []  # Stack for parent-child relationships
        self.lock = threading.Lock()
        
        self.logger = logging.getLogger("bsi.execution")
        
        # Create execution log file
        self.log_file = self.log_dir / f"execution_{self.execution_id}.jsonl"
        self.file_handler = logging.FileHandler(self.log_file)
        self.file_handler.setFormatter(
            logging.Formatter('%(message)s')
        )
        self.logger.addHandler(self.file_handler)

    def start_step(
        self,
        phase: str,
        tool: str,
        action: str,
        inputs: Dict[str, Any],
        timeout_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ExecutionStep:
        """Start a new execution step"""
        with self.lock:
            step_id = str(uuid.uuid4())
            parent_step_id = self.step_stack[-1] if self.step_stack else None
            
            step = ExecutionStep(
                step_id=step_id,
                parent_step_id=parent_step_id,
                phase=phase,
                tool=tool,
                action=action,
                status=StepStatus.RUNNING,
                start_time=datetime.utcnow().isoformat(),
                inputs=inputs,
                timeout_seconds=timeout_seconds,
                metadata=metadata or {}
            )
            
            self.steps[step_id] = step
            self.step_stack.append(step_id)
            
            # Log step start
            self._log_step_event(step, "step_started")
            
            return step

    def end_step(
        self,
        step: ExecutionStep,
        outputs: Dict[str, Any],
        observations: Optional[List[Observation]] = None,
        security_signals: Optional[List[SecuritySignal]] = None
    ):
        """End an execution step"""
        with self.lock:
            step.outputs = outputs
            step.status = StepStatus.COMPLETED
            step.end_time = datetime.utcnow().isoformat()
            
            if step.start_time:
                start = datetime.fromisoformat(step.start_time)
                end = datetime.fromisoformat(step.end_time)
                step.duration_seconds = (end - start).total_seconds()
            
            if observations:
                step.observations.extend(observations)
            
            if security_signals:
                step.security_signals.extend(security_signals)
            
            # Log step completion
            self._log_step_event(step, "step_completed")
            
            # Pop from stack
            if self.step_stack and self.step_stack[-1] == step.step_id:
                self.step_stack.pop()

    def fail_step(
        self,
        step: ExecutionStep,
        error_msg: str,
        error_type: str = "unknown",
        partial_outputs: Optional[Dict[str, Any]] = None
    ):
        """Mark a step as failed"""
        with self.lock:
            step.mark_failed(error_msg, error_type)
            if partial_outputs:
                step.outputs = partial_outputs
            
            # Log step failure
            self._log_step_event(step, "step_failed")
            
            # Pop from stack
            if self.step_stack and self.step_stack[-1] == step.step_id:
                self.step_stack.pop()

    def timeout_step(self, step: ExecutionStep, partial_outputs: Optional[Dict[str, Any]] = None):
        """Mark a step as timed out"""
        with self.lock:
            step.mark_timeout()
            if partial_outputs:
                step.outputs = partial_outputs
                step.status = StepStatus.PARTIAL
            
            # Log step timeout
            self._log_step_event(step, "step_timeout")
            
            # Pop from stack
            if self.step_stack and self.step_stack[-1] == step.step_id:
                self.step_stack.pop()

    def record_retry(self, step: ExecutionStep, reason: str):
        """Record a retry attempt"""
        with self.lock:
            step.record_retry(reason)
            self._log_step_event(step, "step_retry", {"reason": reason})

    def add_observation(self, step: ExecutionStep, observation: Observation):
        """Add an observation to a step"""
        with self.lock:
            step.add_observation(observation)
            self._log_observation(observation)

    def add_security_signal(self, step: ExecutionStep, signal: SecuritySignal):
        """Add a security signal to a step"""
        with self.lock:
            step.add_security_signal(signal)
            self._log_security_signal(signal)

    def _log_step_event(self, step: ExecutionStep, event_type: str, extra_data: Optional[Dict] = None):
        """Log a step event"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": self.execution_id,
            "event_type": event_type,
            "step": step.to_dict()
        }
        if extra_data:
            log_entry.update(extra_data)
        
        self.logger.info(json.dumps(log_entry))

    def _log_observation(self, observation: Observation):
        """Log an observation"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": self.execution_id,
            "event_type": "observation_recorded",
            "observation": observation.to_dict()
        }
        self.logger.info(json.dumps(log_entry))

    def _log_security_signal(self, signal: SecuritySignal):
        """Log a security signal"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": self.execution_id,
            "event_type": "security_signal_detected",
            "signal": signal.to_dict()
        }
        self.logger.info(json.dumps(log_entry))

    def get_execution_summary(self) -> Dict[str, Any]:
        """Get a summary of the execution"""
        with self.lock:
            total_steps = len(self.steps)
            completed = sum(1 for s in self.steps.values() if s.status == StepStatus.COMPLETED)
            failed = sum(1 for s in self.steps.values() if s.status == StepStatus.FAILED)
            timeout = sum(1 for s in self.steps.values() if s.status == StepStatus.TIMEOUT)
            
            total_duration = 0
            for step in self.steps.values():
                if step.duration_seconds:
                    total_duration += step.duration_seconds
            
            all_observations = []
            all_signals = []
            for step in self.steps.values():
                all_observations.extend(step.observations)
                all_signals.extend(step.security_signals)
            
            return {
                "execution_id": self.execution_id,
                "total_steps": total_steps,
                "completed": completed,
                "failed": failed,
                "timeout": timeout,
                "total_duration_seconds": total_duration,
                "observations_count": len(all_observations),
                "security_signals_count": len(all_signals),
                "log_file": str(self.log_file)
            }

    def export_execution_tree(self) -> Dict[str, Any]:
        """Export execution as a tree structure"""
        with self.lock:
            # Find root steps (no parent)
            roots = [s for s in self.steps.values() if s.parent_step_id is None]
            
            def build_tree(step: ExecutionStep) -> Dict[str, Any]:
                children = [s for s in self.steps.values() if s.parent_step_id == step.step_id]
                return {
                    "step": step.to_dict(),
                    "children": [build_tree(child) for child in children]
                }
            
            return {
                "execution_id": self.execution_id,
                "tree": [build_tree(root) for root in roots]
            }

    def export_to_json(self, filepath: str):
        """Export execution data to JSON"""
        with self.lock:
            data = {
                "execution_id": self.execution_id,
                "summary": self.get_execution_summary(),
                "steps": {step_id: step.to_dict() for step_id, step in self.steps.items()},
                "tree": self.export_execution_tree()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)


# Global execution logger instance
_execution_logger: Optional[ExecutionLogger] = None


def get_execution_logger() -> ExecutionLogger:
    """Get or create the global execution logger"""
    global _execution_logger
    if _execution_logger is None:
        _execution_logger = ExecutionLogger()
    return _execution_logger


def reset_execution_logger():
    """Reset the global execution logger"""
    global _execution_logger
    _execution_logger = None
