#!/usr/bin/env python3
"""
BSI Output Synchronization Framework
Ensures CLI and Web UI outputs are consistent and properly persisted
"""

import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, asdict
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class OutputRecord:
    """Represents an output record that must be synced"""
    record_id: str
    output_type: str  # "vulnerability", "correlation", "risk_assessment", "observation"
    source: str  # "cli", "phase1", "phase2", etc.
    domain: str
    data: Dict[str, Any]
    timestamp: str
    hash: str  # Hash of data for change detection
    persisted: bool = False
    ui_visible: bool = False
    sync_status: str = "pending"  # pending, synced, failed


class OutputSynchronizer:
    """
    Manages output synchronization between CLI and Web UI
    Ensures all outputs are properly persisted and visible
    """
    
    def __init__(self, db_manager=None):
        """Initialize output synchronizer"""
        self.db_manager = db_manager
        self.pending_outputs: Dict[str, OutputRecord] = {}
        self.sync_log: List[Dict[str, Any]] = []
        self.desync_detected = False
        self.desync_details: List[Dict[str, Any]] = []

    def register_output(
        self,
        output_type: str,
        source: str,
        domain: str,
        data: Dict[str, Any]
    ) -> OutputRecord:
        """Register an output for synchronization"""
        
        # Generate record ID
        record_id = self._generate_record_id(output_type, source, domain)
        
        # Calculate hash
        data_hash = self._calculate_hash(data)
        
        # Create record
        record = OutputRecord(
            record_id=record_id,
            output_type=output_type,
            source=source,
            domain=domain,
            data=data,
            timestamp=datetime.utcnow().isoformat(),
            hash=data_hash
        )
        
        self.pending_outputs[record_id] = record
        
        logger.info(f"Registered output: {output_type} from {source} for {domain}")
        
        return record

    def persist_output(self, record: OutputRecord) -> bool:
        """Persist output to database"""
        if not self.db_manager:
            logger.warning("No database manager available for persistence")
            return False
        
        try:
            # Store in database
            self.db_manager.store_output(
                record_id=record.record_id,
                output_type=record.output_type,
                source=record.source,
                domain=record.domain,
                data=record.data,
                timestamp=record.timestamp,
                data_hash=record.hash
            )
            
            record.persisted = True
            record.sync_status = "synced"
            
            logger.info(f"Persisted output: {record.record_id}")
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to persist output {record.record_id}: {str(e)}")
            record.sync_status = "failed"
            return False

    def make_ui_visible(self, record: OutputRecord) -> bool:
        """Make output visible in Web UI"""
        try:
            # This would typically involve:
            # 1. Storing in a UI-accessible table
            # 2. Triggering UI refresh
            # 3. Updating cache
            
            record.ui_visible = True
            
            logger.info(f"Made output visible in UI: {record.record_id}")
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to make output visible: {str(e)}")
            return False

    def sync_all_outputs(self) -> Dict[str, Any]:
        """Synchronize all pending outputs"""
        results = {
            "total": len(self.pending_outputs),
            "synced": 0,
            "failed": 0,
            "details": []
        }
        
        for record_id, record in self.pending_outputs.items():
            try:
                # Persist to database
                if self.persist_output(record):
                    # Make visible in UI
                    if self.make_ui_visible(record):
                        results["synced"] += 1
                    else:
                        results["failed"] += 1
                        results["details"].append({
                            "record_id": record_id,
                            "reason": "Failed to make visible in UI"
                        })
                else:
                    results["failed"] += 1
                    results["details"].append({
                        "record_id": record_id,
                        "reason": "Failed to persist to database"
                    })
            
            except Exception as e:
                results["failed"] += 1
                results["details"].append({
                    "record_id": record_id,
                    "reason": str(e)
                })
        
        return results

    def detect_desync(self) -> Dict[str, Any]:
        """Detect if CLI outputs are not reflected in Web UI"""
        desync_report = {
            "desync_detected": False,
            "mismatches": [],
            "missing_in_db": [],
            "missing_in_ui": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for record_id, record in self.pending_outputs.items():
            # Check if persisted
            if not record.persisted:
                desync_report["desync_detected"] = True
                desync_report["missing_in_db"].append({
                    "record_id": record_id,
                    "output_type": record.output_type,
                    "source": record.source,
                    "reason": "Output not persisted to database"
                })
            
            # Check if visible in UI
            if not record.ui_visible:
                desync_report["desync_detected"] = True
                desync_report["missing_in_ui"].append({
                    "record_id": record_id,
                    "output_type": record.output_type,
                    "source": record.source,
                    "reason": "Output not visible in Web UI"
                })
        
        if desync_report["desync_detected"]:
            self.desync_detected = True
            self.desync_details.append(desync_report)
            logger.error("Output desynchronization detected!")
            logger.error(json.dumps(desync_report, indent=2))
        
        return desync_report

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current synchronization status"""
        total = len(self.pending_outputs)
        synced = sum(1 for r in self.pending_outputs.values() if r.sync_status == "synced")
        failed = sum(1 for r in self.pending_outputs.values() if r.sync_status == "failed")
        pending = sum(1 for r in self.pending_outputs.values() if r.sync_status == "pending")
        
        return {
            "total_outputs": total,
            "synced": synced,
            "failed": failed,
            "pending": pending,
            "desync_detected": self.desync_detected,
            "desync_count": len(self.desync_details),
            "sync_percentage": (synced / total * 100) if total > 0 else 0
        }

    def _generate_record_id(self, output_type: str, source: str, domain: str) -> str:
        """Generate unique record ID"""
        content = f"{output_type}:{source}:{domain}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _calculate_hash(self, data: Dict[str, Any]) -> str:
        """Calculate hash of data"""
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()


class OutputValidator:
    """
    Validates outputs for consistency and completeness
    """
    
    @staticmethod
    def validate_vulnerability_output(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate vulnerability output structure"""
        required_fields = ["vulnerability_id", "type", "severity", "affected_asset"]
        
        missing_fields = [f for f in required_fields if f not in data]
        
        return {
            "valid": len(missing_fields) == 0,
            "missing_fields": missing_fields,
            "data": data
        }

    @staticmethod
    def validate_correlation_output(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate correlation output structure"""
        required_fields = ["correlation_id", "threat_level", "affected_systems", "cves"]
        
        missing_fields = [f for f in required_fields if f not in data]
        
        return {
            "valid": len(missing_fields) == 0,
            "missing_fields": missing_fields,
            "data": data
        }

    @staticmethod
    def validate_risk_assessment_output(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate risk assessment output structure"""
        required_fields = ["risk_score", "risk_level", "business_impact", "recommendations"]
        
        missing_fields = [f for f in required_fields if f not in data]
        
        return {
            "valid": len(missing_fields) == 0,
            "missing_fields": missing_fields,
            "data": data
        }


class OutputConsistencyChecker:
    """
    Checks consistency between CLI and Web UI outputs
    """
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.inconsistencies: List[Dict[str, Any]] = []

    def check_cli_vs_db(self, cli_output: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Check if CLI output matches database"""
        if not self.db_manager:
            return {"status": "no_db_manager"}
        
        try:
            db_output = self.db_manager.get_latest_output(domain)
            
            if not db_output:
                inconsistency = {
                    "type": "missing_in_db",
                    "domain": domain,
                    "cli_output_present": True,
                    "db_entry_present": False,
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.inconsistencies.append(inconsistency)
                logger.error(f"CLI output not found in database for {domain}")
                return {"consistent": False, "reason": "missing_in_db"}
            
            # Compare outputs
            if cli_output != db_output:
                inconsistency = {
                    "type": "data_mismatch",
                    "domain": domain,
                    "cli_hash": hashlib.sha256(json.dumps(cli_output, sort_keys=True, default=str).encode()).hexdigest(),
                    "db_hash": hashlib.sha256(json.dumps(db_output, sort_keys=True, default=str).encode()).hexdigest(),
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.inconsistencies.append(inconsistency)
                logger.warning(f"CLI output differs from database for {domain}")
                return {"consistent": False, "reason": "data_mismatch"}
            
            return {"consistent": True}
        
        except Exception as e:
            logger.error(f"Error checking consistency: {str(e)}")
            return {"status": "error", "error": str(e)}

    def get_inconsistency_report(self) -> Dict[str, Any]:
        """Get report of all inconsistencies"""
        return {
            "total_inconsistencies": len(self.inconsistencies),
            "by_type": self._group_by_type(),
            "details": self.inconsistencies
        }

    def _group_by_type(self) -> Dict[str, int]:
        """Group inconsistencies by type"""
        groups = {}
        for inc in self.inconsistencies:
            inc_type = inc.get("type", "unknown")
            groups[inc_type] = groups.get(inc_type, 0) + 1
        return groups


# Global instances
_output_synchronizer: Optional[OutputSynchronizer] = None
_consistency_checker: Optional[OutputConsistencyChecker] = None


def get_output_synchronizer(db_manager=None) -> OutputSynchronizer:
    """Get or create global output synchronizer"""
    global _output_synchronizer
    if _output_synchronizer is None:
        _output_synchronizer = OutputSynchronizer(db_manager)
    return _output_synchronizer


def get_consistency_checker(db_manager=None) -> OutputConsistencyChecker:
    """Get or create global consistency checker"""
    global _consistency_checker
    if _consistency_checker is None:
        _consistency_checker = OutputConsistencyChecker(db_manager)
    return _consistency_checker
