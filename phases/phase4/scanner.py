"""
Phase 4: Main Correlation Scanner
Orchestrates vulnerability correlation and threat intelligence
"""

import logging
import json
import tempfile
import os
from typing import Dict, Any
from .correlation import VulnerabilityCorrelation

logger = logging.getLogger(__name__)


class AIPhase4Scanner:
    """Main orchestrator for Phase 4: Vulnerability Correlation"""
    
    def __init__(self):
        self.correlation = VulnerabilityCorrelation()
        self.report_data = None
        logger.info("AIPhase4Scanner initialized")
    
    def run_correlation(self, phase1_path: str, phase2_path: str, phase3_path: str) -> Dict[str, Any]:
        """Run correlation analysis"""
        
        try:
            # Load phase data
            with open(phase1_path, 'r') as f:
                phase1_data = json.load(f)
            
            with open(phase2_path, 'r') as f:
                phase2_data = json.load(f)
            
            with open(phase3_path, 'r') as f:
                phase3_data = json.load(f)
            
            # Correlate vulnerabilities
            correlation_result = self.correlation.correlate_vulnerabilities(
                phase1_data, phase2_data, phase3_data
            )
            
            self.report_data = correlation_result
            logger.info("Correlation analysis complete")
            return correlation_result
            
        except Exception as e:
            logger.error(f"Correlation failed: {str(e)}")
            return {'error': str(e)}
    
    def save_report(self, outdir: str = "reports") -> str:
        """Save correlation report"""
        
        try:
            if not os.path.exists(outdir):
                os.makedirs(outdir)
            
            if self.report_data:
                filename = os.path.join(outdir, f"Phase4_Report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                with open(filename, 'w') as f:
                    json.dump(self.report_data, f, indent=2, default=str)
                
                logger.info(f"Report saved to {filename}")
                return filename
        except Exception as e:
            logger.error(f"Report save failed: {str(e)}")
        
        return ""
