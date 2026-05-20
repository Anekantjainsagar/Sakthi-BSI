"""
BSI Orchestrator - Manages parallel execution of all analysis phases
"""

import asyncio
import time
import json
import tempfile
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any
import streamlit as st

from config.gemini_config import GEMINI_API_KEYS
from phases.phase4 import AIPhase4Scanner
from phases.phase5 import RiskAssessmentEngine
from phases.phase1 import CompanyIntelligenceAnalyzer
from phases.phase2 import BSIInfrastructureDiscovery
from phases.phase3 import CompleteBSIScanner


class BSIOrchestrator:
    """Orchestrates parallel execution of BSI analysis phases"""
    
    def __init__(self):
        self.domain = None
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
    
    def run_business_analysis(self, domain: str) -> Dict[str, Any]:
        """Run business domain understanding analysis"""
        try:
            self.results['status']['business_domain'] = 'running'
            analyzer = CompanyIntelligenceAnalyzer()
            result = analyzer.analyze_company(domain.split('.')[0].title(), domain)
            self.results['business_domain'] = result
            self.results['status']['business_domain'] = 'completed'
            return result
        except Exception as e:
            self.results['status']['business_domain'] = 'failed'
            return {'error': str(e)}
    
    async def run_infrastructure_analysis(self, domain: str) -> Dict[str, Any]:
        """Run infrastructure discovery analysis"""
        try:
            self.results['status']['infrastructure'] = 'running'
            async with BSIInfrastructureDiscovery() as discovery:
                data = await discovery.discover_infrastructure(domain)
                from dataclasses import asdict
                result = asdict(data)
                self.results['infrastructure'] = result
                self.results['status']['infrastructure'] = 'completed'
                return result
        except Exception as e:
            self.results['status']['infrastructure'] = 'failed'
            return {'error': str(e)}
    
    def run_infrastructure_wrapper(self, domain: str) -> Dict[str, Any]:
        """Wrapper to run async infrastructure analysis in thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.run_infrastructure_analysis(domain))
        finally:
            loop.close()

    def run_application_analysis(self, domain: str) -> Dict[str, Any]:
        """Run application landscape assessment"""
        try:
            self.results['status']['application_landscape'] = 'running'
            scanner = CompleteBSIScanner(domain)
            result = scanner.run_full_scan()
            self.results['application_landscape'] = result
            self.results['status']['application_landscape'] = 'completed'
            return result
        except Exception as e:
            self.results['status']['application_landscape'] = 'failed'
            return {'error': str(e)}
        
    def run_correlation_analysis(self, domain: str) -> Dict[str, Any]:
        """Run Phase 4 correlation analysis using ALL data"""
        try:
            self.results['status']['correlation_analysis'] = 'running'
        
            phase1_data = self.results.get('business_domain', {})
            phase2_data = self.results.get('infrastructure', {})
            phase3_data = self.results.get('application_landscape', {})
        
            if not phase2_data or not phase3_data:
                raise Exception("Phase 2 or Phase 3 data not available")
        
            if 'error' in phase2_data or 'error' in phase3_data:
                raise Exception("Phase 2 or Phase 3 analysis failed")
        
            # Save ALL THREE phase files
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase1.json', delete=False, encoding='utf-8') as f1:
                json.dump(phase1_data, f1, default=str, indent=2)
                phase1_path = f1.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase2.json', delete=False, encoding='utf-8') as f2:
                json.dump(phase2_data, f2, default=str, indent=2)
                phase2_path = f2.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase3.json', delete=False, encoding='utf-8') as f3:
                json.dump(phase3_data, f3, default=str, indent=2)
                phase3_path = f3.name
        
            try:
                scanner = AIPhase4Scanner()
                result = scanner.run_correlation(phase1_path, phase2_path, phase3_path)

                if result and 'error' not in result:
                    scanner.save_report()

                self.results['correlation_analysis'] = result
                self.results['status']['correlation_analysis'] = 'completed'
                return result
                
            finally:
                try:
                    os.unlink(phase1_path)
                    os.unlink(phase2_path)
                    os.unlink(phase3_path)
                except:
                    pass
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.results['status']['correlation_analysis'] = 'failed'
            return {'error': str(e)}
        
    
    def run_risk_assessment(self, domain: str) -> Dict[str, Any]:
        """Run Phase 5: Risk Assessment and Categorization"""
        try:
            self.results['status']['risk_assessment'] = 'running'
            
            correlation_data = self.results.get('correlation_analysis', {})
            infra_data = self.results.get('infrastructure', {})
            domain_data = self.results.get('business_domain', {})
            app_data = self.results.get('application_landscape', {})
            
            if not correlation_data or 'error' in correlation_data:
                raise Exception("Correlation analysis data not available or failed")
            
            engine = RiskAssessmentEngine()
            
            assessment = engine.run_full_assessment(
                correlation_data=correlation_data,
                infra_data=infra_data,
                domain_data=domain_data,
                app_data=app_data
            )
            
            self.results['risk_assessment'] = assessment
            self.results['status']['risk_assessment'] = 'completed'
            return assessment

        except Exception as e:
            self.results['status']['risk_assessment'] = 'failed'
            return {'error': str(e)}
                

    def analyze_domain_parallel(self, domain: str):
        """Run all analyses in parallel"""
        self.domain = domain
        self.results['timestamp'] = datetime.now().isoformat()
    
        # Phase 1-3 run in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_business = executor.submit(self.run_business_analysis, domain)
            future_infrastructure = executor.submit(self.run_infrastructure_wrapper, domain)
            future_application = executor.submit(self.run_application_analysis, domain)
        
            futures = {
                future_business: 'business_domain',
                future_infrastructure: 'infrastructure',
                future_application: 'application_landscape'
            }
        
            for future in as_completed(futures):
                phase = futures[future]
                try:
                    result = future.result(timeout=600)
                except Exception as e:
                    self.results['status'][phase] = 'failed'
                    st.error(f"{phase} analysis failed: {str(e)}")
    
        # Phase 4: Wait for completion explicitly
        if (self.results['infrastructure'] and 
            self.results['application_landscape']):
            st.info("🔗 Starting Phase 4...")
            self.run_correlation_analysis(domain)
    
            while self.results['status']['correlation_analysis'] == 'running':
                time.sleep(1)

        # Phase 5: Only start after Phase 4 is COMPLETED
        if (self.results.get('correlation_analysis') and 
            self.results['status']['correlation_analysis'] == 'completed'):
            st.info("📊 Starting Phase 5...")
            self.run_risk_assessment(domain)
