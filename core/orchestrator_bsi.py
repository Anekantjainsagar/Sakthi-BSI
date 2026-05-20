"""
BSI Orchestrator - Manages parallel execution of all analysis phases
Enhanced with dark web scanning and response time tracking
"""

import asyncio
import time
import json
import tempfile
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import streamlit as st
import pandas as pd

from config.gemini_config import GEMINI_API_KEYS
from phases.phase4 import AIPhase4Scanner
from phases.phase5 import RiskAssessmentEngine
from phases.phase1 import CompanyIntelligenceAnalyzer
from phases.phase2 import BSIInfrastructureDiscovery
from phases.phase3 import CompleteBSIScanner
from phases.phase_dark_web import DarkWebIntelligencePhase


class ResponseTimeTracker:
    """Tracks response times for each phase and overall analysis"""
    
    def __init__(self):
        self.phase_times: Dict[str, float] = {}
        self.phase_start_times: Dict[str, float] = {}
        self.overall_start_time: Optional[float] = None
        self.overall_end_time: Optional[float] = None
    
    def start_overall(self):
        """Start overall timer"""
        self.overall_start_time = time.time()
    
    def end_overall(self):
        """End overall timer"""
        self.overall_end_time = time.time()
    
    def start_phase(self, phase_name: str):
        """Start timer for a phase"""
        self.phase_start_times[phase_name] = time.time()
    
    def end_phase(self, phase_name: str):
        """End timer for a phase"""
        if phase_name in self.phase_start_times:
            elapsed = time.time() - self.phase_start_times[phase_name]
            self.phase_times[phase_name] = elapsed
            return elapsed
        return 0
    
    def get_phase_time(self, phase_name: str) -> float:
        """Get time for a specific phase"""
        return self.phase_times.get(phase_name, 0)
    
    def get_overall_time(self) -> float:
        """Get overall analysis time"""
        if self.overall_start_time and self.overall_end_time:
            return self.overall_end_time - self.overall_start_time
        return 0
    
    def format_time(self, seconds: float) -> str:
        """Format seconds to human-readable format"""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.2f}h"
    
    def get_summary(self) -> Dict[str, Any]:
        """Get timing summary"""
        return {
            "overall_time_seconds": self.get_overall_time(),
            "overall_time_formatted": self.format_time(self.get_overall_time()),
            "phase_times": {
                phase: {
                    "seconds": time_val,
                    "formatted": self.format_time(time_val)
                }
                for phase, time_val in self.phase_times.items()
            },
            "start_time": datetime.fromtimestamp(self.overall_start_time).isoformat() if self.overall_start_time else None,
            "end_time": datetime.fromtimestamp(self.overall_end_time).isoformat() if self.overall_end_time else None
        }
    
    def display_summary(self):
        """Display timing summary in Streamlit"""
        summary = self.get_summary()
        
        st.markdown("---")
        st.subheader("⏱️ Response Time Summary")
        
        # Overall time
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Analysis Time", summary["overall_time_formatted"])
        
        with col2:
            if summary["start_time"]:
                start_time_str = summary["start_time"].split("T")[1][:8]
                st.metric("Started At", start_time_str)
        
        with col3:
            if summary["end_time"]:
                end_time_str = summary["end_time"].split("T")[1][:8]
                st.metric("Completed At", end_time_str)
        
        # Phase breakdown
        st.markdown("**Phase Breakdown:**")
        phase_data = []
        for phase, times in summary["phase_times"].items():
            phase_display = phase.replace("_", " ").title()
            phase_data.append({
                "Phase": phase_display,
                "Time": times["formatted"],
                "Seconds": f"{times['seconds']:.2f}"
            })
        
        if phase_data:
            df = pd.DataFrame(phase_data)
            st.dataframe(df, use_container_width=True)
            
            # Show percentage breakdown
            st.markdown("**Time Distribution:**")
            total_time = summary["overall_time_seconds"]
            if total_time > 0:
                for phase, times in summary["phase_times"].items():
                    percentage = (times["seconds"] / total_time) * 100
                    phase_display = phase.replace("_", " ").title()
                    st.write(f"• {phase_display}: {percentage:.1f}%")


class BSIOrchestrator:
    """Orchestrates parallel execution of BSI analysis phases"""
    
    def __init__(self):
        self.domain = None
        self.results = {
            'business_domain': None,
            'infrastructure': None,
            'application_landscape': None,
            'dark_web_intelligence': None,
            'correlation_analysis': None,
            'risk_assessment': None,
            'timestamp': None,
            'status': {
                'business_domain': 'pending',
                'infrastructure': 'pending',
                'application_landscape': 'pending',
                'dark_web_intelligence': 'pending',
                'correlation_analysis': 'pending',
                'risk_assessment': 'pending'
            }
        }
        self.response_time_tracker = ResponseTimeTracker()
    
    def run_business_analysis(self, domain: str) -> Dict[str, Any]:
        """Run business domain understanding analysis"""
        try:
            self.response_time_tracker.start_phase("business_domain")
            self.results['status']['business_domain'] = 'running'
            analyzer = CompanyIntelligenceAnalyzer()
            result = analyzer.analyze_company(domain.split('.')[0].title(), domain)
            self.results['business_domain'] = result
            self.results['status']['business_domain'] = 'completed'
            self.response_time_tracker.end_phase("business_domain")
            return result
        except Exception as e:
            self.results['status']['business_domain'] = 'failed'
            self.response_time_tracker.end_phase("business_domain")
            return {'error': str(e)}
    
    async def run_infrastructure_analysis(self, domain: str) -> Dict[str, Any]:
        """Run infrastructure discovery analysis"""
        try:
            self.response_time_tracker.start_phase("infrastructure")
            self.results['status']['infrastructure'] = 'running'
            async with BSIInfrastructureDiscovery() as discovery:
                data = await discovery.discover_infrastructure(domain)
                from dataclasses import asdict
                result = asdict(data)
                self.results['infrastructure'] = result
                self.results['status']['infrastructure'] = 'completed'
                self.response_time_tracker.end_phase("infrastructure")
                return result
        except Exception as e:
            self.results['status']['infrastructure'] = 'failed'
            self.response_time_tracker.end_phase("infrastructure")
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
            self.response_time_tracker.start_phase("application_landscape")
            self.results['status']['application_landscape'] = 'running'
            scanner = CompleteBSIScanner(domain)
            result = scanner.run_full_scan()
            self.results['application_landscape'] = result
            self.results['status']['application_landscape'] = 'completed'
            self.response_time_tracker.end_phase("application_landscape")
            return result
        except Exception as e:
            self.results['status']['application_landscape'] = 'failed'
            self.response_time_tracker.end_phase("application_landscape")
            return {'error': str(e)}
    
    def run_dark_web_analysis(self, domain: str) -> Dict[str, Any]:
        """Run dark web intelligence analysis"""
        try:
            self.response_time_tracker.start_phase("dark_web_intelligence")
            self.results['status']['dark_web_intelligence'] = 'running'
            
            dark_web_phase = DarkWebIntelligencePhase()
            result = dark_web_phase.run_dark_web_scan(domain)
            
            self.results['dark_web_intelligence'] = result
            self.results['status']['dark_web_intelligence'] = 'completed'
            self.response_time_tracker.end_phase("dark_web_intelligence")
            return result
        except Exception as e:
            self.results['status']['dark_web_intelligence'] = 'failed'
            self.response_time_tracker.end_phase("dark_web_intelligence")
            return {'error': str(e)}
        
    def run_correlation_analysis(self, domain: str) -> Dict[str, Any]:
        """Run Phase 4 correlation analysis using ALL data (T1.3: Direct data passing, no temp files)"""
        try:
            self.response_time_tracker.start_phase("correlation_analysis")
            self.results['status']['correlation_analysis'] = 'running'
        
            phase1_data = self.results.get('business_domain', {})
            phase2_data = self.results.get('infrastructure', {})
            phase3_data = self.results.get('application_landscape', {})
            dark_web_data = self.results.get('dark_web_intelligence', {})
        
            if not phase2_data or not phase3_data:
                raise Exception("Phase 2 or Phase 3 data not available")
        
            if 'error' in phase2_data or 'error' in phase3_data:
                raise Exception("Phase 2 or Phase 3 analysis failed")
        
            # T1.3: Pass data directly to scanner instead of writing temp files
            scanner = AIPhase4Scanner()
            result = scanner.run_correlation_direct(phase1_data, phase2_data, phase3_data, dark_web_data)

            if result and 'error' not in result:
                scanner.save_report()

            self.results['correlation_analysis'] = result
            self.results['status']['correlation_analysis'] = 'completed'
            self.response_time_tracker.end_phase("correlation_analysis")
            return result
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.results['status']['correlation_analysis'] = 'failed'
            self.response_time_tracker.end_phase("correlation_analysis")
            return {'error': str(e)}
        
    
    def run_risk_assessment(self, domain: str) -> Dict[str, Any]:
        """Run Phase 5: Risk Assessment and Categorization"""
        try:
            self.response_time_tracker.start_phase("risk_assessment")
            self.results['status']['risk_assessment'] = 'running'
            
            correlation_data = self.results.get('correlation_analysis', {})
            infra_data = self.results.get('infrastructure', {})
            domain_data = self.results.get('business_domain', {})
            app_data = self.results.get('application_landscape', {})
            dark_web_data = self.results.get('dark_web_intelligence', {})
            
            if not correlation_data or 'error' in correlation_data:
                raise Exception("Correlation analysis data not available or failed")
            
            engine = RiskAssessmentEngine()
            
            assessment = engine.run_full_assessment(
                correlation_data=correlation_data,
                infra_data=infra_data,
                domain_data=domain_data,
                app_data=app_data,
                dark_web_data=dark_web_data
            )
            
            self.results['risk_assessment'] = assessment
            self.results['status']['risk_assessment'] = 'completed'
            self.response_time_tracker.end_phase("risk_assessment")
            return assessment

        except Exception as e:
            self.results['status']['risk_assessment'] = 'failed'
            self.response_time_tracker.end_phase("risk_assessment")
            return {'error': str(e)}
                

    async def analyze_domain_parallel_async(self, domain: str):
        """T2.7: Run all analyses in parallel using pure asyncio (no ThreadPoolExecutor)"""
        self.domain = domain
        self.results['timestamp'] = datetime.now().isoformat()
        
        # Start overall timer
        self.response_time_tracker.start_overall()
    
        # T2.7: Phase 1-3 and Dark Web run in parallel using asyncio
        tasks = [
            asyncio.to_thread(self.run_business_analysis, domain),
            self.run_infrastructure_analysis(domain),
            asyncio.to_thread(self.run_application_analysis, domain),
            asyncio.to_thread(self.run_dark_web_analysis, domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Map results back to phases
        phase_names = ['business_domain', 'infrastructure', 'application_landscape', 'dark_web_intelligence']
        for phase_name, result in zip(phase_names, results):
            if isinstance(result, Exception):
                self.results['status'][phase_name] = 'failed'
            elif result and 'error' not in result:
                self.results['status'][phase_name] = 'completed'
            else:
                self.results['status'][phase_name] = 'failed'
    
        # Phase 4: Wait for completion explicitly
        if (self.results['infrastructure'] and 
            self.results['application_landscape']):
            self.run_correlation_analysis(domain)
    
            while self.results['status']['correlation_analysis'] == 'running':
                await asyncio.sleep(1)

        # Phase 5: Only start after Phase 4 is COMPLETED
        if (self.results.get('correlation_analysis') and 
            self.results['status']['correlation_analysis'] == 'completed'):
            self.run_risk_assessment(domain)
        
        # End overall timer
        self.response_time_tracker.end_overall()

    def analyze_domain_parallel(self, domain: str):
        """Sync wrapper for analyze_domain_parallel_async"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.analyze_domain_parallel_async(domain))
        finally:
            loop.close()
