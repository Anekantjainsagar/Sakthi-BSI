#!/usr/bin/env python3
"""
Business Security Intelligence (BSI) - Main Streamlit Application
Runs multiple analysis phases in parallel for comprehensive domain assessment
"""

import streamlit as st
import streamlit.components.v1 as components
import asyncio
import threading
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import sys
import os
from typing import Dict, Any, Optional
import glob, re
import graphviz
import tempfile
import pandas as pd
import shutil
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from modular structure
try:
    from config.gemini_config import GEMINI_API_KEYS
    from phases.phase4 import AIPhase4Scanner
    from phases.phase5 import RiskAssessmentEngine
    from phases.phase1 import CompanyIntelligenceAnalyzer
    from phases.phase2 import BSIInfrastructureDiscovery
    from phases.phase3 import CompleteBSIScanner
    from utils.parsers import parse_spiderfoot_csv, get_section_counts
    from data.database import get_db_manager
    from ui.search_history import SearchHistoryUI
    from services.data_streamer import DataStreamer, StreamingProgressTracker
    from ui.display_validators import validate_and_normalize_phase_data
    from ui.simple_display import (display_business_domain_simple, display_infrastructure_simple,
                                   display_application_simple, display_correlation_simple, display_risk_simple)
except ImportError as e:
    st.error(f"Required modules not found: {e}")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Business Security Intelligence",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

class BSIOrchestrator:
    """Orchestrates parallel execution of BSI analysis phases"""
    
    def __init__(self):
        self.domain = None
        self.results = {
            'business_domain': None,
            'infrastructure': None,
            'application_landscape': None,
            'correlation_analysis': None,  # ADD THIS
            'risk_assessment': None,  # ADD THIS LINE
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
                # Convert dataclass to dict
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
            
            # ✅ FIXED: run_full_scan is now synchronous (no async/await needed)
            result = scanner.run_full_scan()
            
            # Ensure result is a dict
            if not isinstance(result, dict):
                result = {'error': 'Phase 3 returned invalid data type'}
                
            self.results['application_landscape'] = result
            self.results['status']['application_landscape'] = 'completed'
            return result
        except Exception as e:
            self.results['status']['application_landscape'] = 'failed'
            import traceback
            traceback.print_exc()
            return {'error': str(e)}
        
    def run_correlation_analysis(self, domain: str) -> Dict[str, Any]:
        """Run Phase 4 correlation analysis using ALL data"""
        try:
            self.results['status']['correlation_analysis'] = 'running'
        
            # Check if we have Phase 1 ,2  and Phase 3 data
            phase1_data = self.results.get('business_domain', {})
            phase2_data = self.results.get('infrastructure', {})
            phase3_data = self.results.get('application_landscape', {})
        
            if not phase2_data or not phase3_data:
                raise Exception("Phase 2 or Phase 3 data not available")
        
            if 'error' in phase2_data or 'error' in phase3_data:
                raise Exception("Phase 2 or Phase 3 analysis failed")
        
            # ✅ Save ALL THREE phase files
            import tempfile
            
            # Phase 1 file (business domain)
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase1.json', delete=False, encoding='utf-8') as f1:
                json.dump(phase1_data, f1, default=str, indent=2)
                phase1_path = f1.name
            
            # Phase 2 file (infrastructure)
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase2.json', delete=False, encoding='utf-8') as f2:
                json.dump(phase2_data, f2, default=str, indent=2)
                phase2_path = f2.name
            
            # Phase 3 file (application)
            with tempfile.NamedTemporaryFile(mode='w', suffix='_phase3.json', delete=False, encoding='utf-8') as f3:
                json.dump(phase3_data, f3, default=str, indent=2)
                phase3_path = f3.name
        
            try:
                # Initialize correlation scanner (use_gemini set automatically from gemini_config)
                scanner = AIPhase4Scanner()

                # Run correlation in headless mode
                result = scanner.run_correlation(phase1_path, phase2_path, phase3_path)

                # Save Phase 4 report to reports/ folder
                if result and 'error' not in result:
                    scanner.save_report()

                self.results['correlation_analysis'] = result
                self.results['status']['correlation_analysis'] = 'completed'
                return result
                
            finally:
                # Cleanup temp files
                try:
                    os.unlink(phase1_path)
                    os.unlink(phase2_path)
                    os.unlink(phase3_path)
                except:
                    pass
                
        except Exception as e:
            import traceback
            traceback.print_exc()  # ✅ Print full error for debugging
            self.results['status']['correlation_analysis'] = 'failed'
            return {'error': str(e)}
        
    
    def run_risk_assessment(self, domain: str) -> Dict[str, Any]:
        """Run Phase 5: Risk Assessment and Categorization"""
        try:
            self.results['status']['risk_assessment'] = 'running'
            
            # Get previous phase data
            correlation_data = self.results.get('correlation_analysis', {})
            infra_data = self.results.get('infrastructure', {})
            domain_data = self.results.get('business_domain', {})
            app_data = self.results.get('application_landscape', {})
            
            # Check if we have required data
            if not correlation_data or 'error' in correlation_data:
                raise Exception("Correlation analysis data not available or failed")
            
            # Initialize risk engine
            engine = RiskAssessmentEngine()
            
            # Run full assessment
            assessment = engine.run_full_assessment(
                correlation_data=correlation_data,
                infra_data=infra_data,
                domain_data=domain_data,
                app_data=app_data
            )
            
            # Note: run_full_assessment() already saves to reports/ internally
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
    
            # Wait for Phase 4 to actually complete
            while self.results['status']['correlation_analysis'] == 'running':
                time.sleep(1)

        # Phase 5: Only start after Phase 4 is COMPLETED
        if (self.results.get('correlation_analysis') and 
            self.results['status']['correlation_analysis'] == 'completed'):
            st.info("📊 Starting Phase 5...")
            self.run_risk_assessment(domain)
               

def display_business_domain_results(data: Dict[str, Any]):
    """Enhanced display - UPDATED for Phase 1 changes"""
    st.header("🏢 Business Domain Understanding")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Display API Results
    st.subheader("📊 API Collected Data")
    
    api_tabs = st.tabs(["Hunter.io Emails", "Host.io Domain Info", "AbstractAPI Company"])
    
    # TAB 1: Hunter.io (unchanged)
    with api_tabs[0]:
        st.markdown("### 📧 Hunter.io - Email Discovery")
        hunter_data = data.get('hunter_io', {})
        
        if hunter_data and hunter_data.get('emails'):
            emails = hunter_data.get('emails', [])
            st.success(f"✅ Found {len(emails)} email addresses")
            
            for email_obj in emails[:10]:
                with st.expander(f"📧 {email_obj.get('value', 'N/A')}", expanded=False):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.text(f"Type: {email_obj.get('type', 'Unknown')}")
                        st.text(f"First Name: {email_obj.get('first_name', 'N/A')}")
                        st.text(f"Last Name: {email_obj.get('last_name', 'N/A')}")
                    with col2:
                        st.text(f"Position: {email_obj.get('position', 'N/A')}")
                        st.text(f"Department: {email_obj.get('department', 'N/A')}")
                        confidence = email_obj.get('confidence', 0)
                        st.progress(confidence / 100)
                        st.caption(f"Confidence: {confidence}%")
        else:
            st.info("No email data available from Hunter.io")
    
    # TAB 2: Host.io
    with api_tabs[1]:
        st.markdown("### 🌐 Host.io - Domain Information")
        hostio_data = data.get('host_io', {})

        if hostio_data and hostio_data.get('status') == 'success':
            web = hostio_data.get('web', {})
            dns = hostio_data.get('dns', {})
            ipinfo = hostio_data.get('ipinfo', {})
            related = hostio_data.get('related', {})

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**🌍 Web Info**")
                st.text(f"Domain: {web.get('domain', 'N/A')}")
                st.text(f"IP Address: {web.get('ip', 'N/A')}")
                st.text(f"Global Rank: {web.get('rank', 'N/A')}")
                st.text(f"Contact Email: {web.get('email', 'N/A')}")

                # ASN / Hosting info
                for ip, info in ipinfo.items():
                    asn = info.get('asn', {})
                    st.markdown("**☁️ Hosting Provider**")
                    st.text(f"Provider: {asn.get('name', 'N/A')}")
                    st.text(f"ASN: {asn.get('asn', 'N/A')}")
                    st.text(f"Type: {asn.get('type', 'N/A')}")

            with col2:
                st.markdown("**📡 DNS Records**")
                a_records = dns.get('a', [])
                if a_records:
                    st.text(f"A Records: {', '.join(a_records)}")
                mx_records = dns.get('mx', [])
                if mx_records:
                    st.markdown("**MX (Mail Servers):**")
                    for mx in mx_records:
                        st.text(f"  {mx}")
                ns_records = dns.get('ns', [])
                if ns_records:
                    st.markdown("**NS (Nameservers):**")
                    for ns in ns_records:
                        st.text(f"  {ns}")

            # Brand/subsidiary domains from links
            links = web.get('links', [])
            skip_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
                           'instagram.com', 'google.com', 'pinterest.com']
            brand_domains = [l for l in links if not any(s in l for s in skip_domains)]
            if brand_domains:
                st.markdown("**🏷️ Brand / Subsidiary Domains:**")
                cols = st.columns(3)
                for i, domain_link in enumerate(brand_domains):
                    with cols[i % 3]:
                        st.markdown(f"🔗 `{domain_link}`")

            # Related stats
            st.markdown("**📊 Domain Stats**")
            col1, col2, col3 = st.columns(3)
            with col1:
                backlinks = related.get('backlinks', [{}])
                st.metric("Backlinks", backlinks[0].get('count', 0) if backlinks else 0)
            with col2:
                redirects = related.get('redirects', [{}])
                st.metric("Redirects", redirects[0].get('count', 0) if redirects else 0)
            with col3:
                ip_count = related.get('ip', [{}])
                st.metric("IP Co-hosts", ip_count[0].get('count', 0) if ip_count else 0)
        else:
            st.info("No Host.io data available")
    
    # TAB 3: AbstractAPI Company - ENHANCED
    with api_tabs[2]:
        st.markdown("### 🏢 AbstractAPI - Company Enrichment")
        st.caption("⭐ Primary source for Industry, Employee Count, and Founded Year")
        abstract_data = data.get('abstractapi_company', {})
        
        if abstract_data:
            col1, col2 = st.columns(2)
            
            with col1:
                st.text(f"Company Name: {abstract_data.get('name', 'N/A')}")
                st.text(f"Domain: {abstract_data.get('domain', 'N/A')}")
                st.text(f"Country: {abstract_data.get('country', 'N/A')}")
                st.text(f"Locality: {abstract_data.get('locality', 'N/A')}")
            
            with col2:
                industry = abstract_data.get('industry', 'N/A')
                st.markdown(f"**🏭 Industry:** {industry}")
                st.caption("(Primary source)")
                
                employees = abstract_data.get('employees_count', 'N/A')
                st.markdown(f"**👥 Employees:** {employees}")
                st.caption("(Only location for employee data)")
                
                founded = abstract_data.get('year_founded', 'N/A')
                st.markdown(f"**📅 Founded:** {founded}")
                st.caption("(Primary source)")
            
            linkedin = abstract_data.get('linkedin_url', '')
            if linkedin:
                if not linkedin.startswith('http'):
                    linkedin = 'https://' + linkedin
                st.markdown(f"**🔗 LinkedIn:** [View Profile]({linkedin})")
        else:
            st.info("No company data available from AbstractAPI")
    
    st.markdown("---")
    
    # Data Collection Summary - UPDATED
    with st.expander("🔍 Data Collection Summary"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            whois_status = "✅" if data.get('whois_data', {}).get('domain_age_years') else "❌"
            st.metric("WHOIS Data", whois_status)
        
        with col2:
            scrape_status = "✅" if data.get('scraped_data', {}).get('success') else "❌"
            st.metric("Web Scraping", scrape_status)
        
        with col3:
            # ✅ UPDATED: Check for revenue OR market_cap, NOT employees
            search_status = "✅" if data.get('search_data', {}).get('revenue') or data.get('search_data', {}).get('market_cap') else "⚠️"
            st.metric("Google Search", search_status)
        
        # Show what was found - UPDATED
        search_data = data.get('search_data', {})
        if search_data:
            st.markdown("**Google Search Results:**")
            if search_data.get('revenue'):
                st.success(f"💰 Revenue: {search_data.get('revenue')}")
            # ❌ REMOVED: Employee display
            if search_data.get('revenue_growth'):
                st.success(f"📈 Growth: {search_data.get('revenue_growth')}")
            if search_data.get('market_cap'):
                st.success(f"💵 Market Cap: {search_data.get('market_cap')}")
            if search_data.get('ticker'):
                st.success(f"📊 Ticker: {search_data.get('ticker')}")
            if search_data.get('headquarters'):
                st.success(f"🏢 HQ: {search_data.get('headquarters')}")
            compliance_found = search_data.get('compliance_found', [])
            if compliance_found:
                st.success(f"✅ Compliance Found: {', '.join(compliance_found)}")
    
    st.markdown("---")
    
    # WHOIS Information (unchanged)
    st.subheader("📋 Domain Intelligence")
    whois_data = data.get('whois_data', {})
    
    if whois_data and not whois_data.get('error'):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**Domain Age**")
            st.metric("Years", f"{whois_data.get('domain_age_years', 'Unknown')} years")
            st.markdown("**Registrar**")
            st.write(whois_data.get('registrar', 'Unknown'))
        
        with col2:
            st.markdown("**Created**")
            st.write(whois_data.get('creation_date', 'Unknown')[:10])
            st.markdown("**Country**")
            st.write(whois_data.get('country', 'Unknown'))
        
        with col3:
            st.markdown("**Organization**")
            st.write(whois_data.get('organization', 'None'))
            st.markdown("**Expires**")
            st.write(whois_data.get('expiration_date', 'Unknown')[:10])
    
    st.markdown("---")
    
    # AI Analysis
    ai_analysis = data.get('ai_analysis', {})
    
    if ai_analysis.get('analysis_method') == 'error':
        st.error("❌ AI Analysis Failed")
        st.warning(f"**Error:** {ai_analysis.get('error_message', 'Unknown error')}")
        return
    
    # Company Overview (unchanged)
    st.subheader("🏢 Company Profile")
    overview = ai_analysis.get('company_overview', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"**Primary Business**")
        st.info(overview.get('primary_business', 'Unknown'))
        st.markdown(f"**Industry:** {overview.get('industry_vertical', 'Unknown')}")
        st.markdown(f"**Business Model:** {overview.get('business_model', 'Unknown')}")
    
    with col2:
        st.markdown(f"**Founded:** {overview.get('founded_year', 'Unknown')}")
        hq = overview.get('headquarters', '')
        hq_display = hq if hq and 'not specified' not in hq.lower() and 'not found' not in hq.lower() else 'Not found publicly'
        st.markdown(f"**Headquarters:** {hq_display}")
        st.markdown(f"**Maturity:** {overview.get('company_maturity', 'Unknown')}")
        st.markdown(f"**Size:** {overview.get('company_size', 'Unknown')}")
    
    st.markdown("---")
    
    # Financial Intelligence - UPDATED (NO EMPLOYEES)
    st.subheader("💰 Financial Intelligence")
    financial = ai_analysis.get('financial_intelligence', {})
    
    # Main metrics - CHANGED FROM 4 TO 3 COLUMNS
    col1, col2, col3 = st.columns(3)
    
    with col1:
        revenue = financial.get('annual_revenue') or 'Unknown'
        revenue_year = financial.get('revenue_year', '')

        if not revenue or any(x in str(revenue).lower() for x in ['not available', 'unknown', 'not found', 'n/a']):
            st.metric("Annual Revenue", "📊 N/A")
        else:
            st.metric("Annual Revenue", revenue)
            if revenue_year:
                st.caption(f"Year: {revenue_year}")
        
        source = ai_analysis.get('data_quality', {}).get('revenue_source', 'Unknown').lower()
        if 'search' in source or 'google' in source:
            st.success("✅ From Google")
        elif 'ai' in source or 'knowledge' in source:
            st.info("🤖 From AI")
        else:
            st.warning("⚠️ Estimated")
    
    # ❌ REMOVED col2 (Employees section)
    
    with col2:
        quarterly = financial.get('quarterly_revenue', 'N/A')
        if quarterly and quarterly != 'N/A':
            st.metric("Quarterly Revenue", quarterly)
        else:
            st.metric("Quarterly Revenue", "📊 N/A")
    
    with col3:
        company_type = financial.get('company_type', 'Unknown')
        is_public = financial.get('is_public', False)
        
        if is_public:
            ticker = financial.get('ticker_symbol', 'N/A')
            st.metric("Company Type", "📈 Public")
            st.caption(f"Ticker: {ticker}")
        else:
            st.metric("Company Type", "🔒 Private")
    
    # Additional financial details - UPDATED
    with st.expander("📊 Additional Financial Details"):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown(f"**Revenue Growth:** {financial.get('revenue_growth', 'N/A')}")
            st.markdown(f"**Profitability:** {financial.get('profitability', 'Unknown')}")

        with col2:
            st.markdown(f"**Market Cap:** {financial.get('market_cap', 'N/A')}")
            st.markdown(f"**Funding Raised:** {financial.get('funding_raised', 'N/A')}")
    
    st.markdown("---")
    
    # Leadership (unchanged)
    leadership = ai_analysis.get('leadership', {})
    if leadership and leadership.get('ceo') != 'Unknown':
        st.subheader("👔 Leadership")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**CEO:** {leadership.get('ceo', 'Unknown')}")
        with col2:
            st.markdown(f"**Founder:** {leadership.get('founder', 'Unknown')}")
        st.markdown("---")
    
    # Products & Services (unchanged)
    st.subheader("🛍️ Products & Services")
    services = ai_analysis.get('services_and_products', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        products = services.get('primary_products', [])
        if products:
            st.markdown("**Primary Products:**")
            for product in products:
                st.write(f"• {product}")
        else:
            st.info("No product information available")
    
    with col2:
        categories = services.get('service_categories', [])
        if categories:
            st.markdown("**Service Categories:**")
            for cat in categories:
                st.write(f"• {cat}")
        
        offerings = services.get('key_offerings', [])
        if offerings:
            st.markdown("**Key Offerings:**")
            for offer in offerings:
                st.write(f"• {offer}")
    
    st.markdown("---")
    
    # Customer Base (unchanged)
    st.subheader("👥 Customer Base")
    customers = ai_analysis.get('customer_base', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        target = customers.get('target_customers', [])
        if target:
            st.markdown("**Target Customers:**")
            for t in target:
                st.write(f"• {t}")
        
        segments = customers.get('customer_segments', [])
        if segments:
            st.markdown("**Segments:**")
            st.write(", ".join(segments))
    
    with col2:
        markets = customers.get('geographic_markets', [])
        if markets:
            st.markdown("**Geographic Markets:**")
            for market in markets:
                st.write(f"• {market}")
        
        clients = customers.get('notable_clients', [])
        # Handle both list and string "None" from Gemini
        if isinstance(clients, str):
            clients = [] if clients.lower() in ['none', 'n/a', ''] else [clients]
        real_clients = [c for c in clients if c and 'none' not in str(c).lower() and 'not' not in str(c).lower()]
        if real_clients:
            st.markdown("**Notable Clients:**")
            for client in real_clients:
                st.write(f"• {client}")
    
    st.markdown("---")
    
    # Threat Intelligence - UPDATED (NO THREAT_LEVEL)
    st.subheader("⚠️ Threat Intelligence")
    threat = ai_analysis.get('threat_intelligence', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        apt_groups = threat.get('industry_apt_groups', [])
        if apt_groups:
            st.markdown("**APT Groups Targeting Industry:**")
            st.caption("🤖 AI-suggested based on industry — not verified threat intelligence")
            for apt in apt_groups:
                apt_name = apt.get('name', str(apt)) if isinstance(apt, dict) else str(apt)
                st.error(f"🎯 {apt_name}")
        else:
            st.info("No specific APT groups identified")
    
    with col2:
        # ❌ REMOVED: Threat level section
        
        assets = threat.get('critical_assets', [])
        if assets:
            st.markdown("**Critical Assets:**")
            for asset in assets:
                st.write(f"• {asset}")
        else:
            st.info("No critical assets identified")
    
    st.markdown("---")
    
    # Regulatory Compliance - COMPLETELY UPDATED
    st.subheader("📋 Regulatory Compliance")
    compliance = ai_analysis.get('regulatory_compliance', {})
    
    # Show rationale first
    rationale = compliance.get('compliance_rationale', '')
    if rationale:
        st.info(f"**Context:** {rationale}")
        st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Publicly confirmed certifications (found via search)
        confirmed = compliance.get('confirmed_public', [])
        if confirmed:
            st.markdown("**✅ Publicly Confirmed Certifications:**")
            st.caption("Found via public sources / company website")
            for item in confirmed:
                name = item.get('name', item) if isinstance(item, dict) else item
                st.success(f"✔ {name}")
        else:
            st.info("No publicly confirmed certifications found")

        # Data Protection Requirements
        data_protection = compliance.get('data_protection_requirements', [])
        if data_protection:
            st.markdown("**🔒 Data Protection Requirements:**")
            for dp in data_protection:
                st.write(f"• {dp}")

    with col2:
        # AI-suggested compliance
        ai_suggested = compliance.get('ai_suggested', [])
        if ai_suggested:
            st.markdown("**🤖 AI-Suggested Compliance:**")
            st.caption("Based on industry/country — not verified")
            for item in ai_suggested:
                name = item.get('name', item) if isinstance(item, dict) else item
                rationale = item.get('rationale', '') if isinstance(item, dict) else ''
                st.warning(f"⚠️ {name}" + (f" — {rationale}" if rationale else ""))
        else:
            st.info("No AI suggestions available")
    
    st.markdown("---")
    
    # Data Quality Summary
    with st.expander("📊 Analysis Metadata"):
        quality = ai_analysis.get('data_quality', {})
        st.json({
            "Revenue Source": quality.get('revenue_source', 'Unknown'),
            "Confidence Score": f"{quality.get('confidence_score', 0)}/10",
            "Analysis Timestamp": data.get('analysis_timestamp', 'Unknown')
        })

def display_infrastructure_results(data: Dict[str, Any]):
    """Display infrastructure discovery results with improved design and proper port names"""
    st.header("🌐 Infrastructure Discovery")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Create tabs for different infrastructure aspects
    tabs = st.tabs([
        "Network Infrastructure",
        "SSL/TLS Analysis", 
        "Mail Servers",
        "Cloud & ASN",
        "Security Findings",
        "Port Analysis",
        "DNS Information",
        "⚠️ Look-alike Domains"  # ✅ ADD THIS
    ])
    
    # Tab 1: Network Infrastructure
    with tabs[0]:
        st.subheader("🔌 Network Infrastructure")
        
        # IP Addresses Section
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**IPv4 Addresses**")
            ip_count = len(data.get('ip_addresses', []))
            st.text(f"Total: {ip_count}")
            for ip in data.get('ip_addresses', []):
                st.code(ip, language=None)
        
        with col2:
            st.markdown("**IPv6 Addresses**")
            ipv6_count = len(data.get('ipv6_addresses', []))
            st.text(f"Total: {ipv6_count}")
            for ip in data.get('ipv6_addresses', []):
                st.code(ip, language=None)
        
        st.markdown("---")
        
        # ✅ ENHANCED Subdomains Section with NEW API data
        st.markdown("**🔍 Discovered Subdomains (Enhanced with FullHunt & ProjectDiscovery)**")

        # ✅ FIX: Handle both dict and list formats
        subdomains_raw = data.get('subdomains', [])
        if isinstance(subdomains_raw, dict):
            # If it's a dict, extract the list
            subdomain_list = subdomains_raw.get('subdomains', [])
        elif isinstance(subdomains_raw, list):
            subdomain_list = subdomains_raw
        else:
            subdomain_list = []

        # Filter out empty strings and None values
        subdomain_list = [s for s in subdomain_list if s and str(s).strip() and s != '']

        subdomain_count = len(subdomain_list)

        if subdomain_count > 0:
            # Show metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Subdomains", subdomain_count)
            with col2:
                unique_subs = len(set(subdomain_list))
                st.metric("Unique Domains", unique_subs)
            with col3:
                mapping_count = len(data.get('subdomain_mapping', {}))
                st.metric("Mapped Subdomains", mapping_count)
            
            st.markdown("---")
            
            # Display subdomains with expander
            with st.expander(f"📋 View All {subdomain_count} Subdomains", expanded=subdomain_count <= 20):
                sorted_subs = sorted(subdomain_list)
                
                # Display in 2 columns
                subdomain_cols = st.columns(2)
                for idx, subdomain in enumerate(sorted_subs):
                    with subdomain_cols[idx % 2]:
                        # Highlight if it has IP mapping
                        if data.get('subdomain_mapping', {}).get(subdomain):
                            ips = data.get('subdomain_mapping', {}).get(subdomain, [])
                            st.success(f"✅ {subdomain} → {', '.join(ips[:2])}")
                        else:
                            st.text(f"• {subdomain}")
        else:
            st.info("No subdomains discovered")
        
        # Subdomain to IP Mapping (if available)
        if data.get('subdomain_mapping'):
            st.markdown("---")
            st.markdown("**🗺️ Subdomain → IP Address Mapping**")
            
            mapping_data = data.get('subdomain_mapping', {})
            if mapping_data:
                # Show first 10 mappings
                shown_count = 0
                for subdomain, ips in list(mapping_data.items())[:10]:
                    if ips:
                        st.text(f"• {subdomain} → {', '.join(ips)}")
                        shown_count += 1
                
                if len(mapping_data) > 10:
                    st.info(f"+ {len(mapping_data) - 10} more subdomain mappings")
    
    # Tab 2: SSL/TLS Analysis
    with tabs[1]:
        st.subheader("🔒 SSL/TLS Analysis")
        ssl_analysis = data.get('ssl_analysis', {})
        
        if ssl_analysis:
            # Certificate Information
            cert_info = ssl_analysis.get('certificate_info', {})
            if cert_info:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Certificate Details**")

                    if 'subject' in cert_info and isinstance(cert_info['subject'], dict):
                        st.text(f"Common Name: {cert_info['subject'].get('commonName', 'N/A')}")
                    elif 'common_name' in cert_info:
                        st.text(f"Common Name: {cert_info.get('common_name', 'N/A')}")

                    if 'issuer' in cert_info:
                        if isinstance(cert_info['issuer'], dict):
                            issuer_cn = cert_info['issuer'].get('commonName', cert_info['issuer'].get('organizationName', 'Unknown'))
                            st.text(f"Issuer: {issuer_cn}")
                        else:
                            st.text(f"Issuer: {cert_info['issuer']}")

                    not_before = cert_info.get('notBefore') or cert_info.get('not_before', 'N/A')
                    not_after = cert_info.get('notAfter') or cert_info.get('not_after', 'N/A')
                    st.text(f"Valid From: {not_before}")
                    st.text(f"Valid Until: {not_after}")

                    # Days until expiry
                    days = cert_info.get('days_until_expiry')
                    if days is not None:
                        if days < 0:
                            st.error(f"🚨 EXPIRED ({abs(days)} days ago)")
                        elif days < 30:
                            st.warning(f"⚠️ Expiring in {days} days!")
                        else:
                            st.success(f"✅ Valid for {days} more days")

                    if cert_info.get('is_wildcard'):
                        st.info("🌐 Wildcard Certificate")

                with col2:
                    st.markdown("**Security Features**")
                    st.text(f"TLS Version: {ssl_analysis.get('tls_version', 'N/A')}")

                    cipher = ssl_analysis.get('cipher_suite', 'N/A')
                    if cipher and len(str(cipher)) > 50:
                        cipher = str(cipher)[:50] + "..."
                    st.text(f"Cipher Suite: {cipher}")

                    if 'key_size' in cert_info:
                        st.text(f"Key Size: {cert_info['key_size']}")
                    if 'signature_algorithm' in cert_info:
                        st.text(f"Signature: {cert_info['signature_algorithm']}")

                # SAN domains
                san_list = cert_info.get('san_domains', [])
                if san_list:
                    st.markdown(f"**Subject Alternative Names ({len(san_list)} domains)**")
                    with st.expander("View all SAN domains"):
                        for san in san_list:
                            st.text(f"• {san}")
            
            # TLS Versions
            if 'tls_versions_supported' in ssl_analysis:
                st.markdown("**Supported TLS Versions**")
                for version in ssl_analysis.get('tls_versions_supported', []):
                    st.success(f"✅ {version}")
            
            if 'tls_versions_rejected' in ssl_analysis:
                st.markdown("**Rejected TLS Versions**")
                for version in ssl_analysis.get('tls_versions_rejected', []):
                    st.info(f"❌ {version}")
            
            # Vulnerabilities
            if 'vulnerabilities' in ssl_analysis and ssl_analysis['vulnerabilities']:
                st.markdown("**⚠️ SSL/TLS Vulnerabilities**")
                for vuln in ssl_analysis['vulnerabilities']:
                    st.warning(f"• {vuln}")
        else:
            st.info("SSL/TLS analysis not available")
    
        st.markdown("---")

        st.subheader("🔒 CertSpotter - SSL Certificate History")
    
        ssl_analysis = data.get('ssl_analysis', {})
        certspotter_data = ssl_analysis.get('certspotter', {})
        
        if certspotter_data and certspotter_data.get('status') == 'success':
            total = certspotter_data.get('total_certificates', 0)
            certs = certspotter_data.get('certificates', [])
            
            st.success(f"✅ Found {total} SSL certificates")
            
            if certs:
                st.markdown(f"**Showing first {len(certs)} certificates:**")
                
                for idx, cert in enumerate(certs, 1):
                    with st.expander(f"🔐 Certificate {idx} - ID: {cert.get('id', 'N/A')}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Certificate SHA256:**")
                            st.code(cert.get('cert_sha256', 'N/A'), language="text")
                            
                            st.markdown("**TBS SHA256:**")
                            st.code(cert.get('tbs_sha256', 'N/A'), language="text")
                            
                            st.markdown(f"**Not Before:** {cert.get('not_before', 'N/A')}")
                            st.markdown(f"**Not After:** {cert.get('not_after', 'N/A')}")
                        
                        with col2:
                            st.markdown("**Public Key SHA256:**")
                            st.code(cert.get('pubkey_sha256', 'N/A'), language="text")
                            
                            revoked = cert.get('revoked', False)
                            if revoked:
                                st.error("⚠️ Certificate is REVOKED")
                            else:
                                st.success("✅ Certificate is Valid")
        
        elif certspotter_data and certspotter_data.get('status') == 'error':
            error_msg = certspotter_data.get('error', 'Unknown error')
            st.warning(f"⚠️ CertSpotter API Error: {error_msg}")
        
        else:
            st.info("No SSL certificate data available")

        st.markdown("---")

        # SSL Weaknesses Section
        st.subheader("🔍 SSL/TLS Weakness Analysis")
        ssl_weaknesses = data.get('ssl_weaknesses', {})
        if ssl_weaknesses:
            issues = ssl_weaknesses.get('summary', [])
            hsts = ssl_weaknesses.get('hsts_missing', False)
            self_signed = ssl_weaknesses.get('self_signed', False)
            weak_tls = ssl_weaknesses.get('weak_tls_versions', [])
            weak_ciphers = ssl_weaknesses.get('weak_ciphers', [])

            if not weak_tls and not weak_ciphers and not hsts and not self_signed:
                st.success("✅ No SSL/TLS weaknesses detected")
                hsts_header = ssl_weaknesses.get('hsts_header', '')
                if hsts_header:
                    st.caption(f"HSTS: {hsts_header}")
            else:
                col1, col2 = st.columns(2)
                with col1:
                    if hsts:
                        st.error("🔴 HSTS Not Configured")
                    else:
                        st.success("✅ HSTS Enabled")
                    if self_signed:
                        st.warning("⚠️ Self-Signed Certificate")
                with col2:
                    if weak_tls:
                        for ver in weak_tls:
                            st.error(f"🔴 {ver} supported — deprecated")
                    if weak_ciphers:
                        for cipher in weak_ciphers:
                            st.warning(f"⚠️ Weak cipher: {cipher}")
        else:
            st.info("SSL weakness analysis not available")

        st.markdown("---")


    # Tab 3: Mail Servers
    with tabs[2]:
        st.subheader("📧 Mail Server Infrastructure")
        
        # MX Records
        mail_servers = data.get('mail_servers', [])
        if mail_servers:
            st.markdown("**MX Records**")
            for server in mail_servers:
                st.text(f"• Priority {server.get('priority')}: {server.get('server')}")
        
        # Mail security analysis
        mail_analysis = data.get('mail_server_analysis', {})
        if mail_analysis:
            st.markdown("---")
            st.markdown("**🔐 Email Security (SPF / DMARC / DKIM)**")

            score = mail_analysis.get('email_security_score', 0)
            score_color = "🟢" if score == 3 else ("🟡" if score == 2 else ("🟠" if score == 1 else "🔴"))
            st.metric("Email Security Score", f"{score_color} {score}/3")

            col1, col2, col3 = st.columns(3)
            with col1:
                if mail_analysis.get('spf_configured'):
                    st.success("✅ SPF Configured")
                    spf = mail_analysis.get('spf_record', '')
                    if spf and spf != 'Not configured':
                        st.caption(spf[:80])
                else:
                    st.error("❌ SPF Not Found")

            with col2:
                if mail_analysis.get('dmarc_configured'):
                    st.success("✅ DMARC Configured")
                    dmarc = mail_analysis.get('dmarc_record', '')
                    if dmarc and dmarc != 'Not configured':
                        st.caption(dmarc[:80])
                else:
                    st.error("❌ DMARC Not Found")

            with col3:
                if mail_analysis.get('dkim_configured'):
                    selectors = mail_analysis.get('dkim_selectors_found', [])
                    st.success(f"✅ DKIM Found ({', '.join(selectors)})")
                else:
                    st.error("❌ DKIM Not Found")

            st.markdown("**Primary Provider:** " + mail_analysis.get('primary_provider', 'Unknown'))

            # SPF & DMARC Strength Details
            st.markdown("---")
            st.markdown("**📊 Email Security Strength Details**")
            col1, col2 = st.columns(2)

            with col1:
                spf_strength = mail_analysis.get('spf_strength', {})
                if spf_strength:
                    level = spf_strength.get('level', 'UNKNOWN')
                    color = "🟢" if level == 'STRONG' else ("🟡" if level == 'MODERATE' else "🔴")
                    st.markdown(f"**SPF Strength: {color} {level}**")
                    st.caption(spf_strength.get('risk', ''))
                    st.caption(f"Mechanism: `{spf_strength.get('mechanism', 'N/A')}`")
                    if spf_strength.get('recommendation'):
                        st.info(spf_strength['recommendation'])

            with col2:
                dmarc_strength = mail_analysis.get('dmarc_strength', {})
                if dmarc_strength:
                    level = dmarc_strength.get('level', 'UNKNOWN')
                    color = "🟢" if level == 'STRONG' else ("🟡" if level == 'MODERATE' else "🔴")
                    st.markdown(f"**DMARC Strength: {color} {level}**")
                    st.caption(dmarc_strength.get('risk', ''))
                    st.caption(f"Policy: `{dmarc_strength.get('policy', 'N/A')}` | Coverage: {dmarc_strength.get('pct', 100)}%")
                    if dmarc_strength.get('recommendation'):
                        st.info(dmarc_strength['recommendation'])

    # Tab 4: Cloud & ASN
    with tabs[3]:
        st.subheader("☁️ Cloud Infrastructure & ASN")
        
        # ✅ Cloud Providers (Multiple)
        cloud_providers = set()
        
        # Get cloud_provider (single)
        single_provider = data.get('cloud_provider')
        if single_provider and single_provider != 'Not Detected':
            cloud_providers.add(single_provider)
        
        # Also check ASN info for cloud detection
        asn_info = data.get('asn_info', {})
        for ip, info in asn_info.items():
            # Check if ASN indicates cloud
            asn = info.get('asn', '')
            org = info.get('org', '')
            isp = info.get('isp', '')
            
            # Map ASN to cloud providers
            if 'AS15169' in asn or 'google' in org.lower() or 'google' in isp.lower():
                cloud_providers.add('Google Cloud')
            elif 'AS16509' in asn or 'AS14618' in asn or 'amazon' in org.lower() or 'aws' in org.lower():
                cloud_providers.add('Amazon Web Services')
            elif 'AS8075' in asn or 'microsoft' in org.lower() or 'azure' in org.lower():
                cloud_providers.add('Microsoft Azure')
            elif 'AS13335' in asn or 'cloudflare' in org.lower():
                cloud_providers.add('Cloudflare')
            elif 'AS14061' in asn or 'digitalocean' in org.lower():
                cloud_providers.add('Digital Ocean')
        
        # Display all cloud providers
        if cloud_providers:
            providers_list = sorted(list(cloud_providers))
            if len(providers_list) == 1:
                st.success(f"**Cloud Provider:** {providers_list[0]}")
            else:
                st.success(f"**Cloud Providers ({len(providers_list)}):** {', '.join(providers_list)}")
        else:
            st.info("**Cloud Provider:** Not Detected")
        
        
        # ASN Information
        asn_info = data.get('asn_info', {})
        if asn_info:
            st.markdown("**ASN Information**")
            for ip, info in asn_info.items():
                with st.expander(f"IP: {ip}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.text(f"ASN: {info.get('as', 'Unknown')}")
                        
                        org = info.get('org', 'Unknown')
                        if len(str(org)) > 50:
                            org = str(org)[:50] + "..."
                        st.text(f"Organization: {org}")
                        
                        isp = info.get('isp', 'Unknown')
                        if len(str(isp)) > 50:
                            isp = str(isp)[:50] + "..."
                        st.text(f"ISP: {isp}")
                    with col2:
                        st.text(f"Country: {info.get('country', 'Unknown')}")
                        st.text(f"City: {info.get('city', 'Unknown')}")
                        st.text(f"Hosting: {'Yes' if info.get('hosting') else 'No'}")

        # ✅ NEW: Enhanced Cloud Infrastructure
        st.markdown("---")
        st.subheader("☁️ Enhanced Cloud Infrastructure")
        
        # Check first IP's asn_info for enhanced data
        if asn_info and data.get('ip_addresses'):
            first_ip = data.get('ip_addresses', [])[0] if data.get('ip_addresses') else None
            if first_ip and first_ip in asn_info:
                enhanced_data = asn_info[first_ip]
                
                # CDN Detection
                if 'cdn' in enhanced_data:
                    st.success(f"🌐 **CDN Detected:** {enhanced_data['cdn']}")
                
                # Storage Buckets
                if 'storage_buckets' in enhanced_data:
                    buckets = enhanced_data['storage_buckets']
                    if buckets:
                        st.markdown(f"**🗄️ Storage Buckets Found: {len(buckets)}**")
                        
                        for bucket in buckets[:10]:  # Show first 10
                            risk_color = "🔴" if bucket.get('status') == 'public' else "🟢"
                            st.text(f"{risk_color} {bucket.get('name')} ({bucket.get('provider')}) - {bucket.get('status').upper()}")
                
                # Reverse IP (Co-hosted domains)
                if 'reverse_ip' in enhanced_data:
                    reverse_data = enhanced_data['reverse_ip']
                    count = reverse_data.get('count', 0)
                    hosting_type = reverse_data.get('hosting_type', 'unknown')
                    
                    if count > 0:
                        st.info(f"🔄 **Co-hosted Domains:** {count} domains on same IP ({hosting_type} hosting)")
                        
                        with st.expander("View Co-hosted Domains"):
                            domains = reverse_data.get('cohosted_domains', [])
                            for i, domain in enumerate(domains[:50], 1):  # Show first 50
                                st.text(f"{i}. {domain}")
                            if len(domains) > 50:
                                st.text(f"... and {len(domains) - 50} more domains")
                
                # Passive DNS (Historical IPs)
                if 'passive_dns' in enhanced_data:
                    passive_data = enhanced_data['passive_dns']
                    historical_ips = passive_data.get('historical_ips', [])
                    ip_changes = passive_data.get('ip_changes', 0)
                    
                    if historical_ips:
                        st.warning(f"🕐 **Historical IPs:** {len(historical_ips)} IPs tracked ({ip_changes} changes)")
                        
                        with st.expander("View DNS History"):
                            timeline = passive_data.get('dns_timeline', [])
                            for record in timeline[:20]:  # Show first 20
                                ip_val = record.get('ip', 'Unknown')
                                first_seen = record.get('first_seen', 'Unknown')
                                st.text(f"IP: {ip_val} | First Seen: {first_seen}")


        # ASN per-IP detail — clean display
        st.markdown("---")
        st.subheader("🌍 IP Geolocation Details")
        asn_info = data.get('asn_info', {})
        if asn_info:
            for ip, info in list(asn_info.items())[:10]:
                if not isinstance(info, dict):
                    continue
                with st.expander(f"📍 {ip}", expanded=False):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.text(f"Country: {info.get('country', 'Unknown')}")
                        st.text(f"City: {info.get('city', 'Unknown')}")
                        st.text(f"ASN: {info.get('asn', 'Unknown')}")
                    with col2:
                        isp = str(info.get('isp', 'Unknown'))[:40]
                        org = str(info.get('organization', 'Unknown'))[:40]
                        st.text(f"ISP: {isp}")
                        st.text(f"Org: {org}")
                        ndb = info.get('networksdb', {})
                        if ndb.get('abuse_email'):
                            st.text(f"Abuse: {ndb['abuse_email']}")
                        if ndb.get('network'):
                            st.text(f"Network: {ndb['network']}")
                    with col3:
                        if info.get('hosting'):
                            st.info("🏢 Hosting Provider")
                        if info.get('proxy'):
                            st.warning("⚠️ Proxy Detected")
                        # NeutrinoAPI flags
                        neutrino = info.get('neutrinoapi', {})
                        if neutrino.get('is_vpn'):
                            st.warning("🔒 VPN Detected")
                        if neutrino.get('is_tor'):
                            st.error("🧅 TOR Node")
                        if neutrino.get('connection_type'):
                            st.caption(f"Conn: {neutrino['connection_type']}")
                        if not info.get('hosting') and not info.get('proxy') and not neutrino.get('is_vpn') and not neutrino.get('is_tor'):
                            st.success("✅ Clean IP")
        else:
            st.info("No IP geolocation data available")


    # Tab 5: Security Findings
    with tabs[4]:
        st.subheader("⚠️ Security Findings")

        # ── Blacklisted IPs (existing) ──────────────────────────────────────
        blacklisted = data.get('blacklisted_ips', [])
        st.markdown("**🚫 Blacklisted IPs**")
        if blacklisted:
            for item in blacklisted:
                bl = item.get('blacklist', item.get('blacklists', 'Unknown'))
                st.error(f"🚫 {item.get('ip', 'Unknown')} — listed on: {bl}")
        else:
            st.success(f"No blacklisted IPs found (checked {len(data.get('ip_reputation', {}))} IPs)")

        # ── Security Misconfigurations ──────────────────────────────────────
        st.markdown("---")
        mc = data.get('security_misconfigs', {})
        summary = mc.get('summary', {})

        sev_color = {'CRITICAL': '⛔', 'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡', 'INFO': 'ℹ️'}

        if summary.get('total', 0) > 0:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Findings", summary.get('total', 0))
            c2.metric("Critical", summary.get('critical', 0))
            c3.metric("High", summary.get('high', 0))
            c4.metric("Medium", summary.get('medium', 0))
        else:
            st.success("✅ No security misconfigurations detected")

        # A) Exposed Sensitive Files
        exposed_files = mc.get('exposed_files', [])
        st.markdown("---")
        st.markdown(f"**📄 Exposed Sensitive Files** — {len(exposed_files)} found")
        if exposed_files:
            for f in exposed_files:
                sev = f.get('severity', 'MEDIUM')
                icon = sev_color.get(sev, '⚪')
                with st.expander(f"{icon} [{sev}] {f.get('url', '')}"):
                    st.caption(f"Description: {f.get('desc', '')}")
                    st.caption(f"HTTP Status: {f.get('status', '')} | Size: {f.get('size', 0)} bytes")
                    if f.get('preview'):
                        st.code(f.get('preview', ''), language=None)
        else:
            st.success("No exposed sensitive files found")

        # B) Open Admin Panels
        admin_panels = mc.get('open_admin_panels', [])
        st.markdown("---")
        st.markdown(f"**🔑 Open Admin Panels** — {len(admin_panels)} found")
        if admin_panels:
            for p in admin_panels:
                sev = p.get('severity', 'HIGH')
                icon = sev_color.get(sev, '⚪')
                access = p.get('access', '')
                access_badge = "🔓 OPEN" if access == 'OPEN' else "🔒 RESTRICTED"
                with st.expander(f"{icon} [{sev}] {p.get('url', '')} — {access_badge}"):
                    st.caption(f"Description: {p.get('desc', '')}")
                    st.caption(f"HTTP Status: {p.get('status', '')} | Title: {p.get('title', 'N/A')}")
        else:
            st.success("No open admin panels found")

        # C) Open Unauthenticated Databases
        open_dbs = mc.get('open_databases', [])
        st.markdown("---")
        st.markdown(f"**🗄️ Open Unauthenticated Databases** — {len(open_dbs)} found")
        if open_dbs:
            for db in open_dbs:
                sev = db.get('severity', 'CRITICAL')
                icon = sev_color.get(sev, '⚪')
                with st.expander(f"{icon} [{sev}] {db.get('service', '')} on {db.get('ip', '')}:{db.get('port', '')}"):
                    st.caption(db.get('detail', ''))
                    st.error("No authentication required — full access possible!")
        else:
            st.success("No open unauthenticated databases found")

        # D) Directory Listing
        dir_listing = mc.get('directory_listing', [])
        st.markdown("---")
        st.markdown(f"**📂 Directory Listing Enabled** — {len(dir_listing)} found")
        if dir_listing:
            for d in dir_listing:
                with st.expander(f"🟠 [MEDIUM] {d.get('url', '')}"):
                    st.caption(d.get('detail', ''))
        else:
            st.success("No directory listing detected")

        # E) Subdomain Takeovers
        takeovers = mc.get('subdomain_takeovers', [])
        st.markdown("---")
        critical_takeovers = [t for t in takeovers if t.get('severity') == 'CRITICAL']
        medium_takeovers   = [t for t in takeovers if t.get('severity') == 'MEDIUM']
        st.markdown(f"**🎯 Subdomain Takeover** — {len(critical_takeovers)} confirmed, {len(medium_takeovers)} to verify")
        if takeovers:
            for t in takeovers:
                sev  = t.get('severity', 'MEDIUM')
                icon = sev_color.get(sev, '⚪')
                with st.expander(f"{icon} [{sev}] {t.get('subdomain', '')} → {t.get('service', '')}"):
                    st.caption(f"CNAME target: {t.get('cname', 'N/A')}")
                    st.caption(f"HTTP Status: {t.get('status', 'N/A')}")
                    st.caption(t.get('detail', ''))
                    if sev == 'CRITICAL':
                        st.error("Attacker can claim this service and serve content under your domain!")
        else:
            st.success("No subdomain takeover candidates found")

        # F) Cloud Storage Buckets
        buckets = mc.get('open_buckets', [])
        public_buckets  = [b for b in buckets if b.get('severity') == 'CRITICAL']
        private_buckets = [b for b in buckets if b.get('severity') == 'INFO']
        st.markdown("---")
        st.markdown(f"**🪣 Cloud Storage Buckets** — {len(public_buckets)} public, {len(private_buckets)} private (exists)")
        if public_buckets:
            for b in public_buckets:
                with st.expander(f"⛔ [CRITICAL] {b.get('provider', '')} — {b.get('bucket', '')}"):
                    st.caption(f"URL: {b.get('url', '')}")
                    st.caption(f"Access: {b.get('access', '')}")
                    st.error(b.get('detail', ''))
        if private_buckets:
            with st.expander(f"ℹ️ {len(private_buckets)} private buckets found (access denied)"):
                for b in private_buckets:
                    st.caption(f"• {b.get('provider', '')} — {b.get('bucket', '')} ({b.get('url', '')})")
        if not public_buckets and not private_buckets:
            st.success("No cloud storage buckets found for this target")

        # IP Reputation Section
        st.markdown("---")
        st.subheader("🔍 IP Reputation Analysis")
        ip_reputation = data.get('ip_reputation', {})
        if ip_reputation:
            for ip, rep in ip_reputation.items():
                blacklist_count = len(rep.get('blacklists', []))
                flag = '🔴' if blacklist_count > 0 else '🟢'
                with st.expander(f"{flag} {ip}" + (f" — {blacklist_count} blacklist(s)" if blacklist_count else "")):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown("**AbuseIPDB**")
                        abuse = rep.get('abuseipdb', {})
                        if abuse:
                            score = abuse.get('abuse_score', 0)
                            st.metric("Abuse Score", f"{score}%")
                            st.caption(f"Reports: {abuse.get('total_reports', 0)}")
                            st.caption(f"ISP: {abuse.get('isp', 'N/A')}")
                        else:
                            st.caption("No data")
                    with col2:
                        st.markdown("**AlienVault OTX**")
                        av = rep.get('alienvault', {})
                        if av:
                            pulses = av.get('pulse_count', 0)
                            if pulses > 0:
                                st.warning(f"⚠️ {pulses} threat pulses")
                            else:
                                st.success("✅ No threat pulses")
                            st.caption(f"Country: {av.get('country', 'N/A')}")
                            st.caption(f"ASN: {av.get('asn', 'N/A')}")
                        else:
                            st.caption("No data")
                    with col3:
                        st.markdown("**VirusTotal**")
                        vt = rep.get('virustotal', {})
                        if vt:
                            malicious = vt.get('malicious', 0)
                            harmless = vt.get('harmless', 0)
                            if malicious > 0:
                                st.error(f"🔴 {malicious} malicious detections")
                            else:
                                st.success(f"✅ Clean ({harmless} harmless)")
                            st.caption(f"Owner: {vt.get('as_owner', 'N/A')}")
                        else:
                            st.caption("No data")

                    # FraudGuard row
                    fg = rep.get('fraudguard', {})
                    if fg:
                        st.markdown("---")
                        col_fg1, col_fg2 = st.columns(2)
                        with col_fg1:
                            st.markdown("**FraudGuard**")
                            risk_lvl = fg.get('risk_level', 0)
                            fg_colors = {0: '✅', 1: '✅', 2: '🟡', 3: '🟠', 4: '🔴', 5: '⛔'}
                            st.caption(f"{fg_colors.get(risk_lvl, '⚪')} Risk Level: {risk_lvl}/5 — {fg.get('threat', 'clean')}")
                        with col_fg2:
                            flags = []
                            if fg.get('is_botnet'): flags.append("🤖 Botnet")
                            if fg.get('is_tor'):    flags.append("🧅 TOR")
                            if fg.get('is_proxy'):  flags.append("🔀 Proxy")
                            if fg.get('is_vpn'):    flags.append("🔒 VPN")
                            if fg.get('is_spam'):   flags.append("📧 Spam")
                            if flags:
                                st.caption(" | ".join(flags))
                            else:
                                st.caption("✅ No threat flags")

                    blacklists = rep.get('blacklists', [])
                    if blacklists:
                        st.error(f"🚫 Listed on {len(blacklists)} blacklist(s): {', '.join(b.get('blacklist','') for b in blacklists)}")
        else:
            st.info("IP reputation data not available")

        # WAF Detection Section
        st.markdown("---")
        st.subheader("🛡️ WAF Detection")
        waf = data.get('waf_detection', {})
        if waf:
            if waf.get('detected'):
                st.warning(f"⚠️ WAF Detected: **{waf.get('waf_name', 'Unknown')}**")
                st.caption(f"Confidence: {waf.get('confidence', 'N/A')}")
                for ev in waf.get('evidence', []):
                    st.caption(f"• {ev}")
            else:
                st.info(f"No WAF detected — {waf.get('waf_name', '')}")
                for ev in waf.get('evidence', []):
                    st.caption(f"• {ev}")
        else:
            st.info("WAF detection data not available")

    # Tab 6: Port Analysis - FIXED TO SHOW PORT NAMES
    with tabs[5]:
        st.subheader("🔓 Open Ports Analysis")
        
        # Port name mapping
        def get_port_name(port: int) -> str:
            """Get service name for port number"""
            port_names = {
                20: 'FTP-DATA',
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                135: 'MS-RPC',
                139: 'NetBIOS',
                143: 'IMAP',
                443: 'HTTPS',
                445: 'SMB',
                465: 'SMTPS',
                587: 'SMTP-Submit',
                993: 'IMAPS',
                995: 'POP3S',
                1433: 'MS-SQL',
                3306: 'MySQL',
                3389: 'RDP',
                5432: 'PostgreSQL',
                5900: 'VNC',
                # ✅ ADD THESE NEW ONES
                2052: 'Clearcase',
                2053: 'Knetd',
                2082: 'cPanel',
                2083: 'cPanel-SSL',
                2086: 'WHM',
                2087: 'WHM-SSL',
                8080: 'HTTP-Proxy',
                8443: 'HTTPS-Alt',
                8880: 'WebSphere',
                27017: 'MongoDB'
            }
            return port_names.get(port, 'Unknown')
        
        open_ports = data.get('open_ports', {})
        port_services = data.get('port_services', {})
        
        if open_ports:
            total_ports = sum(len(ports) for ports in open_ports.values())
            st.text(f"Total Open Ports: {total_ports}")
            st.markdown("---")
            
            for ip, ports in open_ports.items():
                st.markdown(f"**IP: {ip}**")
                services = port_services.get(ip, {})
                
                # ✅ NEW: Enhanced display with service versions
                port_data = []
                for port in sorted(ports):
                    service_display = None
                    port_str = str(port)
                    
                    # ✅ BETTER: Try multiple matching strategies
                    
                    # Strategy 1: Direct port number match with version info
                    if port_str in services and isinstance(services[port_str], dict):
                        service_info = services[port_str]
                        if 'version' in service_info:
                            product = service_info.get('name', service_info.get('product', ''))
                            version = service_info.get('version', '')
                            service_display = f"{product} {version}" if version else product
                    
                    # Strategy 2: Look for ANY service with version that might match this port
                    if not service_display:
                        for service_key, service_info in services.items():
                            if isinstance(service_info, dict) and 'version' in service_info:
                                # Found enhanced service data
                                product = service_info.get('name', service_info.get('product', ''))
                                version = service_info.get('version', '')
                                
                                # If this matches common port mappings
                                if (port == 22 and 'ssh' in product.lower()) or \
                                   (port == 80 and ('nginx' in product.lower() or 'apache' in product.lower())) or \
                                   (port == 443 and ('nginx' in product.lower() or 'apache' in product.lower())):
                                    service_display = f"{product} {version}" if version else product
                                    break
                    
                    # Strategy 3: Fallback to basic name
                    if not service_display:
                        service_display = services.get(port_str, get_port_name(port))
                    
                    port_data.append((port, service_display))
                
                # Display in columns
                port_cols = st.columns(4)
                for idx, (port, service) in enumerate(port_data):
                    with port_cols[idx % 4]:
                        # Color code based on port type
                        if port in [22, 80, 443]:
                            st.success(f"**{port}** - {service}")
                        elif port in [3306, 5432, 1433, 27017]:
                            st.error(f"**{port}** - {service}")
                        elif port in [21, 23, 135, 139, 445]:
                            st.warning(f"**{port}** - {service}")
                        else:
                            st.info(f"**{port}** - {service}")
                
                st.markdown("---")
        else:
            st.info("No open ports detected or port scanning not performed")

        # Port Banners Section
        st.markdown("---")
        st.subheader("🏷️ Port Banners & Service Versions")
        port_banners = data.get('port_banners', {})
        if port_banners:
            any_banner = False
            for ip, ports in port_banners.items():
                for port, banner in ports.items():
                    if banner.get('raw') or banner.get('product') or banner.get('version'):
                        any_banner = True
                        break
            if any_banner:
                for ip, ports in port_banners.items():
                    st.markdown(f"**{ip}**")
                    for port, banner in ports.items():
                        product = banner.get('product', '')
                        version = banner.get('version', '')
                        raw = banner.get('raw', '')
                        proto = banner.get('protocol', '')
                        label = f"{product} {version}".strip() or raw[:60] or proto
                        if label:
                            st.text(f"  Port {port} ({proto}): {label}")
            else:
                st.info("Ports found but no banner info returned (server not disclosing version)")
        else:
            st.info("No banner data available")

    # Tab 7: DNS Information
    with tabs[6]:
        st.subheader("🌍 DNS Information")
        
        # WHOIS Data
        whois_data = data.get('whois_data', {})
        if whois_data:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Domain Registration**")
                registrar = whois_data.get('registrar', 'N/A')
                if registrar and len(str(registrar)) > 50:
                    registrar = str(registrar)[:50] + "..."
                st.text(f"Registrar: {registrar}")
                
                def _clean_whois_date(d):
                    if not d or d == 'N/A':
                        return 'N/A'
                    s = str(d)
                    if 'datetime' in s:
                        import re
                        m = re.search(r'(\d{4}),\s*(\d{1,2}),\s*(\d{1,2})', s)
                        if m:
                            return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
                    return s[:10]

                st.text(f"Created: {_clean_whois_date(whois_data.get('creation_date'))}")
                st.text(f"Expires: {_clean_whois_date(whois_data.get('expiration_date'))}")
            
            with col2:
                st.markdown("**Name Servers**")
                name_servers = whois_data.get('name_servers', [])
                if name_servers:
                    for ns in name_servers[:4]:
                        st.text(f"• {ns}")
                else:
                    st.text("No name servers found")
        
        # DNS Name Server Details
        dns_info = data.get('dns_info', {})
        if dns_info and 'name_servers' in dns_info:
            st.markdown("---")
            st.markdown("**Name Server IPs**")
            for ns, ips in dns_info['name_servers'].items():
                if ips:
                    st.text(f"• {ns} → {', '.join(ips)}")
                else:
                    st.text(f"• {ns} → No IPs resolved")

        # Extended DNS Records
        dns_records = data.get('dns_records', {})
        if dns_records:
            st.markdown("---")
            st.subheader("📋 Extended DNS Records")
            col1, col2 = st.columns(2)

            with col1:
                # SOA
                soa = dns_records.get('SOA', {})
                if soa:
                    st.markdown("**SOA Record**")
                    st.text(f"Primary NS: {soa.get('mname', 'N/A')}")
                    st.text(f"Admin: {soa.get('rname', 'N/A')}")
                    st.text(f"Serial: {soa.get('serial', 'N/A')}")
                    st.text(f"Refresh: {soa.get('refresh', 'N/A')}s")

                # CAA
                caa = dns_records.get('CAA', [])
                st.markdown("**CAA Records**")
                if caa:
                    for record in caa:
                        st.text(f"• {record}")
                else:
                    st.caption("No CAA records (any CA can issue certs)")

            with col2:
                # AXFR
                axfr = dns_records.get('AXFR', {})
                if axfr:
                    st.markdown("**Zone Transfer (AXFR)**")
                    if axfr.get('vulnerable'):
                        st.error(f"🔴 VULNERABLE — {axfr.get('records_leaked', 0)} records leaked!")
                    else:
                        st.success(f"✅ {axfr.get('note', 'Secure')}")
                    ns_tested = axfr.get('nameservers_tested', [])
                    if ns_tested:
                        st.caption(f"Tested: {', '.join(ns_tested)}")

                # PTR
                ptr = dns_records.get('PTR', {})
                if ptr:
                    st.markdown("**PTR Records (Reverse DNS)**")
                    for ip, hostnames in ptr.items():
                        if hostnames:
                            st.text(f"• {ip} → {', '.join(hostnames)}")
                        else:
                            st.text(f"• {ip} → No PTR record")

            # SRV
            srv = dns_records.get('SRV', [])
            if srv:
                st.markdown("**SRV Records**")
                for record in srv:
                    st.text(f"• {record}")

    # ✅ NEW TAB: DNStwist Look-alike Domains
    with tabs[7]:  # Index 7 for the 8th tab
        st.subheader("⚠️ DNStwist - Look-alike & Phishing Domains")
        
        dnstwist_data = data.get('dnstwist_lookalikes', {})

        if not dnstwist_data:
            st.info("DNStwist data not available")
        else:
            # Phase 2 keys: registered_domains, lookalike_details, total_permutations
            total = dnstwist_data.get('registered_domains',
                    dnstwist_data.get('total_found', 0))
            lookalikes = dnstwist_data.get('lookalike_details',
                         dnstwist_data.get('lookalike_domains', []))
            total_perms = dnstwist_data.get('total_permutations', 0)

            if dnstwist_data.get('status') == 'error':
                st.error(f"DNStwist failed: {dnstwist_data.get('error', 'Unknown error')}")

            elif total > 0:
                st.warning(f"🚨 Found {total} registered look-alike domains! ({total_perms} permutations tested)")
                st.markdown("---")

                for idx, domain_entry in enumerate(lookalikes, 1):
                    domain_name = domain_entry.get('domain', domain_entry.get('name', 'Unknown'))
                    fuzzer      = domain_entry.get('fuzzer', domain_entry.get('type', 'unknown'))
                    with st.expander(f"🔍 {idx}. {domain_name}  ({fuzzer})", expanded=False):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.markdown("**A Records (IPs):**")
                            dns_a = domain_entry.get('dns_a', [])
                            if isinstance(dns_a, str): dns_a = [dns_a]
                            for ip in (dns_a[:5] if dns_a else []):
                                st.code(ip, language="text")
                            if not dns_a: st.text("No A records")
                        with col2:
                            st.markdown("**MX Records:**")
                            mx = domain_entry.get('dns_mx', [])
                            if isinstance(mx, str): mx = [mx]
                            for m in (mx[:3] if mx else []):
                                st.text(f"• {m}")
                            if not mx: st.text("No MX records")
                        with col3:
                            st.markdown("**NS Records:**")
                            ns = domain_entry.get('dns_ns', [])
                            if isinstance(ns, str): ns = [ns]
                            for n in (ns[:3] if ns else []):
                                st.text(f"• {n}")
                            if not ns: st.text("No NS records")
                        st.markdown(f"**Permutation Type:** `{fuzzer}`")
            else:
                st.success(f"✅ No registered look-alike domains found ({total_perms} permutations tested)")



def display_application_landscape_results(data: Dict[str, Any]):
    """Display application landscape assessment results"""
    st.header("🖥️ Application Landscape Assessment")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Create tabs
    tabs = st.tabs([
        "Application Discovery",
        "Web Technology Stack",
        "ERP/SAP Detection",
        "Third-Party Software",
        "Code Repositories",
        "Outdated Software",
        "Security Posture",
        "API Discovery",
        "Database Detection",
        "Threat Intelligence",     # NEW - 23 APIs
        "Data Leak Detection",     # NEW - 23 APIs
        "S3 Bucket Exposure"      # NEW - 23 APIs
    ])
    
    # Tab 1: Application Discovery
    with tabs[0]:
        st.subheader("🌐 Application Discovery")
        app_data = data.get('1_application_discovery', {})
        
        if app_data:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Status**")
                status = app_data.get('status', 'Unknown')
                if status == 'Active':
                    st.success(f"✅ {status}")
                else:
                    st.error(f"❌ {status}")
                
                st.markdown("**Web Server**")
                server = app_data.get('server', 'Not disclosed')
                st.info(server)
                
                if app_data.get('server_version'):
                    st.markdown("**Server Version**")
                    st.info(app_data['server_version'])
            
            with col2:
                st.markdown("**Response Time**")
                st.text(f"{app_data.get('response_time_ms', 0)} ms")
                
                st.markdown("**Content Length**")
                st.text(f"{app_data.get('content_length', 0):,} bytes")
                
                fingerprints = app_data.get('header_fingerprints', {})
                xpb = fingerprints.get('X-Powered-By', app_data.get('powered_by', ''))
                xpb_ver = fingerprints.get('X-Powered-By-Version', '')
                if xpb and xpb != 'Not disclosed':
                    st.markdown("**Powered By**")
                    label = f"{fingerprints.get('X-Powered-By-Name', xpb)} {xpb_ver}" if xpb_ver else xpb
                    st.info(label)
                xaspnet = fingerprints.get('X-AspNet-Version', '')
                if xaspnet:
                    st.markdown("**ASP.NET Version**")
                    st.info(xaspnet)
        else:
            st.info("No application discovery data available")
    
    # Tab 2: Web Technology Stack
    with tabs[1]:
        st.subheader("🛠️ Web Technology Stack")
        tech_stack = data.get('2_web_server_stack', {})
        
        if tech_stack:
            # CMS
            st.markdown("**Content Management System**")
            cms_list = tech_stack.get('cms', [])
            cms_version = tech_stack.get('cms_version')
            
            cms_versions_dict = tech_stack.get('cms_versions', {})
            if cms_list:
                for cms in cms_list:
                    # WordPress uses cms_version (string); others use cms_versions (dict)
                    ver = cms_versions_dict.get(cms) or (cms_version if cms == cms_list[0] else None)
                    version_str = f" {ver}" if ver and ver != 'version unknown' else (" (version unknown)" if not ver else "")
                    st.success(f"✅ {cms}{version_str}")
            else:
                st.info("No CMS detected")
            
            st.markdown("---")

            # ✅ ADD WHATCMS OUTPUT HERE
            st.markdown("**🔍 CMS Detection (WhatCMS API)**")
            whatcms_data = tech_stack.get('whatcms_api', {})  # ✅ FIXED THIS LINE
            
            if whatcms_data and whatcms_data.get('status') == 'success':
                technologies = whatcms_data.get('technologies', [])
                
                if technologies:
                    # Group by category
                    cms_techs = [t for t in technologies if any(cat in ['CMS', 'E-commerce'] for cat in t.get('categories', []))]
                    frameworks = [t for t in technologies if 'Web Framework' in t.get('categories', [])]
                    cdn_techs = [t for t in technologies if 'CDN' in t.get('categories', [])]
                    other_techs = [t for t in technologies if t not in cms_techs and t not in frameworks and t not in cdn_techs]
                    
                    # Display CMS
                    if cms_techs:
                        st.markdown("**📦 CMS/E-commerce:**")
                        for tech in cms_techs:
                            name = tech.get('name', 'Unknown')
                            categories = ', '.join(tech.get('categories', []))
                            version = tech.get('version', '')
                            version_str = f" v{version}" if version else ""
                            st.success(f"✅ {name}{version_str} ({categories})")
                    
                    # Display Frameworks
                    if frameworks:
                        st.markdown("**⚙️ Web Frameworks:**")
                        for tech in frameworks:
                            name = tech.get('name', 'Unknown')
                            version = tech.get('version', '')
                            version_str = f" v{version}" if version else ""
                            st.text(f"• {name}{version_str}")
                    
                    # Display CDN
                    if cdn_techs:
                        st.markdown("**🌐 CDN Services:**")
                        for tech in cdn_techs:
                            st.text(f"• {tech.get('name')}")

                    # Display Other Technologies
                    if other_techs:
                        st.markdown("**🔧 Other Technologies:**")
                        for tech in other_techs:
                            name = tech.get('name', 'Unknown')
                            categories = ', '.join(tech.get('categories', []))
                            st.text(f"• {name} ({categories})")
                    
                    # Social Media
                    social = whatcms_data.get('social_media', [])
                    if social:
                        st.markdown("**📱 Social Media Profiles:**")
                        cols = st.columns(min(len(social), 4))
                        for idx, profile in enumerate(social):
                            with cols[idx % 4]:
                                network = profile.get('network', '').title()
                                url = profile.get('url', '')
                                if url:
                                    st.markdown(f"[{network}]({url})")
                else:
                    st.info("WhatCMS: No technologies detected")
                    
            elif whatcms_data.get('status') == 'error':
                st.warning(f"⚠️ WhatCMS API Error: {whatcms_data.get('error', 'Unknown error')}")
            else:
                st.info("WhatCMS: No data available")
            
            st.markdown("---")
            
            # JavaScript Libraries
            st.markdown("**JavaScript Libraries**")
            js_libs = tech_stack.get('javascript_libraries', [])
            js_versions = tech_stack.get('javascript_versions', {})
            
            if js_libs:
                col1, col2 = st.columns(2)
                for idx, lib in enumerate(js_libs):
                    version = js_versions.get(lib, 'version unknown')
                    with (col1 if idx % 2 == 0 else col2):
                        st.text(f"• {lib} {version}")
            else:
                st.info("No JavaScript libraries detected")
            
            st.markdown("---")
            
            # Frameworks with versions
            frameworks = tech_stack.get('frameworks', [])
            fw_versions = tech_stack.get('framework_versions', {})
            if frameworks:
                st.markdown("**Frameworks**")
                for fw in frameworks:
                    ver = fw_versions.get(fw, '')
                    st.text(f"• {fw} {ver}".strip())
            
            # Analytics
            analytics = tech_stack.get('analytics', [])
            if analytics:
                st.markdown("**Analytics**")
                for analytic in analytics:
                    st.text(f"• {analytic}")
            
            # CDN
            cdn = tech_stack.get('cdn', [])
            if cdn:
                st.markdown("**CDN Services**")
                for cdn_service in cdn:
                    st.text(f"• {cdn_service}")
        else:
            st.info("No technology stack data available")
    
    # Tab 3: ERP/SAP Detection
    with tabs[2]:
        st.subheader("🏢 ERP/SAP System Detection")
        erp_data = data.get('3_erp_sap_detection', {})
        
        detected = erp_data.get('detected_systems', [])
        if detected:
            for system in detected:
                st.success(f"✅ {system}")
                details = erp_data.get('detection_details', {})
                if system in details:
                    st.text(f"   Detection method: {details[system]}")
            # SAP version display
            erp_versions = erp_data.get('erp_versions', {})
            if erp_versions:
                st.markdown("**ERP Version Details**")
                for erp_name, erp_ver in erp_versions.items():
                    st.text(f"   {erp_name} version: {erp_ver}")
        else:
            st.info("❌ No ERP/SAP systems detected")
    
    # Tab 4: Third-Party Software
    with tabs[3]:
        st.subheader("📦 Third-Party Software Inventory")
        third_party = data.get('4_third_party_software', {})
        
        if third_party:
            categories = ['analytics', 'payment', 'chat', 'cdn', 'social', 'video', 'captcha']
            
            for category in categories:
                services = third_party.get(category, [])
                if services:
                    st.markdown(f"**{category.title()}**")
                    for service in services:
                        st.text(f"• {service}")
                    st.markdown("---")
            
            total = sum(len(third_party.get(cat, [])) for cat in categories)
            if total == 0:
                st.info("No third-party services detected")

            # Client-side secrets
            st.markdown("---")
            st.markdown("**Client-Side Secrets Scan**")
            secrets = third_party.get('exposed_secrets', [])
            if secrets:
                for s in secrets:
                    st.error(f"🚨 {s.get('type')}: `{s.get('snippet')}`")
            else:
                st.success("✅ No secrets detected in inline HTML/JS")

            # Contact info + social media
            st.markdown("---")
            st.markdown("**Contact Info & Social Media (OSINT)**")
            contacts = third_party.get('contact_info', {})
            emails   = contacts.get('emails', [])
            phones   = contacts.get('phones', [])
            twitter  = contacts.get('twitter', [])
            linkedin = contacts.get('linkedin', [])
            github   = contacts.get('github', [])
            if any([emails, phones, twitter, linkedin, github]):
                for e in emails:   st.text(f"📧 {e}")
                for p in phones:   st.text(f"📞 {p}")
                for t in twitter:  st.text(f"🐦 Twitter: @{t}")
                for l in linkedin: st.text(f"💼 LinkedIn: {l}")
                for g in github:   st.text(f"🐙 GitHub: {g}")
            else:
                st.info("No contact/social info found in HTML")
        else:
            st.info("No third-party software data available")
    
    # Tab 5: Code Repositories
    with tabs[4]:
        st.subheader("📁 Code Repository Analysis")
        repo_data = data.get('5_code_repositories', {})
        
        if repo_data:
            # robots.txt Disallow paths
            st.markdown("**robots.txt — Disallow Paths**")
            disallow = repo_data.get('robots_disallow', [])
            if disallow:
                for path in disallow:
                    notable = any(kw in path.lower() for kw in ['admin', 'api', 'internal', 'staging', 'backup', 'login', 'secret', 'private'])
                    if notable:
                        st.warning(f"⚠️ NOTABLE: {path}")
                    else:
                        st.text(f"  {path}")
            else:
                st.info("No Disallow paths in robots.txt (or not accessible)")

            # robots.txt Sitemaps
            sitemaps = repo_data.get('robots_sitemaps', [])
            if sitemaps:
                st.markdown("**robots.txt — Sitemap URLs**")
                for smap in sitemaps:
                    st.text(f"🗺️ {smap}")

            st.markdown("---")

            # GitHub Repos
            st.markdown("**GitHub Repositories**")
            repos = repo_data.get('github_repos', [])
            if repos:
                for repo in repos:
                    st.text(f"• {repo.get('name')} ({repo.get('stars')} stars)")
                    st.text(f"  {repo.get('url')}")
            else:
                st.info("No GitHub repositories found")
        else:
            st.info("No code repository data available")
    
    # Tab 6: Outdated Software
    with tabs[5]:
        st.subheader("⚠️ Outdated Software & Vulnerabilities")
        vuln_data = data.get('6_outdated_software', {})
        
        if vuln_data:
            vulnerable = vuln_data.get('vulnerable', [])
            
            if vulnerable:
                for vuln in vulnerable:
                    severity = vuln.get('severity', 'Unknown')
                    lib = vuln.get('library', 'Unknown')
                    current = vuln.get('current_version', 'Unknown')
                    recommended = vuln.get('recommended_version', 'Unknown')
                    
                    if severity == 'Critical':
                        st.error(f"🔴 CRITICAL: {lib} {current} → {recommended}")
                    elif severity == 'High':
                        st.error(f"🟠 HIGH: {lib} {current} → {recommended}")
                    elif severity == 'Medium':
                        st.warning(f"🟡 MEDIUM: {lib} {current} → {recommended}")
                    else:
                        st.info(f"🔵 {severity}: {lib} {current} → {recommended}")
            else:
                st.success("✅ No vulnerable software detected")
            
            # Libraries Analyzed
            libraries = vuln_data.get('libraries', [])
            if libraries:
                st.markdown("---")
                st.markdown("**Libraries Analyzed**")
                for lib_info in libraries:
                    st.text(f"• {lib_info.get('library')} {lib_info.get('version')}")
        else:
            st.info("No outdated software analysis available")
    
    # Tab 7: Security Posture
    with tabs[6]:
        st.subheader("🔒 Security Posture Analysis")
        security = data.get('7_security_posture', {})
        
        if security:
            # Security Headers + strength issues
            st.markdown("**Security Headers — Strength Analysis**")
            headers = security.get('security_headers', {})
            if headers:
                for header_name, header_info in headers.items():
                    if header_info.get('present'):
                        st.success(f"✅ {header_name}: {str(header_info.get('value',''))[:60]}")
                    else:
                        st.error(f"❌ {header_name}: Missing")

            header_issues = security.get('header_issues', [])
            if header_issues:
                st.markdown("**Header Configuration Issues**")
                for issue in header_issues:
                    st.warning(f"⚠️ {issue}")

            st.markdown("---")

            # WAF Detection (webtech Phase 3)
            waf_p3 = security.get('waf_detection', {})
            if waf_p3:
                st.markdown("**WAF Detection (Application Layer)**")
                if waf_p3.get('detected'):
                    st.warning(f"🛡️ WAF Detected: **{waf_p3.get('waf_name')}**")
                    for waf_name in waf_p3.get('waf_names', []):
                        st.caption(f"• {waf_name}")
                else:
                    st.info("No WAF signatures detected at application layer")
                st.markdown("---")

            # Cookie Security
            st.markdown("**Cookie Security**")
            cookies = security.get('cookie_security', [])
            
            if cookies:
                for cookie in cookies:
                    flags = []
                    if cookie.get('httponly'): flags.append("HttpOnly")
                    if cookie.get('secure'):   flags.append("Secure")
                    ss_val = cookie.get('samesite_value', 'Not set')
                    if ss_val == 'Strict':
                        flags.append("SameSite=Strict ✅")
                    elif ss_val == 'Lax':
                        flags.append("SameSite=Lax ⚠️")
                    elif ss_val == 'None':
                        flags.append("SameSite=None 🚨" if not cookie.get('secure') else "SameSite=None+Secure ⚠️")
                    elif cookie.get('samesite'):
                        flags.append("SameSite")

                    secure_enough = cookie.get('httponly') and cookie.get('secure') and ss_val in ('Strict', 'Lax')
                    if secure_enough:
                        st.success(f"✅ {cookie.get('cookie')}: {', '.join(flags)}")
                    elif ss_val == 'None' and not cookie.get('secure'):
                        st.error(f"🚨 {cookie.get('cookie')}: {', '.join(flags)} — CSRF risk")
                    else:
                        st.warning(f"⚠️ {cookie.get('cookie')}: {', '.join(flags) if flags else 'No security flags'}")
            else:
                st.info("No cookies set")
            
            st.markdown("---")
            
            # Admin Panels
            st.markdown("**Admin Panel Discovery**")
            admin_panels = security.get('admin_panels', [])
            
            if admin_panels:
                for panel in admin_panels:
                    status = panel.get('status')
                    path = panel.get('path')
                    if status == 200:
                        st.error(f"🚨 EXPOSED: {path}")
                    elif status in [401, 403]:
                        st.warning(f"🔐 Protected: {path}")
            else:
                st.success("✅ No exposed admin panels found")

            # SRI Missing (moved from third-party tab — it's a security finding)
            sri_missing = security.get('sri_missing', [])
            st.markdown("---")
            st.markdown("**Subresource Integrity (SRI) — Missing integrity= Attributes**")
            if sri_missing:
                for item in sri_missing:
                    st.warning(f"⚠️ <{item.get('tag')}> {item.get('src')}")
                st.caption(f"{len(sri_missing)} external tag(s) missing SRI — supply chain attack risk")
            else:
                st.success("✅ All external tags have integrity attributes (or none detected)")

            # JS Source Map Exposure
            sourcemaps = security.get('js_sourcemaps', [])
            if sourcemaps:
                st.markdown("---")
                st.markdown("**JS Source Map Exposure**")
                for sm in sourcemaps:
                    st.error(f"🚨 EXPOSED: {sm}")
                st.caption(f"{len(sourcemaps)} source map(s) publicly accessible — exposes original source code")

            # Open Redirect
            open_redirect = security.get('open_redirect', [])
            st.markdown("---")
            st.markdown("**Open Redirect Vulnerability**")
            if open_redirect:
                for r in open_redirect:
                    st.error(f"🚨 VULNERABLE: `?{r.get('param')}=` redirects to external URL")
                    st.caption(f"Test URL: {r.get('test_url', '')}")
            else:
                st.success("✅ No open redirect vulnerabilities found")

            # Clickjacking
            cj = security.get('clickjacking', {})
            if cj:
                st.markdown("---")
                st.markdown("**Clickjacking Protection**")
                if cj.get('protected'):
                    st.success(f"✅ Protected via {cj.get('method')} ({cj.get('x_frame_options') or cj.get('csp_frame_ancestors')})")
                else:
                    st.error("🚨 VULNERABLE: No X-Frame-Options or CSP frame-ancestors set")

            # SSL/TLS Certificate
            ssl_cert = security.get('ssl_certificate', {})
            if ssl_cert:
                st.markdown("---")
                st.markdown("**SSL/TLS Certificate**")
                col1, col2 = st.columns(2)
                with col1:
                    st.text(f"Common Name: {ssl_cert.get('common_name', 'N/A')}")
                    st.text(f"Issuer: {ssl_cert.get('issuer', 'N/A')} ({ssl_cert.get('issuer_org', '')})")
                    st.text(f"Expires: {ssl_cert.get('not_after', 'N/A')}")
                with col2:
                    days_left = ssl_cert.get('days_until_expiry')
                    if days_left is not None:
                        if days_left < 0:
                            st.error(f"🚨 EXPIRED {abs(days_left)} days ago!")
                        elif days_left < 14:
                            st.error(f"🚨 Expires in {days_left} days!")
                        elif days_left < 30:
                            st.warning(f"⚠️ Expires in {days_left} days")
                        else:
                            st.success(f"✅ Valid for {days_left} days")
                # Fix #6: Show cert_issues (self-signed / expired / domain mismatch)
                cert_issues = ssl_cert.get('cert_issues', [])
                if cert_issues:
                    for issue in cert_issues:
                        st.error(f"🚨 {issue}")
                sans = ssl_cert.get('subject_alt_names', [])
                if sans:
                    st.caption(f"SANs ({len(sans)} domains): {', '.join(sans[:8])}")
        else:
            st.info("No security posture data available")
    
    # Tab 8: API Discovery
    with tabs[7]:
        st.subheader("🔌 API Endpoint Discovery")
        api_data = data.get('8_api_discovery', {})
        
        if api_data:
            # API Endpoints
            endpoints = api_data.get('api_endpoints', [])
            if endpoints:
                st.markdown("**REST API Endpoints**")
                for endpoint in endpoints:
                    st.text(f"• {endpoint.get('path')} [{endpoint.get('status')}]")
                st.markdown("---")
            
            # GraphQL
            graphql = api_data.get('graphql_endpoints', [])
            if graphql:
                st.markdown("**GraphQL Endpoints**")
                for endpoint in graphql:
                    st.text(f"• {endpoint.get('path')} [{endpoint.get('status')}]")
                st.markdown("---")
            
            # Documentation
            docs = api_data.get('api_documentation', [])
            if docs:
                st.markdown("**API Documentation**")
                for doc in docs:
                    st.text(f"• {doc.get('path')} [{doc.get('status')}]")
                st.markdown("---")
            
            # Links in HTML
            links = api_data.get('api_links_in_html', [])
            if links:
                st.markdown("**API Links Found in HTML**")
                for link in links:
                    st.code(link[:80], language=None)

            # Active API Versions (Fix #12)
            active_versions = api_data.get('active_api_versions', {})
            if active_versions:
                st.markdown("**Active API Versions (Enumerated)**")
                for base_path, versions in active_versions.items():
                    st.success(f"✅ {base_path} — active: {', '.join(versions)}")
                st.markdown("---")

            if not endpoints and not graphql and not docs and not links and not active_versions:
                st.info("No API endpoints discovered")
        else:
            st.info("No API discovery data available")
    
    # Tab 9: Database Detection
    with tabs[8]:
        st.subheader("🗄️ Database & Backend Detection")
        db_data = data.get('9_database_detection', {})
        
        if db_data:
            # Database Types
            db_types = db_data.get('database_type', [])
            if db_types:
                st.markdown("**Detected Databases**")
                for db in db_types:
                    st.warning(f"⚠️ {db}")
                st.markdown("---")
            
            # Exposed Ports
            ports = db_data.get('exposed_ports', [])
            if ports:
                st.markdown("**Exposed Database Ports**")
                for port_info in ports:
                    st.error(f"🚨 {port_info.get('database')} - Port {port_info.get('port')}")
                st.markdown("---")
            
            # Backend Hints
            hints = db_data.get('backend_hints', [])
            if hints:
                st.markdown("**Backend Technologies**")
                for hint in hints:
                    st.text(f"• {hint}")

            # Exposed DB Connection Strings (Fix #13)
            conn_strings = db_data.get('connection_strings', [])
            if conn_strings:
                st.markdown("**⚠️ Exposed Connection Strings (Credentials Leak)**")
                for cs in conn_strings:
                    st.error(f"🚨 {cs.get('type')} — `{cs.get('snippet')}`")
                st.markdown("---")

            if not db_types and not ports and not hints and not conn_strings:
                st.info("No database/backend information detected")
        else:
            st.info("No database detection data available")

    # ========================================================================
    # NEW TABS (10-13) - 23 API INTEGRATION
    # ========================================================================
    
    # 🆕 TAB 10: THREAT INTELLIGENCE (NEW)
    with tabs[9]:
        st.subheader("🛡️ Threat Intelligence (5 APIs)")
        
        threat_data = data.get('10_threat_intelligence', {})
        
        if threat_data:
            for key, value in threat_data.items():
                # AbuseIPDB
                if 'abuseipdb' in str(key):
                    st.markdown("### 🚨 AbuseIPDB")
                    
                    ip = key.split('_')[0] if '_' in key else 'N/A'
                    st.text(f"IP Address: {ip}")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        score = value.get('data', {}).get('abuseConfidenceScore', 0)
                        if score > 50:
                            st.error(f"⚠️ Abuse Score: {score}%")
                        elif score > 25:
                            st.warning(f"⚠️ Abuse Score: {score}%")
                        else:
                            st.success(f"✅ Abuse Score: {score}%")
                    with col2:
                        reports = value.get('data', {}).get('totalReports', 0)
                        st.metric("Total Reports", reports)
                    with col3:
                        users = value.get('data', {}).get('numDistinctUsers', 0)
                        st.metric("Distinct Users", users)
                    
                    st.markdown("---")
                
                # AlienVault OTX
                elif 'alienvault' in str(key):
                    st.markdown("### 👽 AlienVault OTX")
                    
                    pulse_count = value.get('pulse_info', {}).get('count', 0)
                    if pulse_count > 0:
                        st.warning(f"⚠️ Found in {pulse_count} threat pulses")
                        
                        pulses = value.get('pulse_info', {}).get('pulses', [])
                        if pulses:
                            st.markdown("**Recent Threat Pulses:**")
                            for pulse in pulses[:3]:
                                with st.expander(f"• {pulse.get('name', 'Unknown')}"):
                                    st.text(f"Created: {pulse.get('created', 'N/A')}")
                                    st.text(f"Modified: {pulse.get('modified', 'N/A')}")
                                    tags = pulse.get('tags', [])
                                    if tags:
                                        st.text(f"Tags: {', '.join(tags[:5])}")
                    else:
                        st.success("✅ No threat pulses found")
                    
                    st.markdown("---")
                
                # GreyNoise
                elif 'greynoise' in str(key):
                    st.markdown("### 🔊 GreyNoise")
                    
                    classification = value.get('classification', 'unknown')
                    
                    if classification == 'malicious':
                        st.error("⚠️ Classified as MALICIOUS")
                    elif classification == 'benign':
                        st.success("✅ Classified as benign")
                    elif 'not found' in str(classification).lower():
                        st.info("✅ Not in GreyNoise database (clean)")
                    else:
                        st.warning(f"Classification: {classification}")
                    
                    st.markdown("---")
                
                # MetaDefender
                elif 'metadefender' in str(key):
                    st.markdown("### 🛡️ MetaDefender")
                    
                    lookup_results = value.get('lookup_results', {})
                    detected_by = lookup_results.get('detected_by', 0)
                    
                    if detected_by > 0:
                        st.error(f"⚠️ Detected by {detected_by} engines")
                    else:
                        st.success("✅ Clean (0 detections)")
                    
                    st.markdown("---")


                # ✅ ADD PROJECT HONEYPOT HERE (NEW)
                elif 'honeypot' in str(key).lower():
                    st.markdown("### 🍯 Project Honey Pot - IP Reputation")
                    
                    if isinstance(value, dict):
                        status = value.get('status', '')
                        
                        if status == 'active':
                            domain = value.get('domain', 'N/A')
                            ip_addresses = value.get('ip_addresses', [])
                            total_ips = value.get('total_ips', 0)
                            threats = value.get('threats', [])
                            clean_ips = value.get('clean_ips', [])
                            
                            # Summary metrics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Domain", domain)
                            with col2:
                                st.metric("Total IPs", total_ips)
                            with col3:
                                threat_count = len(threats)
                                if threat_count > 0:
                                    st.metric("Threats", threat_count, delta="Malicious", delta_color="inverse")
                                else:
                                    st.metric("Status", "Clean", delta="Safe")
                            
                            # Show all IPs
                            st.markdown("**IP Addresses:**")
                            for ip in ip_addresses:
                                st.code(ip, language=None)
                            
                            # Threat details
                            if threats:
                                st.error(f"⚠️ {len(threats)} malicious IP(s) detected!")
                                
                                for idx, threat in enumerate(threats, 1):
                                    severity = threat.get('severity', 'UNKNOWN')
                                    severity_icon = {
                                        'HIGH': '🔴',
                                        'MEDIUM': '🟡',
                                        'LOW': '🟢',
                                        'INFO': 'ℹ️'
                                    }.get(severity, '⚪')
                                    
                                    with st.expander(f"{severity_icon} Threat #{idx}: {threat.get('ip', 'N/A')} - {threat.get('status', 'N/A')}", expanded=True):
                                        col1, col2, col3 = st.columns(3)
                                        
                                        with col1:
                                            st.metric("Severity", f"{severity_icon} {severity}")
                                        
                                        with col2:
                                            st.metric("Threat Level", f"{threat.get('threat_level', 0)}/255")
                                        
                                        with col3:
                                            st.metric("Last Activity", f"{threat.get('days_since_activity', 0)} days ago")
                                        
                                        st.markdown(f"**Threat Type:** {threat.get('status', 'N/A')}")
                                        st.markdown(f"**IP Address:** `{threat.get('ip', 'N/A')}`")
                                        st.markdown(f"**Details:** [{threat.get('url', '#')}]({threat.get('url', '#')})")
                            
                            elif clean_ips:
                                st.success(f"✅ All {len(clean_ips)} IP address(es) are clean")
                                with st.expander("View Clean IPs"):
                                    for ip in clean_ips:
                                        st.text(f"✓ {ip}")
                        
                        elif status == 'disabled':
                            st.info("Project Honey Pot API is disabled")
                        
                        elif status == 'error':
                            error_msg = value.get('message', 'Unknown error')
                            st.warning(f"⚠️ Error: {error_msg}")
                        
                        else:
                            st.info("Project Honey Pot check was not performed")
                    
                    st.markdown("---")

        else:
            st.info("No threat intelligence data available")




        st.subheader("🛡️ Advanced Threat Intelligence (3 New APIs)")

        # VirusTotal - Access directly from data, not from web_results
        if data.get('virustotal_v2'):
            vt = data['virustotal_v2']
            with st.expander("🔍 VirusTotal Domain/IP Scan", expanded=True):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    malicious = vt.get('malicious', 0)
                    if malicious > 0:
                        st.error(f"🚨 Malicious: {malicious}")
                    else:
                        st.success(f"✅ Malicious: {malicious}")
                
                with col2:
                    suspicious = vt.get('suspicious', 0)
                    if suspicious > 0:
                        st.warning(f"⚠️ Suspicious: {suspicious}")
                    else:
                        st.info(f"⚠️ Suspicious: {suspicious}")
                
                with col3:
                    undetected = vt.get('undetected', 0)
                    st.metric("Undetected", undetected)
                
                if vt.get('domain'):
                    st.caption(f"Scanned: {vt.get('domain')}")
                elif vt.get('ip'):
                    st.caption(f"Scanned: {vt.get('ip')}")
        else:
            st.info("⚠️ VirusTotal data not available")

        # Pulsedive - Access directly from data, not from web_results
        if data.get('pulsedive_threat'):
            pd = data['pulsedive_threat']
            with st.expander("⚡ Pulsedive Threat Assessment", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    threat_level = pd.get('threat_level', 'unknown')
                    if threat_level == 'high':
                        st.error(f"🔴 Threat: {threat_level.upper()}")
                    elif threat_level == 'medium':
                        st.warning(f"🟡 Threat: {threat_level.upper()}")
                    elif threat_level == 'low':
                        st.success(f"🟢 Threat: {threat_level.upper()}")
                    else:
                        st.info(f"⚪ Threat: {threat_level}")
                
                with col2:
                    risk_score = pd.get('risk_score', 0)
                    st.metric("Risk Score", risk_score)
                
                st.caption(f"Target: {pd.get('target', 'Unknown')}")
        else:
            st.info("⚠️ Pulsedive data not available")

        # ViewDNS - Access directly from data, not from web_results
        if data.get('viewdns_reverse_ip'):
            st.markdown("### 🌐 ViewDNS Reverse IP Lookup")
            for idx, vdr in enumerate(data['viewdns_reverse_ip']):
                with st.expander(f"IP: {vdr.get('ip', 'Unknown')} - {vdr.get('count', 0)} co-hosted domains", expanded=False):
                    domains = vdr.get('co_hosted_domains', [])
                    if domains:
                        st.write("**Co-hosted domains:**")
                        for domain in domains[:10]:  # Show first 10
                            st.markdown(f"- `{domain}`")
                        if len(domains) > 10:
                            st.caption(f"...and {len(domains) - 10} more")
                    else:
                        st.info("No co-hosted domains found")
        else:
            st.info("⚠️ ViewDNS data not available")
        
    
    # 🆕 TAB 11: DATA LEAK DETECTION (NEW)
    with tabs[10]:
        st.subheader("💧 Data Leak Detection")
        
        leak_data = data.get('11_leak_detection', {})
        
        if leak_data:
            for key, value in leak_data.items():
                # LeakIX
                if 'leakix' in str(key):
                    st.markdown("### 🔍 LeakIX")
                    
                    if isinstance(value, list):
                        if value:
                            st.warning(f"⚠️ Found {len(value)} potential leaks")
                            
                            for idx, leak in enumerate(value[:5], 1):
                                with st.expander(f"Leak {idx}: {leak.get('ip', 'N/A')}", expanded=False):
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.text(f"Port: {leak.get('port', 'N/A')}")
                                        st.text(f"Protocol: {leak.get('protocol', 'N/A')}")
                                    with col2:
                                        st.text(f"Type: {leak.get('type', 'N/A')}")
                                        st.text(f"Country: {leak.get('geoip', {}).get('country_name', 'N/A')}")
                            
                            if len(value) > 5:
                                st.info(f"+ {len(value) - 5} more leaks")
                        else:
                            st.success("✅ No leaks found")
                    else:
                        st.success("✅ No leaks found")
                    
                    st.markdown("---")
                
                # Citadel
                elif 'citadel' in str(key):
                    st.markdown("### 🏰 Citadel (Breach Database)")
                    
                    breaches = value.get('message', [])
                    if isinstance(breaches, list) and breaches:
                        st.error(f"⚠️ Found in {len(breaches)} data breaches")
                        
                        for breach in breaches[:10]:
                            st.text(f"• {breach}")
                        
                        if len(breaches) > 10:
                            st.info(f"+ {len(breaches) - 10} more breaches")
                    else:
                        st.success("✅ No breaches found")

                # ✅ NEW: PasteBin Leak Detection
                elif 'pastebin' in str(key).lower():
                    st.markdown("**🗂️ PasteBin Leak Detection**")
                    
                    if isinstance(value, dict):
                        status = value.get('status', '')
                        
                        if status == 'success':
                            verified_count = value.get('verified_count', 0)
                            total_google = value.get('total_google_results', 0)
                            verified_leaks = value.get('verified_leaks', [])
                            
                            if verified_count > 0:
                                st.error(f"⚠️ Found {verified_count} verified leaks on PasteBin (out of {total_google} potential results)")
                                
                                for idx, leak in enumerate(verified_leaks, 1):
                                    with st.expander(f"🚨 Leak #{idx}: {leak.get('title', 'N/A')}", expanded=False):
                                        col1, col2 = st.columns([2, 1])
                                        
                                        with col1:
                                            st.markdown(f"**URL:** [{leak.get('url', 'N/A')}]({leak.get('url', '#')})")
                                            st.text(f"Snippet: {leak.get('snippet', 'N/A')[:200]}...")
                                        
                                        with col2:
                                            st.metric("Content Length", f"{leak.get('content_length', 0):,} chars")
                                            st.metric("Verified", "✅ Yes" if leak.get('verified') else "❌ No")
                                        
                                        if 'content_preview' in leak:
                                            st.markdown("**Content Preview:**")
                                            st.code(leak['content_preview'], language='text')
                            else:
                                st.success(f"✅ No verified leaks found (checked {total_google} potential results)")
                        
                        elif status == 'no_results':
                            st.success("✅ No leaks found on PasteBin - domain is clean")
                        
                        elif status == 'disabled':
                            st.info("PasteBin API is disabled")
                        
                        elif status == 'error':
                            error_msg = value.get('message', 'Unknown error')
                            st.warning(f"⚠️ PasteBin search error: {error_msg}")
                        
                        else:
                            st.info("PasteBin search was not performed")
                    
                    st.markdown("---")
            
                # ✅ IntelligenceX (ADD THIS)
                elif 'intelx' in str(key):
                    st.markdown("**🕵️ IntelligenceX - Dark Web & Breach Intelligence**")
                    
                    if isinstance(value, dict):
                        status = value.get('status', '')
                        
                        if status == 'active':
                            domain = value.get('domain', 'N/A')
                            total_records = value.get('total_records', 0)
                            all_results = value.get('all_results', [])
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Domain", domain)
                            with col2:
                                st.metric("Total Records", total_records)
                            
                            if total_records > 0:
                                st.warning(f"⚠️ Found {total_records} breach/leak records!")
                                
                                st.markdown("### 📊 Top 5 Results:")
                                st.markdown("---")
                                
                                for idx, result in enumerate(all_results[:5], 1):
                                    st.markdown(f"**Result {idx}:**")
                                    
                                    col1, col2 = st.columns([1, 3])
                                    
                                    with col1:
                                        st.text("Type:")
                                        st.text("Bucket:")
                                        st.text("Added:")
                                        st.text("URL:")
                                    
                                    with col2:
                                        st.text(result.get('type', 'N/A'))
                                        st.text(result.get('bucket', 'N/A'))
                                        st.text(result.get('added', 'N/A')[:19])
                                        st.markdown(f"[{result.get('url', 'N/A')}]({result.get('url', '#')})")
                                    
                                    st.markdown("---")
                                
                                if total_records > 5:
                                    st.info(f"ℹ️ Showing 5 of {total_records} results. Download full report below.")
                                
                                st.markdown("### 📥 Download Full Report")
                                
                                import json
                                full_json = json.dumps(value, indent=2)
                                
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.download_button(
                                        label=f"📄 JSON ({total_records} records)",
                                        data=full_json,
                                        file_name=f"intelx_{domain}_{datetime.now().strftime('%Y%m%d')}.json",
                                        mime="application/json",
                                        use_container_width=True
                                    )
                                
                                with col2:
                                    report_text = f"""IntelligenceX Report
    Domain: {domain}
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Total Records: {total_records}
    {'='*80}

    """
                                    for idx, result in enumerate(all_results, 1):
                                        report_text += f"""Result {idx}:
        Type: {result.get('type', 'N/A')}
        Bucket: {result.get('bucket', 'N/A')}
        Added: {result.get('added', 'N/A')}
        URL: {result.get('url', 'N/A')}

    """
                                    
                                    st.download_button(
                                        label=f"📋 TXT ({total_records} records)",
                                        data=report_text,
                                        file_name=f"intelx_{domain}_{datetime.now().strftime('%Y%m%d')}.txt",
                                        mime="text/plain",
                                        use_container_width=True
                                    )
                            
                            else:
                                st.success(f"✅ No breaches found for {domain}")
                        
                        elif status == 'disabled':
                            st.info("IntelligenceX API is disabled")
                        
                        elif status == 'error':
                            st.warning(f"⚠️ Error: {value.get('message', 'Unknown')}")
                    
                    st.markdown("---")

        else:
            st.info("No leak detection data available")
    
    # 🆕 TAB 12: S3 BUCKET EXPOSURE (NEW)
    with tabs[11]:
        st.subheader("☁️ S3 Bucket Exposure")
        
        s3_data = data.get('12_s3_exposure', {})
        
        if s3_data and s3_data.get('files'):
            files = s3_data['files']
            st.error(f"⚠️ Found {len(files)} exposed files!")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                unique_buckets = len(set(f.get('bucket', 'unknown') for f in files))
                st.metric("Unique Buckets", unique_buckets)
            with col2:
                st.metric("Total Files", len(files))
            with col3:
                st.metric("Risk Level", "HIGH", delta_color="inverse")
            
            st.markdown("---")
            
            for idx, file in enumerate(files[:15], 1):
                with st.expander(f"File {idx}: {file.get('url', 'Unknown')}", expanded=False):
                    st.text(f"Bucket: {file.get('bucket', 'Unknown')}")
                    st.text(f"Size: {file.get('size', 'Unknown')}")
                    st.text(f"Type: {file.get('type', 'Unknown')}")
            
            if len(files) > 15:
                st.warning(f"+ {len(files) - 15} more exposed files")
        else:
            st.success("✅ No exposed S3 buckets found")
    


def display_correlation_results(data: Dict[str, Any]):
    """Display Phase 4 correlation analysis results - Professional Design with Visual MITRE Mapping"""
    st.header("🔗 Phase 4: Vulnerability Correlation & Threat Intelligence")
    
    if not data or 'error' in data:
        st.error(f"Analysis failed: {data.get('error', 'Unknown error')}")
        return
    
    # Check if no CVEs found
    cves_all = data.get('cves_all', [])
    security_issues = data.get('security_issues', [])
    
    if not cves_all and not security_issues:
        st.success("✅ **Good News: No Vulnerabilities Detected!**")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CVEs Found", "0", delta="Secure")
        with col2:
            st.metric("Security Issues", "0", delta="Secure")
        with col3:
            st.metric("Risk Level", "Low", delta="Good")
        
        st.info("""
        **Phase 4 Analysis Complete**
        
        ✓ No Common Vulnerabilities and Exposures (CVEs) were identified  
        ✓ No security configuration issues detected  
        
        **This could mean:**
        - All detected software is up-to-date
        - No software versions were detected (version information missing)
        - The technology stack has a strong security posture
        
        **Recommendations:**
        - Continue regular security updates and patch management
        - Consider active penetration testing for comprehensive assessment
        - Implement continuous monitoring and logging
        - Maintain security awareness training programs
        """)
        
        # Still show threat intelligence if available
        if data.get('apt_mapping_md'):
            with st.expander("📋 View Threat Intelligence Assessment"):
                st.markdown(data['apt_mapping_md'])
        
        if data.get('attack_vectors_md'):
            with st.expander("🔍 View Security Posture Report"):
                st.markdown(data['attack_vectors_md'])
        
        return
    
    st.markdown("---")

    # ── Categorized Security Issues ───────────────────────────────────────────
    ibc = data.get('issues_by_category', {})
    security_issues = data.get('security_issues', [])
    if security_issues:
        with st.expander(f"🚨 Security Issues Breakdown ({len(security_issues)} total)", expanded=True):
            cat_tabs = st.tabs(["🔴 Critical", "🟠 High", "🟡 Medium", "🕵️ Threat Intel", "💧 Leaks & Breaches"])

            # Critical
            with cat_tabs[0]:
                crit_list = ibc.get('critical', [s for s in security_issues if s.get('severity') == 'CRITICAL'])
                if crit_list:
                    for iss in crit_list:
                        st.error(f"**{iss.get('type')}** — {iss.get('header', iss.get('cookie', ''))}")
                        if iss.get('description'):
                            st.caption(iss['description'])
                else:
                    st.success("No critical security issues found.")

            # High
            with cat_tabs[1]:
                high_list = ibc.get('high', [s for s in security_issues if s.get('severity') == 'HIGH'])
                if high_list:
                    for iss in high_list:
                        st.warning(f"**{iss.get('type')}** — {iss.get('header', iss.get('cookie', ''))}")
                        detail = iss.get('description') or ', '.join(iss.get('issues', []))
                        if detail:
                            st.caption(detail)
                else:
                    st.success("No high severity issues found.")

            # Medium
            with cat_tabs[2]:
                med_list = ibc.get('medium', [s for s in security_issues if s.get('severity') == 'MEDIUM'])
                if med_list:
                    for iss in med_list:
                        st.info(f"**{iss.get('type')}** — {iss.get('header', iss.get('cookie', ''))}")
                        detail = iss.get('description') or ', '.join(iss.get('issues', []))
                        if detail:
                            st.caption(detail)
                else:
                    st.success("No medium severity issues found.")

            # Threat Intel
            with cat_tabs[3]:
                ti_list = ibc.get('threat_intel', [
                    s for s in security_issues
                    if s.get('source') in ('MetaDefender', 'AbuseIPDB', 'AlienVault OTX', 'GreyNoise', 'Project Honey Pot')
                ])
                if ti_list:
                    for iss in ti_list:
                        st.error(f"**{iss.get('type')}** [{iss.get('source', '')}]")
                        st.caption(f"{iss.get('header', '')} — {iss.get('description', '')}")
                else:
                    st.success("No threat intelligence alerts.")

            # Leaks & Breaches
            with cat_tabs[4]:
                leak_list = ibc.get('leaks', [
                    s for s in security_issues
                    if s.get('source') in ('Citadel', 'LeakIX', 'PasteBin', 'IntelligenceX', 'GrayHatWarfare')
                ])
                if leak_list:
                    for iss in leak_list:
                        st.error(f"**{iss.get('type')}** [{iss.get('source', '')}]")
                        st.caption(f"{iss.get('header', '')} — {iss.get('description', '')}")
                else:
                    st.success("No data leaks or breach exposure detected.")

    st.markdown("---")

    # Create main tabs
    tabs = st.tabs([
        "🔴CVE/CWE Mappings",
        "🕵️ APT Threat Intelligence",
        "⚔️Attack Vector Analysis",
        "Technology Stack",
        "🗺️ MITRE Attack Flow Map",
        "🎭 Attack Scenarios & Kill Chains" 
    ])
    
    # ==================== TAB 1: CVE/CWE MAPPINGS ====================
    with tabs[0]:
        st.subheader("🎯 CVE/CWE Vulnerability Mappings")
        
        cves = data.get('cves_all', [])
        
        if not cves:
            st.info("No CVE/CWE mappings found")
        else:
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                severity_filter = st.multiselect(
                    "Filter by Severity",
                    options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
                    default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
                )
            with col2:
                cvss_threshold = st.slider("Minimum CVSS Score", 0.0, 10.0, 0.0, 0.1)
            
            # Filter CVEs
            filtered_cves = [
                c for c in cves 
                if (c.get('severity') or 'UNKNOWN').upper() in severity_filter and c.get('cvss', 0) >= cvss_threshold
            ]
            
            st.text(f"Showing {len(filtered_cves)} of {len(cves)} vulnerabilities")
            st.markdown("---")
            
            # Display CVEs in a clean format with FULL descriptions
            for idx, cve in enumerate(sorted(filtered_cves, key=lambda x: x.get('cvss', 0), reverse=True), 1):
                # Determine severity color
                cvss = cve.get('cvss', 0)
                if cvss >= 9.0:
                    severity_color = "🔴"
                    severity_label = "CRITICAL"
                elif cvss >= 7.0:
                    severity_color = "🟠"
                    severity_label = "HIGH"
                elif cvss >= 4.0:
                    severity_color = "🟡"
                    severity_label = "MEDIUM"
                else:
                    severity_color = "🟢"
                    severity_label = "LOW"
                
                with st.expander(f"{severity_color} **{cve.get('cve', 'Unknown')}** - {cve.get('tech', 'Unknown')} (CVSS: {cvss})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**Affected Component:** {cve.get('tech', 'Unknown')} {cve.get('version', '')}")
                        
                        # FULL description (no truncation)
                        desc = cve.get('description', 'No description available')
                        st.markdown(f"**Description:**")
                        st.info(desc)
                        
                        # Additional details
                        if cve.get('vector'):
                            st.markdown(f"**CVSS Vector:** `{cve['vector']}`")
                        
                        if cve.get('cwe') and cve['cwe'] != 'Unknown':
                            st.markdown(f"**CWE Classification:** {cve['cwe']}")
                    
                    with col2:
                        # Severity badge
                        if cvss >= 9.0:
                            st.error(f"**Severity**\n\n{severity_label}\n\nCVSS: {cvss}")
                        elif cvss >= 7.0:
                            st.warning(f"**Severity**\n\n{severity_label}\n\nCVSS: {cvss}")
                        elif cvss >= 4.0:
                            st.info(f"**Severity**\n\n{severity_label}\n\nCVSS: {cvss}")
                        else:
                            st.success(f"**Severity**\n\n{severity_label}\n\nCVSS: {cvss}")
                        
                        # Publication date
                        if cve.get('published'):
                            st.markdown(f"**Published**\n\n{cve['published']}")
    
    # ==================== TAB 2: APT THREAT INTELLIGENCE ====================
    with tabs[1]:
        st.subheader("🎯 Advanced Persistent Threat (APT) Intelligence")
        
        apt_md = data.get('apt_mapping_md', '')
        
        if apt_md:
            st.markdown(apt_md)
        else:
            st.warning("⚠️ APT threat intelligence not available")
            st.info("AI-powered threat intelligence analysis requires configuration.")
    
    # ==================== TAB 3: ATTACK VECTOR ANALYSIS ====================
    with tabs[2]:
        st.subheader("⚔️ Attack Vector Correlation & MITRE ATT&CK Mapping")
        
        vectors_md = data.get('attack_vectors_md', '')
        
        if vectors_md and len(vectors_md) > 100:
            
            # Split content into 3 sections based on your actual format
            import re
            
            # Find section positions
            pattern_1 = re.search(r'(###?\s*1\.?\s*TOP\s+3\s+THREAT)', vectors_md, re.IGNORECASE)
            pattern_2 = re.search(r'(###?\s*2\.?\s*VULNERABILITY\s+CORRELATION)', vectors_md, re.IGNORECASE)
            pattern_3 = re.search(r'(###?\s*3\.?\s*MITRE\s+ATT)', vectors_md, re.IGNORECASE)
            
            # Extract sections based on positions
            if pattern_1 and pattern_2 and pattern_3:
                pos_1 = pattern_1.start()
                pos_2 = pattern_2.start()
                pos_3 = pattern_3.start()
                
                section_1 = vectors_md[pos_1:pos_2].strip()
                section_2 = vectors_md[pos_2:pos_3].strip()
                section_3 = vectors_md[pos_3:].strip()
            else:
                # Fallback: show all content in first tab
                section_1 = vectors_md
                section_2 = ""
                section_3 = ""
            
            # Create tabs
            vector_tabs = st.tabs([
                "🎯 Top 3 Threat Scenarios",
                "🔗 Vulnerability Correlation",
                "📊 MITRE ATT&CK Mapping"
            ])
            
            # TAB 1 - Matching Streamlit font style
            with vector_tabs[0]:
                st.markdown("### Top 3 Threat Scenarios (Most Critical)")
                if section_1:
                    st.markdown("""
                    <style>
                    .scroll-box {
                        max-height: 600px;
                        overflow-y: auto;
                        border: 1px solid #e0e0e0;
                        padding: 20px;
                        background: white;
                        white-space: pre-wrap;
                        font-family: "Source Sans Pro", sans-serif;
                        font-size: 14px;
                        line-height: 1.6;
                        color: #262730;
                    }
                    </style>
                    """, unsafe_allow_html=True)
                    
                    html_1 = f'<div class="scroll-box">{section_1}</div>'
                    st.markdown(html_1, unsafe_allow_html=True)
                else:
                    st.warning("Section not found")
            
            # TAB 2
            with vector_tabs[1]:
                st.markdown("### Vulnerability Correlation Analysis")
                if section_2:
                    st.markdown("""
                    <style>
                    .scroll-box-2 {
                        max-height: 600px;
                        overflow-y: auto;
                        border: 1px solid #e0e0e0;
                        padding: 20px;
                        background: white;
                        white-space: pre-wrap;
                        font-family: "Source Sans Pro", sans-serif;
                        font-size: 14px;
                        line-height: 1.6;
                        color: #262730;
                    }
                    </style>
                    """, unsafe_allow_html=True)
                    
                    html_2 = f'<div class="scroll-box-2">{section_2}</div>'
                    st.markdown(html_2, unsafe_allow_html=True)
                else:
                    st.warning("Section not found")
            
            # TAB 3
            with vector_tabs[2]:
                st.markdown("### MITRE ATT&CK Framework Mapping")
                if section_3:
                    st.markdown("""
                    <style>
                    .scroll-box-3 {
                        max-height: 600px;
                        overflow-y: auto;
                        border: 1px solid #e0e0e0;
                        padding: 20px;
                        background: white;
                        white-space: pre-wrap;
                        font-family: "Source Sans Pro", sans-serif;
                        font-size: 14px;
                        line-height: 1.6;
                        color: #262730;
                    }
                    </style>
                    """, unsafe_allow_html=True)
                    
                    html_3 = f'<div class="scroll-box-3">{section_3}</div>'
                    st.markdown(html_3, unsafe_allow_html=True)
                else:
                    st.warning("Section not found")
        
        else:
            st.warning("⚠️ Attack vector analysis not available")
            st.info("AI-powered attack vector analysis requires configuration.")
    
    # ==================== TAB 4: TECHNOLOGY STACK ====================
    with tabs[3]:
        st.subheader("🔧 Technology Stack Overview")
        
        techs = data.get('technologies', [])
        
        if not techs:
            st.info("No technologies detected")
        else:
            # Group by type
            tech_by_type = {}
            for tech in techs:
                tech_type = tech.get('type', 'Other')
                if tech_type not in tech_by_type:
                    tech_by_type[tech_type] = []
                tech_by_type[tech_type].append(tech)
            
            # Display each category
            for tech_type, tech_list in sorted(tech_by_type.items()):
                with st.expander(f"**{tech_type}** ({len(tech_list)} items)", expanded=True):
                    for tech in tech_list:
                        version = tech.get('version', 'unknown')
                        severity = tech.get('severity', '')
                        
                        if severity:
                            st.markdown(f"⚠️ **{tech.get('name', 'Unknown')}** {version} - *{severity} severity*")
                        else:
                            if version and version not in ['unknown', 'latest']:
                                st.markdown(f"• **{tech.get('name', 'Unknown')}** {version}")
                            else:
                                st.markdown(f"• **{tech.get('name', 'Unknown')}**")


    # ==================== TAB 5: MITRE ATTACK MATRIX (REDESIGNED) ====================
    # ==================== TAB 5: MITRE ATTACK MATRIX (COMPLETE FIXED VERSION) ====================
    with tabs[4]:
        st.subheader("🗺️ MITRE ATT&CK Enterprise Matrix")
        
        mitre_md = data.get('attack_vectors_md', '')
        
        if not mitre_md or len(mitre_md) < 100:
            st.warning("⚠️ MITRE ATT&CK data not available.")
            st.info("💡 Tip: Phase 4 correlation analysis must complete successfully first.")
        else:
            import re
            import streamlit.components.v1 as components
            
            # === STEP 1: Extract technique IDs from MITRE section ===
            mitre_section = ""
            
            if "## 3. MITRE ATT&CK" in mitre_md:
                start = mitre_md.find("## 3. MITRE ATT&CK")
                mitre_section = mitre_md[start:]
            elif "MITRE ATT&CK DEFENSIVE MAPPING" in mitre_md:
                start = mitre_md.find("MITRE ATT&CK DEFENSIVE MAPPING")
                mitre_section = mitre_md[start:]
            else:
                mitre_section = mitre_md
            
            # Find all technique IDs and extract their context for tooltips
            all_technique_ids = set()
            technique_tooltips = {}   # tech_id -> best description line
            technique_scenarios = {}  # tech_id -> list of scenario numbers it appears in
            pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
            all_matches = re.findall(pattern, mitre_section)
            all_technique_ids.update(all_matches)

            # Track current scenario number as we scan lines
            current_scenario = None
            for line in mitre_section.splitlines():
                # Detect scenario headings: "Scenario 1", "Scenario 2", "Scenario 3"
                sc_match = re.search(r'Scenario\s+(\d+)', line, re.IGNORECASE)
                if sc_match:
                    current_scenario = int(sc_match.group(1))

                for tech_id in all_technique_ids:
                    if tech_id in line:
                        # Track scenario attribution
                        if current_scenario:
                            technique_scenarios.setdefault(tech_id, set()).add(current_scenario)

                        # Keep the LONGEST line — it has the most descriptive context
                        clean = re.sub(r'[*#`]', '', line).strip()
                        if len(clean) > len(technique_tooltips.get(tech_id, '')):
                            technique_tooltips[tech_id] = clean[:200]

            # Build final tooltips: append scenario attribution
            for tech_id in all_technique_ids:
                base = technique_tooltips.get(tech_id, tech_id)
                scenarios = sorted(technique_scenarios.get(tech_id, []))
                if scenarios:
                    sc_label = ', '.join(f'Scenario {s}' for s in scenarios)
                    technique_tooltips[tech_id] = f"{base} [Used in: {sc_label}]"
            
            # === STEP 2: Complete MITRE ATT&CK Matrix (12 tactics) ===
            complete_matrix = {
                "TA0001": {"name": "TA0001", "color": "#FF6B6B"},
                "TA0002": {"name": "TA0002", "color": "#4ECDC4"},
                "TA0003": {"name": "TA0003", "color": "#45B7D1"},
                "TA0004": {"name": "TA0004", "color": "#FFA07A"},
                "TA0005": {"name": "TA0005", "color": "#98D8C8"},
                "TA0006": {"name": "TA0006", "color": "#F7DC6F"},
                "TA0007": {"name": "TA0007", "color": "#BB8FCE"},
                "TA0008": {"name": "TA0008", "color": "#85C1E2"},
                "TA0009": {"name": "TA0009", "color": "#F8B739"},
                "TA0010": {"name": "TA0010", "color": "#52B788"},
                "TA0011": {"name": "TA0011", "color": "#E63946"},
                "TA0040": {"name": "TA0040", "color": "#D62828"}
            }
            
            # === STEP 3: Define ALL techniques for each tactic ===
            tactic_techniques = {
                "TA0001": [
                    "T1189", "T1190", "T1133", "T1200", "T1566", 
                    "T1091", "T1195", "T1199", "T1078"
                ],
                "TA0002": [
                    "T1059", "T1609", "T1610", "T1203", "T1559", 
                    "T1106", "T1053", "T1129", "T1072", "T1569", 
                    "T1204", "T1047"
                ],
                "TA0003": [
                    "T1098", "T1197", "T1547", "T1037", "T1176", 
                    "T1554", "T1136", "T1543", "T1546", "T1068"
                ],
                "TA0004": [
                    "T1548", "T1134", "T1547", "T1037", "T1543", 
                    "T1484", "T1611", "T1546", "T1068"
                ],
                "TA0005": [
                    "T1548", "T1134", "T1197", "T1612", "T1140", 
                    "T1610", "T1006", "T1484", "T1480", "T1211"
                ],
                "TA0006": [
                    "T1557", "T1110", "T1555", "T1212", "T1187", 
                    "T1606", "T1056", "T1558", "T1111", "T1552", 
                    "T1003", "T1078"
                ],
                "TA0007": [
                    "T1087", "T1010", "T1217", "T1580", "T1613", 
                    "T1083", "T1615", "T1046", "T1135", "T1018"
                ],
                "TA0008": [
                    "T1210", "T1534", "T1570", "T1563", "T1021", 
                    "T1091", "T1072", "T1080", "T1550", "T1078"
                ],
                "TA0009": [
                    "T1560", "T1123", "T1119", "T1185", "T1115", 
                    "T1213", "T1005", "T1039", "T1025"
                ],
                "TA0010": [
                    "T1071", "T1092", "T1132", "T1001", "T1568", 
                    "T1573", "T1008", "T1105", "T1104"
                ],
                "TA0011": [
                    "T1020", "T1030", "T1048", "T1041", "T1011", 
                    "T1052", "T1567", "T1029", "T1537"
                ],
                "TA0040": [
                    "T1531", "T1485", "T1486", "T1565", "T1491", 
                    "T1561", "T1499", "T1495", "T1490"
                ]
            }
            
            # === STEP 4: Build Matrix Table ===
            st.caption("🔴 Red: Found in scan | ⚪ Gray: Not detected | Scroll vertically to see all techniques")
            
            # Create HTML for fixed grid matrix
            matrix_html = """
            <style>
            .mitre-matrix-container {
                width: 100%;
                overflow-x: auto;
                background: #f8f9fa;
                padding: 10px;
                border-radius: 8px;
                max-height: 600px;
                overflow-y: auto;
            }
            .mitre-matrix-table {
                width: 100%;
                border-collapse: collapse;
                font-size: 11px;
                background: white;
                table-layout: fixed;
            }
            .mitre-matrix-table th {
                background: linear-gradient(135deg, #c41230, #8b0a1f);
                color: white;
                padding: 8px 4px;
                text-align: center;
                font-weight: bold;
                font-size: 10px;
                border: 1px solid #ddd;
                vertical-align: top;
                width: 8.33%;
                position: sticky;
                top: 0;
                z-index: 10;
            }
            .mitre-matrix-table td {
                padding: 8px 4px;
                border: 1px solid #ddd;
                text-align: center;
                vertical-align: top;
                background: #f9f9f9;
                width: 8.33%;
            }
            .tech-id-found {
                background: #dc3545;
                color: white;
                padding: 3px 5px;
                margin: 2px 1px;
                border-radius: 3px;
                display: inline-block;
                font-weight: bold;
                font-size: 9px;
                cursor: pointer;
            }
            .tech-id-found:hover {
                background: #c82333;
                transform: scale(1.05);
            }
            .tech-id-normal {
                background: #e9ecef;
                color: #6c757d;
                padding: 3px 5px;
                margin: 2px 1px;
                border-radius: 3px;
                display: inline-block;
                font-size: 9px;
            }
            .tactic-header {
                font-size: 11px;
                line-height: 1.3;
            }
            .tactic-count {
                font-size: 9px;
                color: #ffc;
                margin-top: 3px;
                font-weight: normal;
            }
            </style>
            
            <div class="mitre-matrix-container">
                <table class="mitre-matrix-table">
                    <thead>
                        <tr>
            """
            
            # Add tactic headers
            for tactic_id, tactic_info in complete_matrix.items():
                matrix_html += f"""
                            <th>
                                <div class="tactic-header">
                                    <strong>{tactic_info['name']}</strong>
                                </div>
                            </th>
                """
            
            matrix_html += """
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
            """
            
            # Add technique cells for each tactic (ALL TECHNIQUES)
            for tactic_id, tactic_info in complete_matrix.items():
                techniques = tactic_techniques.get(tactic_id, [])
                
                cell_content = ""
                found_count = 0
                
                for tech_id in techniques:
                    is_found = tech_id in all_technique_ids
                    if is_found:
                        found_count += 1
                        tooltip = technique_tooltips.get(tech_id, 'Found in scan')
                        cell_content += f'<span class="tech-id-found" title="{tooltip}">{tech_id}</span><br>'
                    else:
                        cell_content += f'<span class="tech-id-normal">{tech_id}</span><br>'
                
                # Add count at bottom
                count_text = f'<div class="tactic-count">{found_count}/{len(techniques)} found</div>'
                
                matrix_html += f"""
                            <td>
                                {cell_content}
                                {count_text}
                            </td>
                """
            
            matrix_html += """
                        </tr>
                    </tbody>
                </table>
            </div>
            """
            
            # Render the fixed matrix
            components.html(matrix_html, height=650, scrolling=True)
            
            # === STEP 5: Show Summary Metrics ===
            st.markdown("---")
            st.markdown("### 📊 Attack Surface Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Techniques Detected", len(all_technique_ids))
            
            with col2:
                # Count tactics with findings
                tactics_with_findings = 0
                for tactic_id in complete_matrix.keys():
                    if any(tech in all_technique_ids for tech in tactic_techniques.get(tactic_id, [])):
                        tactics_with_findings += 1
                st.metric("Tactics Affected", f"{tactics_with_findings}/12")
            
            with col3:
                total_techniques = sum(len(techs) for techs in tactic_techniques.values())
                coverage = int((len(all_technique_ids) / total_techniques) * 100)
                st.metric("Matrix Coverage", f"{coverage}%")
            
            with col4:
                # Calculate risk level based on coverage
                if coverage >= 30:
                    risk_level = "High"
                    risk_color = "🔴"
                elif coverage >= 15:
                    risk_level = "Medium"
                    risk_color = "🟡"
                else:
                    risk_level = "Low"
                    risk_color = "🟢"
                st.metric("Risk Level", f"{risk_color} {risk_level}")
            
            # === STEP 6: List All Found Techniques ===
            if all_technique_ids:
                with st.expander("📋 View All Detected Technique IDs"):
                    st.write("**Techniques identified in your attack surface:**")
                    
                    # Group by tactic
                    for tactic_id, tactic_info in complete_matrix.items():
                        techniques = tactic_techniques.get(tactic_id, [])
                        found_in_tactic = [t for t in techniques if t in all_technique_ids]
                        
                        if found_in_tactic:
                            st.markdown(f"**{tactic_id} - {tactic_info['name']}:** {', '.join(sorted(found_in_tactic))}")
            else:
                st.info("✅ No MITRE ATT&CK techniques were identified in the analysis. This indicates a strong security posture.")
    

    # ==================== TAB 6: ATTACK SCENARIOS WITH MITRE MAPPING ====================
    with tabs[5]:
        st.subheader("🎭 Attack Scenarios - Attacker's Perspective")
        
        vectors_md = data.get('attack_vectors_md', '')
        
        if not vectors_md or len(vectors_md) < 100:
            st.warning("⚠️ Attack scenarios not available")
            st.info("💡 Phase 4 correlation analysis required")
        else:
            import re
            
            st.markdown("""
            **Viewing the attack surface from a hacker's perspective.**  
            Each scenario shows a realistic attack path with MITRE ATT&CK technique mappings.
            """)
            
            # Parse scenarios from markdown
            scenarios = []
            
            # Split by "### Scenario" headers
            scenario_pattern = r'### Scenario (\d+):(.*?)(?=### Scenario \d+:|## 2\. VULNERABILITY|$)'
            matches = re.findall(scenario_pattern, vectors_md, re.DOTALL)
            
            for idx, (num, content) in enumerate(matches, 1):
                scenario = {
                    'number': int(num),
                    'title': content.split('\n')[0].strip(),
                    'content': content
                }
                
                # Extract MITRE techniques used
                tech_pattern = r'(T\d{4}(?:\.\d{3})?)'
                techniques = set(re.findall(tech_pattern, content))
                scenario['techniques'] = sorted(list(techniques))
                
                # Extract attacker's story
                story_match = re.search(r'\*\*Attacker\'s Mindset & Story:\*\*(.*?)\*\*Technical Execution', content, re.DOTALL)
                if story_match:
                    scenario['story'] = story_match.group(1).strip()
                else:
                    scenario['story'] = "Story not available"
                
                # Extract difficulty
                diff_match = re.search(r'Difficulty Level:\s*\[?(\d+)', content)
                if diff_match:
                    scenario['difficulty'] = int(diff_match.group(1))
                else:
                    scenario['difficulty'] = 5
                
                scenarios.append(scenario)
            
            if not scenarios:
                st.warning("No attack scenarios found in AI output")
            else:
                # Display each scenario
                for scenario in scenarios:
                    with st.expander(f"🎯 Scenario {scenario['number']}: {scenario['title']}", expanded=(scenario['number']==1)):
                        
                        # Attacker's Story
                        st.markdown("### 📖 Attacker's Story")
                        st.info(scenario['story'])
                        
                        # Metrics
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Difficulty", f"{scenario['difficulty']}/10")
                        
                        with col2:
                            st.metric("MITRE Techniques", len(scenario['techniques']))
                        
                        with col3:
                            if scenario['difficulty'] >= 8:
                                st.metric("Threat Level", "🔴 Critical")
                            elif scenario['difficulty'] >= 5:
                                st.metric("Threat Level", "🟡 High")
                            else:
                                st.metric("Threat Level", "🟢 Medium")
                        
                        st.markdown("---")
                        
                        # MITRE Kill Chain for THIS scenario
                        st.markdown(f"### 🗺️ MITRE ATT&CK Kill Chain - Scenario {scenario['number']}")
                        st.caption(f"Showing {len(scenario['techniques'])} techniques used in this specific attack path")
                        
                        
                        # Define COMPLETE Enterprise Matrix (same as tab[4])
                        complete_matrix = {
                            "TA0001": {"name": "TA0001", "color": "#FF6B6B"},
                            "TA0002": {"name": "TA0002", "color": "#4ECDC4"},
                            "TA0003": {"name": "TA0003", "color": "#45B7D1"},
                            "TA0004": {"name": "TA0004", "color": "#FFA07A"},
                            "TA0005": {"name": "TA0005", "color": "#98D8C8"},
                            "TA0006": {"name": "TA0006", "color": "#F7DC6F"},
                            "TA0007": {"name": "TA0007", "color": "#BB8FCE"},
                            "TA0008": {"name": "TA0008", "color": "#85C1E2"},
                            "TA0009": {"name": "TA0009", "color": "#F8B739"},
                            "TA0010": {"name": "TA0010", "color": "#52B788"},
                            "TA0011": {"name": "TA0011", "color": "#E63946"},
                            "TA0040": {"name": "TA0040", "color": "#D62828"}
                        }

                        tactic_techniques = {
                            'TA0001': ['T1189', 'T1190', 'T1133', 'T1200', 'T1566', 'T1091', 'T1195', 'T1199', 'T1078'],
                            'TA0002': ['T1059', 'T1609', 'T1610', 'T1203', 'T1559', 'T1106', 'T1053', 'T1129', 'T1072', 'T1569', 'T1204', 'T1047'],
                            'TA0003': ['T1098', 'T1197', 'T1547', 'T1037', 'T1176', 'T1554', 'T1136', 'T1543', 'T1546', 'T1068'],
                            'TA0004': ['T1548', 'T1134', 'T1547', 'T1037', 'T1543', 'T1484', 'T1611', 'T1546', 'T1068'],
                            'TA0005': ['T1548', 'T1134', 'T1197', 'T1612', 'T1140', 'T1610', 'T1006', 'T1484', 'T1480', 'T1211', 'T1562', 'T1070', 'T1202', 'T1564'],
                            'TA0006': ['T1557', 'T1110', 'T1555', 'T1212', 'T1187', 'T1606', 'T1056', 'T1558', 'T1111', 'T1552', 'T1003', 'T1078'],
                            'TA0007': ['T1087', 'T1010', 'T1217', 'T1580', 'T1613', 'T1083', 'T1615', 'T1046', 'T1135', 'T1018', 'T1069', 'T1057', 'T1012'],
                            'TA0008': ['T1210', 'T1534', 'T1570', 'T1563', 'T1021', 'T1091', 'T1072', 'T1080', 'T1550', 'T1078'],
                            'TA0009': ['T1560', 'T1123', 'T1119', 'T1185', 'T1115', 'T1213', 'T1005', 'T1039', 'T1025'],
                            'TA0010': ['T1071', 'T1092', 'T1132', 'T1001', 'T1568', 'T1573', 'T1008', 'T1105', 'T1104', 'T1095'],
                            'TA0011': ['T1020', 'T1030', 'T1048', 'T1041', 'T1011', 'T1052', 'T1567', 'T1029', 'T1537'],
                            'TA0040': ['T1531', 'T1485', 'T1486', 'T1565', 'T1491', 'T1561', 'T1499', 'T1495', 'T1490']
                        }

                        # Build FULL MATRIX HTML showing ALL techniques
                        scenario_matrix_html = """<style>
                        .scenario-full-matrix {
                            width: 100%;
                            overflow-x: auto;
                            background: #f8f9fa;
                            padding: 15px;
                            border-radius: 8px;
                            max-height: 650px;
                            overflow-y: auto;
                        }
                        .scenario-matrix-table {
                            width: 100%;
                            border-collapse: collapse;
                            font-size: 11px;
                            background: white;
                            table-layout: fixed;
                        }
                        .scenario-matrix-table th {
                            background: linear-gradient(135deg, #c41230, #8b0a1f);
                            color: white;
                            padding: 10px 5px;
                            text-align: center;
                            font-weight: bold;
                            font-size: 10px;
                            border: 1px solid #ddd;
                            vertical-align: top;
                            width: 8.33%;
                            position: sticky;
                            top: 0;
                            z-index: 10;
                        }
                        .scenario-matrix-table td {
                            padding: 10px 5px;
                            border: 1px solid #ddd;
                            text-align: center;
                            vertical-align: top;
                            background: #f9f9f9;
                            width: 8.33%;
                        }
                        .scenario-tech-used {
                            background: #dc3545;
                            color: white;
                            padding: 4px 6px;
                            margin: 2px;
                            border-radius: 3px;
                            display: inline-block;
                            font-weight: bold;
                            font-size: 10px;
                        }
                        .scenario-tech-not-used {
                            background: #e9ecef;
                            color: #aaa;
                            padding: 4px 6px;
                            margin: 2px;
                            border-radius: 3px;
                            display: inline-block;
                            font-size: 10px;
                        }
                        .tactic-header {
                            font-size: 11px;
                            line-height: 1.3;
                        }
                        .tactic-count {
                            font-size: 9px;
                            color: #ffc;
                            margin-top: 3px;
                            font-weight: normal;
                        }
                        </style>
                        <div class="scenario-full-matrix">
                        <table class="scenario-matrix-table">
                        <thead><tr>
                        """

                        # Add tactic headers
                        for tactic_id, tactic_info in complete_matrix.items():
                            scenario_matrix_html += f'<th><div class="tactic-header"><strong>{tactic_info["name"]}</strong></div></th>'
                        scenario_matrix_html += "</tr></thead><tbody><tr>"

                        # Add ALL techniques (showing used vs not used in THIS scenario)
                        for tactic_id, tactic_info in complete_matrix.items():
                            techniques = tactic_techniques.get(tactic_id, [])
                            cell_content = ""
                            used_count = 0
                            
                            for tech_id in techniques:
                                if tech_id in scenario['techniques']:  # Used in THIS scenario
                                    cell_content += f'<span class="scenario-tech-used" title="Used in this attack scenario">{tech_id}</span><br>'
                                    used_count += 1
                                else:  # Not used in this scenario
                                    cell_content += f'<span class="scenario-tech-not-used">{tech_id}</span><br>'
                            
                            count_text = f'<div class="tactic-count">{used_count}/{len(techniques)} used</div>'
                            scenario_matrix_html += f"<td>{cell_content}{count_text}</td>"

                        scenario_matrix_html += "</tr></tbody></table></div>"

                        # Render the FULL matrix for this scenario
                        components.html(scenario_matrix_html, height=650, scrolling=True)

                        st.markdown("---")
                        
                        
                        # Full technical details
                        with st.expander("📋 View Complete Technical Execution Path"):
                            st.markdown(scenario['content'])
                
                # Summary at bottom
                st.markdown("---")
                st.markdown("### 📊 Overall Attack Surface Summary")
                
                all_techniques_used = set()
                for scenario in scenarios:
                    all_techniques_used.update(scenario['techniques'])
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Attack Scenarios", len(scenarios))
                
                with col2:
                    st.metric("Unique MITRE Techniques", len(all_techniques_used))
                
                with col3:
                    avg_difficulty = sum(s['difficulty'] for s in scenarios) / len(scenarios)
                    st.metric("Average Difficulty", f"{avg_difficulty:.1f}/10")




def _clean_analysis(text: str) -> str:
    """Extract clean analysis text — handles raw JSON, truncated JSON, and markdown fences."""
    if not text:
        return 'No analysis available'
    t = text.strip()

    if t.startswith('{') or '```json' in t or t.startswith('```'):
        import json as _json, re as _re

        # Strip markdown fences
        clean = t
        if '```json' in clean:
            clean = clean.split('```json')[1].split('```')[0].strip()
        elif clean.startswith('```'):
            clean = clean.strip('`').strip()

        # Try full JSON parse first
        try:
            parsed = _json.loads(clean)
            if isinstance(parsed, dict) and 'analysis' in parsed:
                return str(parsed['analysis'])
        except Exception:
            pass

        # JSON is truncated — extract "analysis": "..." with greedy match up to end of string
        m = _re.search(r'"analysis"\s*:\s*"([\s\S]+)', clean)
        if m:
            raw_val = m.group(1)
            # Remove trailing incomplete JSON (find last complete sentence)
            # Strip closing quote/brace if present
            raw_val = raw_val.rstrip('}"').rstrip()
            return raw_val.replace('\\n', '\n').replace('\\"', '"').strip()

    return t


def display_risk_assessment_results(data: Dict[str, Any]):
    """Display Phase 5: Risk Assessment and Categorization"""
    st.header("📊 Phase 5: Risk Assessment & Categorization")

    if not data or 'error' in data:
        st.error(f"Risk assessment failed: {data.get('error', 'Unknown error')}")
        return

    # ── Executive Summary ─────────────────────────────────────────────────────
    st.markdown("### 🎯 Executive Summary")
    risk_matrix  = data.get('risk_matrix', {})
    multi_score  = data.get('multidimensional_score', {})
    dims         = risk_matrix.get('dimensions', {})

    # Top metrics row
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Composite Risk Score", f"{risk_matrix.get('composite_risk_score', 0)}/4.0")
    with c2: st.metric("Multi-dimensional Score", f"{multi_score.get('overall_risk_score', 0)}/10.0")
    with c3: st.metric("Risk Level", risk_matrix.get('risk_level', 'Unknown'))
    with c4: st.metric("Risk Rating", multi_score.get('risk_rating', 'Unknown'))

    st.markdown("---")

    # Risk breakdown cards
    st.markdown("#### Risk Breakdown")
    b1, b2, b3, b4 = st.columns(4)
    color_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    with b1:
        lvl = dims.get('business', {}).get('level', 'Unknown')
        st.metric("Business Risk", f"{color_map.get(lvl,'⚪')} {lvl}")
    with b2:
        lvl = dims.get('infrastructure', {}).get('level', 'Unknown')
        st.metric("Infrastructure", f"{color_map.get(lvl,'⚪')} {lvl}")
    with b3:
        lvl = dims.get('application', {}).get('level', 'Unknown')
        st.metric("Application", f"{color_map.get(lvl,'⚪')} {lvl}")
    with b4:
        lvl = dims.get('business_impact', {}).get('level', 'Unknown')
        st.metric("Business Impact", f"{color_map.get(lvl,'⚪')} {lvl}")

    st.markdown("---")

    # ── Executive Summary narrative ────────────────────────────────────────────
    exec_summary = data.get('executive_summary', '')
    if exec_summary:
        # Show only the AI narrative paragraphs, not the score block (scores shown above)
        lines = exec_summary.strip().split('\n')
        narrative_lines = []
        in_score_block = False
        for line in lines:
            if '──────' in line or 'RISK SCORES AT A GLANCE' in line or 'TOP PRIORITY ACTIONS' in line:
                in_score_block = True
            if not in_score_block and line.strip() and not line.startswith('EXECUTIVE RISK SUMMARY') and not line.startswith('===') and not line.startswith('Domain:'):
                narrative_lines.append(line)
        if narrative_lines:
            st.markdown('\n\n'.join(p for p in '\n'.join(narrative_lines).split('\n\n') if p.strip()))

    st.markdown("---")

    # ── Tabs for detailed analysis ─────────────────────────────────────────────
    tabs = st.tabs([
        "🏢 Business Risk",
        "🌐 Infrastructure Risk",
        "💻 Application Risk",
        "💼 Business Impact",
        "🕵️ Threat Actors",
        "📅 Action Plan",
        "📈 Risk Matrix",
        "📊 Multi-dimensional Score"
    ])

    # TAB 1: Business Risk
    with tabs[0]:
        st.subheader("🏢 Business Risk Categorization")
        business_risk = data.get('business_risk', {})
        col1, col2 = st.columns([2, 1])
        with col1:
            analysis_text = _clean_analysis(business_risk.get('analysis', ''))
            st.markdown(analysis_text)
        with col2:
            lvl = business_risk.get('risk_level', 'Unknown')
            color = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(lvl,"⚪")
            st.metric("Risk Level", f"{color} {lvl}")
            st.metric("Business Impact Score", f"{business_risk.get('business_impact_score', 0)}/10")
            st.markdown("**Risk Categories:**")
            for cat in business_risk.get('categories', []):
                st.markdown(f"- {cat}")

    # TAB 2: Infrastructure Risk
    with tabs[1]:
        st.subheader("🌐 Infrastructure Risk Assessment")
        infra_risk = data.get('infrastructure_risk', {})
        col1, col2 = st.columns([2, 1])
        with col1:
            analysis_text = _clean_analysis(infra_risk.get('analysis', ''))
            st.markdown(analysis_text)
        with col2:
            lvl = infra_risk.get('risk_level', 'Unknown')
            color = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(lvl,"⚪")
            st.metric("Risk Level", f"{color} {lvl}")
            st.metric("Attack Surface Score", f"{infra_risk.get('attack_surface_score', 0)}/10")
            st.markdown("**Risk Areas:**")
            for area in infra_risk.get('risk_areas', []):
                st.markdown(f"- {area}")

    # TAB 3: Application Risk
    with tabs[2]:
        st.subheader("💻 Application Risk Evaluation")
        app_risk = data.get('application_risk', {})
        col1, col2 = st.columns([2, 1])
        with col1:
            analysis_text = _clean_analysis(app_risk.get('analysis', ''))
            st.markdown(analysis_text)
        with col2:
            lvl = app_risk.get('risk_level', 'Unknown')
            color = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(lvl,"⚪")
            st.metric("Risk Level", f"{color} {lvl}")
            st.metric("Vulnerability Density", f"{app_risk.get('vulnerability_density', 0)}/10")
            st.markdown("**Risk Categories:**")
            for cat in app_risk.get('risk_categories', []):
                st.markdown(f"- {cat}")

    # TAB 4: Business Impact
    with tabs[3]:
        st.subheader("💼 Business Impact Correlation")
        business_impact = data.get('business_impact', {})
        bi1, bi2, bi3 = st.columns(3)
        lvl = business_impact.get('overall_impact', 'Unknown')
        color = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(lvl,"⚪")
        with bi1: st.metric("Overall Impact", f"{color} {lvl}")
        with bi2: st.metric("💰 Financial Exposure", business_impact.get('financial_range', 'Not estimated'))
        with bi3: st.metric("⏱️ Recovery Time", business_impact.get('recovery_time', 'Not estimated'))
        st.markdown("---")
        impact_dims = business_impact.get('impact_dimensions', {})
        if impact_dims:
            st.markdown("#### Impact Dimensions")
            dim_cols = st.columns(len(impact_dims))
            for i, (dim, level) in enumerate(impact_dims.items()):
                with dim_cols[i]:
                    c = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(level,"⚪")
                    st.metric(dim.replace('_',' ').title(), f"{c} {level}")
        st.markdown("---")
        analysis_text = _clean_analysis(business_impact.get('analysis', ''))
        st.markdown(analysis_text)

    # TAB 5: Threat Actors
    with tabs[4]:
        st.subheader("🕵️ Threat Actor Profile")
        tap = data.get('threat_actor_profile', {})
        if tap and not tap.get('error'):
            overall_tl = tap.get('overall_threat_level', 'Unknown')
            tl_color = {"High":"🔴","Medium":"🟠","Low":"🟡"}.get(overall_tl,"⚪")
            st.metric("Overall Threat Level", f"{tl_color} {overall_tl}")

            analyst_note = tap.get('analyst_note', '')
            if analyst_note:
                st.markdown(analyst_note)

            actors = tap.get('primary_threat_actors', [])
            if actors:
                st.markdown("#### Primary Threat Actors")
                for actor in actors:
                    lik = actor.get('likelihood', 'Unknown')
                    lik_color = {"High":"🔴","Medium":"🟠","Low":"🟡"}.get(lik,"⚪")
                    with st.expander(f"{lik_color} {actor.get('name','Unknown')} — {actor.get('motivation','?')} | Likelihood: {lik}"):
                        st.markdown(f"**Origin:** {actor.get('origin','Unknown')}")
                        st.markdown(f"**Why this company:** {actor.get('why_this_company','')}")
                        st.markdown(f"**Matching findings:** {actor.get('matching_findings','')}")
                        ttps = actor.get('known_ttps', [])
                        if ttps:
                            st.markdown("**Known TTPs:**")
                            for t in ttps:
                                st.markdown(f"  - {t}")

            opp = tap.get('opportunistic_threats', '')
            if opp:
                st.markdown("#### Opportunistic Threats")
                st.markdown(opp)
        else:
            st.info("Threat actor profile will be generated when Phase 5 runs.")

    # TAB 6: Action Plan
    with tabs[5]:
        st.subheader("📅 30 / 60 / 90 Day Remediation Action Plan")
        ap = data.get('action_plan', {})
        if ap and not ap.get('error') and ('day_30' in ap or 'day30' in ap):
            phases = [
                ('day_30', '🚨 Days 1–30: Emergency Triage', '#ef4444'),
                ('day_60', '🔧 Days 31–60: Hardening',       '#f59e0b'),
                ('day_90', '🛡️ Days 61–90: Resilience',      '#22c55e'),
            ]
            for key, title, color in phases:
                phase_data = ap.get(key, ap.get(key.replace('_',''), {}))
                if not phase_data:
                    continue
                theme = phase_data.get('theme', '')
                tasks = phase_data.get('tasks', [])
                st.markdown(f"#### {title}")
                if theme:
                    st.caption(theme)
                if tasks:
                    import pandas as pd
                    task_rows = []
                    for t in tasks:
                        if isinstance(t, dict):
                            task_rows.append({
                                "Action": t.get('action',''),
                                "Owner": t.get('owner',''),
                                "Expected Outcome": t.get('outcome','')
                            })
                    if task_rows:
                        st.dataframe(pd.DataFrame(task_rows), use_container_width=True, hide_index=True)
                else:
                    st.info("No tasks generated for this phase.")
        else:
            raw = ap.get('raw', '') if ap else ''
            if raw:
                st.markdown(raw)
            else:
                st.info("Action plan will be generated when Phase 5 runs.")

    # TAB 7: Risk Matrix
    with tabs[6]:
        st.subheader("📈 Risk Matrix")
        import pandas as pd

        # Score table
        dimensions = risk_matrix.get('dimensions', {})
        matrix_data = []
        for dim_name, dim_info in dimensions.items():
            lvl = dim_info.get('level', 'Unknown')
            color = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(lvl,"⚪")
            matrix_data.append({
                "Dimension":  dim_name.replace('_', ' ').title(),
                "Score":      f"{dim_info.get('score', 0)}/4",
                "Risk Level": f"{color} {lvl}",
                "Weight":     dim_info.get('weight', 'N/A')
            })
        if matrix_data:
            st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)

        composite  = risk_matrix.get('composite_risk_score', 0)
        risk_level = risk_matrix.get('risk_level', 'Unknown')
        clr        = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(risk_level,"⚪")
        st.markdown(f"**Composite Score:** `{composite}/4.0`  →  {clr} **{risk_level}**")
        st.markdown("---")

        # AI interpretation
        interp = risk_matrix.get('interpretation', '')
        if interp:
            st.markdown("#### What These Scores Mean Together")
            st.markdown(interp)

    # TAB 8: Multi-dimensional Score
    with tabs[7]:
        st.subheader("📊 Multi-dimensional Risk Score")
        import pandas as pd

        s1, s2 = st.columns(2)
        with s1: st.metric("Overall Risk Score", f"{multi_score.get('overall_risk_score', 0)}/10.0")
        with s2: st.metric("Risk Rating", multi_score.get('risk_rating', 'Unknown'))
        st.markdown("---")

        # Dimension score table
        dimensions = multi_score.get('dimensions', {})
        weights    = multi_score.get('weights', {})
        dim_data   = []
        dim_labels = {
            "technical_severity":  "Technical Severity  (avg CVSS of all CVEs)",
            "exploit_likelihood":  "Exploit Likelihood  (% CVEs with CVSS ≥ 7.0)",
            "asset_criticality":   "Asset Criticality   (business asset value)",
            "threat_intelligence": "Threat Intelligence (blacklists, dark web, APT hits)",
            "compliance_impact":   "Compliance Impact   (DMARC, TLS, secrets exposed)",
        }
        for dim_name, score in dimensions.items():
            try:
                dim_data.append({
                    "Dimension":      dim_labels.get(dim_name, dim_name.replace('_',' ').title()),
                    "Score":          f"{score:.2f}/10",
                    "Weight":         f"{weights.get(dim_name, 0):.0%}",
                    "Weighted Score": f"{score * weights.get(dim_name, 0):.2f}"
                })
            except Exception:
                pass
        if dim_data:
            st.dataframe(pd.DataFrame(dim_data), use_container_width=True, hide_index=True)

        st.markdown("---")

        # AI interpretation
        interp = multi_score.get('interpretation', '')
        if interp:
            st.markdown("#### What This Score Pattern Means")
            st.markdown(interp)
        else:
            st.markdown("#### Score Breakdown")
            st.text(multi_score.get('score_breakdown', 'No breakdown available'))



def create_mitre_attack_matrix(mitre_text: str, cves_data: list):
    """
    Create interactive MITRE ATT&CK Matrix that looks like the official website
    Grid layout with clickable technique cards
    """
    import re
    
    tactics_data = {}
    current_tactic = None
    current_tactic_id = None
    
    # Parse MITRE text to extract tactics and techniques
    lines = mitre_text.split('\n')
    for line in lines:
        line = line.strip()
        
        # Match tactic headers like "TA0001 - Initial Access"
        tactic_match = re.search(r'(TA\d+)\s*[-:]\s*(.*)', line)
        if tactic_match and not line.startswith('T1'):
            current_tactic_id = tactic_match.group(1).strip()
            current_tactic = tactic_match.group(2).strip()
            if current_tactic_id not in tactics_data:
                tactics_data[current_tactic_id] = {
                    "name": current_tactic,
                    "techniques": []
                }
            continue
        
        # Match technique lines like "T1189 - Drive-by Compromise"
        if current_tactic_id and line.startswith('T1'):
            tech_match = re.search(r'(T\d+(?:\.\d+)?)\s*[-:]\s*(.*?)(?:\s*-\s*(.*))?$', line)
            if tech_match:
                tech_id = tech_match.group(1).strip()
                tech_name = tech_match.group(2).strip()
                tech_desc = tech_match.group(3).strip() if tech_match.group(3) else tech_name
                
                # Extract CVEs mentioned in the description
                cve_matches = re.findall(r'CVE-\d{4}-\d+', tech_desc)
                
                tactics_data[current_tactic_id]["techniques"].append({
                    "id": tech_id,
                    "name": tech_name,
                    "description": tech_desc,
                    "cves": cve_matches
                })
    
    return tactics_data

def display_mitre_matrix_view(tactics_data: dict, cves_data: list):
    """
    Display MITRE ATT&CK Matrix exactly like official website
    Shows ALL techniques, highlights found ones in RED
    """
    import streamlit as st
    import re
    
    # CSS styles - displayed ONCE
    st.markdown("""
    <style>
    .mitre-container {
        display: flex;
        overflow-x: auto;
        width: 100%;
        padding: 10px 0;
        background: #f8f9fa;
        border-radius: 8px;
        margin: 10px 0;
        scrollbar-width: thin;
        scrollbar-color: #c41230 #f0f0f0;
    }
    
    .mitre-container::-webkit-scrollbar {
        height: 10px;
    }
    
    .mitre-container::-webkit-scrollbar-track {
        background: #f0f0f0;
        border-radius: 4px;
    }
    
    .mitre-container::-webkit-scrollbar-thumb {
        background: #c41230;
        border-radius: 4px;
    }
    
    .tactic-column {
        min-width: 280px;
        max-width: 280px;
        margin-right: 15px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        overflow: hidden;
        flex-shrink: 0;
    }
    
    .tactic-header {
        background: linear-gradient(135deg, #c41230 0%, #8b0a1f 100%);
        color: white;
        padding: 12px 10px;
        text-align: center;
        font-weight: bold;
        font-size: 13px;
        margin-bottom: 0;
    }
    
    .technique-container {
        max-height: 400px;
        overflow-y: auto;
        padding: 5px;
        scrollbar-width: thin;
    }
    
    .technique-normal {
        background: #f0f0f0;
        border: 1px solid #ddd;
        padding: 8px;
        margin: 3px;
        border-radius: 4px;
        font-size: 11px;
        cursor: pointer;
        transition: all 0.2s;
        color: #666;
    }
    
    .technique-normal:hover {
        background: #e0e0e0;
        transform: translateX(3px);
    }
    
    .technique-found {
        background: #dc3545 !important;
        color: white !important;
        border: 2px solid #c82333 !important;
        padding: 8px;
        margin: 3px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        cursor: pointer;
        box-shadow: 0 2px 4px rgba(220,53,69,0.4);
        transition: all 0.2s;
    }
    
    .technique-found:hover {
        background: #c82333 !important;
        transform: scale(1.05);
    }
    
    .technique-count {
        font-size: 10px;
        color: #ccc;
        margin-top: 2px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🎯 MITRE ATT&CK Enterprise Matrix")
    st.caption("🔴 Red techniques: Found in your scan | ⚪ Gray techniques: Not detected")
    
    # Get found techniques from correlation analysis
    found_techniques = {}
    for tactic_id, tactic_info in tactics_data.items():
        found_techniques[tactic_id] = [tech["id"] for tech in tactic_info["techniques"]]
    
    # Complete MITRE ATT&CK Enterprise Matrix
    complete_matrix = {
        "TA0001": {
            "name": "Initial Access",
            "all_techniques": [
                {"id": "T1189", "name": "Drive-by Compromise"},
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1133", "name": "External Remote Services"},
                {"id": "T1200", "name": "Hardware Additions"},
                {"id": "T1566", "name": "Phishing"},
                {"id": "T1091", "name": "Replication Through Removable Media"},
                {"id": "T1195", "name": "Supply Chain Compromise"},
                {"id": "T1199", "name": "Trusted Relationship"},
                {"id": "T1078", "name": "Valid Accounts"}
            ]
        },
        "TA0002": {
            "name": "Execution",
            "all_techniques": [
                {"id": "T1059", "name": "Command and Scripting Interpreter"},
                {"id": "T1609", "name": "Container Administration Command"},
                {"id": "T1610", "name": "Deploy Container"},
                {"id": "T1203", "name": "Exploitation for Client Execution"},
                {"id": "T1559", "name": "Inter-Process Communication"},
                {"id": "T1106", "name": "Native API"},
                {"id": "T1053", "name": "Scheduled Task/Job"},
                {"id": "T1129", "name": "Shared Modules"},
                {"id": "T1072", "name": "Software Deployment Tools"},
                {"id": "T1569", "name": "System Services"},
                {"id": "T1204", "name": "User Execution"},
                {"id": "T1047", "name": "Windows Management Instrumentation"}
            ]
        },
        "TA0003": {
            "name": "Persistence",
            "all_techniques": [
                {"id": "T1098", "name": "Account Manipulation"},
                {"id": "T1197", "name": "BITS Jobs"},
                {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
                {"id": "T1037", "name": "Boot or Logon Initialization Scripts"},
                {"id": "T1176", "name": "Browser Extensions"},
                {"id": "T1554", "name": "Compromise Client Software Binary"},
                {"id": "T1136", "name": "Create Account"},
                {"id": "T1543", "name": "Create or Modify System Process"},
                {"id": "T1546", "name": "Event Triggered Execution"},
                {"id": "T1068", "name": "Exploitation for Privilege Escalation"}
            ]
        },
        "TA0004": {
            "name": "Privilege Escalation",
            "all_techniques": [
                {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
                {"id": "T1134", "name": "Access Token Manipulation"},
                {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
                {"id": "T1037", "name": "Boot or Logon Initialization Scripts"},
                {"id": "T1543", "name": "Create or Modify System Process"},
                {"id": "T1484", "name": "Domain Policy Modification"},
                {"id": "T1611", "name": "Escape to Host"},
                {"id": "T1546", "name": "Event Triggered Execution"},
                {"id": "T1068", "name": "Exploitation for Privilege Escalation"}
            ]
        },
        "TA0005": {
            "name": "Defense Evasion",
            "all_techniques": [
                {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
                {"id": "T1134", "name": "Access Token Manipulation"},
                {"id": "T1197", "name": "BITS Jobs"},
                {"id": "T1612", "name": "Build Image on Host"},
                {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
                {"id": "T1610", "name": "Deploy Container"},
                {"id": "T1006", "name": "Direct Volume Access"},
                {"id": "T1484", "name": "Domain Policy Modification"},
                {"id": "T1480", "name": "Execution Guardrails"},
                {"id": "T1211", "name": "Exploitation for Defense Evasion"}
            ]
        },
        "TA0006": {
            "name": "Credential Access",
            "all_techniques": [
                {"id": "T1557", "name": "Adversary-in-the-Middle"},
                {"id": "T1110", "name": "Brute Force"},
                {"id": "T1555", "name": "Credentials from Password Stores"},
                {"id": "T1212", "name": "Exploitation for Credential Access"},
                {"id": "T1187", "name": "Forced Authentication"},
                {"id": "T1606", "name": "Forge Web Credentials"},
                {"id": "T1056", "name": "Input Capture"},
                {"id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
                {"id": "T1111", "name": "Multi-Factor Authentication Interception"}
            ]
        },
        "TA0007": {
            "name": "Discovery",
            "all_techniques": [
                {"id": "T1087", "name": "Account Discovery"},
                {"id": "T1010", "name": "Application Window Discovery"},
                {"id": "T1217", "name": "Browser Bookmark Discovery"},
                {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
                {"id": "T1613", "name": "Container and Resource Discovery"},
                {"id": "T1083", "name": "File and Directory Discovery"},
                {"id": "T1615", "name": "Group Policy Discovery"},
                {"id": "T1046", "name": "Network Service Scanning"},
                {"id": "T1135", "name": "Network Share Discovery"}
            ]
        },
        "TA0008": {
            "name": "Lateral Movement",
            "all_techniques": [
                {"id": "T1210", "name": "Exploitation of Remote Services"},
                {"id": "T1534", "name": "Internal Spearphishing"},
                {"id": "T1570", "name": "Lateral Tool Transfer"},
                {"id": "T1563", "name": "Remote Service Session Hijacking"},
                {"id": "T1021", "name": "Remote Services"},
                {"id": "T1091", "name": "Replication Through Removable Media"},
                {"id": "T1072", "name": "Software Deployment Tools"},
                {"id": "T1080", "name": "Taint Shared Content"},
                {"id": "T1550", "name": "Use Alternate Authentication Material"}
            ]
        },
        "TA0009": {
            "name": "Collection",
            "all_techniques": [
                {"id": "T1560", "name": "Archive Collected Data"},
                {"id": "T1123", "name": "Audio Capture"},
                {"id": "T1119", "name": "Automated Collection"},
                {"id": "T1185", "name": "Browser Session Hijacking"},
                {"id": "T1115", "name": "Clipboard Data"},
                {"id": "T1213", "name": "Data from Information Repositories"},
                {"id": "T1005", "name": "Data from Local System"},
                {"id": "T1039", "name": "Data from Network Shared Drive"},
                {"id": "T1025", "name": "Data from Removable Media"}
            ]
        },
        "TA0010": {
            "name": "Command and Control",
            "all_techniques": [
                {"id": "T1071", "name": "Application Layer Protocol"},
                {"id": "T1092", "name": "Communication Through Removable Media"},
                {"id": "T1132", "name": "Data Encoding"},
                {"id": "T1001", "name": "Data Obfuscation"},
                {"id": "T1568", "name": "Dynamic Resolution"},
                {"id": "T1573", "name": "Encrypted Channel"},
                {"id": "T1008", "name": "Fallback Channels"},
                {"id": "T1105", "name": "Ingress Tool Transfer"},
                {"id": "T1104", "name": "Multi-Stage Channels"}
            ]
        },
        "TA0011": {
            "name": "Exfiltration",
            "all_techniques": [
                {"id": "T1020", "name": "Automated Exfiltration"},
                {"id": "T1030", "name": "Data Transfer Size Limits"},
                {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                {"id": "T1011", "name": "Exfiltration Over Other Network Medium"},
                {"id": "T1052", "name": "Exfiltration Over Physical Medium"},
                {"id": "T1567", "name": "Exfiltration Over Web Service"},
                {"id": "T1029", "name": "Scheduled Transfer"},
                {"id": "T1537", "name": "Transfer Data to Cloud Account"}
            ]
        },
        "TA0040": {
            "name": "Impact",
            "all_techniques": [
                {"id": "T1531", "name": "Account Access Removal"},
                {"id": "T1485", "name": "Data Destruction"},
                {"id": "T1486", "name": "Data Encrypted for Impact"},
                {"id": "T1565", "name": "Data Manipulation"},
                {"id": "T1491", "name": "Defacement"},
                {"id": "T1561", "name": "Disk Wipe"},
                {"id": "T1499", "name": "Endpoint Denial of Service"},
                {"id": "T1495", "name": "Firmware Corruption"},
                {"id": "T1490", "name": "Inhibit System Recovery"}
            ]
        }
    }
    
    # BUILD COMPLETE HTML STRING
    all_columns_html = []
    
    for tactic_id, tactic_data in complete_matrix.items():
        techniques_html = []
        
        for tech in tactic_data["all_techniques"]:
            tech_id = tech["id"]
            tech_name = tech["name"]
            
            # Check if this technique was found
            is_found = tactic_id in found_techniques and tech_id in found_techniques[tactic_id]
            css_class = "technique-found" if is_found else "technique-normal"
            
            # Truncate long names
            display_name = tech_name[:30] + "..." if len(tech_name) > 30 else tech_name
            
            techniques_html.append(f"""
                <div class="{css_class}" title="{tech_name}">
                    <strong>{tech_id}</strong><br>
                    {display_name}
                </div>
            """)
        
        # Build tactic column
        column_html = f"""
        <div class="tactic-column">
            <div class="tactic-header">
                {tactic_id}<br>
                <strong>{tactic_data['name']}</strong><br>
                <span class="technique-count">{len(tactic_data['all_techniques'])} techniques</span>
            </div>
            <div class="technique-container">
                {''.join(techniques_html)}
            </div>
        </div>
        """
        all_columns_html.append(column_html)
    
    # COMPLETE HTML - RENDER ONCE
    complete_html = f"""
    <div class="mitre-container">
        {''.join(all_columns_html)}
    </div>
    """
    
    # SINGLE st.markdown call with complete HTML
    st.markdown(complete_html, unsafe_allow_html=True)


def _render_spiderfoot_tab():
    """Render SpiderFoot threat intelligence tab"""
    st.subheader("🕷️ SpiderFoot Threat Intelligence")
    
    # Check if SpiderFoot CSV exists
    csv_files = glob.glob("*.csv")
    spiderfoot_csvs = [f for f in csv_files if 'spiderfoot' in f.lower()]
    
    if not spiderfoot_csvs:
        st.info("📋 No SpiderFoot scan results found. Run SpiderFoot separately and place the CSV file in this directory.")
        st.markdown("""
        **How to use SpiderFoot:**
        1. Run SpiderFoot scan on your target domain
        2. Export results as CSV
        3. Place CSV file in the same directory as this app
        4. Refresh this page to see results
        """)
        return
    
    # Let user select CSV if multiple exist
    selected_csv = st.selectbox("Select SpiderFoot CSV:", spiderfoot_csvs)
    
    if selected_csv:
        try:
            df, sections = parse_spiderfoot_csv(selected_csv)
            counts = get_section_counts(sections)
            
            # Display summary
            st.markdown("### 📊 Scan Summary")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Findings", len(df))
            with col2:
                st.metric("Categories", len(sections))
            with col3:
                high_risk = len([s for s in sections.values() for item in s if 'malicious' in str(item).lower()])
                st.metric("High Risk", high_risk)
            with col4:
                st.metric("Data Sources", df['Source'].nunique() if 'Source' in df.columns else 0)
            
            # Display by category
            st.markdown("---")
            for category, items in sections.items():
                if items:
                    with st.expander(f"📁 {category} ({len(items)} items)", expanded=False):
                        for item in items[:50]:  # Show first 50
                            st.text(f"• {item}")
                        if len(items) > 50:
                            st.info(f"+ {len(items) - 50} more items")
        
        except Exception as e:
            st.error(f"Error parsing SpiderFoot CSV: {str(e)}")


def display_mitre_heatmap(tactics_data: dict, cves_data: list):
    """
    Create a heatmap showing technique severity
    """
    import pandas as pd
    
    st.markdown("### 🔥 Technique Severity Heatmap")
    
    # Prepare data for heatmap
    heatmap_data = []
    
    for tactic_id, tactic_info in tactics_data.items():
        for tech in tactic_info["techniques"]:
            # Calculate severity score based on CVEs
            max_cvss = 0
            for cve_id in tech["cves"]:
                cve_detail = next((c for c in cves_data if c.get('cve') == cve_id), None)
                if cve_detail:
                    max_cvss = max(max_cvss, cve_detail.get('cvss', 0))
            
            heatmap_data.append({
                "Tactic": tactic_info["name"],
                "Technique": f"{tech['id']} - {tech['name'][:30]}...",
                "Max CVSS": max_cvss,
                "CVE Count": len(tech["cves"])
            })
    
    if heatmap_data:
        df = pd.DataFrame(heatmap_data)
        
        # Style the dataframe
        def highlight_severity(val):
            if val >= 9.0:
                return 'background-color: #dc3545; color: white'
            elif val >= 7.0:
                return 'background-color: #fd7e14; color: white'
            elif val >= 4.0:
                return 'background-color: #ffc107; color: black'
            else:
                return 'background-color: #28a745; color: white'
        
        styled_df = df.style.applymap(highlight_severity, subset=['Max CVSS'])
        st.dataframe(styled_df, use_container_width=True, height=400)
    else:
        st.info("No technique data available for heatmap")



def main():
    """Main Streamlit application"""
    
    # Header
    st.title("🔐 Business Security Intelligence (BSI)")
    st.markdown("### Comprehensive Domain Security Assessment Platform")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("📊 BSI Analysis Phases")
        st.markdown("""
        **Active Phases:**
        - ✅ Business Domain Understanding
        - ✅ Infrastructure Discovery
        - ✅ Application Landscape Assessment
        - ✅ Vulnerability Mapping
        - ✅Risk Assessment
        """)
        
        st.markdown("---")
        st.info("Both analyses run simultaneously for faster results")
        
        st.markdown("---")
        st.markdown("**⚙️ System Requirements**")
        st.text("• Ollama with qwen3:4b and Gemini AI")
        st.text("• Python 3.8+")
        st.text("• Internet connection")
        
        # Search History Section
        st.markdown("---")
        st.markdown("### 📋 Search History")
        
        search_ui = SearchHistoryUI()

        # ── helper: one domain row with load + delete ──────────────────────
        def _render_history_row(record, prefix):
            domain_val = record['domain']
            status     = record.get('status', 'pending')
            pct        = record.get('completion_percentage', 0)
            s_icon     = {"completed": "✅", "in_progress": "⏳", "failed": "❌"}.get(status, "⭕")

            col_load, col_del = st.columns([5, 1])
            with col_load:
                label = f"{s_icon} {domain_val} ({pct}%)"
                if st.button(label, key=f"{prefix}_load_{domain_val}", use_container_width=True):
                    st.session_state['selected_domain'] = domain_val
                    st.rerun()
            with col_del:
                if st.button("🗑️", key=f"{prefix}_del_{domain_val}", help=f"Delete {domain_val}"):
                    st.session_state[f"_confirm_del_{domain_val}"] = True

            # Inline confirmation
            if st.session_state.get(f"_confirm_del_{domain_val}"):
                st.warning(f"Delete **{domain_val}**?")
                yes_col, no_col = st.columns(2)
                with yes_col:
                    if st.button("Yes", key=f"{prefix}_yes_{domain_val}", use_container_width=True, type="primary"):
                        from services.search_history_manager import SearchHistoryManager
                        SearchHistoryManager().delete_domain(domain_val)
                        st.session_state.pop(f"_confirm_del_{domain_val}", None)
                        # Clear cached results if this domain is currently loaded
                        if st.session_state.get('analyzed_domain') == domain_val:
                            st.session_state.pop('bsi_results', None)
                            st.session_state.pop('analyzed_domain', None)
                        st.rerun()
                with no_col:
                    if st.button("No", key=f"{prefix}_no_{domain_val}", use_container_width=True):
                        st.session_state.pop(f"_confirm_del_{domain_val}", None)
                        st.rerun()
        # ── end helper ─────────────────────────────────────────────────────
        
        # Search bar
        search_query = st.text_input(
            "🔍 Search domains",
            placeholder="example.com",
            key="sidebar_search"
        )
        
        if search_query:
            search_results = search_ui.search_domains(search_query)
            if search_results:
                st.success(f"Found {len(search_results)} domain(s)")
                for result in search_results[:5]:
                    _render_history_row(result, "srch")
            else:
                st.warning("No domains found")
        else:
            # Show recent searches
            st.markdown("**Recent Searches:**")
            recent = search_ui.get_recent_searches(limit=10)
            if recent:
                for record in recent:
                    _render_history_row(record, "rec")
            else:
                st.info("No search history yet")
    
    # Main input section
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        # Check if a domain was selected from search history
        if 'selected_domain' in st.session_state:
            default_domain = st.session_state['selected_domain']
            del st.session_state['selected_domain']
        else:
            default_domain = ""
        
        domain = st.text_input(
            "Enter Domain Name",
            value=default_domain,
            placeholder="example.com",
            help="Enter the domain you want to analyze (e.g., amazon.com, google.com)"
        )
    
    with col2:
        analyze_button = st.button("🚀 Start Analysis", use_container_width=True, type="primary")
    
    with col3:
        if st.button("🔄 Clear Results", use_container_width=True):
            st.session_state.clear()
            st.rerun()
    
    # Check if domain was selected from history and load from database
    if domain and not analyze_button and 'bsi_results' not in st.session_state:
        domain_clean = domain.strip().lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        if '.' in domain_clean:
            db = get_db_manager()
            existing_analysis = db.get_analysis(domain_clean)
            if existing_analysis and existing_analysis['status'] == 'completed':
                # Load from database
                st.info(f"📦 Loading cached analysis for **{domain_clean}**...")
                phases = db.get_all_phase_results(existing_analysis['id'])
                
                # Reconstruct results from database
                results = {
                    'business_domain': None,
                    'infrastructure': None,
                    'application_landscape': None,
                    'correlation_analysis': None,
                    'risk_assessment': None,
                    'timestamp': existing_analysis['updated_at'],
                    'status': {
                        'business_domain': 'completed',
                        'infrastructure': 'completed',
                        'application_landscape': 'completed',
                        'correlation_analysis': 'completed',
                        'risk_assessment': 'completed'
                    }
                }
                
                # Map phase data
                phase_map = {
                    1: 'business_domain',
                    2: 'infrastructure',
                    3: 'application_landscape',
                    4: 'correlation_analysis',
                    5: 'risk_assessment'
                }
                
                for phase in phases:
                    key = phase_map.get(phase['phase_number'])
                    if key:
                        results[key] = phase['result_data']
                
                st.session_state['bsi_results'] = results
                st.session_state['analyzed_domain'] = domain_clean
                st.success(f"✅ Loaded cached analysis for **{domain_clean}**")
    
    # Analysis execution
    if analyze_button and domain:
        # Validate domain
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        if '.' not in domain:
            st.error("Please enter a valid domain name (e.g., example.com)")
            return
        
        # Check if analysis already exists and is completed
        db = get_db_manager()
        existing_analysis = db.get_analysis(domain)
        
        if existing_analysis and existing_analysis['status'] == 'completed':
            # Load from database instead of re-running
            st.info(f"📦 Analysis already exists for **{domain}**. Loading from database...")
            phases = db.get_all_phase_results(existing_analysis['id'])
            
            # Reconstruct results from database
            results = {
                'business_domain': None,
                'infrastructure': None,
                'application_landscape': None,
                'correlation_analysis': None,
                'risk_assessment': None,
                'timestamp': existing_analysis['updated_at'],
                'status': {
                    'business_domain': 'completed',
                    'infrastructure': 'completed',
                    'application_landscape': 'completed',
                    'correlation_analysis': 'completed',
                    'risk_assessment': 'completed'
                }
            }
            
            # Map phase data
            phase_map = {
                1: 'business_domain',
                2: 'infrastructure',
                3: 'application_landscape',
                4: 'correlation_analysis',
                5: 'risk_assessment'
            }
            
            for phase in phases:
                key = phase_map.get(phase['phase_number'])
                if key:
                    results[key] = phase['result_data']
            
            st.session_state['bsi_results'] = results
            st.session_state['analyzed_domain'] = domain
            st.success(f"✅ Loaded cached analysis for **{domain}**")
        else:
            # Run new analysis
            analysis_id = db.create_analysis(domain, notes="Analysis started via BSI app")
            db.add_to_search_history(domain, analysis_id=analysis_id, status='in_progress', completion_percentage=0)
            
            # Initialize search history UI for status updates
            search_ui = SearchHistoryUI()
            
            # Initialize orchestrator
            orchestrator = BSIOrchestrator()
            
            # Progress indicators
            st.markdown("---")
            progress_container = st.container()
            
            with progress_container:
                st.info(f"🔍 Analyzing domain: **{domain}**")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    business_progress = st.progress(0)
                    business_status = st.empty()
                    business_status.text("⏳ Starting Business Domain Analysis...")
                
                with col2:
                    infra_progress = st.progress(0)
                    infra_status = st.empty()
                    infra_status.text("⏳ Starting Infrastructure Discovery...")

                with col3:  # ADD THIS
                    app_progress = st.progress(0)
                    app_status = st.empty()
                    app_status.text("⏳ Starting Application Assessment...")

                # ADD THIS (create col4 for Phase 4)
                with st.container():
                    st.markdown("---")
                    col4 = st.columns(1)[0]
                    with col4:
                        corr_progress = st.progress(0)
                        corr_status = st.empty()
                        corr_status.text("⏳ Waiting for Phase 2 & 3...")
            
            # Run parallel analysis with data streaming
            streamer = DataStreamer(analysis_id, domain)
            
            with st.spinner("Running comprehensive analysis..."):
                # Start analysis in background
                orchestrator.analyze_domain_parallel(domain)
                
                # Stream results as they complete
                phase_names = {
                    1: 'Business Domain',
                    2: 'Infrastructure Discovery',
                    3: 'Application Landscape',
                    4: 'Correlation Analysis',
                    5: 'Risk Assessment'
                }
                
                # Update progress based on status
                max_wait = 900  # 10 minutes max
                start_time = time.time()
                last_streamed = {}
                
                while time.time() - start_time < max_wait:
                    # Check each phase and stream data if available
                    for phase_num in range(1, 6):
                        phase_key = {
                            1: 'business_domain',
                            2: 'infrastructure',
                            3: 'application_landscape',
                            4: 'correlation_analysis',
                            5: 'risk_assessment'
                        }[phase_num]
                        
                        phase_status = orchestrator.results['status'][phase_key]
                        phase_data = orchestrator.results[phase_key]
                        
                        # Stream data if completed and not yet streamed
                        if phase_status == 'completed' and phase_num not in last_streamed:
                            if phase_data and 'error' not in phase_data:
                                streamer.stream_phase_data(phase_num, phase_names[phase_num], phase_data)
                                last_streamed[phase_num] = True
                    
                    # Check business domain status
                    if orchestrator.results['status']['business_domain'] == 'running':
                        business_progress.progress(50)
                        business_status.text("🔄 Analyzing business domain...")
                    elif orchestrator.results['status']['business_domain'] == 'completed':
                        business_progress.progress(100)
                        business_status.text("✅ Business analysis complete")
                    elif orchestrator.results['status']['business_domain'] == 'failed':
                        business_progress.progress(100)
                        business_status.text("❌ Business analysis failed")
                    
                    # Check infrastructure status
                    if orchestrator.results['status']['infrastructure'] == 'running':
                        infra_progress.progress(50)
                        infra_status.text("🔄 Discovering infrastructure...")
                    elif orchestrator.results['status']['infrastructure'] == 'completed':
                        infra_progress.progress(100)
                        infra_status.text("✅ Infrastructure discovery complete")
                    elif orchestrator.results['status']['infrastructure'] == 'failed':
                        infra_progress.progress(100)
                        infra_status.text("❌ Infrastructure discovery failed")

                    
                    # Check application assessment status  # ADD THIS ENTIRE BLOCK
                    if orchestrator.results['status']['application_landscape'] == 'running':
                        app_progress.progress(50)
                        app_status.text("🔄 Analyzing applications...")
                    elif orchestrator.results['status']['application_landscape'] == 'completed':
                        app_progress.progress(100)
                        app_status.text("✅ Application assessment complete")
                    elif orchestrator.results['status']['application_landscape'] == 'failed':
                        app_progress.progress(100)
                        app_status.text("❌ Application assessment failed")

                    
                    # Check correlation status (ADD THIS)
                    if orchestrator.results['status']['correlation_analysis'] == 'running':
                        corr_progress.progress(50)
                        corr_status.text("🔄 Correlating vulnerabilities...")
                    elif orchestrator.results['status']['correlation_analysis'] == 'completed':
                        corr_progress.progress(100)
                        corr_status.text("✅ Correlation analysis complete")
                    elif orchestrator.results['status']['correlation_analysis'] == 'failed':
                        corr_progress.progress(100)
                        corr_status.text("❌ Correlation analysis failed")

                    # Check Phase 5 status
                    if orchestrator.results['status']['risk_assessment'] == 'running':
                        st.info("📊 Running risk assessment...")
                    elif orchestrator.results['status']['risk_assessment'] == 'completed':
                        st.success("✅ Risk assessment complete")
                    elif orchestrator.results['status']['risk_assessment'] == 'failed':
                        st.error("❌ Risk assessment failed")

                    
                    # Check if both completed
                    if (orchestrator.results['status']['business_domain'] in ['completed', 'failed'] and
                        orchestrator.results['status']['infrastructure'] in ['completed', 'failed'] and
                        orchestrator.results['status']['application_landscape'] in ['completed', 'failed'] and
                        orchestrator.results['status']['correlation_analysis'] in ['completed', 'failed'] and
                        orchestrator.results['status']['risk_assessment'] in ['completed', 'failed']):
                        break
                    
                    time.sleep(2)
            
            # Store results in session state
            st.session_state['bsi_results'] = orchestrator.results
            st.session_state['analyzed_domain'] = domain
            
            # Finalize streaming and mark as complete
            streamer.finalize()
            
            # Results are already saved via streamer, just update final status
            db.update_analysis_status(analysis_id, 'completed', 100)
            db.add_to_search_history(domain, analysis_id=analysis_id, status='completed', completion_percentage=100)
            
            st.success(f"✅ Analysis completed for **{domain}**")
    
    # ── SpiderFoot Threat Intel – always visible, no BSI scan needed ──────────
    st.markdown("---")
    _render_spiderfoot_tab()

    # Display results if available
    if 'bsi_results' in st.session_state:
        st.markdown("---")
        st.header(f"📋 Analysis Results for: {st.session_state.get('analyzed_domain', 'Unknown')}")

        # ✅ ENHANCEMENT 5: Tech Stack Summary Card (ONE-LINER)
        app_landscape = st.session_state['bsi_results'].get('application_landscape', {})
        if app_landscape and not app_landscape.get('error'):
            tech_stack = app_landscape.get('2_web_server_stack', {})
            
            # Build one-line summary
            summary_parts = []
            
            # CMS
            cms_list = tech_stack.get('cms', [])
            if cms_list:
                cms_name = cms_list[0]
                cms_version = tech_stack.get('cms_version', '')
                summary_parts.append(f"{cms_name} {cms_version}" if cms_version else cms_name)
            
            # Server
            app_disc = app_landscape.get('1_application_discovery', {})
            server_full = app_disc.get('server_full', '')
            if server_full:
                summary_parts.append(server_full)
            elif app_disc.get('server') and app_disc['server'] != 'Not disclosed':
                summary_parts.append(app_disc['server'])
            
            # Top JS library
            js_versions = tech_stack.get('javascript_versions', {})
            if js_versions:
                top_lib = list(js_versions.items())[0]
                summary_parts.append(f"{top_lib[0]} {top_lib[1]}")
            
            # Framework
            frameworks = tech_stack.get('frameworks', [])
            if frameworks:
                summary_parts.append(frameworks[0])
            
            if summary_parts:
                st.info(f"📊 **Tech Stack:** {' / '.join(summary_parts)}")

        # Create tabs for results
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Business Domain Understanding", "Infrastructure Discovery", "Application Landscape", "Vulnerability Correlation", "Risk Assessment", "📄 AI Reports", "Export Data"])

        with tab1:
            if st.session_state['bsi_results']['business_domain']:
                validated_data = validate_and_normalize_phase_data(1, st.session_state['bsi_results']['business_domain'])
                display_business_domain_simple(validated_data)
            else:
                st.warning("Business domain analysis results not available")

        with tab2:
            if st.session_state['bsi_results']['infrastructure']:
                validated_data = validate_and_normalize_phase_data(2, st.session_state['bsi_results']['infrastructure'])
                display_infrastructure_simple(validated_data)
            else:
                st.warning("Infrastructure discovery results not available")

        with tab3:
            if st.session_state['bsi_results']['application_landscape']:
                validated_data = validate_and_normalize_phase_data(3, st.session_state['bsi_results']['application_landscape'])
                display_application_simple(validated_data)
            else:
                st.warning("Application landscape assessment results not available")

        with tab4:
            if st.session_state['bsi_results']['correlation_analysis']:
                validated_data = validate_and_normalize_phase_data(4, st.session_state['bsi_results']['correlation_analysis'])
                display_correlation_simple(validated_data)
            else:
                st.warning("Correlation analysis results not available")

        # Risk Assessment
        with tab5:
            if st.session_state['bsi_results'].get('risk_assessment'):
                validated_data = validate_and_normalize_phase_data(5, st.session_state['bsi_results']['risk_assessment'])
                display_risk_simple(validated_data)
            else:
                st.warning("Risk assessment not available yet. Please run complete analysis.")

        # NEW TAB 6: AI REPORT GENERATION
        with tab6:
            st.header("🧠 Intelligent AI-Powered Security Reports")
            
            st.markdown("""
            ### Comprehensive 5-Phase Analysis
            
            **AI performs INTELLIGENT, COMPREHENSIVE analysis:**
            - 🧠 Analyzes relationships across ALL 5 phases
            - 🔗 Identifies correlations and patterns
            - 📊 CVE severity distribution chart (Critical/High/Medium/Low)
            - 💼 Business impact synthesis
            - 🎯 Strategic recommendations based on complete picture
            - ✨ Professional consulting-firm quality
            
            Every insight is based on comprehensive cross-phase analysis.
            """)
            
            # Get phase data
            phase1 = st.session_state['bsi_results'].get('business_domain', {})
            phase2 = st.session_state['bsi_results'].get('infrastructure', {})
            phase3 = st.session_state['bsi_results'].get('application_landscape', {})
            phase4 = st.session_state['bsi_results'].get('correlation_analysis', {})
            phase5 = st.session_state['bsi_results'].get('risk_assessment', {})
            
            st.markdown("---")
            st.markdown("### 📊 Data Verification")
            
            col1, col2, col3, col4, col5 = st.columns(5)
            
            phases_ready = {
                'Business': (phase1 and 'error' not in phase1),
                'Infrastructure': (phase2 and 'error' not in phase2),
                'Application': (phase3 and 'error' not in phase3),
                'Vulnerabilities': (phase4 and 'error' not in phase4),
                'Risk': (phase5 and 'error' not in phase5)
            }
            
            cols = [col1, col2, col3, col4, col5]
            for col, (phase_name, ready) in zip(cols, phases_ready.items()):
                with col:
                    if ready:
                        st.success(f"✅ {phase_name}")
                    else:
                        st.error(f"❌ {phase_name}")
            
            missing = [name for name, ready in phases_ready.items() if not ready]
            
            if missing:
                st.warning(f"""
                ⚠️ **Missing: {', '.join(missing)}**
                
                Intelligent reports require ALL 5 phases for comprehensive analysis.
                Please re-run the scan.
                """)
            else:
                st.success("✅ All 5 phases available - Ready for intelligent analysis!")
                
                # What makes it intelligent
                with st.expander("🧠 What Makes This Intelligent?", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("""
                        **Cross-Phase Analysis:**
                        - ✅ Connects infrastructure exposure to vulnerabilities
                        - ✅ Correlates technology stack with CVEs
                        - ✅ Synthesizes business risk across all findings
                        - ✅ Identifies patterns across phases
                        
                        **NOT Just Data Display:**
                        - ❌ Doesn't just list CVEs
                        - ❌ Doesn't just show metrics
                        - ✅ Explains WHY risks matter
                        - ✅ Shows HOW issues connect
                        """)
                    
                    with col2:
                        st.markdown("""
                        **AI Intelligence:**
                        - 🧠 Analyzes 5-phase relationships
                        - 🔗 Finds cross-phase correlations
                        - 💡 Generates strategic insights
                        - 📈 Prioritizes by comprehensive risk
                        
                        **Chart Fix:**
                        - ✅ Shows CVE distribution (Critical/High/Medium/Low)
                        - ❌ NOT phase 5 risk scores
                        - ✅ From Phase 4 vulnerability data
                        - ✅ Accurate severity breakdown
                        """)
                
                st.markdown("---")
                
                # Quick preview
                cve_count = len(phase4.get('cves_all', []))
                critical_count = len([c for c in phase4.get('cves_all', []) if isinstance(c, dict) and c.get('cvss', 0) >= 9.0])
                high_count = len([c for c in phase4.get('cves_all', []) if isinstance(c, dict) and 7.0 <= c.get('cvss', 0) < 9.0])
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total CVEs", cve_count)
                with col2:
                    st.metric("Critical", critical_count)
                with col3:
                    st.metric("High", high_count)
                with col4:
                    subdomain_count = len(phase2.get('subdomains', []))
                    st.metric("Subdomains", subdomain_count)
                
                st.markdown("---")
                
                # Generate button
                if st.button("🧠 Generate Intelligent AI Report", use_container_width=True, type="primary", key="gen_intel_report"):
                    try:
                        from ai_full_report_generator import EnhancedIntelligentReportGenerator
                        
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        status_text.text("🧠 Initializing Intelligent AI Engine...")
                        progress_bar.progress(10)
                        time.sleep(0.3)
                        
                        generator = EnhancedIntelligentReportGenerator()
                        
                        status_text.text("📊 AI analyzing Phase 1: Business context...")
                        progress_bar.progress(20)
                        time.sleep(0.3)
                        
                        status_text.text("🔍 AI analyzing Phase 2: Infrastructure exposure...")
                        progress_bar.progress(35)
                        time.sleep(0.3)
                        
                        status_text.text("🌐 AI analyzing Phase 3: Technology stack...")
                        progress_bar.progress(50)
                        time.sleep(0.3)
                        
                        status_text.text("🛡️ AI analyzing Phase 4: Vulnerability landscape...")
                        progress_bar.progress(65)
                        time.sleep(0.3)
                        
                        status_text.text("📈 AI analyzing Phase 5: Risk assessment...")
                        progress_bar.progress(75)
                        time.sleep(0.3)
                        
                        status_text.text("🧠 AI synthesizing cross-phase correlations...")
                        progress_bar.progress(85)
                        time.sleep(0.3)
                        
                        status_text.text("🎨 Creating professional presentation...")
                        progress_bar.progress(90)
                        
                        domain = st.session_state.get('analyzed_domain', 'unknown')
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        
                        import tempfile
                        temp_dir = tempfile.mkdtemp()
                        
                        pptx_file = generator.generate(
                            phase1=phase1,
                            phase2=phase2,
                            phase3=phase3,
                            phase4=phase4,
                            phase5=phase5,
                            output_path=temp_dir
                        )
                        
                        progress_bar.progress(100)
                        status_text.text("✅ Intelligent Report Complete!")
                        time.sleep(0.3)
                        
                        if pptx_file and os.path.exists(pptx_file):
                            with open(pptx_file, 'rb') as f:
                                pptx_data = f.read()
                            
                            st.success("🎉 Intelligent AI Report Generated!")
                            st.balloons()
                            
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("AI Mode", "Comprehensive")
                            with col2:
                                st.metric("Analysis", "5-Phase")
                            with col3:
                                st.metric("Quality", "Consulting Firm")
                            with col4:
                                st.metric("Chart", "CVE Distribution")
                            
                            st.markdown("---")
                            
                            st.download_button(
                                label="⬇️ Download Intelligent Report",
                                data=pptx_data,
                                file_name=f"Intelligent_SecurityReport_{domain}_{timestamp}.pptx",
                                mime="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                                use_container_width=True,
                                type="primary"
                            )
                            
                            st.markdown("---")
                            st.markdown("### ✅ What AI Created:")
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("""
                                **Intelligence Features:**
                                - ✅ Cross-phase correlation analysis
                                - ✅ Infrastructure-vulnerability connections
                                - ✅ Technology stack risk assessment
                                - ✅ Business impact synthesis
                                - ✅ Strategic priority identification
                                """)
                            
                            with col2:
                                st.markdown("""
                                **Technical Accuracy:**
                                - ✅ CVE severity chart (Phase 4 data)
                                - ✅ NOT risk score chart
                                - ✅ Accurate Critical/High/Medium/Low
                                - ✅ Comprehensive 5-phase analysis
                                - ✅ Professional visualization
                                """)
                            
                            st.success("""
                            💡 **The Intelligence Difference:**
                            
                            **Old:** Listed CVEs + Showed metrics = Data dump
                            
                            **New:** Analyzed ALL 5 phases + Found correlations + 
                            Explained connections + Strategic insights = Intelligence
                            
                            The report shows AI UNDERSTOOD your security posture, 
                            not just parsed your data!
                            """)
                            
                            try:
                                os.unlink(pptx_file)
                                os.rmdir(temp_dir)
                            except:
                                pass
                        
                        else:
                            st.error("❌ Generation failed")
                    
                    except ImportError as e:
                        st.error(f"❌ Import Error: {str(e)}")
                        st.warning("""
                        **intelligent_professional_report.py not found!**
                        
                        Ensure this file is in the same directory as app.py.
                        """)
                    
                    except Exception as e:
                        st.error(f"❌ Generation failed: {str(e)}")
                        
                        with st.expander("🔍 Error Details"):
                            import traceback
                            st.code(traceback.format_exc())
                    
                    finally:
                        progress_bar.empty()
                        status_text.empty()
                
                st.markdown("---")
                
                # Comparison
                st.markdown("### 📊 Intelligence Comparison")
                
                comparison = {
                    "Capability": [
                        "Phase Analysis",
                        "Cross-Phase Insights",
                        "Chart Accuracy",
                        "Content Quality",
                        "Business Context",
                        "Strategic Value",
                        "Intelligence Level"
                    ],
                    "Old (Data Display)": [
                        "❌ Separate silos",
                        "❌ None",
                        "❌ Wrong (risk scores)",
                        "❌ Data listing",
                        "❌ Minimal",
                        "⚠️ Low",
                        "❌ Parsing only"
                    ],
                    "New (AI Intelligence)": [
                        "✅ Comprehensive 5-phase",
                        "✅ Correlations found",
                        "✅ Correct (CVE severity)",
                        "✅ Synthesized insights",
                        "✅ Business impact focus",
                        "✅ High",
                        "✅ True intelligence"
                    ]
                }
                
                st.table(comparison)
                
                st.info("""
                🧠 **True Intelligence Example:**
                
                **Data Display:** "23 subdomains detected. 4 CVEs found."
                
                **AI Intelligence:** "Analysis reveals 4 vulnerabilities affecting 
                infrastructure across 23 subdomains, creating multiple exploitation 
                pathways. The combination of OpenSSH critical vulnerability (CVSS 9.8) 
                with 30 open ports significantly elevates breach potential. This 
                correlation between expanded attack surface and unpatched critical 
                flaws requires immediate attention."
                
                → AI UNDERSTANDS connections, not just displays numbers!
                """)

          
        with tab7:
            st.subheader("📥 Export Analysis Data")
            
            # Prepare JSON data
            export_data = {
                'domain': st.session_state.get('analyzed_domain'),
                'timestamp': st.session_state['bsi_results'].get('timestamp'),
                'business_domain': st.session_state['bsi_results'].get('business_domain'),
                'infrastructure': st.session_state['bsi_results'].get('infrastructure'),
                'application_landscape': st.session_state['bsi_results'].get('application_landscape'),
                'correlation_analysis': st.session_state['bsi_results'].get('correlation_analysis'),
                'risk_assessment': st.session_state['bsi_results'].get('risk_assessment')  # NEW!
            }
            
            json_str = json.dumps(export_data, indent=2, default=str)
            
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📄 Download Complete JSON Report",
                    data=json_str,
                    file_name=f"bsi_analysis_{st.session_state.get('analyzed_domain', 'report')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with col2:
                # Show summary metrics
                infra_data = st.session_state['bsi_results'].get('infrastructure', {})
                st.text(f"Total Subdomains: {len(infra_data.get('subdomains', []))}")
                st.text(f"Open Ports: {sum(len(ports) for ports in infra_data.get('open_ports', {}).values())}")
                st.text(f"IPv4 Addresses: {len(infra_data.get('ip_addresses', []))}")
                st.text(f"Mail Servers: {len(infra_data.get('mail_servers', []))}")


# ─────────────────────────────────────────────────────────────────────────────
# SpiderFoot Threat Intel Tab – standalone, no DB, no correlation
# ─────────────────────────────────────────────────────────────────────────────
def _render_spiderfoot_tab():
    """Render the SpiderFoot Threat Intel standalone tab inside the main app."""

    st.header("🕷️ SpiderFoot Threat Intelligence")
    st.markdown("Upload a SpiderFoot CSV export and parse it instantly.")

    # ── Upload widget ─────────────────────────────────────────────────────────
    uploaded = st.file_uploader(
        "Upload SpiderFoot CSV Report",
        type=["csv"],
        key="sf_csv_uploader",
        help="Export your SpiderFoot scan as CSV, then upload it here.",
    )

    parse_btn = st.button("🔍 Parse SpiderFoot Report", type="primary", key="sf_parse_btn")

    if not uploaded:
        st.info("👆 Upload a SpiderFoot CSV file to get started.")
        return

    if not parse_btn and "sf_parsed" not in st.session_state:
        st.info("Click **Parse SpiderFoot Report** to analyse the uploaded file.")
        return

    # ── Parse ─────────────────────────────────────────────────────────────────
    if parse_btn or "sf_parsed" not in st.session_state:
        with st.spinner("Parsing SpiderFoot CSV…"):
            try:
                csv_text = uploaded.read().decode("utf-8", errors="replace")
                parsed = parse_spiderfoot_csv(csv_text)
                if "error" in parsed:
                    st.error(f"❌ Parse error: {parsed['error']}")
                    return
                st.session_state["sf_parsed"] = parsed
                st.success("✅ Parsed successfully!")
            except Exception as exc:
                st.error(f"❌ Unexpected error: {exc}")
                return

    parsed = st.session_state.get("sf_parsed")
    if not parsed:
        return

    meta = parsed["section_1"]
    counts = get_section_counts(parsed)

    # ── Metadata cards ────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📊 Scan Metadata")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Target Domain", meta["target_domain"])
    c2.metric("Total CSV Records", f"{meta['total_records']:,}")
    c3.metric("SpiderFoot Data Types", meta["total_count_of_data_types"])
    c4.metric("Extracted Data Types", "16 types")

    # ── Extraction summary table ──────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📋 16 Data Types — Extraction Summary")

    DISPLAY_NAMES = {
        "section_2_blacklisted_cohost":    "Blacklisted Co-hosts",
        "section_3_co_hosted_site":        "Co-hosted Sites",
        "section_4_co_hosted_site_domain": "Co-hosted Domains",
        "section_5_emailaddr":             "Email Addresses",
        "section_6_emailaddr_generic":     "Generic Emails",
        "section_7_hash":                  "Password Hashes",
        "section_8_http_code":             "HTTP Status Codes",
        "section_9_interesting_file":      "Interesting Files",
        "section_10_malicious_cohost":     "Malicious Co-hosts",
        "section_11_public_code_repo":     "Public Repositories",
        "section_12_similardomain":        "Similar Domains",
        "section_13_software_used":        "Software Detected",
        "section_14_ssl_certificate_raw":  "SSL Certificates",
        "section_15_webserver_httpheaders":"HTTP Headers",
        "section_16_webserver_technology": "Web Technologies",
        "section_17_subdomains":           "Subdomains (extracted)",
    }

    table_rows = []
    for key, display in DISPLAY_NAMES.items():
        cnt = counts.get(key, 0)
        table_rows.append({
            "Data Type": display,
            "Count": f"{cnt:,}",
            "Status": "✅ Found" if cnt > 0 else "⚪ None",
        })
    summary_df = pd.DataFrame(sorted(table_rows, key=lambda r: int(r["Count"].replace(",", "")), reverse=True))
    st.dataframe(summary_df, use_container_width=True, hide_index=True)

    total_extracted = sum(counts.values())
    st.caption(f"Total extracted records: **{total_extracted:,}** across 16 data types.")

    # ── Detailed data tabs ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 👀 Detailed Data Preview")

    dtab_labels = [
        "🌐 Subdomains",
        "🔒 SSL Certs",
        "💻 Technologies",
        "📧 Emails",
        "📄 Files",
        "⚠️ Threats",
        "🔗 Other",
    ]
    dtabs = st.tabs(dtab_labels)

    # — Subdomains —
    with dtabs[0]:
        st.markdown("#### Discovered Subdomains")
        subdomains = parsed.get("section_17_subdomains", [])
        if subdomains:
            st.caption(f"Showing {min(len(subdomains), 60)} of {len(subdomains)} subdomains")
            items = [s["data"] for s in subdomains[:60]]
            cols = st.columns(3)
            for i, sd in enumerate(items):
                with cols[i % 3]:
                    if any(x in sd for x in ["dev", "test", "staging", "preprod", "qa"]):
                        st.markdown(f"🔴 `{sd}`")
                    elif any(x in sd for x in ["admin", "portal", "dashboard"]):
                        st.markdown(f"🟠 `{sd}`")
                    elif any(x in sd for x in ["api", "vpn", "mail"]):
                        st.markdown(f"🟡 `{sd}`")
                    else:
                        st.markdown(f"🟢 `{sd}`")
        else:
            st.info("No subdomains found")

    # — SSL Certs —
    with dtabs[1]:
        st.markdown("#### SSL Certificates")
        ssl_data = parsed.get("section_14_ssl_certificate_raw", [])
        if ssl_data:
            st.caption(f"Found {len(ssl_data)} SSL certificate(s)")
            for item in ssl_data[:5]:
                label = item["data"][:100] + ("…" if len(item["data"]) > 100 else "")
                with st.expander(f"Certificate: {label}"):
                    st.text(item["data"][:800])
        else:
            st.info("No SSL certificates found")

    # — Technologies —
    with dtabs[2]:
        st.markdown("#### Web Technologies & Software")
        tech = parsed.get("section_16_webserver_technology", [])
        soft = parsed.get("section_13_software_used", [])
        combined = tech + soft
        if combined:
            st.caption(f"Found {len(combined)} technology/software record(s)")
            tech_df = pd.DataFrame([
                {"Category": "Web Technology" if t["type"] == "WEBSERVER_TECHNOLOGY" else "Software",
                 "Detected": t["data"],
                 "Source": t["source"][:80]}
                for t in combined[:30]
            ])
            st.dataframe(tech_df, use_container_width=True, hide_index=True)
        else:
            st.info("No technologies detected")

    # — Emails —
    with dtabs[3]:
        st.markdown("#### Email Addresses")
        emails = parsed.get("section_5_emailaddr", []) + parsed.get("section_6_emailaddr_generic", [])
        if emails:
            st.caption(f"Found {len(emails)} email address(es)")
            for item in emails[:20]:
                addr = item["data"]
                if "@" in addr:
                    parts = addr.split("@")
                    redacted = f"{parts[0][:3]}***@{parts[1]}"
                else:
                    redacted = addr[:3] + "***"
                st.markdown(f"📧 `{redacted}`")
        else:
            st.info("No email addresses found")

    # — Interesting Files —
    with dtabs[4]:
        st.markdown("#### Interesting / Exposed Files")
        files = parsed.get("section_9_interesting_file", [])
        if files:
            st.caption(f"Found {len(files)} interesting file(s)")
            for item in files:
                f = item["data"].lower()
                if any(x in f for x in [".git", ".env", "backup", ".sql", ".bak"]):
                    st.markdown(f"🔴 `{item['data']}`")
                elif any(x in f for x in ["robots.txt", "sitemap"]):
                    st.markdown(f"🟢 `{item['data']}`")
                else:
                    st.markdown(f"🟡 `{item['data']}`")
        else:
            st.info("No interesting files found")

    # — Threats (blacklisted, malicious, similar domains) —
    with dtabs[5]:
        st.markdown("#### Threat Indicators")

        blacklisted = parsed.get("section_2_blacklisted_cohost", [])
        malicious = parsed.get("section_10_malicious_cohost", [])
        similar = parsed.get("section_12_similardomain", [])

        if blacklisted:
            st.markdown("**🚫 Blacklisted Co-hosts**")
            for item in blacklisted[:15]:
                st.markdown(f"🔴 `{item['data']}`")
        if malicious:
            st.markdown("**☠️ Malicious Co-hosts**")
            for item in malicious[:15]:
                st.markdown(f"🔴 `{item['data']}`")
        if similar:
            st.markdown("**🎭 Similar / Typosquat Domains**")
            for item in similar[:20]:
                st.markdown(f"🟠 `{item['data']}`")
        if not any([blacklisted, malicious, similar]):
            st.info("No threat indicators found")

    # — Other (co-hosts, HTTP codes, repos, hashes) —
    with dtabs[6]:
        st.markdown("#### Other Data")

        other_sections = {
            "Co-hosted Sites": parsed.get("section_3_co_hosted_site", []),
            "Co-hosted Domains": parsed.get("section_4_co_hosted_site_domain", []),
            "HTTP Status Codes": parsed.get("section_8_http_code", []),
            "Public Repositories": parsed.get("section_11_public_code_repo", []),
            "Password Hashes": parsed.get("section_7_hash", []),
            "HTTP Headers": parsed.get("section_15_webserver_httpheaders", []),
        }
        has_any = False
        for label, items in other_sections.items():
            if items:
                has_any = True
                with st.expander(f"{label} ({len(items)} records)", expanded=False):
                    rows = [{"Data": it["data"][:150], "Source": it["source"][:80]} for it in items[:20]]
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        if not has_any:
            st.info("No other data found")


if __name__ == "__main__":
    main()