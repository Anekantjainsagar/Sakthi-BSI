"""
Phase 1: Main Analyzer
Orchestrates all Phase 1 business intelligence analysis
"""

import asyncio
import logging
from typing import Dict, Any
from .api_queries import APIQueries
from .data_extraction import DataExtraction
from .ai_analysis import AIAnalysis

logger = logging.getLogger(__name__)


class CompanyIntelligenceAnalyzer:
    """Main analyzer for Phase 1: Business Domain Understanding"""
    
    def __init__(self):
        self.api_queries = APIQueries()
        self.data_extraction = DataExtraction()
        self.ai_analysis = AIAnalysis(use_gemini=True)
        
        logger.info("CompanyIntelligenceAnalyzer initialized")
    
    async def analyze_company_async(self, company_name: str, domain: str = None) -> Dict[str, Any]:
        """Main entry point for company analysis (async - T1.1: Parallelize Phase 1 API calls)"""
        
        if not domain:
            domain = company_name.lower().replace(' ', '') + '.com'
        
        logger.info(f"Starting async analysis for {company_name} ({domain})")
        
        # T1.1: Parallelize all Phase 1 API calls using asyncio.gather()
        # Collect data from all sources in parallel
        hunter_data, hostio_data, abstractapi_data = await asyncio.gather(
            self.api_queries.query_hunter_io_async(domain),
            self.api_queries.query_hostio_async(domain),
            self.api_queries.query_abstractapi_company_async(domain),
            return_exceptions=True
        )
        
        # Handle exceptions from parallel calls
        if isinstance(hunter_data, Exception):
            logger.error(f"Hunter.io error: {hunter_data}")
            hunter_data = {'status': 'error', 'emails': [], 'error': str(hunter_data)}
        if isinstance(hostio_data, Exception):
            logger.error(f"Host.io error: {hostio_data}")
            hostio_data = {'status': 'error', 'error': str(hostio_data)}
        if isinstance(abstractapi_data, Exception):
            logger.error(f"AbstractAPI error: {abstractapi_data}")
            abstractapi_data = {'status': 'error', 'error': str(abstractapi_data)}
        
        # Data extraction (can be parallelized too)
        whois_data, scraped_data = await asyncio.gather(
            asyncio.to_thread(self.data_extraction.get_whois_information, domain),
            asyncio.to_thread(self.data_extraction.scrape_company_website, domain),
            return_exceptions=True
        )
        
        if isinstance(whois_data, Exception):
            logger.error(f"WHOIS error: {whois_data}")
            whois_data = {}
        if isinstance(scraped_data, Exception):
            logger.error(f"Scraping error: {scraped_data}")
            scraped_data = {}
        
        # Placeholder for search data
        search_data = {}
        
        # Perform AI analysis
        ai_analysis = self.ai_analysis.analyze_with_gemini(
            company_name, domain, whois_data, hunter_data, 
            hostio_data, abstractapi_data, scraped_data, search_data
        )
        
        # Compile results
        result = {
            'company_name': company_name,
            'domain': domain,
            'hunter_io': hunter_data,
            'host_io': hostio_data,
            'abstractapi_company': abstractapi_data,
            'whois_data': whois_data,
            'scraped_data': scraped_data,
            'search_data': search_data,
            'ai_analysis': ai_analysis,
            'analysis_timestamp': __import__('datetime').datetime.now().isoformat()
        }
        
        logger.info(f"Async analysis complete for {company_name}")
        return result
    
    def analyze_company(self, company_name: str, domain: str = None) -> Dict[str, Any]:
        """Sync wrapper for analyze_company_async"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in async context, use sync fallback
                return self._analyze_company_sync(company_name, domain)
            return loop.run_until_complete(self.analyze_company_async(company_name, domain))
        except Exception:
            return self._analyze_company_sync(company_name, domain)
    
    def _analyze_company_sync(self, company_name: str, domain: str = None) -> Dict[str, Any]:
        """Synchronous fallback for analyze_company"""
        
        if not domain:
            domain = company_name.lower().replace(' ', '') + '.com'
        
        logger.info(f"Starting sync analysis for {company_name} ({domain})")
        
        # Collect data from all sources (sequential fallback)
        hunter_data = self.api_queries.query_hunter_io(domain)
        hostio_data = self.api_queries.query_hostio(domain)
        abstractapi_data = self.api_queries.query_abstractapi_company(domain)
        
        whois_data = self.data_extraction.get_whois_information(domain)
        scraped_data = self.data_extraction.scrape_company_website(domain)
        
        # Placeholder for search data
        search_data = {}
        
        # Perform AI analysis
        ai_analysis = self.ai_analysis.analyze_with_gemini(
            company_name, domain, whois_data, hunter_data, 
            hostio_data, abstractapi_data, scraped_data, search_data
        )
        
        # Compile results
        result = {
            'company_name': company_name,
            'domain': domain,
            'hunter_io': hunter_data,
            'host_io': hostio_data,
            'abstractapi_company': abstractapi_data,
            'whois_data': whois_data,
            'scraped_data': scraped_data,
            'search_data': search_data,
            'ai_analysis': ai_analysis,
            'analysis_timestamp': __import__('datetime').datetime.now().isoformat()
        }
        
        logger.info(f"Sync analysis complete for {company_name}")
        return result
