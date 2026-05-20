"""
Phase 1: Main Analyzer
Orchestrates all Phase 1 business intelligence analysis
"""

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
    
    def analyze_company(self, company_name: str, domain: str = None) -> Dict[str, Any]:
        """Main entry point for company analysis"""
        
        if not domain:
            domain = company_name.lower().replace(' ', '') + '.com'
        
        logger.info(f"Starting analysis for {company_name} ({domain})")
        
        # Collect data from all sources
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
        
        logger.info(f"Analysis complete for {company_name}")
        return result
