"""
Phase 1: AI Analysis Methods
Handles Gemini AI calls for business intelligence analysis
"""

import logging
from typing import Dict, Any
from config.gemini_config import call_gemini

logger = logging.getLogger(__name__)


class AIAnalysis:
    """Handles AI-powered analysis for Phase 1"""
    
    def __init__(self, use_gemini: bool = True):
        self.use_gemini = use_gemini
    
    def analyze_with_gemini(self, company_name: str, domain: str, whois_data: Dict, 
                           hunter_data: Dict, hostio_data: Dict, abstractapi_data: Dict,
                           scraped_data: Dict, search_data: Dict) -> Dict[str, Any]:
        """Analyze company data with Gemini AI"""
        
        if not self.use_gemini:
            return self._create_fallback_response(company_name, domain, whois_data)
        
        try:
            prompt = self._build_analysis_prompt(
                company_name, domain, whois_data, hunter_data, 
                hostio_data, abstractapi_data, scraped_data, search_data
            )
            
            response = call_gemini(prompt)
            
            # Parse response
            analysis = self._parse_gemini_response(response) if response else {}
            
            return {
                'analysis_method': 'gemini',
                'company_overview': analysis.get('company_overview', {}),
                'financial_intelligence': analysis.get('financial_intelligence', {}),
                'leadership': analysis.get('leadership', {}),
                'services_and_products': analysis.get('services_and_products', {}),
                'customer_base': analysis.get('customer_base', {}),
                'threat_intelligence': analysis.get('threat_intelligence', {}),
                'regulatory_compliance': analysis.get('regulatory_compliance', {}),
                'data_quality': analysis.get('data_quality', {})
            }
        except Exception as e:
            logger.error(f"Gemini analysis failed: {str(e)}")
            return self._create_fallback_response(company_name, domain, whois_data)
    
    def _build_analysis_prompt(self, company_name: str, domain: str, whois_data: Dict,
                              hunter_data: Dict, hostio_data: Dict, abstractapi_data: Dict,
                              scraped_data: Dict, search_data: Dict) -> str:
        """Build prompt for Gemini analysis"""

        # Summarize data to keep prompt concise
        emails_count = len(hunter_data.get('emails', []))
        whois_summary = {k: v for k, v in whois_data.items() if k in ('registrar', 'creation_date', 'country', 'organization', 'domain_age_years')}
        abstract_summary = {k: v for k, v in abstractapi_data.items() if k in ('name', 'industry', 'employees_count', 'year_founded', 'country', 'locality', 'linkedin_url')} if abstractapi_data else {}
        hostio_web = hostio_data.get('web', {}) if hostio_data else {}
        scraped_summary = {k: v for k, v in scraped_data.items() if k in ('title', 'description', 'keywords', 'financial_data')} if scraped_data else {}

        prompt = f"""You are a business intelligence analyst. Analyze the following data for {company_name} ({domain}) and return ONLY valid JSON.

DATA:
- WHOIS: {whois_summary}
- Emails found: {emails_count}
- Host.io web info: {hostio_web}
- AbstractAPI company: {abstract_summary}
- Website scrape: {scraped_summary}

Return ONLY this JSON structure (no markdown, no explanation):
{{
  "company_overview": {{
    "primary_business": "string",
    "industry_vertical": "string",
    "business_model": "B2B|B2C|B2B2C|Marketplace|SaaS|Other",
    "founded_year": "string or null",
    "headquarters": "string or null",
    "company_maturity": "Startup|Growth|Established|Enterprise",
    "company_size": "1-10|11-50|51-200|201-1000|1001-5000|5000+"
  }},
  "financial_intelligence": {{
    "annual_revenue": "string or null",
    "revenue_year": "string or null",
    "quarterly_revenue": "string or null",
    "revenue_growth": "string or null",
    "market_cap": "string or null",
    "funding_raised": "string or null",
    "profitability": "Profitable|Loss-making|Unknown",
    "company_type": "Public|Private|Non-profit|Government",
    "is_public": false,
    "ticker_symbol": "string or null"
  }},
  "leadership": {{
    "ceo": "string or Unknown",
    "founder": "string or Unknown",
    "key_executives": []
  }},
  "services_and_products": {{
    "primary_products": [],
    "service_categories": [],
    "key_offerings": []
  }},
  "customer_base": {{
    "target_customers": [],
    "customer_segments": [],
    "geographic_markets": [],
    "notable_clients": []
  }},
  "threat_intelligence": {{
    "industry_apt_groups": [],
    "critical_assets": [],
    "data_sensitivity": "High|Medium|Low"
  }},
  "regulatory_compliance": {{
    "confirmed_public": [],
    "ai_suggested": ["GDPR", "ISO 27001"],
    "data_protection_requirements": []
  }},
  "data_quality": {{
    "confidence_score": 5,
    "revenue_source": "AbstractAPI|Google|AI estimate|Unknown"
  }}
}}"""
        return prompt

    def _parse_gemini_response(self, response: str) -> Dict[str, Any]:
        """Parse Gemini response, stripping markdown if present"""
        import json
        import re
        if not response:
            return {}
        # Strip markdown code blocks
        cleaned = re.sub(r'```(?:json)?\s*', '', response).strip().rstrip('`').strip()
        # Find JSON object
        match = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {'raw_analysis': response}
    
    def _create_fallback_response(self, company_name: str, domain: str, whois_data: Dict) -> Dict[str, Any]:
        """Create fallback response when AI is unavailable"""
        
        return {
            'analysis_method': 'fallback',
            'company_overview': {
                'primary_business': 'Unknown',
                'industry_vertical': 'Unknown',
                'business_model': 'Unknown',
                'founded_year': whois_data.get('creation_date', 'Unknown'),
                'headquarters': 'Unknown',
                'company_maturity': 'Unknown',
                'company_size': 'Unknown'
            },
            'financial_intelligence': {
                'annual_revenue': 'Not available',
                'company_type': 'Unknown',
                'is_public': False
            },
            'leadership': {
                'ceo': 'Unknown',
                'founder': 'Unknown'
            },
            'services_and_products': {
                'primary_products': [],
                'service_categories': [],
                'key_offerings': []
            },
            'customer_base': {
                'target_customers': [],
                'customer_segments': [],
                'geographic_markets': [],
                'notable_clients': []
            },
            'threat_intelligence': {
                'industry_apt_groups': [],
                'critical_assets': []
            },
            'regulatory_compliance': {
                'confirmed_public': [],
                'ai_suggested': [],
                'data_protection_requirements': []
            },
            'data_quality': {
                'confidence_score': 3,
                'revenue_source': 'Unknown'
            }
        }
