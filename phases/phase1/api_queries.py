"""
Phase 1: API Query Methods
Handles all external API calls for business intelligence
"""

import requests
import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)


class APIQueries:
    """Handles all API queries for Phase 1"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BSI-Scanner/1.0'})
    
    def query_hunter_io(self, domain: str) -> dict:
        """Query Hunter.io for email discovery"""
        try:
            # Match key name from config/api_config.py
            api_key = os.getenv('HUNTER_IO_KEY') or os.getenv('HUNTER_IO_API_KEY')
            if not api_key:
                logger.warning("Hunter.io API key not configured (HUNTER_IO_KEY)")
                return {'status': 'no_key', 'emails': [], 'error': 'Hunter.io API key not configured'}
            
            url = "https://api.hunter.io/v2/domain-search"
            params = {'domain': domain, 'limit': 100, 'api_key': api_key}
            
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                # Normalize: hunter returns data.emails
                return data.get('data', data)
            elif response.status_code == 401:
                return {'status': 'error', 'emails': [], 'error': 'Invalid Hunter.io API key'}
            elif response.status_code == 429:
                return {'status': 'rate_limited', 'emails': [], 'error': 'Hunter.io rate limit reached'}
            return {'status': 'error', 'emails': [], 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Hunter.io query failed: {str(e)}")
            return {'status': 'error', 'emails': [], 'error': str(e)}
    
    def query_hostio(self, domain: str) -> dict:
        """Query Host.io for domain information"""
        try:
            # Match key name from config/api_config.py
            api_key = os.getenv('HOST_IO_KEY') or os.getenv('HOSTIO_API_KEY')
            if not api_key:
                logger.warning("Host.io API key not configured (HOST_IO_KEY)")
                return {'status': 'no_key', 'error': 'Host.io API key not configured'}
            
            url = f"https://host.io/api/full/{domain}"
            params = {'token': api_key}
            
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                data['status'] = 'success'
                return data
            elif response.status_code == 401:
                return {'status': 'error', 'error': 'Invalid Host.io API key'}
            elif response.status_code == 429:
                return {'status': 'rate_limited', 'error': 'Host.io rate limit reached'}
            return {'status': 'error', 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Host.io query failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def query_abstractapi_company(self, domain: str) -> dict:
        """Query AbstractAPI for company enrichment"""
        try:
            api_key = os.getenv('ABSTRACTAPI_COMPANY_KEY')
            if not api_key:
                logger.warning("AbstractAPI Company key not configured (ABSTRACTAPI_COMPANY_KEY)")
                return {'status': 'no_key', 'error': 'AbstractAPI Company key not configured'}
            
            url = "https://companyenrichment.abstractapi.com/v1/"
            params = {'api_key': api_key, 'domain': domain}
            
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {'status': 'error', 'error': 'Invalid AbstractAPI key'}
            elif response.status_code == 429:
                return {'status': 'rate_limited', 'error': 'AbstractAPI rate limit reached'}
            return {'status': 'error', 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"AbstractAPI query failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
