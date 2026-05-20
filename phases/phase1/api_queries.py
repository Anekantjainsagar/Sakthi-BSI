"""
Phase 1: API Query Methods
Handles all external API calls for business intelligence
"""

import asyncio
import aiohttp
import logging
import os
from typing import Dict, Any
from core.connection_pool import ConnectionPoolManager
from core.cache_manager import CacheManager

logger = logging.getLogger(__name__)

# Initialize cache manager (24-hour TTL)
cache_manager = CacheManager(cache_dir=".cache/phase1", ttl_hours=24)


class APIQueries:
    """Handles all API queries for Phase 1"""
    
    def __init__(self):
        self.pool_manager = ConnectionPoolManager()
        self.session = self.pool_manager.get_requests_session()
        self.session.headers.update({'User-Agent': 'BSI-Scanner/2.0'})
    
    async def query_hunter_io_async(self, domain: str) -> dict:
        """Query Hunter.io for email discovery (async)"""
        try:
            # Check cache first
            cache_key = {'domain': domain}
            cached = cache_manager.get('hunter_io', cache_key)
            if cached:
                return cached
            
            api_key = os.getenv('HUNTER_IO_KEY') or os.getenv('HUNTER_IO_API_KEY')
            if not api_key:
                logger.warning("Hunter.io API key not configured (HUNTER_IO_KEY)")
                return {'status': 'no_key', 'emails': [], 'error': 'Hunter.io API key not configured'}
            
            url = "https://api.hunter.io/v2/domain-search"
            params = {'domain': domain, 'limit': 100, 'api_key': api_key}
            
            session = self.pool_manager.get_aiohttp_session()
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    result = data.get('data', data)
                    cache_manager.set('hunter_io', cache_key, result)
                    return result
                elif response.status == 401:
                    return {'status': 'error', 'emails': [], 'error': 'Invalid Hunter.io API key'}
                elif response.status == 429:
                    return {'status': 'rate_limited', 'emails': [], 'error': 'Hunter.io rate limit reached'}
                return {'status': 'error', 'emails': [], 'error': f'HTTP {response.status}'}
        except Exception as e:
            logger.error(f"Hunter.io query failed: {str(e)}")
            return {'status': 'error', 'emails': [], 'error': str(e)}
    
    def query_hunter_io(self, domain: str) -> dict:
        """Query Hunter.io for email discovery (sync wrapper)"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in async context, use sync fallback
                return self._query_hunter_io_sync(domain)
            return loop.run_until_complete(self.query_hunter_io_async(domain))
        except Exception:
            return self._query_hunter_io_sync(domain)
    
    def _query_hunter_io_sync(self, domain: str) -> dict:
        """Synchronous fallback for Hunter.io"""
        try:
            api_key = os.getenv('HUNTER_IO_KEY') or os.getenv('HUNTER_IO_API_KEY')
            if not api_key:
                logger.warning("Hunter.io API key not configured (HUNTER_IO_KEY)")
                return {'status': 'no_key', 'emails': [], 'error': 'Hunter.io API key not configured'}
            
            url = "https://api.hunter.io/v2/domain-search"
            params = {'domain': domain, 'limit': 100, 'api_key': api_key}
            
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', data)
            elif response.status_code == 401:
                return {'status': 'error', 'emails': [], 'error': 'Invalid Hunter.io API key'}
            elif response.status_code == 429:
                return {'status': 'rate_limited', 'emails': [], 'error': 'Hunter.io rate limit reached'}
            return {'status': 'error', 'emails': [], 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Hunter.io query failed: {str(e)}")
            return {'status': 'error', 'emails': [], 'error': str(e)}
    
    async def query_hostio_async(self, domain: str) -> dict:
        """Query Host.io for domain information (async)"""
        try:
            # Check cache first
            cache_key = {'domain': domain}
            cached = cache_manager.get('hostio', cache_key)
            if cached:
                return cached
            
            api_key = os.getenv('HOST_IO_KEY') or os.getenv('HOSTIO_API_KEY')
            if not api_key:
                logger.warning("Host.io API key not configured (HOST_IO_KEY)")
                return {'status': 'no_key', 'error': 'Host.io API key not configured'}
            
            url = f"https://host.io/api/full/{domain}"
            params = {'token': api_key}
            
            session = self.pool_manager.get_aiohttp_session()
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    data['status'] = 'success'
                    cache_manager.set('hostio', cache_key, data)
                    return data
                elif response.status == 401:
                    return {'status': 'error', 'error': 'Invalid Host.io API key'}
                elif response.status == 429:
                    return {'status': 'rate_limited', 'error': 'Host.io rate limit reached'}
                return {'status': 'error', 'error': f'HTTP {response.status}'}
        except Exception as e:
            logger.error(f"Host.io query failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def query_hostio(self, domain: str) -> dict:
        """Query Host.io for domain information (sync wrapper)"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return self._query_hostio_sync(domain)
            return loop.run_until_complete(self.query_hostio_async(domain))
        except Exception:
            return self._query_hostio_sync(domain)
    
    def _query_hostio_sync(self, domain: str) -> dict:
        """Synchronous fallback for Host.io"""
        try:
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
    
    async def query_abstractapi_company_async(self, domain: str) -> dict:
        """Query AbstractAPI for company enrichment (async)"""
        try:
            # Check cache first
            cache_key = {'domain': domain}
            cached = cache_manager.get('abstractapi_company', cache_key)
            if cached:
                return cached
            
            api_key = os.getenv('ABSTRACTAPI_COMPANY_KEY')
            if not api_key:
                logger.warning("AbstractAPI Company key not configured (ABSTRACTAPI_COMPANY_KEY)")
                return {'status': 'no_key', 'error': 'AbstractAPI Company key not configured'}
            
            url = "https://companyenrichment.abstractapi.com/v1/"
            params = {'api_key': api_key, 'domain': domain}
            
            session = self.pool_manager.get_aiohttp_session()
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    cache_manager.set('abstractapi_company', cache_key, data)
                    return data
                elif response.status == 401:
                    return {'status': 'error', 'error': 'Invalid AbstractAPI key'}
                elif response.status == 429:
                    return {'status': 'rate_limited', 'error': 'AbstractAPI rate limit reached'}
                return {'status': 'error', 'error': f'HTTP {response.status}'}
        except Exception as e:
            logger.error(f"AbstractAPI query failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def query_abstractapi_company(self, domain: str) -> dict:
        """Query AbstractAPI for company enrichment (sync wrapper)"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return self._query_abstractapi_company_sync(domain)
            return loop.run_until_complete(self.query_abstractapi_company_async(domain))
        except Exception:
            return self._query_abstractapi_company_sync(domain)
    
    def _query_abstractapi_company_sync(self, domain: str) -> dict:
        """Synchronous fallback for AbstractAPI"""
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
