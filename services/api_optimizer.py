#!/usr/bin/env python3
"""
API Optimizer Service
Optimizes API calls for Phase 1 (Business Domain Intelligence)
Implements parallel execution, caching, and retry logic
"""

import requests
import time
import logging
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api-optimizer")


class APIOptimizer:
    """
    Optimizes API calls with parallel execution, caching, and retry logic
    """
    
    def __init__(self, cache_manager=None, max_workers: int = 5, timeout: int = 30):
        """
        Initialize API optimizer
        
        Args:
            cache_manager: Optional cache manager for caching responses
            max_workers: Maximum concurrent API calls
            timeout: Timeout for each API call in seconds
        """
        self.cache_manager = cache_manager
        self.max_workers = max_workers
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.stats = {
            'total_calls': 0,
            'cached_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'total_time': 0
        }
    
    def _make_request(self, url: str, method: str = 'GET', headers: Dict = None, 
                     params: Dict = None, json_data: Dict = None, timeout: int = None) -> Dict[str, Any]:
        """
        Make a single HTTP request with error handling
        
        Args:
            url: URL to request
            method: HTTP method (GET, POST, etc.)
            headers: Request headers
            params: Query parameters
            json_data: JSON body data
            timeout: Request timeout in seconds
        
        Returns:
            Response data or error dict
        """
        if timeout is None:
            timeout = self.timeout
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=timeout, verify=False)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, params=params, json=json_data, timeout=timeout, verify=False)
            else:
                return {'error': f'Unsupported method: {method}'}
            
            response.raise_for_status()
            
            # Try to parse as JSON, fallback to text
            try:
                return response.json()
            except:
                return {'data': response.text}
        
        except requests.Timeout:
            return {'error': f'Request timeout after {timeout}s'}
        except requests.ConnectionError as e:
            return {'error': f'Connection error: {str(e)}'}
        except requests.HTTPError as e:
            return {'error': f'HTTP error: {e.response.status_code}'}
        except Exception as e:
            return {'error': f'Request failed: {str(e)}'}
    
    def _get_cached_or_fetch(self, cache_key: str, fetch_func, cache_ttl: int = 3600) -> Dict[str, Any]:
        """
        Get from cache or fetch and cache
        
        Args:
            cache_key: Cache key
            fetch_func: Function to fetch data if not cached
            cache_ttl: Cache time-to-live in seconds
        
        Returns:
            Cached or fetched data
        """
        # Try cache first
        if self.cache_manager:
            cached = self.cache_manager.get(cache_key)
            if cached:
                logger.info(f"✓ Cache hit for {cache_key}")
                self.stats['cached_calls'] += 1
                return cached
        
        # Fetch if not cached
        logger.info(f"Fetching {cache_key}...")
        result = fetch_func()
        
        # Cache successful results
        if result and 'error' not in result and self.cache_manager:
            self.cache_manager.set(cache_key, result, ttl=cache_ttl)
            logger.info(f"✓ Cached {cache_key}")
        
        return result
    
    def parallelize_phase1_apis(self, domain: str, api_configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parallelize all Phase 1 API calls
        
        Args:
            domain: Domain to analyze
            api_configs: API configuration dict
        
        Returns:
            Combined results from all APIs
        """
        logger.info(f"Starting parallel Phase 1 API calls for {domain}")
        start_time = time.time()
        
        # Define all API calls
        api_calls = []
        
        # Hunter.io API
        if api_configs.get('hunter_io', {}).get('api_key'):
            api_calls.append({
                'name': 'hunter_io',
                'func': self._call_hunter_io,
                'args': (domain, api_configs['hunter_io']['api_key']),
                'cache_key': f'hunter_io_{domain}'
            })
        
        # Host.io API
        if api_configs.get('host_io', {}).get('api_key'):
            api_calls.append({
                'name': 'host_io',
                'func': self._call_host_io,
                'args': (domain, api_configs['host_io']['api_key']),
                'cache_key': f'host_io_{domain}'
            })
        
        # AbstractAPI
        if api_configs.get('abstractapi', {}).get('api_key'):
            api_calls.append({
                'name': 'abstractapi',
                'func': self._call_abstractapi,
                'args': (domain, api_configs['abstractapi']['api_key']),
                'cache_key': f'abstractapi_{domain}'
            })
        
        # WHOIS lookup
        api_calls.append({
            'name': 'whois',
            'func': self._call_whois,
            'args': (domain,),
            'cache_key': f'whois_{domain}'
        })
        
        # Google Search
        api_calls.append({
            'name': 'google_search',
            'func': self._call_google_search,
            'args': (domain,),
            'cache_key': f'google_search_{domain}'
        })
        
        # Execute all in parallel
        futures = {}
        results = {}
        errors = {}
        
        for call in api_calls:
            name = call['name']
            func = call['func']
            args = call['args']
            cache_key = call.get('cache_key')
            
            # Check cache first
            if cache_key and self.cache_manager:
                cached = self.cache_manager.get(cache_key)
                if cached:
                    logger.info(f"✓ Cache hit for {name}")
                    results[name] = cached
                    self.stats['cached_calls'] += 1
                    continue
            
            # Submit to executor
            future = self.executor.submit(func, *args)
            futures[name] = (future, cache_key)
        
        # Collect results as they complete
        for name, (future, cache_key) in futures.items():
            try:
                result = future.result(timeout=self.timeout)
                results[name] = result
                self.stats['successful_calls'] += 1
                logger.info(f"✓ {name} completed successfully")
                
                # Cache successful result
                if cache_key and self.cache_manager and result and 'error' not in result:
                    self.cache_manager.set(cache_key, result, ttl=3600)
            
            except Exception as e:
                error_msg = f"{name} failed: {str(e)}"
                logger.error(error_msg)
                errors[name] = error_msg
                self.stats['failed_calls'] += 1
        
        elapsed = time.time() - start_time
        self.stats['total_time'] += elapsed
        self.stats['total_calls'] += len(api_calls)
        
        logger.info(f"Parallel Phase 1 APIs completed in {elapsed:.2f}s")
        logger.info(f"Results: {len(results)} successful, {len(errors)} failed")
        
        return {
            'results': results,
            'errors': errors,
            'elapsed_time': elapsed,
            'cached_count': self.stats['cached_calls'],
            'executed_count': len(futures)
        }
    
    def _call_hunter_io(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Call Hunter.io API"""
        logger.info("Calling Hunter.io API...")
        url = f"https://api.hunter.io/v2/domain-search"
        params = {'domain': domain, 'limit': 100, 'offset': 0}
        headers = {'Authorization': f'Bearer {api_key}'}
        
        return self._make_request(url, params=params, headers=headers)
    
    def _call_host_io(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Call Host.io API"""
        logger.info("Calling Host.io API...")
        url = f"https://host.io/api/full/{domain}"
        params = {'apikey': api_key}
        
        return self._make_request(url, params=params)
    
    def _call_abstractapi(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Call AbstractAPI"""
        logger.info("Calling AbstractAPI...")
        url = f"https://companyenrich.abstractapi.com/v1/"
        params = {'api_key': api_key, 'domain': domain}
        
        return self._make_request(url, params=params)
    
    def _call_whois(self, domain: str) -> Dict[str, Any]:
        """Call WHOIS lookup"""
        logger.info("Calling WHOIS lookup...")
        try:
            import whois
            whois_data = whois.whois(domain)
            return {
                'domain': whois_data.domain,
                'registrar': whois_data.registrar,
                'creation_date': str(whois_data.creation_date),
                'expiration_date': str(whois_data.expiration_date),
                'name_servers': whois_data.name_servers,
                'organization': whois_data.org
            }
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def _call_google_search(self, domain: str) -> Dict[str, Any]:
        """Call Google Search (via SerpAPI or similar)"""
        logger.info("Calling Google Search...")
        # This is a placeholder - implement with actual search API
        return {
            'revenue': 'Not available',
            'employees': 'Not available',
            'founded': 'Not available'
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            'total_calls': self.stats['total_calls'],
            'cached_calls': self.stats['cached_calls'],
            'successful_calls': self.stats['successful_calls'],
            'failed_calls': self.stats['failed_calls'],
            'total_time': self.stats['total_time'],
            'cache_hit_rate': (self.stats['cached_calls'] / max(self.stats['total_calls'], 1)) * 100
        }
    
    def shutdown(self):
        """Shutdown the executor"""
        self.executor.shutdown(wait=True)
        logger.info("API Optimizer shutdown complete")


class DNSOptimizer:
    """
    Optimizes DNS queries with parallel execution and caching
    """
    
    def __init__(self, cache_manager=None, max_workers: int = 10):
        """
        Initialize DNS optimizer
        
        Args:
            cache_manager: Optional cache manager
            max_workers: Maximum concurrent DNS queries
        """
        self.cache_manager = cache_manager
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def parallelize_dns_queries(self, domains: List[str], query_types: List[str] = None) -> Dict[str, Any]:
        """
        Parallelize DNS queries for multiple domains
        
        Args:
            domains: List of domains to query
            query_types: List of query types (A, MX, NS, TXT, etc.)
        
        Returns:
            Combined DNS results
        """
        if query_types is None:
            query_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        
        logger.info(f"Starting parallel DNS queries for {len(domains)} domains")
        start_time = time.time()
        
        futures = {}
        results = {}
        
        for domain in domains:
            for query_type in query_types:
                cache_key = f'dns_{domain}_{query_type}'
                
                # Check cache
                if self.cache_manager:
                    cached = self.cache_manager.get(cache_key)
                    if cached:
                        results[cache_key] = cached
                        continue
                
                # Submit query
                future = self.executor.submit(self._query_dns, domain, query_type)
                futures[cache_key] = future
        
        # Collect results
        for cache_key, future in futures.items():
            try:
                result = future.result(timeout=10)
                results[cache_key] = result
                
                # Cache result
                if self.cache_manager:
                    self.cache_manager.set(cache_key, result, ttl=3600)
            
            except Exception as e:
                logger.error(f"DNS query {cache_key} failed: {e}")
                results[cache_key] = {'error': str(e)}
        
        elapsed = time.time() - start_time
        logger.info(f"Parallel DNS queries completed in {elapsed:.2f}s")
        
        return {
            'results': results,
            'elapsed_time': elapsed,
            'total_queries': len(domains) * len(query_types)
        }
    
    def _query_dns(self, domain: str, query_type: str) -> Dict[str, Any]:
        """Execute a single DNS query"""
        try:
            import dns.resolver
            
            answers = dns.resolver.resolve(domain, query_type)
            return {
                'domain': domain,
                'type': query_type,
                'records': [str(rdata) for rdata in answers]
            }
        except Exception as e:
            return {'error': f'DNS query failed: {str(e)}'}
    
    def shutdown(self):
        """Shutdown the executor"""
        self.executor.shutdown(wait=True)


# Example usage
if __name__ == "__main__":
    # Example: Parallel Phase 1 APIs
    api_configs = {
        'hunter_io': {'api_key': 'your_key'},
        'host_io': {'api_key': 'your_key'},
        'abstractapi': {'api_key': 'your_key'}
    }
    
    optimizer = APIOptimizer(max_workers=5, timeout=30)
    result = optimizer.parallelize_phase1_apis('example.com', api_configs)
    print(f"Results: {result}")
    print(f"Stats: {optimizer.get_stats()}")
    optimizer.shutdown()
