"""
Global Connection Pool Manager
Provides reusable HTTP and aiohttp session pools for all phases
"""

import aiohttp
import requests
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class ConnectionPoolManager:
    """Manages global connection pools for HTTP requests"""
    
    _instance = None
    _aiohttp_session: Optional[aiohttp.ClientSession] = None
    _requests_session: Optional[requests.Session] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConnectionPoolManager, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def get_aiohttp_session(cls) -> aiohttp.ClientSession:
        """Get or create global aiohttp session with connection pooling"""
        if cls._aiohttp_session is None or cls._aiohttp_session.closed:
            connector = aiohttp.TCPConnector(
                limit=100,  # Total connection limit
                limit_per_host=30,  # Per-host limit
                ttl_dns_cache=300,  # DNS cache 5 minutes
                ssl=False,  # Allow self-signed certs
                enable_cleanup_closed=True
            )
            timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
            cls._aiohttp_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'BSI-Scanner/2.0',
                    'Accept-Encoding': 'gzip, deflate'
                }
            )
            logger.info("✅ Global aiohttp session created with connection pooling")
        return cls._aiohttp_session
    
    @classmethod
    def get_requests_session(cls) -> requests.Session:
        """Get or create global requests session with connection pooling"""
        if cls._requests_session is None:
            cls._requests_session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=requests.adapters.Retry(
                    total=3,
                    backoff_factor=0.5,
                    status_forcelist=[429, 500, 502, 503, 504]
                )
            )
            cls._requests_session.mount('http://', adapter)
            cls._requests_session.mount('https://', adapter)
            cls._requests_session.headers.update({'User-Agent': 'BSI-Scanner/2.0'})
            logger.info("✅ Global requests session created with connection pooling")
        return cls._requests_session
    
    @classmethod
    async def close_aiohttp_session(cls):
        """Close aiohttp session gracefully"""
        if cls._aiohttp_session and not cls._aiohttp_session.closed:
            await cls._aiohttp_session.close()
            cls._aiohttp_session = None
            logger.info("✅ aiohttp session closed")
    
    @classmethod
    def close_requests_session(cls):
        """Close requests session gracefully"""
        if cls._requests_session:
            cls._requests_session.close()
            cls._requests_session = None
            logger.info("✅ requests session closed")
