"""
API Response Caching Layer
Implements 24-48 hour TTL caching for API responses to reduce redundant calls
"""

import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Any, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching of API responses with TTL"""
    
    def __init__(self, cache_dir: str = ".cache", ttl_hours: int = 24):
        """
        Initialize cache manager
        
        Args:
            cache_dir: Directory to store cache files
            ttl_hours: Time-to-live for cache entries in hours (24-48)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        logger.info(f"✅ Cache manager initialized: {cache_dir} (TTL: {ttl_hours}h)")
    
    def _get_cache_key(self, api_name: str, params: Dict[str, Any]) -> str:
        """Generate cache key from API name and parameters"""
        params_str = json.dumps(params, sort_keys=True)
        hash_obj = hashlib.md5(params_str.encode())
        return f"{api_name}_{hash_obj.hexdigest()}"
    
    def _get_cache_file(self, cache_key: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(self, api_name: str, params: Dict[str, Any]) -> Optional[Any]:
        """
        Retrieve cached response if valid
        
        Args:
            api_name: Name of the API (e.g., 'hunter_io', 'hostio')
            params: Request parameters
            
        Returns:
            Cached response or None if expired/not found
        """
        cache_key = self._get_cache_key(api_name, params)
        cache_file = self._get_cache_file(cache_key)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check TTL
            cached_at = datetime.fromisoformat(cache_data['timestamp'])
            if datetime.now() - cached_at > self.ttl:
                logger.debug(f"Cache expired for {api_name}: {cache_key}")
                cache_file.unlink()  # Delete expired cache
                return None
            
            logger.debug(f"✅ Cache hit for {api_name}: {cache_key}")
            return cache_data['response']
        except Exception as e:
            logger.warning(f"Cache read error for {cache_key}: {e}")
            return None
    
    def set(self, api_name: str, params: Dict[str, Any], response: Any) -> bool:
        """
        Store response in cache
        
        Args:
            api_name: Name of the API
            params: Request parameters
            response: Response to cache
            
        Returns:
            True if cached successfully
        """
        cache_key = self._get_cache_key(api_name, params)
        cache_file = self._get_cache_file(cache_key)
        
        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'api_name': api_name,
                'response': response
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
            logger.debug(f"✅ Cached response for {api_name}: {cache_key}")
            return True
        except Exception as e:
            logger.warning(f"Cache write error for {cache_key}: {e}")
            return False
    
    def clear(self, api_name: Optional[str] = None):
        """
        Clear cache entries
        
        Args:
            api_name: If specified, only clear entries for this API; otherwise clear all
        """
        try:
            if api_name:
                # Clear specific API cache
                for cache_file in self.cache_dir.glob(f"{api_name}_*.json"):
                    cache_file.unlink()
                logger.info(f"✅ Cleared cache for {api_name}")
            else:
                # Clear all cache
                for cache_file in self.cache_dir.glob("*.json"):
                    cache_file.unlink()
                logger.info("✅ Cleared all cache")
        except Exception as e:
            logger.warning(f"Cache clear error: {e}")
    
    def cleanup_expired(self):
        """Remove all expired cache entries"""
        try:
            removed_count = 0
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        cache_data = json.load(f)
                    cached_at = datetime.fromisoformat(cache_data['timestamp'])
                    if datetime.now() - cached_at > self.ttl:
                        cache_file.unlink()
                        removed_count += 1
                except Exception:
                    pass
            if removed_count > 0:
                logger.info(f"✅ Cleaned up {removed_count} expired cache entries")
        except Exception as e:
            logger.warning(f"Cache cleanup error: {e}")
