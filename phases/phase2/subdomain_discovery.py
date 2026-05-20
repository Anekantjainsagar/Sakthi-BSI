"""
Phase 2: Subdomain Discovery
Handles subdomain enumeration from multiple sources
"""

import asyncio
import logging
import os
from typing import Set
import aiohttp

logger = logging.getLogger(__name__)

TIMEOUT = aiohttp.ClientTimeout(total=20)


class SubdomainDiscovery:
    """Handles subdomain discovery from multiple sources"""

    async def discover_subdomains(self, domain: str) -> Set[str]:
        """Discover subdomains from all available sources"""
        subdomains: Set[str] = set()

        tasks = [
            self._crtsh_subdomains(domain),
            self._hackertarget_subdomains(domain),
            self._fullhunt_subdomains(domain),
            self._certspotter_subdomains(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, set):
                subdomains.update(result)
            elif isinstance(result, Exception):
                logger.debug(f"Subdomain source failed: {result}")

        # Normalize: strip wildcards, ensure they end with domain
        cleaned = set()
        for sub in subdomains:
            sub = sub.strip().lstrip('*').lstrip('.')
            if sub and sub.endswith(domain) and sub != domain:
                cleaned.add(sub.lower())

        logger.info(f"Discovered {len(cleaned)} subdomains for {domain}")
        return cleaned

    async def _crtsh_subdomains(self, domain: str) -> Set[str]:
        """Query crt.sh certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        subs = set()
                        for entry in data:
                            for name in entry.get('name_value', '').split('\n'):
                                subs.add(name.strip())
                        return subs
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")
        return set()

    async def _hackertarget_subdomains(self, domain: str) -> Set[str]:
        """Query HackerTarget hostsearch API"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=TIMEOUT) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        subs = set()
                        for line in text.splitlines():
                            parts = line.split(',')
                            if parts and parts[0].strip():
                                subs.add(parts[0].strip())
                        return subs
        except Exception as e:
            logger.debug(f"HackerTarget failed: {e}")
        return set()

    async def _fullhunt_subdomains(self, domain: str) -> Set[str]:
        """Query FullHunt API for subdomains"""
        api_key = os.getenv('FULLHUNT_KEY')
        if not api_key:
            return set()
        try:
            url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
            headers = {'X-API-KEY': api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return set(data.get('hosts', []))
        except Exception as e:
            logger.debug(f"FullHunt failed: {e}")
        return set()

    async def _certspotter_subdomains(self, domain: str) -> Set[str]:
        """Query CertSpotter for certificate issuances"""
        api_key = os.getenv('CERTSPOTTER_KEY')
        try:
            url = f"https://api.certspotter.com/v1/issuances"
            params = {'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'}
            headers = {}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers, timeout=TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subs = set()
                        for cert in data:
                            for name in cert.get('dns_names', []):
                                subs.add(name)
                        return subs
        except Exception as e:
            logger.debug(f"CertSpotter failed: {e}")
        return set()
