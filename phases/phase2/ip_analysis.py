"""
Phase 2: IP Analysis
Handles IP enumeration, geolocation, and reputation analysis
"""

import asyncio
import logging
import os
import socket
from typing import List, Dict, Any, Set
import aiohttp

logger = logging.getLogger(__name__)


class IPAnalysis:
    """Handles IP-related analysis"""

    async def enumerate_ips(self, domain: str) -> Set[str]:
        """Enumerate IP addresses for domain via DNS"""
        ips = set()
        try:
            results = socket.getaddrinfo(domain, None)
            for item in results:
                ip = item[4][0]
                ips.add(ip)
                logger.info(f"Resolved {domain} → {ip}")
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
        except Exception as e:
            logger.error(f"IP enumeration failed: {e}")
        return ips

    async def analyze_ip_reputation(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Analyze reputation of IP addresses.
        Queries AbuseIPDB and GreyNoise; falls back gracefully if keys missing.
        Returns a dict keyed by IP with reputation info, and populates
        blacklisted_ips list for Phase 4 consumption.
        """
        reputation_data = {}
        blacklisted = []

        async with aiohttp.ClientSession() as session:
            tasks = [self._query_ip_reputation(session, ip) for ip in ip_addresses]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for ip, result in zip(ip_addresses, results):
            if isinstance(result, Exception):
                reputation_data[ip] = {'ip': ip, 'reputation': 'unknown', 'blacklisted': False, 'error': str(result)}
            else:
                reputation_data[ip] = result
                if result.get('blacklisted'):
                    blacklisted.append({'ip': ip, 'reason': result.get('reason', 'Flagged by reputation service'), 'score': result.get('abuse_score', 0)})

        # Attach blacklisted list so discovery.py can store it on InfrastructureData
        reputation_data['_blacklisted_ips'] = blacklisted
        return reputation_data

    async def _query_ip_reputation(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB then GreyNoise for IP reputation"""
        result = {'ip': ip, 'reputation': 'unknown', 'blacklisted': False, 'abuse_score': 0, 'sources': []}

        # --- AbuseIPDB ---
        abuseipdb_key = os.getenv('ABUSEIPDB_KEY')
        if abuseipdb_key:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check"
                headers = {'Key': abuseipdb_key, 'Accept': 'application/json'}
                params = {'ipAddress': ip, 'maxAgeInDays': 90}
                async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = (await resp.json()).get('data', {})
                        score = data.get('abuseConfidenceScore', 0)
                        result['abuse_score'] = score
                        result['country_code'] = data.get('countryCode', '')
                        result['isp'] = data.get('isp', '')
                        result['usage_type'] = data.get('usageType', '')
                        result['total_reports'] = data.get('totalReports', 0)
                        result['sources'].append('AbuseIPDB')
                        if score >= 25:
                            result['blacklisted'] = True
                            result['reputation'] = 'malicious'
                            result['reason'] = f'AbuseIPDB score {score}/100'
                        elif score > 0:
                            result['reputation'] = 'suspicious'
                        else:
                            result['reputation'] = 'clean'
            except Exception as e:
                logger.debug(f"AbuseIPDB query failed for {ip}: {e}")

        # --- GreyNoise ---
        greynoise_key = os.getenv('GREYNOISE_KEY')
        if greynoise_key:
            try:
                url = f"https://api.greynoise.io/v3/community/{ip}"
                headers = {'key': greynoise_key}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result['greynoise_noise'] = data.get('noise', False)
                        result['greynoise_riot'] = data.get('riot', False)
                        result['greynoise_classification'] = data.get('classification', 'unknown')
                        result['sources'].append('GreyNoise')
                        if data.get('classification') == 'malicious':
                            result['blacklisted'] = True
                            result['reputation'] = 'malicious'
                            result['reason'] = result.get('reason', 'Flagged by GreyNoise')
            except Exception as e:
                logger.debug(f"GreyNoise query failed for {ip}: {e}")

        # --- AlienVault OTX ---
        alienvault_key = os.getenv('ALIENVAULT_KEY')
        if alienvault_key and result['reputation'] == 'unknown':
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
                headers = {'X-OTX-API-KEY': alienvault_key}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        rep_score = data.get('reputation', {}).get('threat_score', 0)
                        result['otx_threat_score'] = rep_score
                        result['sources'].append('AlienVault')
                        if rep_score > 50:
                            result['blacklisted'] = True
                            result['reputation'] = 'malicious'
                            result['reason'] = result.get('reason', f'AlienVault threat score {rep_score}')
                        elif rep_score > 0:
                            result['reputation'] = 'suspicious'
            except Exception as e:
                logger.debug(f"AlienVault query failed for {ip}: {e}")

        # If no keys configured, mark as unknown but not blacklisted
        if not result['sources']:
            result['reputation'] = 'unknown'
            result['note'] = 'No reputation API keys configured'

        return result

    async def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for IP via ipinfo.io"""
        try:
            ipinfo_key = os.getenv('IPINFO_KEY')
            url = f"https://ipinfo.io/{ip}/json"
            params = {}
            if ipinfo_key:
                params['token'] = ipinfo_key

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'ip': ip,
                            'asn': data.get('org', 'unknown'),
                            'organization': data.get('org', 'unknown'),
                            'country': data.get('country', 'unknown'),
                            'city': data.get('city', 'unknown'),
                            'region': data.get('region', 'unknown'),
                            'hostname': data.get('hostname', ''),
                        }
        except Exception as e:
            logger.error(f"ASN lookup failed for {ip}: {e}")
        return {'ip': ip, 'asn': 'unknown', 'organization': 'unknown', 'country': 'unknown'}
