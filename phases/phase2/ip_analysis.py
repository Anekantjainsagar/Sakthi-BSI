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
        T2.2: Parallelize IP reputation checks - query all 5 APIs in parallel per IP
        Analyze reputation of IP addresses.
        Queries AbuseIPDB, GreyNoise, AlienVault, VirusTotal, and IPQualityScore in parallel.
        """
        reputation_data = {}
        blacklisted = []

        async with aiohttp.ClientSession() as session:
            # T2.2: Parallelize all IP reputation queries
            tasks = [self._query_ip_reputation_parallel(session, ip) for ip in ip_addresses]
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

    async def _query_ip_reputation_parallel(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """
        T2.2: Query all 5 reputation APIs in parallel for a single IP
        """
        result = {'ip': ip, 'reputation': 'unknown', 'blacklisted': False, 'abuse_score': 0, 'sources': []}

        # T2.2: Parallelize all API calls for this IP
        tasks = [
            self._query_abuseipdb(session, ip),
            self._query_greynoise(session, ip),
            self._query_alienvault(session, ip),
            self._query_virustotal(session, ip),
            self._query_ipqualityscore(session, ip),
        ]
        
        api_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge results from all APIs
        for api_result in api_results:
            if isinstance(api_result, dict):
                result.update(api_result)
        
        return result

    async def _query_abuseipdb(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation"""
        result = {}
        abuseipdb_key = os.getenv('ABUSEIPDB_KEY')
        if not abuseipdb_key:
            return result
        
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
                    result['sources'] = result.get('sources', []) + ['AbuseIPDB']
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
        
        return result

    async def _query_greynoise(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query GreyNoise for IP reputation"""
        result = {}
        greynoise_key = os.getenv('GREYNOISE_KEY')
        if not greynoise_key:
            return result
        
        try:
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {'key': greynoise_key}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result['greynoise_noise'] = data.get('noise', False)
                    result['greynoise_riot'] = data.get('riot', False)
                    result['greynoise_classification'] = data.get('classification', 'unknown')
                    result['sources'] = result.get('sources', []) + ['GreyNoise']
                    if data.get('classification') == 'malicious':
                        result['blacklisted'] = True
                        result['reputation'] = 'malicious'
                        result['reason'] = result.get('reason', 'Flagged by GreyNoise')
        except Exception as e:
            logger.debug(f"GreyNoise query failed for {ip}: {e}")
        
        return result

    async def _query_alienvault(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query AlienVault OTX for IP reputation"""
        result = {}
        alienvault_key = os.getenv('ALIENVAULT_KEY')
        if not alienvault_key:
            return result
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
            headers = {'X-OTX-API-KEY': alienvault_key}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    rep_score = data.get('reputation', {}).get('threat_score', 0)
                    result['otx_threat_score'] = rep_score
                    result['sources'] = result.get('sources', []) + ['AlienVault']
                    if rep_score > 50:
                        result['blacklisted'] = True
                        result['reputation'] = 'malicious'
                        result['reason'] = result.get('reason', f'AlienVault threat score {rep_score}')
                    elif rep_score > 0:
                        result['reputation'] = 'suspicious'
        except Exception as e:
            logger.debug(f"AlienVault query failed for {ip}: {e}")
        
        return result

    async def _query_virustotal(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for IP reputation"""
        result = {}
        vt_key = os.getenv('VIRUSTOTAL_KEY')
        if not vt_key:
            return result
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': vt_key}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    result['virustotal_malicious'] = malicious
                    result['sources'] = result.get('sources', []) + ['VirusTotal']
                    if malicious > 5:
                        result['blacklisted'] = True
                        result['reputation'] = 'malicious'
                        result['reason'] = result.get('reason', f'VirusTotal: {malicious} vendors flagged')
        except Exception as e:
            logger.debug(f"VirusTotal query failed for {ip}: {e}")
        
        return result

    async def _query_ipqualityscore(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """Query IPQualityScore for IP reputation"""
        result = {}
        ipqs_key = os.getenv('IPQUALITYSCORE_KEY')
        if not ipqs_key:
            return result
        
        try:
            url = f"https://ipqualityscore.com/api/json/ip/{ipqs_key}/{ip}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    fraud_score = data.get('fraud_score', 0)
                    result['ipqs_fraud_score'] = fraud_score
                    result['sources'] = result.get('sources', []) + ['IPQualityScore']
                    if fraud_score > 75:
                        result['blacklisted'] = True
                        result['reputation'] = 'malicious'
                        result['reason'] = result.get('reason', f'IPQualityScore fraud score {fraud_score}')
        except Exception as e:
            logger.debug(f"IPQualityScore query failed for {ip}: {e}")
        
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
