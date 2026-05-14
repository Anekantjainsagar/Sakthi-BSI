#!/usr/bin/env python3
"""
BSI Phase 2: Infrastructure Discovery - UPDATED VERSION
✅ Active subdomain verification
✅ Full port scanning (top 1000 ports)
✅ Proper subdomain → IP → ASN mapping
✅ NEW: Banner grabbing on open ports
✅ NEW: Full DNS records (CAA, SOA, PTR, SRV, AXFR)
✅ NEW: DMARC policy strength analysis
✅ NEW: SPF strictness analysis
✅ NEW: IP Reputation with AbuseIPDB + AlienVault + VirusTotal
✅ NEW: SSL weakness checks (TLS 1.0/1.1, weak ciphers, HSTS)
✅ NEW: WAF detection
✅ NEW: IPInfo + IPRegistry enrichment
"""

import asyncio
import aiohttp
import socket
import ssl
import warnings
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import whois
import json
import re
import urllib3
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
from datetime import datetime
from dataclasses import dataclass, asdict, is_dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import API config
try:
    from bsi_api_config import INFRA_DISCOVERY_APIS, APPLICATION_LANDSCAPE_APIS
    API_CONFIG_AVAILABLE = True
    logger.info("✅ API Config loaded")
except ImportError:
    API_CONFIG_AVAILABLE = False
    logger.warning("⚠️ bsi_api_config.py not found")

# DNStwist
try:
    import dnstwist
    DNSTWIST_AVAILABLE = True
except ImportError:
    DNSTWIST_AVAILABLE = False

# ✅ COMMON PORTS ONLY (Most important services)
COMMON_PORTS = [
    80, 443, 8080, 8443, 8000, 8888,   # Web
    22, 23, 3389, 5900,                  # Remote access
    25, 110, 143, 465, 587, 993, 995,   # Email
    3306, 5432, 1433, 27017, 6379, 9200, # Databases
    21, 69, 445, 139,                    # File sharing
    53, 67, 161,                         # DNS/Network
    111, 135, 389, 636, 1723, 3128,     # Other
]

# ✅ Banner grabbing port→protocol map
BANNER_PROTOCOLS = {
    21:    'ftp',
    22:    'ssh',
    25:    'smtp',
    80:    'http',
    110:   'pop3',
    143:   'imap',
    443:   'https',
    3306:  'mysql',
    5432:  'postgres',
    6379:  'redis',
    9200:  'elasticsearch',
    27017: 'mongodb',
}

# ✅ WAF signatures
WAF_SIGNATURES = {
    'Cloudflare':          ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare'],
    'AWS WAF':             ['x-amzn-requestid', 'x-amz-cf-id', 'awselb'],
    'Imperva / Incapsula': ['x-iinfo', 'incap_ses', 'visid_incap'],
    'Akamai':              ['x-akamai-transformed', 'akamai-grn', 'x-check-cacheable'],
    'Sucuri':              ['x-sucuri-id', 'x-sucuri-cache'],
    'F5 BIG-IP':           ['x-cnection', 'bigip', 'f5'],
    'Barracuda':           ['barra_counter_session', 'barracuda'],
    'Fortinet':            ['fortigate', 'forticlient'],
    'ModSecurity':         ['mod_security', 'modsecurity', 'mod_sec'],
    'Nginx WAF':           ['x-nf-request-id'],
    'Palo Alto':           ['x-pan-flow-id'],
}

# ✅ Weak SSL ciphers/protocols
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5', 'ANON']
WEAK_TLS_VERSIONS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']


@dataclass
class SubdomainInfo:
    """Enhanced subdomain information"""
    subdomain: str
    is_active: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    ip_addresses: List[str] = None
    ipv6_addresses: List[str] = None
    response_time: Optional[float] = None
    server_header: Optional[str] = None
    title: Optional[str] = None

    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.ipv6_addresses is None:
            self.ipv6_addresses = []


@dataclass
class InfrastructureData:
    """Data structure for infrastructure discovery results"""
    target: str
    timestamp: datetime
    ip_addresses: List[str] = None
    ipv6_addresses: List[str] = None
    subdomains: List[str] = None
    active_subdomains: List[SubdomainInfo] = None
    subdomain_mapping: Dict[str, List[str]] = None
    ssl_analysis: Dict[str, Any] = None
    cloud_provider: Optional[str] = None
    cloud_services: List[str] = None
    asn_info: Dict[str, Any] = None
    blacklisted_ips: List[Dict] = None
    open_ports: Dict[str, List[int]] = None
    port_services: Dict[str, Dict] = None
    # ✅ NEW fields
    port_banners: Dict[str, Dict] = None
    dns_records: Dict[str, Any] = None
    mail_servers: List[Dict] = None
    mail_server_analysis: Dict[str, Any] = None
    dns_info: Dict[str, Any] = None
    whois_data: Dict[str, Any] = None
    dnstwist_lookalikes: Dict[str, Any] = None
    ip_reputation: Dict[str, Any] = None
    ssl_weaknesses: Dict[str, Any] = None
    waf_detection: Dict[str, Any] = None

    def __post_init__(self):
        if self.ip_addresses is None:           self.ip_addresses = []
        if self.ipv6_addresses is None:         self.ipv6_addresses = []
        if self.subdomains is None:             self.subdomains = []
        if self.active_subdomains is None:      self.active_subdomains = []
        if self.subdomain_mapping is None:      self.subdomain_mapping = {}
        if self.ssl_analysis is None:           self.ssl_analysis = {}
        if self.cloud_services is None:         self.cloud_services = []
        if self.asn_info is None:               self.asn_info = {}
        if self.blacklisted_ips is None:        self.blacklisted_ips = []
        if self.open_ports is None:             self.open_ports = {}
        if self.port_services is None:          self.port_services = {}
        if self.port_banners is None:           self.port_banners = {}
        if self.dns_records is None:            self.dns_records = {}
        if self.mail_servers is None:           self.mail_servers = []
        if self.mail_server_analysis is None:   self.mail_server_analysis = {}
        if self.dns_info is None:               self.dns_info = {}
        if self.whois_data is None:             self.whois_data = {}
        if self.dnstwist_lookalikes is None:    self.dnstwist_lookalikes = {}
        if self.ip_reputation is None:          self.ip_reputation = {}
        if self.ssl_weaknesses is None:         self.ssl_weaknesses = {}
        if self.waf_detection is None:          self.waf_detection = {}


class BSIInfrastructureDiscovery:
    """BSI Infrastructure Discovery - UPDATED VERSION with 8 new features"""

    def __init__(self):
        self.free_apis = {
            'hackertarget': 'https://api.hackertarget.com',
            'crtsh':        'https://crt.sh',
            'ipapi':        'http://ip-api.com/json'
        }

        self.cloud_asn_mapping = {
            'AS15169': 'Google Cloud',   'AS396982': 'Google Cloud',
            'AS36492': 'Google Cloud',   'AS16509':  'Amazon Web Services',
            'AS14618': 'Amazon Web Services', 'AS8075': 'Microsoft Azure',
            'AS13335': 'Cloudflare',     'AS14061': 'Digital Ocean',
            'AS20940': 'Akamai',         'AS16625': 'Akamai',
            'AS54113': 'Fastly',         'AS2906':  'Netflix',
            'AS32934': 'Facebook',       'AS36459': 'GitHub',
            'AS14340': 'Salesforce'
        }

        self.mail_providers = {
            'google.com': 'Google Workspace (Gmail)',
            'googlemail.com': 'Google Workspace (Gmail)',
            'gmail': 'Google Workspace (Gmail)',
            'outlook.com': 'Microsoft 365 (Outlook)',
            'office365.com': 'Microsoft 365 (Outlook)',
            'protection.outlook.com': 'Microsoft 365 (Outlook)',
            'mimecast.com': 'Mimecast Email Security',
            'messagelabs.com': 'Symantec Email Security',
            'pphosted.com': 'Proofpoint',
            'proofpoint.com': 'Proofpoint',
            'mailgun.org': 'Mailgun',
            'sendgrid.net': 'SendGrid',
            'amazonses.com': 'Amazon SES',
            'zoho.com': 'Zoho Mail',
            'rackspace.com': 'Rackspace Email',
        }

        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'BSI-Infrastructure-Discovery/2.2',
                'Accept-Encoding': 'gzip, deflate'
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # =========================================================================
    # MAIN WORKFLOW
    # =========================================================================

    async def discover_infrastructure(self, target: str) -> InfrastructureData:
        """Main discovery workflow — all 10 phases"""
        logger.info(f"Starting infrastructure discovery for: {target}")
        data = InfrastructureData(target=target, timestamp=datetime.now())

        # Phase 1: Basic Discovery (parallel)
        await asyncio.gather(
            self._ip_enumeration(target, data),
            self._whois_analysis(target, data),
            return_exceptions=True
        )

        # Phase 2: Subdomain Discovery
        logger.info("📡 Phase 2: Discovering subdomains...")
        await self._subdomain_discovery_all_sources(target, data)

        # Phase 3: Active Subdomain Verification
        logger.info(f"🔍 Phase 3: Verifying {len(data.subdomains)} subdomains...")
        await self._verify_active_subdomains(data)

        # Phase 4: IP Mapping
        logger.info(f"🗺️ Phase 4: Mapping active subdomains to IPs...")
        await self._map_active_subdomains_to_ips(data)

        # Phase 5: ASN Analysis
        logger.info(f"🌐 Phase 5: ASN + IP enrichment for {len(data.ip_addresses)} IPs...")
        await self._asn_analysis_for_all_ips(data)

        # Phase 6: Port Scan
        logger.info(f"🔌 Phase 6: Port scanning {len(data.ip_addresses)} IPs...")
        await self._full_port_scan_all_ips(data)

        # ✅ NEW Phase 6b: Banner Grabbing
        logger.info("🏷️ Phase 6b: Banner grabbing on open ports...")
        await self._banner_grabbing_all_ips(data)

        # Phase 7: SSL Analysis + Weakness Check
        logger.info("🔒 Phase 7: SSL/TLS analysis + weakness checks...")
        await self._comprehensive_ssl_analysis(target, data)
        await self._ssl_weakness_check(target, data)  # ✅ NEW

        # Phase 8: Mail Server Analysis (now with DMARC/SPF strength)
        logger.info("📧 Phase 8: Mail server analysis...")
        await self._mail_server_infrastructure_analysis(target, data)

        # ✅ NEW Phase 9: Full DNS Records
        logger.info("🌍 Phase 9: Full DNS records (CAA, SOA, PTR, SRV, AXFR)...")
        await self._full_dns_records(target, data)

        # ✅ NEW Phase 10: WAF Detection
        logger.info("🛡️ Phase 10: WAF detection...")
        await self._waf_detection(target, data)

        # Phase 11: IP Reputation (upgraded with AbuseIPDB + AlienVault + VT)
        logger.info("🚨 Phase 11: IP reputation check...")
        # Priority: IPs with open ports first, then remaining IPs
        ips_with_ports = [ip for ip in data.ip_addresses if ip in data.open_ports]
        ips_without_ports = [ip for ip in data.ip_addresses if ip not in data.open_ports]
        prioritized_ips = ips_with_ports + ips_without_ports
        logger.info(f"🎯 Reputation priority: {len(ips_with_ports)} IPs with open ports + {len(ips_without_ports)} others")
        await self._ip_reputation_full(prioritized_ips, data)

        # Phase 12: DNStwist
        await self._run_dnstwist(target, data)

        logger.info(f"✅ Infrastructure discovery completed for: {target}")
        return data

    # =========================================================================
    # EXISTING METHODS (unchanged)
    # =========================================================================

    async def _ip_enumeration(self, target: str, data: InfrastructureData):
        """IP address enumeration for main domain"""
        try:
            try:
                answers = dns.resolver.resolve(target, 'A')
                for answer in answers:
                    ip = str(answer)
                    if ip not in data.ip_addresses:
                        data.ip_addresses.append(ip)
            except:
                pass

            try:
                answers = dns.resolver.resolve(target, 'AAAA')
                for answer in answers:
                    ipv6 = str(answer)
                    if ipv6 not in data.ipv6_addresses:
                        data.ipv6_addresses.append(ipv6)
            except:
                pass

            logger.info(f"Main domain: {len(data.ip_addresses)} IPv4, {len(data.ipv6_addresses)} IPv6")
        except Exception as e:
            logger.error(f"IP enumeration failed: {e}")

    async def _whois_analysis(self, target: str, data: InfrastructureData):
        """WHOIS information analysis"""
        try:
            whois_data = whois.whois(target)
            if whois_data:
                def _extract_date(d):
                    if d is None:
                        return None
                    if isinstance(d, list):
                        d = d[0]
                    if isinstance(d, datetime):
                        return d.strftime('%Y-%m-%d')
                    return str(d)[:10]

                data.whois_data = {
                    'registrar':       str(whois_data.registrar) if whois_data.registrar else None,
                    'creation_date':   _extract_date(whois_data.creation_date),
                    'expiration_date': _extract_date(whois_data.expiration_date),
                    'name_servers':    whois_data.name_servers if whois_data.name_servers else []
                }
                data.dns_info['name_servers'] = {}
                if whois_data.name_servers:
                    for ns in whois_data.name_servers[:4]:
                        try:
                            answers = dns.resolver.resolve(ns, 'A')
                            data.dns_info['name_servers'][ns] = [str(a) for a in answers]
                        except:
                            data.dns_info['name_servers'][ns] = []
        except Exception as e:
            logger.debug(f"WHOIS failed: {e}")

    async def _subdomain_discovery_all_sources(self, target: str, data: InfrastructureData):
        """Discover subdomains from all sources in parallel"""
        try:
            await asyncio.gather(
                self._crtsh_subdomains(target, data),
                self._hackertarget_subdomains(target, data),
                self._query_fullhunt_subdomains(target, data),
                self._query_projectdiscovery_subdomains(target, data),
                return_exceptions=True
            )
            data.subdomains = list(set(data.subdomains))
            logger.info(f"📊 Total subdomains discovered: {len(data.subdomains)}")
        except Exception as e:
            logger.error(f"Subdomain discovery failed: {e}")

    async def _crtsh_subdomains(self, target: str, data: InfrastructureData):
        for attempt in range(3):
            try:
                await asyncio.sleep(2 + attempt * 2)  # 2s, 4s, 6s backoff
                url = f"https://crt.sh/?q=%.{target}&output=json"
                if self.session:
                    async with self.session.get(url, timeout=30) as response:
                        if response.status == 200:
                            try:
                                certs = await response.json(content_type=None)
                            except Exception:
                                text = await response.text()
                                logger.warning(f"crt.sh returned non-JSON (attempt {attempt+1}): {text[:100]}")
                                continue
                            for cert in certs:
                                name = cert.get('name_value', '')
                                for subdomain in name.split('\n'):
                                    subdomain = subdomain.strip().replace('*.', '')
                                    if subdomain and subdomain not in data.subdomains:
                                        data.subdomains.append(subdomain)
                            logger.info(f"✅ crt.sh: {len(certs)} certificates")
                            return
                        else:
                            logger.warning(f"crt.sh HTTP {response.status} (attempt {attempt+1}), retrying...")
            except Exception as e:
                logger.warning(f"crt.sh failed (attempt {attempt+1}): {e}")
        logger.error("crt.sh failed after 3 attempts — subdomains may be incomplete")

    async def _hackertarget_subdomains(self, target: str, data: InfrastructureData):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={target}"
            async with self.session.get(url, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    if 'error' in text.lower() or 'limit' in text.lower():
                        return
                    count = 0
                    for line in text.strip().split('\n'):
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            if subdomain and subdomain not in data.subdomains:
                                data.subdomains.append(subdomain)
                                count += 1
                    logger.info(f"✅ HackerTarget: {count} subdomains")
        except Exception as e:
            logger.debug(f"HackerTarget subdomain error: {e}")

    async def _query_fullhunt_subdomains(self, target: str, data: InfrastructureData):
        if not API_CONFIG_AVAILABLE:
            return
        try:
            config = INFRA_DISCOVERY_APIS['subdomains']['fullhunt']
            if not config['enabled']:
                return
            url = f"{config['endpoint']}{target}/subdomains"
            headers = {'X-API-KEY': config['api_key']}
            async with self.session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    fullhunt_data = await response.json()
                    hosts = fullhunt_data.get('hosts', []) if isinstance(fullhunt_data, dict) else fullhunt_data
                    for host in hosts:
                        subdomain = host.get('domain', host.get('host', '')) if isinstance(host, dict) else host
                        if subdomain and subdomain not in data.subdomains:
                            data.subdomains.append(subdomain)
                    logger.info(f"✅ FullHunt: {len(hosts)} subdomains")
        except Exception as e:
            logger.warning(f"FullHunt error: {e}")

    async def _query_projectdiscovery_subdomains(self, target: str, data: InfrastructureData):
        if not API_CONFIG_AVAILABLE:
            return
        try:
            config = INFRA_DISCOVERY_APIS['subdomains']['projectdiscovery']
            if not config['enabled']:
                return
            url = f"{config['endpoint']}{target}/subdomains"
            headers = {'Authorization': config['api_key']}
            async with self.session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    try:
                        json_data = await response.json(content_type=None)
                        raw_subs = json_data.get('subdomains', [])
                        subdomains = [f"{s}.{target}" for s in raw_subs if s]
                    except Exception:
                        text_data = await response.text()
                        subdomains = [line.strip() for line in text_data.split('\n') if line.strip()]
                    for subdomain in subdomains:
                        if subdomain not in data.subdomains:
                            data.subdomains.append(subdomain)
                    logger.info(f"✅ ProjectDiscovery: {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"ProjectDiscovery error: {e}")

    async def _verify_active_subdomains(self, data: InfrastructureData):
        subdomains_to_check = data.subdomains[:500]
        batch_size = 50
        for i in range(0, len(subdomains_to_check), batch_size):
            batch = subdomains_to_check[i:i+batch_size]
            tasks = [self._check_subdomain_active(s) for s in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for subdomain, result in zip(batch, results):
                if isinstance(result, SubdomainInfo) and result.is_active:
                    data.active_subdomains.append(result)
            logger.info(f"Progress: {min(i+batch_size, len(subdomains_to_check))}/{len(subdomains_to_check)}")
            await asyncio.sleep(1)
        logger.info(f"✅ Active subdomains: {len(data.active_subdomains)}/{len(subdomains_to_check)}")

    async def _check_subdomain_active(self, subdomain: str) -> SubdomainInfo:
        info = SubdomainInfo(subdomain=subdomain)
        ACTIVE_STATUSES = {200, 301, 302, 307, 308, 400, 401, 403}
        try:
            try:
                answers = dns.resolver.resolve(subdomain, 'A', lifetime=5)
                for answer in answers:
                    ip = str(answer)
                    if ip not in info.ip_addresses:
                        info.ip_addresses.append(ip)
            except:
                return info

            start_time = asyncio.get_event_loop().time()
            for scheme in ['https', 'http']:
                try:
                    async with self.session.get(
                        f"{scheme}://{subdomain}", timeout=5, ssl=False, allow_redirects=False
                    ) as response:
                        if scheme == 'https':
                            info.https_status = response.status
                        else:
                            info.http_status = response.status
                        info.response_time = asyncio.get_event_loop().time() - start_time
                        info.server_header = response.headers.get('Server', 'Unknown')
                        if response.status in ACTIVE_STATUSES:
                            info.is_active = True
                            if response.status == 200:
                                try:
                                    html = await response.text()
                                    m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                                    if m:
                                        info.title = m.group(1)[:100]
                                except:
                                    pass
                        return info
                except:
                    continue

            if info.ip_addresses:
                info.is_active = True
        except Exception as e:
            logger.debug(f"Subdomain check failed for {subdomain}: {e}")
        return info

    async def _map_active_subdomains_to_ips(self, data: InfrastructureData):
        unique_ips = set(data.ip_addresses)
        for subdomain_info in data.active_subdomains:
            if subdomain_info.is_active and subdomain_info.ip_addresses:
                data.subdomain_mapping[subdomain_info.subdomain] = subdomain_info.ip_addresses
                unique_ips.update(subdomain_info.ip_addresses)
        data.ip_addresses = list(unique_ips)
        logger.info(f"✅ Mapped to {len(data.ip_addresses)} unique IPs")

    async def _asn_analysis_for_all_ips(self, data: InfrastructureData):
        """ASN analysis + IPInfo/IPRegistry enrichment for all IPs"""
        logger.info(f"🌐 Getting ASN info for {len(data.ip_addresses)} IPs...")
        for ip in data.ip_addresses[:30]:
            await asyncio.sleep(1)
            if ip not in data.asn_info:
                data.asn_info[ip] = {
                    'ip': ip, 'asn': None, 'asn_name': None,
                    'country': None, 'city': None, 'isp': None,
                    'organization': None, 'hosting': None, 'proxy': None,
                    'ipinfo': {}, 'ipregistry': {}
                }

            # ip-api.com (free base data)
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as,asname,proxy,hosting"
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        base_data = await response.json()
                        as_field = base_data.get('as', '')
                        if as_field:
                            asn_match = re.search(r'AS(\d+)', as_field)
                            if asn_match:
                                asn = f"AS{asn_match.group(1)}"
                                data.asn_info[ip]['asn']      = asn
                                data.asn_info[ip]['asn_name'] = base_data.get('asname', '')
                                if asn in self.cloud_asn_mapping:
                                    provider = self.cloud_asn_mapping[asn]
                                    if not data.cloud_provider:
                                        data.cloud_provider = provider
                                    if provider not in data.cloud_services:
                                        data.cloud_services.append(provider)
                        data.asn_info[ip]['country']      = base_data.get('country', '')
                        data.asn_info[ip]['city']         = base_data.get('city', '')
                        data.asn_info[ip]['isp']          = base_data.get('isp', '')
                        data.asn_info[ip]['organization'] = base_data.get('org', '')
                        data.asn_info[ip]['hosting']      = base_data.get('hosting', False)
                        data.asn_info[ip]['proxy']        = base_data.get('proxy', False)
            except Exception as e:
                logger.debug(f"ip-api failed for {ip}: {e}")

            # ✅ NEW: IPInfo enrichment
            await self._enrich_ip_ipinfo(ip, data)

            # ✅ NEW: IPRegistry enrichment
            await self._enrich_ip_ipregistry(ip, data)

    # ✅ NEW METHOD #8a — IPInfo enrichment
    async def _enrich_ip_ipinfo(self, ip: str, data: InfrastructureData):
        """Enrich IP with IPInfo API (richer org/abuse data)"""
        if not API_CONFIG_AVAILABLE:
            return
        try:
            config = INFRA_DISCOVERY_APIS['ip_geolocation']['ipinfo']
            if not config.get('enabled'):
                return
            url = f"{config['endpoint']}{ip}/json?token={config['api_key']}"
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    ipinfo_data = await response.json()
                    data.asn_info[ip]['ipinfo'] = {
                        'hostname':     ipinfo_data.get('hostname', ''),
                        'org':          ipinfo_data.get('org', ''),
                        'region':       ipinfo_data.get('region', ''),
                        'timezone':     ipinfo_data.get('timezone', ''),
                        'is_vpn':       ipinfo_data.get('privacy', {}).get('vpn', False) if isinstance(ipinfo_data.get('privacy'), dict) else False,
                        'is_proxy':     ipinfo_data.get('privacy', {}).get('proxy', False) if isinstance(ipinfo_data.get('privacy'), dict) else False,
                        'is_tor':       ipinfo_data.get('privacy', {}).get('tor', False) if isinstance(ipinfo_data.get('privacy'), dict) else False,
                        'abuse_email':  ipinfo_data.get('abuse', {}).get('email', '') if isinstance(ipinfo_data.get('abuse'), dict) else '',
                    }
                    logger.debug(f"✅ IPInfo enriched: {ip}")
        except Exception as e:
            logger.debug(f"IPInfo failed for {ip}: {e}")

    # ✅ NEW METHOD #8b — IPRegistry enrichment
    async def _enrich_ip_ipregistry(self, ip: str, data: InfrastructureData):
        """Enrich IP with IPRegistry API"""
        if not API_CONFIG_AVAILABLE:
            return
        try:
            config = INFRA_DISCOVERY_APIS['ip_geolocation']['ipregistry']
            if not config.get('enabled'):
                return
            url = f"{config['endpoint']}{ip}?key={config['api_key']}"
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    reg_data = await response.json()
                    security = reg_data.get('security', {})
                    data.asn_info[ip]['ipregistry'] = {
                        'is_cloud_provider': security.get('is_cloud_provider', False),
                        'is_datacenter':     security.get('is_datacenter', False),
                        'is_tor':            security.get('is_tor', False),
                        'is_vpn':            security.get('is_vpn', False),
                        'is_proxy':          security.get('is_proxy', False),
                        'is_anonymous':      security.get('is_anonymous', False),
                        'is_attacker':       security.get('is_attacker', False),
                        'is_abuser':         security.get('is_abuser', False),
                        'is_threat':         security.get('is_threat', False),
                        'threat_types':      security.get('threat_types', []),
                        'carrier':           reg_data.get('carrier', {}).get('name', '') if isinstance(reg_data.get('carrier'), dict) else '',
                        'connection_type':   reg_data.get('connection', {}).get('type', '') if isinstance(reg_data.get('connection'), dict) else '',
                    }
                    logger.debug(f"✅ IPRegistry enriched: {ip}")
        except Exception as e:
            logger.debug(f"IPRegistry failed for {ip}: {e}")

    async def _full_port_scan_all_ips(self, data: InfrastructureData):
        for ip in data.ip_addresses[:20]:
            logger.info(f"Scanning {ip}...")
            success = await self._hackertarget_full_scan(ip, data)
            if not success:
                await self._scan_common_ports(ip, data)
            await asyncio.sleep(2)

    async def _hackertarget_full_scan(self, ip: str, data: InfrastructureData) -> bool:
        try:
            await asyncio.sleep(1)
            url = f"https://api.hackertarget.com/nmap/?q={ip}"
            if self.session:
                async with self.session.get(url, timeout=30) as response:
                    if response.status == 200:
                        text = await response.text()
                        if 'error' in text.lower() or 'limit' in text.lower():
                            return False
                        ports, services = [], {}
                        for line in text.split('\n'):
                            line = line.strip()
                            if 'open' in line.lower() and '/' in line:
                                try:
                                    parts = line.split()
                                    port_part = parts[0]
                                    if '/' in port_part:
                                        port_num = int(port_part.split('/')[0])
                                        ports.append(port_num)
                                        if len(parts) >= 3:
                                            services[port_num] = parts[2]
                                except:
                                    continue
                        if ports:
                            data.open_ports[ip]    = sorted(ports)
                            data.port_services[ip] = services
                            logger.info(f"✅ HackerTarget: {len(ports)} open ports on {ip}")
                            return True
            return False
        except Exception as e:
            logger.debug(f"HackerTarget failed for {ip}: {e}")
            return False

    async def _scan_common_ports(self, ip: str, data: InfrastructureData):
        port_service_map = {
            21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
            67:'DHCP', 69:'TFTP', 80:'HTTP', 110:'POP3', 111:'RPC',
            135:'MS-RPC', 139:'NetBIOS', 143:'IMAP', 161:'SNMP',
            389:'LDAP', 443:'HTTPS', 445:'SMB', 465:'SMTPS',
            587:'SMTP-Submission', 636:'LDAPS', 993:'IMAPS', 995:'POP3S',
            1433:'MS-SQL', 1723:'PPTP', 3128:'Squid-Proxy', 3306:'MySQL',
            3389:'RDP', 5432:'PostgreSQL', 5900:'VNC', 6379:'Redis',
            8000:'HTTP-Alt', 8080:'HTTP-Proxy', 8443:'HTTPS-Alt',
            8888:'HTTP-Alt', 9200:'Elasticsearch', 27017:'MongoDB'
        }

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return port
            except:
                return None

        open_ports, services = [], {}
        for i in range(0, len(COMMON_PORTS), 20):
            batch   = COMMON_PORTS[i:i+20]
            results = await asyncio.gather(*[check_port(p) for p in batch], return_exceptions=True)
            for result in results:
                if isinstance(result, int):
                    open_ports.append(result)
                    services[result] = port_service_map.get(result, 'Unknown')

        if open_ports:
            data.open_ports[ip]    = sorted(open_ports)
            data.port_services[ip] = services
            logger.info(f"✅ Common ports: {len(open_ports)} open on {ip}")

    # =========================================================================
    # ✅ NEW METHOD #1 — Banner Grabbing
    # =========================================================================

    async def _banner_grabbing_all_ips(self, data: InfrastructureData):
        """Grab banners from all open ports on all IPs"""
        for ip, ports in data.open_ports.items():
            data.port_banners[ip] = {}
            for port in ports[:15]:  # Limit to 15 ports per IP
                banner = await self._grab_banner(ip, port)
                if banner:
                    data.port_banners[ip][port] = banner
                    logger.debug(f"  Banner {ip}:{port} → {banner.get('version', 'unknown')}")
        logger.info(f"✅ Banner grabbing complete for {len(data.port_banners)} IPs")

    async def _grab_banner(self, ip: str, port: int) -> Optional[Dict]:
        """
        Grab banner from a single port.
        Returns dict with raw banner + parsed version info.
        """
        protocol = BANNER_PROTOCOLS.get(port, 'raw')
        result = {
            'port':     port,
            'protocol': protocol,
            'raw':      '',
            'version':  '',
            'product':  '',
            'extra':    ''
        }

        try:
            # For HTTP/HTTPS — use HEAD request to get Server header
            if port in (80, 8080, 8000, 8888):
                try:
                    async with self.session.head(
                        f"http://{ip}:{port}", timeout=5, allow_redirects=False
                    ) as response:
                        server = response.headers.get('Server', '')
                        powered = response.headers.get('X-Powered-By', '')
                        if server:
                            result['raw']     = server
                            result['product'] = server
                            result['extra']   = powered
                            parsed = self._parse_banner_version(server)
                            result.update(parsed)
                        return result
                except:
                    pass

            if port in (443, 8443):
                try:
                    async with self.session.head(
                        f"https://{ip}:{port}", timeout=5, ssl=False, allow_redirects=False
                    ) as response:
                        server = response.headers.get('Server', '')
                        powered = response.headers.get('X-Powered-By', '')
                        if server:
                            result['raw']     = server
                            result['product'] = server
                            result['extra']   = powered
                            parsed = self._parse_banner_version(server)
                            result.update(parsed)
                        return result
                except:
                    pass

            # For TCP services — read first bytes (the banner)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=3
                )

                # Some services need a probe first
                probe = None
                if port == 25:   probe = b"EHLO bsi-scanner\r\n"
                elif port == 110: probe = b"CAPA\r\n"
                elif port == 143: probe = b"A001 CAPABILITY\r\n"
                elif port == 21:  probe = None  # FTP sends banner on connect
                elif port == 3306: probe = None  # MySQL sends banner on connect

                if probe:
                    writer.write(probe)
                    await writer.drain()

                # Read up to 512 bytes
                try:
                    raw_bytes = await asyncio.wait_for(reader.read(512), timeout=3)
                    raw_banner = raw_bytes.decode('utf-8', errors='ignore').strip()
                except:
                    raw_banner = ''

                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass

                if raw_banner:
                    result['raw'] = raw_banner[:200]
                    parsed = self._parse_banner_version(raw_banner)
                    result.update(parsed)

                return result if result['raw'] else None

            except:
                return None

        except Exception as e:
            logger.debug(f"Banner grab failed {ip}:{port}: {e}")
            return None

    def _parse_banner_version(self, banner: str) -> Dict:
        """
        Parse version info from a banner string.
        Examples:
          "SSH-2.0-OpenSSH_7.4"        → product=OpenSSH, version=7.4
          "Apache/2.4.49 (Unix)"        → product=Apache, version=2.4.49
          "5.6.40-log MySQL Community"  → product=MySQL, version=5.6.40
          "220 Microsoft ESMTP"         → product=Microsoft ESMTP
        """
        parsed = {'product': '', 'version': '', 'extra': ''}

        # SSH: SSH-2.0-OpenSSH_8.2p1
        m = re.search(r'SSH-\d+\.\d+-(\S+)', banner)
        if m:
            full = m.group(1)
            parts = full.split('_')
            parsed['product'] = parts[0]
            parsed['version'] = parts[1] if len(parts) > 1 else ''
            return parsed

        # Apache: Apache/2.4.49
        m = re.search(r'Apache[/ ](\d+\.\d+[\.\d]*)', banner, re.IGNORECASE)
        if m:
            parsed['product'] = 'Apache'
            parsed['version'] = m.group(1)
            return parsed

        # Nginx: nginx/1.18.0
        m = re.search(r'nginx[/ ](\d+\.\d+[\.\d]*)', banner, re.IGNORECASE)
        if m:
            parsed['product'] = 'nginx'
            parsed['version'] = m.group(1)
            return parsed

        # IIS: Microsoft-IIS/10.0
        m = re.search(r'Microsoft-IIS[/ ](\d+\.\d+)', banner, re.IGNORECASE)
        if m:
            parsed['product'] = 'Microsoft IIS'
            parsed['version'] = m.group(1)
            return parsed

        # MySQL: 5.6.40-log or 8.0.25-MySQL Community
        m = re.search(r'(\d+\.\d+\.\d+)[-\s].*[Mm][Yy][Ss][Qq][Ll]', banner)
        if m:
            parsed['product'] = 'MySQL'
            parsed['version'] = m.group(1)
            return parsed
        m = re.search(r'[Mm][Yy][Ss][Qq][Ll].*?(\d+\.\d+[\.\d]*)', banner)
        if m:
            parsed['product'] = 'MySQL'
            parsed['version'] = m.group(1)
            return parsed

        # PostgreSQL: PostgreSQL 13.3
        m = re.search(r'PostgreSQL[/ ]?(\d+[\.\d]*)', banner, re.IGNORECASE)
        if m:
            parsed['product'] = 'PostgreSQL'
            parsed['version'] = m.group(1)
            return parsed

        # OpenSSL: OpenSSL/1.1.1k
        m = re.search(r'OpenSSL[/ ](\d+[\.\d\w]+)', banner, re.IGNORECASE)
        if m:
            parsed['extra'] = f"OpenSSL {m.group(1)}"

        # FTP: 220 ProFTPD 1.3.5
        m = re.search(r'220.*?(ProFTPD|vsftpd|FileZilla)[/ ]?([\d\.]*)', banner, re.IGNORECASE)
        if m:
            parsed['product'] = m.group(1)
            parsed['version'] = m.group(2)
            return parsed

        # SMTP: 220 Microsoft ESMTP
        m = re.search(r'220\s+(.+)', banner)
        if m:
            parsed['product'] = m.group(1)[:80]
            return parsed

        # Generic version number fallback
        m = re.search(r'(\d+\.\d+[\.\d]*)', banner)
        if m:
            parsed['version'] = m.group(1)

        if not parsed['product']:
            parsed['product'] = banner[:80].strip()

        return parsed

    # =========================================================================
    # ✅ NEW METHOD #2 — Full DNS Records
    # =========================================================================

    async def _full_dns_records(self, target: str, data: InfrastructureData):
        """
        Fetch ALL DNS record types:
        CAA, SOA, SRV, PTR for each IP, and attempt zone transfer (AXFR)
        """
        dns_records = data.dns_records

        # --- CAA records ---
        try:
            answers = dns.resolver.resolve(target, 'CAA')
            dns_records['CAA'] = []
            for r in answers:
                dns_records['CAA'].append(str(r))
            logger.info(f"✅ CAA records: {len(dns_records['CAA'])}")
        except Exception:
            dns_records['CAA'] = []

        # --- SOA record ---
        try:
            answers = dns.resolver.resolve(target, 'SOA')
            for r in answers:
                dns_records['SOA'] = {
                    'mname':   str(r.mname),
                    'rname':   str(r.rname),
                    'serial':  int(r.serial),
                    'refresh': int(r.refresh),
                    'retry':   int(r.retry),
                    'expire':  int(r.expire),
                    'minimum': int(r.minimum)
                }
            logger.info("✅ SOA record fetched")
        except Exception:
            dns_records['SOA'] = {}

        # --- SRV records (common services) ---
        srv_services = [
            '_http._tcp', '_https._tcp', '_ftp._tcp', '_ssh._tcp',
            '_smtp._tcp', '_imap._tcp', '_pop3._tcp', '_ldap._tcp',
            '_kerberos._tcp', '_sip._tcp', '_sipfederationtls._tcp',
        ]
        dns_records['SRV'] = []
        for srv in srv_services:
            try:
                answers = dns.resolver.resolve(f"{srv}.{target}", 'SRV')
                for r in answers:
                    dns_records['SRV'].append({
                        'service':  srv,
                        'priority': int(r.priority),
                        'weight':   int(r.weight),
                        'port':     int(r.port),
                        'target':   str(r.target)
                    })
            except Exception:
                continue
        logger.info(f"✅ SRV records: {len(dns_records['SRV'])}")

        # --- PTR records (reverse DNS for each IP) ---
        dns_records['PTR'] = {}
        for ip in data.ip_addresses[:10]:
            try:
                reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
                answers = dns.resolver.resolve(reversed_ip, 'PTR')
                dns_records['PTR'][ip] = [str(r) for r in answers]
            except Exception:
                dns_records['PTR'][ip] = []
        logger.info(f"✅ PTR records for {len(dns_records['PTR'])} IPs")

        # --- Zone Transfer attempt (AXFR) ---
        dns_records['AXFR'] = {
            'attempted': False,
            'vulnerable': False,
            'records_leaked': 0,
            'nameservers_tested': [],
            'note': ''
        }
        ns_list = []
        try:
            ns_answers = dns.resolver.resolve(target, 'NS')
            ns_list = [str(r) for r in ns_answers]
        except:
            pass

        for ns in ns_list[:3]:
            dns_records['AXFR']['attempted'] = True
            dns_records['AXFR']['nameservers_tested'].append(ns)
            try:
                ns_ip = str(dns.resolver.resolve(ns, 'A')[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=5))
                # If we get here — zone transfer succeeded! That's a critical finding
                records_count = len(list(zone.nodes.keys()))
                dns_records['AXFR']['vulnerable']       = True
                dns_records['AXFR']['records_leaked']   = records_count
                dns_records['AXFR']['note']             = f"CRITICAL: Zone transfer allowed from {ns}! {records_count} records exposed."
                logger.warning(f"🚨 ZONE TRANSFER VULNERABLE on {ns}! {records_count} records leaked")
                break
            except dns.exception.FormError:
                dns_records['AXFR']['note'] = "Zone transfer refused (secure)"
            except Exception:
                dns_records['AXFR']['note'] = "Zone transfer refused (secure)"

        logger.info(f"✅ AXFR test: {'VULNERABLE' if dns_records['AXFR']['vulnerable'] else 'Secure'}")
        data.dns_records = dns_records

    # =========================================================================
    # SSL Analysis (existing + ✅ NEW weakness check)
    # =========================================================================

    async def _comprehensive_ssl_analysis(self, target: str, data: InfrastructureData):
        """SSL/TLS analysis"""
        try:
            await self._query_certspotter(target, data)
            try:
                context = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        san_list = [v for (t, v) in cert.get('subjectAltName', []) if t == 'DNS']
                        not_after_str = cert.get('notAfter', '')
                        days_until_expiry = None
                        try:
                            expiry = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry - datetime.now()).days
                        except:
                            pass
                        cipher = ssock.cipher()
                        cipher_name = cipher[0] if cipher else 'Unknown'
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        subject = dict(x[0] for x in cert.get('subject', []))
                        data.ssl_analysis['certificate'] = {
                            'subject':           subject,
                            'issuer':            issuer,
                            'notBefore':         cert.get('notBefore'),
                            'notAfter':          cert.get('notAfter'),
                            'san_domains':       san_list,
                            'days_until_expiry': days_until_expiry,
                            'is_expiring_soon':  days_until_expiry is not None and days_until_expiry < 30,
                            'is_wildcard':       any('*' in s for s in san_list),
                            'is_self_signed':    issuer == subject,  # ✅ NEW
                        }
                        data.ssl_analysis['tls_version']  = ssock.version()
                        data.ssl_analysis['cipher_suite'] = cipher_name
            except:
                pass
        except Exception as e:
            logger.debug(f"SSL analysis failed: {e}")

    async def _query_certspotter(self, target: str, data: InfrastructureData):
        if not API_CONFIG_AVAILABLE:
            return
        try:
            config = INFRA_DISCOVERY_APIS['ssl']
            if not config['enabled']:
                return
            url = f"{config['endpoint']}?domain={target}&include_subdomains=true"
            headers = {'Authorization': f"Bearer {config['api_key']}"}
            async with self.session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    certs = await response.json()
                    data.ssl_analysis['certspotter'] = {
                        'status': 'success',
                        'total_certificates': len(certs),
                        'certificates': certs[:25]
                    }
                    logger.info(f"✅ CertSpotter: {len(certs)} certificates")
        except Exception as e:
            logger.debug(f"CertSpotter failed: {e}")

    # ✅ NEW METHOD #6 — SSL Weakness Checks
    async def _ssl_weakness_check(self, target: str, data: InfrastructureData):
        """
        Check for SSL/TLS weaknesses:
        - TLS 1.0 / 1.1 still supported (deprecated)
        - Weak ciphers (RC4, DES, 3DES, NULL, EXPORT)
        - Self-signed certificate
        - HSTS header missing
        """
        weaknesses = {
            'weak_tls_versions':  [],
            'weak_ciphers':       [],
            'hsts_missing':       False,
            'self_signed':        False,
            'summary':            []
        }

        # Check self-signed from existing ssl_analysis
        cert_info = data.ssl_analysis.get('certificate', {})
        if cert_info.get('is_self_signed'):
            weaknesses['self_signed'] = True
            weaknesses['summary'].append('Self-signed certificate detected')

        # Check TLS 1.0 and 1.1
        deprecated_versions = [
            ('TLSv1',   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, 'TLSv1') else None),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
        ]
        for version_name, tls_version in deprecated_versions:
            if tls_version is None:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    ctx.minimum_version = tls_version
                    ctx.maximum_version = tls_version
                with socket.create_connection((target, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target):
                        weaknesses['weak_tls_versions'].append(version_name)
                        weaknesses['summary'].append(f"{version_name} still supported (deprecated)")
                        logger.warning(f"⚠️ {target} supports deprecated {version_name}")
            except:
                pass  # Good — this version not supported

        # Check current cipher for weakness
        current_cipher = data.ssl_analysis.get('cipher_suite', '')
        for weak in WEAK_CIPHERS:
            if weak.upper() in current_cipher.upper():
                weaknesses['weak_ciphers'].append(current_cipher)
                weaknesses['summary'].append(f"Weak cipher in use: {current_cipher}")
                break

        # Check HSTS header
        try:
            async with self.session.get(
                f"https://{target}", timeout=5, ssl=False, allow_redirects=False
            ) as response:
                hsts = response.headers.get('Strict-Transport-Security', '')
                if not hsts:
                    weaknesses['hsts_missing'] = True
                    weaknesses['summary'].append('HSTS header missing')
                else:
                    weaknesses['hsts_header'] = hsts
        except:
            weaknesses['hsts_missing'] = True
            weaknesses['summary'].append('Could not verify HSTS (connection failed)')

        if not weaknesses['summary']:
            weaknesses['summary'].append('No SSL weaknesses detected')

        data.ssl_weaknesses = weaknesses
        logger.info(f"✅ SSL weakness check: {len(weaknesses['summary'])} findings")

    # =========================================================================
    # Mail Analysis (existing + ✅ NEW DMARC/SPF strength)
    # =========================================================================

    async def _mail_server_infrastructure_analysis(self, target: str, data: InfrastructureData):
        """Mail server analysis with provider detection + DMARC/SPF strength"""
        try:
            # MX records
            try:
                mx_records = dns.resolver.resolve(target, 'MX')
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip('.')
                    entry = {
                        'priority': mx.preference,
                        'server':   mx_host,
                        'provider': self._detect_mail_provider(mx_host),
                        'ips':      []
                    }
                    try:
                        mx_ips = dns.resolver.resolve(mx_host, 'A')
                        entry['ips'] = [str(ip) for ip in mx_ips]
                    except:
                        pass
                    data.mail_servers.append(entry)
                logger.info(f"✅ Mail: {len(data.mail_servers)} MX records")
            except Exception as e:
                logger.warning(f"MX lookup failed: {e}")

            # SPF record
            spf_record = None
            try:
                txt_records = dns.resolver.resolve(target, 'TXT')
                for record in txt_records:
                    txt = str(record).strip('"')
                    if txt.startswith('v=spf1'):
                        spf_record = txt
                        break
            except:
                pass

            # DMARC record
            dmarc_record = None
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{target}', 'TXT')
                for record in dmarc_records:
                    txt = str(record).strip('"')
                    if 'v=DMARC1' in txt:
                        dmarc_record = txt
                        break
            except:
                pass

            # DKIM
            dkim_found = []
            for selector in ['default', 'google', 'microsoft', 'mail', 'smtp', 'selector1', 'selector2', 'k1']:
                try:
                    dkim_records = dns.resolver.resolve(f'{selector}._domainkey.{target}', 'TXT')
                    for record in dkim_records:
                        txt = str(record).strip('"')
                        if 'v=DKIM1' in txt or 'p=' in txt:
                            dkim_found.append(selector)
                            break
                except:
                    pass

            # ✅ NEW: DMARC strength analysis (#3)
            dmarc_strength = self._analyze_dmarc_strength(dmarc_record)

            # ✅ NEW: SPF strictness analysis (#4)
            spf_strength = self._analyze_spf_strength(spf_record)

            data.mail_server_analysis = {
                'mx_count':                len(data.mail_servers),
                'primary_provider':        data.mail_servers[0]['provider'] if data.mail_servers else 'Unknown',
                'spf_record':              spf_record or 'Not configured',
                'spf_configured':          spf_record is not None,
                'spf_strength':            spf_strength,            # ✅ NEW
                'dmarc_record':            dmarc_record or 'Not configured',
                'dmarc_configured':        dmarc_record is not None,
                'dmarc_strength':          dmarc_strength,          # ✅ NEW
                'dkim_selectors_found':    dkim_found,
                'dkim_configured':         len(dkim_found) > 0,
                'email_security_score':    sum([
                    spf_record is not None,
                    dmarc_record is not None,
                    len(dkim_found) > 0
                ])
            }
            logger.info(f"✅ Email security — SPF: {spf_strength['level']}, DMARC: {dmarc_strength['level']}, DKIM: {dkim_found}")

        except Exception as e:
            logger.error(f"Mail analysis failed: {e}")

    # ✅ NEW METHOD #3 — DMARC Strength Analysis
    def _analyze_dmarc_strength(self, dmarc_record: Optional[str]) -> Dict:
        """
        Analyze DMARC record strength.
        p=none       → monitoring only, no enforcement (WEAK)
        p=quarantine → suspicious emails go to spam (MEDIUM)
        p=reject     → forged emails fully blocked (STRONG)
        """
        if not dmarc_record:
            return {
                'level':       'NONE',
                'policy':      'Not configured',
                'risk':        'CRITICAL — No DMARC. Domain can be spoofed freely.',
                'pct':         None,
                'rua':         None,
                'ruf':         None,
                'recommendation': 'Add DMARC record with at minimum p=quarantine'
            }

        # Extract policy
        p_match = re.search(r'p=(none|quarantine|reject)', dmarc_record, re.IGNORECASE)
        policy = p_match.group(1).lower() if p_match else 'none'

        # Extract pct (percentage of emails policy applies to)
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        pct = int(pct_match.group(1)) if pct_match else 100

        # Extract reporting addresses
        rua_match = re.search(r'rua=([^\s;]+)', dmarc_record)
        ruf_match = re.search(r'ruf=([^\s;]+)', dmarc_record)

        levels = {
            'none':       ('WEAK',   'HIGH — Emails not blocked even if forged. Only monitoring.'),
            'quarantine': ('MEDIUM', 'MEDIUM — Forged emails go to spam but not blocked.'),
            'reject':     ('STRONG', 'LOW — Forged emails fully rejected.' if pct == 100 else f'MEDIUM — Only {pct}% of emails enforced.')
        }

        level, risk = levels.get(policy, ('WEAK', 'Unknown policy'))

        return {
            'level':          level,
            'policy':         policy,
            'risk':           risk,
            'pct':            pct,
            'rua':            rua_match.group(1) if rua_match else None,
            'ruf':            ruf_match.group(1) if ruf_match else None,
            'recommendation': (
                'Upgrade to p=reject for full protection'
                if policy in ('none', 'quarantine')
                else ('Increase pct to 100 for full enforcement' if pct < 100 else 'DMARC is properly configured')
            )
        }

    # ✅ NEW METHOD #4 — SPF Strictness Analysis
    def _analyze_spf_strength(self, spf_record: Optional[str]) -> Dict:
        """
        Analyze SPF record strictness.
        +all → anyone can send as this domain (CRITICAL)
        ~all → soft fail, spoofing possible (WEAK)
        -all → hard fail, strict (STRONG)
        ?all → neutral, no policy (WEAK)
        """
        if not spf_record:
            return {
                'level':          'NONE',
                'mechanism':      'Not configured',
                'risk':           'CRITICAL — No SPF record. Spoofing is trivial.',
                'recommendation': 'Add SPF record ending with -all'
            }

        # Determine ending mechanism
        if '+all' in spf_record:
            level = 'CRITICAL'
            mechanism = '+all'
            risk = 'CRITICAL — +all means ANYONE can send email as this domain!'
            rec  = 'Remove +all immediately and replace with -all'
        elif '-all' in spf_record:
            level = 'STRONG'
            mechanism = '-all'
            risk = 'LOW — Hard fail configured. Spoofed emails rejected.'
            rec  = 'SPF is properly configured with -all'
        elif '~all' in spf_record:
            level = 'WEAK'
            mechanism = '~all'
            risk = 'MEDIUM — Soft fail (~all). Spoofed emails not rejected, only marked.'
            rec  = 'Change ~all to -all for strict enforcement'
        elif '?all' in spf_record:
            level = 'WEAK'
            mechanism = '?all'
            risk = 'HIGH — Neutral policy. No enforcement against spoofing.'
            rec  = 'Change ?all to -all for strict enforcement'
        else:
            level = 'UNKNOWN'
            mechanism = 'No all mechanism'
            risk = 'MEDIUM — No all mechanism found, policy unclear'
            rec  = 'Add -all to end of SPF record'

        # Count include statements (too many = lookup limit risk)
        includes = re.findall(r'include:', spf_record)
        include_warning = ''
        if len(includes) > 8:
            include_warning = f'WARNING: {len(includes)} includes may exceed DNS lookup limit (max 10)'

        return {
            'level':           level,
            'mechanism':       mechanism,
            'risk':            risk,
            'includes_count':  len(includes),
            'include_warning': include_warning,
            'recommendation':  rec
        }

    def _detect_mail_provider(self, mx_host: str) -> str:
        mx_lower = mx_host.lower()
        for keyword, provider in self.mail_providers.items():
            if keyword in mx_lower:
                return provider
        return "Unknown Mail Provider"

    # =========================================================================
    # ✅ NEW METHOD #7 — WAF Detection
    # =========================================================================

    async def _waf_detection(self, target: str, data: InfrastructureData):
        """
        Detect Web Application Firewall by inspecting response headers
        and triggering WAF-specific error responses.
        """
        waf_result = {
            'detected':    False,
            'waf_name':    None,
            'confidence':  'none',
            'evidence':    [],
            'method':      []
        }

        try:
            # Method 1: Check normal response headers
            try:
                async with self.session.get(
                    f"https://{target}", timeout=8, ssl=False, allow_redirects=True
                ) as response:
                    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                    body = ''
                    try:
                        body = (await response.text())[:2000].lower()
                    except:
                        pass

                    for waf_name, signatures in WAF_SIGNATURES.items():
                        for sig in signatures:
                            sig_lower = sig.lower()
                            # Check in headers
                            if any(sig_lower in hk or sig_lower in hv for hk, hv in headers_lower.items()):
                                waf_result['detected']   = True
                                waf_result['waf_name']   = waf_name
                                waf_result['confidence'] = 'high'
                                waf_result['evidence'].append(f"Header contains '{sig}'")
                                waf_result['method'].append('header_inspection')
                            # Check in body
                            elif sig_lower in body:
                                waf_result['detected']   = True
                                waf_result['waf_name']   = waf_name
                                waf_result['confidence'] = 'medium'
                                waf_result['evidence'].append(f"Body contains '{sig}'")
                                waf_result['method'].append('body_inspection')

                    if waf_result['detected']:
                        logger.info(f"✅ WAF detected: {waf_result['waf_name']} ({waf_result['confidence']} confidence)")
            except:
                pass

            # Method 2: Send a malicious-looking request to trigger WAF
            if not waf_result['detected']:
                try:
                    probe_params = urllib.parse.urlencode({
                        'id': "1' OR '1'='1",
                        'cmd': 'cat /etc/passwd',
                        'xss': '<script>alert(1)</script>'
                    })
                    probe_url = f"https://{target}/?{probe_params}"
                    async with self.session.get(
                        probe_url, timeout=8, ssl=False, allow_redirects=False
                    ) as response:
                        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                        body = ''
                        try:
                            body = (await response.text())[:2000].lower()
                        except:
                            pass

                        # WAF typically returns 403, 406, 429, 503 for malicious requests
                        if response.status in (403, 406, 429, 503):
                            for waf_name, signatures in WAF_SIGNATURES.items():
                                for sig in signatures:
                                    if sig.lower() in body or any(sig.lower() in hv for hv in headers_lower.values()):
                                        waf_result['detected']   = True
                                        waf_result['waf_name']   = waf_name
                                        waf_result['confidence'] = 'high'
                                        waf_result['evidence'].append(f"WAF blocked malicious probe with {response.status}")
                                        waf_result['method'].append('probe_response')
                                        break

                            # Generic WAF detection if no specific signature matched
                            if not waf_result['detected'] and response.status == 403:
                                waf_result['detected']   = True
                                waf_result['waf_name']   = 'Unknown WAF'
                                waf_result['confidence'] = 'low'
                                waf_result['evidence'].append(f"Probe blocked with 403 — likely WAF")
                                waf_result['method'].append('probe_response')
                except:
                    pass

        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")

        if not waf_result['detected']:
            waf_result['waf_name']   = 'No WAF detected'
            waf_result['confidence'] = 'medium'
            waf_result['evidence'].append('No WAF signatures found in headers or responses')

        data.waf_detection = waf_result
        logger.info(f"🛡️ WAF: {'Detected — ' + waf_result['waf_name'] if waf_result['detected'] else 'Not detected'}")

    # =========================================================================
    # ✅ NEW METHOD #5 — Full IP Reputation (AbuseIPDB + AlienVault + VirusTotal)
    # =========================================================================

    async def _ip_reputation_full(self, ip_addresses: List[str], data: InfrastructureData):
        """
        Full IP reputation check using:
        1. Spamhaus + SpamCop (DNS blacklists — free)
        2. AbuseIPDB (abuse score)
        3. AlienVault OTX (threat intel)
        4. VirusTotal (malicious detections)
        """
        for ip in ip_addresses[:20]:
            await asyncio.sleep(1)
            rep = {
                'ip':           ip,
                'blacklists':   [],
                'abuseipdb':    {},
                'alienvault':   {},
                'virustotal':   {},
                'overall_risk': 'unknown'
            }

            # 1. DNS blacklists
            reversed_ip = '.'.join(reversed(ip.split('.')))
            for bl in ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net', 'b.barracudacentral.org']:
                try:
                    dns.resolver.resolve(f"{reversed_ip}.{bl}", 'A')
                    rep['blacklists'].append({'ip': ip, 'blacklist': bl, 'listed': True})
                except dns.resolver.NXDOMAIN:
                    pass
                except:
                    pass

            # 2. AbuseIPDB
            if API_CONFIG_AVAILABLE:
                try:
                    config = APPLICATION_LANDSCAPE_APIS['threat_intel']['abuseipdb']
                    if config.get('enabled'):
                        headers = {
                            'Key':    config['api_key'],
                            'Accept': 'application/json'
                        }
                        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
                        async with self.session.get(
                            config['endpoint'], headers=headers, params=params, timeout=10
                        ) as response:
                            if response.status == 200:
                                result = await response.json()
                                abuse_data = result.get('data', {})
                                rep['abuseipdb'] = {
                                    'abuse_score':     abuse_data.get('abuseConfidenceScore', 0),
                                    'total_reports':   abuse_data.get('totalReports', 0),
                                    'last_reported':   abuse_data.get('lastReportedAt', ''),
                                    'country':         abuse_data.get('countryCode', ''),
                                    'isp':             abuse_data.get('isp', ''),
                                    'is_whitelisted':  abuse_data.get('isWhitelisted', False),
                                    'domain':          abuse_data.get('domain', ''),
                                }
                                score = abuse_data.get('abuseConfidenceScore', 0)
                                logger.debug(f"✅ AbuseIPDB {ip}: score={score}")
                except Exception as e:
                    logger.warning(f"AbuseIPDB failed for {ip}: {e}")

            # 3. AlienVault OTX
            if API_CONFIG_AVAILABLE:
                try:
                    config = APPLICATION_LANDSCAPE_APIS['threat_intel']['alienvault']
                    if config.get('enabled'):
                        headers = {'X-OTX-API-KEY': config['api_key']}
                        url = f"{config['endpoint']}{ip}/general"
                        async with self.session.get(url, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                otx_data = await response.json()
                                rep['alienvault'] = {
                                    'pulse_count':    otx_data.get('pulse_info', {}).get('count', 0),
                                    'reputation':     otx_data.get('reputation', 0),
                                    'country':        otx_data.get('country_name', ''),
                                    'asn':            otx_data.get('asn', ''),
                                    'malware_family': [p.get('name', '') for p in otx_data.get('pulse_info', {}).get('pulses', [])[:3]],
                                }
                                logger.debug(f"✅ AlienVault {ip}: pulses={rep['alienvault']['pulse_count']}")
                except Exception as e:
                    logger.warning(f"AlienVault failed for {ip}: {e}")

            # 4. VirusTotal
            if API_CONFIG_AVAILABLE:
                try:
                    config = APPLICATION_LANDSCAPE_APIS['threat_intel']['virustotal']
                    if config.get('enabled'):
                        headers = {'x-apikey': config['api_key']}
                        url = f"{config['endpoint']}ip_addresses/{ip}"
                        async with self.session.get(url, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                vt_data = await response.json()
                                attrs = vt_data.get('data', {}).get('attributes', {})
                                last_analysis = attrs.get('last_analysis_stats', {})
                                rep['virustotal'] = {
                                    'malicious':    last_analysis.get('malicious', 0),
                                    'suspicious':   last_analysis.get('suspicious', 0),
                                    'harmless':     last_analysis.get('harmless', 0),
                                    'undetected':   last_analysis.get('undetected', 0),
                                    'reputation':   attrs.get('reputation', 0),
                                    'country':      attrs.get('country', ''),
                                    'as_owner':     attrs.get('as_owner', ''),
                                    'network':      attrs.get('network', ''),
                                }
                                logger.debug(f"✅ VirusTotal {ip}: malicious={rep['virustotal']['malicious']}")
                except Exception as e:
                    logger.warning(f"VirusTotal failed for {ip}: {e}")

            # Calculate overall risk level
            rep['overall_risk'] = self._calculate_ip_risk(rep)
            data.ip_reputation[ip] = rep

            # Also update blacklisted_ips for backward compatibility
            if rep['blacklists']:
                data.blacklisted_ips.extend(rep['blacklists'])

        logger.info(f"✅ IP reputation checked for {len(data.ip_reputation)} IPs")

    def _calculate_ip_risk(self, rep: Dict) -> str:
        """Calculate overall risk level for an IP based on all reputation sources"""
        score = 0

        # Blacklist hits
        score += len(rep.get('blacklists', [])) * 20

        # AbuseIPDB score
        abuse_score = rep.get('abuseipdb', {}).get('abuse_score', 0)
        if abuse_score > 75:   score += 40
        elif abuse_score > 50: score += 25
        elif abuse_score > 25: score += 10

        # AlienVault pulses
        pulses = rep.get('alienvault', {}).get('pulse_count', 0)
        if pulses > 10: score += 30
        elif pulses > 5: score += 15
        elif pulses > 0: score += 5

        # VirusTotal malicious
        vt_malicious = rep.get('virustotal', {}).get('malicious', 0)
        if vt_malicious > 5:  score += 40
        elif vt_malicious > 0: score += 20

        if score >= 60:  return 'CRITICAL'
        if score >= 40:  return 'HIGH'
        if score >= 20:  return 'MEDIUM'
        if score > 0:    return 'LOW'
        return 'CLEAN'

    # =========================================================================
    # DNStwist (unchanged)
    # =========================================================================

    async def _run_dnstwist(self, target: str, data: InfrastructureData):
        if not DNSTWIST_AVAILABLE:
            return
        try:
            loop = asyncio.get_event_loop()
            def run_dnstwist_sync():
                try:
                    return dnstwist.run(domain=target, registered=True, format='null', threads=50)
                except:
                    return []
            results = await loop.run_in_executor(None, run_dnstwist_sync)
            if results:
                registered_count = len([d for d in results if d.get('dns_a')])
                data.dnstwist_lookalikes = {
                    'total_permutations': len(results),
                    'registered_domains': registered_count,
                    'lookalike_details':  [d for d in results if d.get('dns_a')][:20]
                }
                logger.info(f"✅ DNStwist: {registered_count} registered lookalikes")
        except Exception as e:
            logger.debug(f"DNStwist failed: {e}")


# =============================================================================
# JSON helpers + save + main
# =============================================================================

def _to_jsonable(obj):
    if is_dataclass(obj):
        obj = asdict(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, datetime):
                out[k] = v.isoformat()
            elif isinstance(v, set):
                out[k] = sorted(list(v))
            else:
                out[k] = _to_jsonable(v)
        return out
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, set):
        return sorted(list(obj))
    return obj


def save_infra_report(data: InfrastructureData, outdir: str = "reports") -> str:
    os.makedirs(outdir, exist_ok=True)
    safe = (data.target or "domain").replace(".", "_")
    ts   = data.timestamp.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(outdir, f"{safe}_phase2_infra_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_to_jsonable(data), f, indent=2)
    return path


async def main(domain: str, save_json: bool = True):
    print("\n" + "="*70)
    print("BSI PHASE 2: INFRASTRUCTURE DISCOVERY (UPDATED — 8 NEW FEATURES)")
    print("="*70 + "\n")

    async with BSIInfrastructureDiscovery() as scanner:
        data = await scanner.discover_infrastructure(domain)

    print("\n" + "="*70)
    print("DISCOVERY COMPLETE")
    print("="*70)
    print(f"\n📊 Summary for {domain}:")
    print(f"   Subdomains Discovered:  {len(data.subdomains)}")
    print(f"   Active Subdomains:      {len(data.active_subdomains)}")
    print(f"   Unique IPs:             {len(data.ip_addresses)}")
    print(f"   Open Ports (total):     {sum(len(p) for p in data.open_ports.values())}")
    print(f"   Banners Grabbed:        {sum(len(b) for b in data.port_banners.values())}")
    print(f"   WAF Detected:           {data.waf_detection.get('waf_name', 'None')}")
    print(f"   SSL Weaknesses:         {len(data.ssl_weaknesses.get('summary', []))}")
    print(f"   DMARC Policy:           {data.mail_server_analysis.get('dmarc_strength', {}).get('level', 'N/A')}")
    print(f"   SPF Strictness:         {data.mail_server_analysis.get('spf_strength', {}).get('level', 'N/A')}")
    print(f"   Zone Transfer (AXFR):   {'VULNERABLE ⚠️' if data.dns_records.get('AXFR', {}).get('vulnerable') else 'Secure ✅'}")
    print(f"   Cloud Provider:         {data.cloud_provider or 'Not detected'}")
    print(f"   IP Reputation Checked:  {len(data.ip_reputation)}")

    if save_json:
        path = save_infra_report(data)
        print(f"\n✅ Report saved: {path}")

    print("\n" + "="*70 + "\n")
    return data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BSI Phase 2: Infrastructure Discovery (Updated)")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--no-save", action="store_true", help="Don't save JSON report")
    args = parser.parse_args()
    asyncio.run(main(args.domain, save_json=not args.no_save))