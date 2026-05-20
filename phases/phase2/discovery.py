"""
Phase 2: Main Infrastructure Discovery
Orchestrates all infrastructure discovery analysis
"""

import asyncio
import logging
from typing import Dict, Any
from .models import InfrastructureData
from .subdomain_discovery import SubdomainDiscovery
from .ip_analysis import IPAnalysis
from .ssl_analysis import SSLAnalysis

logger = logging.getLogger(__name__)


class BSIInfrastructureDiscovery:
    """Main orchestrator for Phase 2: Infrastructure Discovery"""

    def __init__(self):
        self.subdomain_discovery = SubdomainDiscovery()
        self.ip_analysis = IPAnalysis()
        self.ssl_analysis = SSLAnalysis()
        logger.info("BSIInfrastructureDiscovery initialized")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def discover_infrastructure(self, target: str) -> InfrastructureData:
        """Main entry point for infrastructure discovery"""
        logger.info(f"Starting infrastructure discovery for {target}")

        data = InfrastructureData(domain=target)

        # Run subdomain discovery, IP enumeration, and SSL analysis concurrently
        subdomain_task = self.subdomain_discovery.discover_subdomains(target)
        ip_task = self.ip_analysis.enumerate_ips(target)
        ssl_task = self.ssl_analysis.analyze_ssl(target)

        subdomains, ips, ssl_data = await asyncio.gather(
            subdomain_task, ip_task, ssl_task, return_exceptions=True
        )

        # Subdomains
        if isinstance(subdomains, Exception):
            logger.error(f"Subdomain discovery failed: {subdomains}")
            data.subdomains = []
        else:
            data.subdomains = list(subdomains)

        # IPs
        if isinstance(ips, Exception):
            logger.error(f"IP enumeration failed: {ips}")
            data.ip_addresses = []
        else:
            data.ip_addresses = list(ips)

        # SSL
        if isinstance(ssl_data, Exception):
            logger.error(f"SSL analysis failed: {ssl_data}")
            data.ssl_analysis = {'error': str(ssl_data)}
        else:
            data.ssl_analysis = ssl_data
            # Populate ssl_weaknesses from ssl analysis result
            data.ssl_weaknesses = ssl_data.get('weaknesses', {})

        # IP reputation (includes blacklisted_ips detection)
        if data.ip_addresses:
            try:
                reputation = await self.ip_analysis.analyze_ip_reputation(data.ip_addresses)
                # Separate blacklisted list from per-IP data
                blacklisted = reputation.pop('_blacklisted_ips', [])
                data.asn_info = reputation
                data.blacklisted_ips = blacklisted
            except Exception as e:
                logger.error(f"IP reputation analysis failed: {e}")

        # ASN info for primary IP
        if data.ip_addresses:
            try:
                asn = await self.ip_analysis.get_asn_info(data.ip_addresses[0])
                # Merge into asn_info
                data.asn_info[data.ip_addresses[0]] = {
                    **data.asn_info.get(data.ip_addresses[0], {}),
                    **asn
                }
            except Exception as e:
                logger.error(f"ASN lookup failed: {e}")

        logger.info(
            f"Infrastructure discovery complete for {target}: "
            f"{len(data.subdomains)} subdomains, {len(data.ip_addresses)} IPs, "
            f"{len(data.blacklisted_ips)} blacklisted"
        )
        return data
