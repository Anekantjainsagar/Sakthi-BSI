"""
Phase 2: Data Models
Defines data structures for infrastructure discovery
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class SubdomainInfo:
    """Information about a discovered subdomain"""
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    is_active: bool = False
    status_code: Optional[int] = None
    
    def __post_init__(self):
        if not self.subdomain:
            raise ValueError("Subdomain cannot be empty")


@dataclass
class InfrastructureData:
    """Complete infrastructure discovery data"""
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    subdomain_mapping: Dict[str, List[str]] = field(default_factory=dict)
    mail_servers: List[Dict[str, Any]] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    ssl_analysis: Dict[str, Any] = field(default_factory=dict)
    ssl_weaknesses: Dict[str, Any] = field(default_factory=dict)
    mail_server_analysis: Dict[str, Any] = field(default_factory=dict)
    asn_info: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    blacklisted_ips: List[Dict[str, Any]] = field(default_factory=list)
    security_misconfigs: Dict[str, Any] = field(default_factory=dict)
    cloud_provider: Optional[str] = None
    lookalike_domains: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.domain:
            raise ValueError("Domain cannot be empty")
