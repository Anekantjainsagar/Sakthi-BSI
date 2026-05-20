#!/usr/bin/env python3
"""
Display Validators - Validate and normalize phase data before rendering
"""

import logging
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def validate_and_normalize_phase_data(phase_num: int, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize phase data to ensure display functions work correctly
    """
    if not data or 'error' in data:
        return data
    
    try:
        if phase_num == 1:
            return _normalize_phase1(data)
        elif phase_num == 2:
            return _normalize_phase2(data)
        elif phase_num == 3:
            return _normalize_phase3(data)
        elif phase_num == 4:
            return _normalize_phase4(data)
        elif phase_num == 5:
            return _normalize_phase5(data)
    except Exception as e:
        logger.error(f"❌ Error normalizing Phase {phase_num}: {e}")
    
    return data


def _normalize_phase1(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Phase 1 (Business Domain) data"""
    logger.info("🔍 Normalizing Phase 1 data...")
    
    # Ensure all expected keys exist
    required_keys = ['hunter_io', 'host_io', 'abstractapi_company', 'whois_data', 'search_data']
    for key in required_keys:
        if key not in data:
            data[key] = {}
    
    # Ensure nested structures
    if not isinstance(data.get('hunter_io'), dict):
        data['hunter_io'] = {'emails': []}
    if not isinstance(data.get('host_io'), dict):
        data['host_io'] = {'status': 'failed'}
    if not isinstance(data.get('abstractapi_company'), dict):
        data['abstractapi_company'] = {}
    if not isinstance(data.get('whois_data'), dict):
        data['whois_data'] = {}
    if not isinstance(data.get('search_data'), dict):
        data['search_data'] = {}
    
    logger.info("✅ Phase 1 data normalized")
    return data


def _normalize_phase2(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Phase 2 (Infrastructure) data"""
    logger.info("🔍 Normalizing Phase 2 data...")
    
    # Ensure all expected keys exist
    required_keys = ['subdomains', 'open_ports', 'ssl_analysis', 'dns_records', 
                     'mail_server_analysis', 'ip_reputation', 'security_misconfigs']
    for key in required_keys:
        if key not in data:
            if key == 'subdomains':
                data[key] = []
            elif key == 'open_ports':
                data[key] = {}
            else:
                data[key] = {}
    
    # Ensure lists are lists
    if not isinstance(data.get('subdomains'), list):
        data['subdomains'] = []
    
    # Ensure dicts are dicts
    for key in ['open_ports', 'ssl_analysis', 'dns_records', 'mail_server_analysis', 'ip_reputation', 'security_misconfigs']:
        if not isinstance(data.get(key), dict):
            data[key] = {}
    
    logger.info("✅ Phase 2 data normalized")
    return data


def _normalize_phase3(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Phase 3 (Application Landscape) data"""
    logger.info("🔍 Normalizing Phase 3 data...")
    
    # Ensure all expected keys exist with proper numbering
    required_keys = [
        '1_application_discovery',
        '2_web_server_stack',
        '3_erp_sap_detection',
        '4_third_party_software',
        '5_code_repositories',
        '6_outdated_software',
        '7_security_posture',
        '8_api_discovery',
        '9_database_detection'
    ]
    
    for key in required_keys:
        if key not in data:
            data[key] = {}
    
    # Ensure all are dicts
    for key in required_keys:
        if not isinstance(data.get(key), dict):
            data[key] = {}
    
    logger.info("✅ Phase 3 data normalized")
    return data


def _normalize_phase4(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Phase 4 (Correlation) data"""
    logger.info("🔍 Normalizing Phase 4 data...")

    # ── Ensure list keys exist (but DON'T overwrite non-empty strings — scanner stores
    #    attack_vectors and apt_mapping as markdown strings, not lists) ──
    list_keys = ['cves_all', 'security_issues', 'technologies']
    for key in list_keys:
        if key not in data:
            data[key] = []
        elif not isinstance(data.get(key), list):
            data[key] = []

    # ── Alias: scanner saves CVEs as 'vulnerabilities', engine uses 'cves_all' ──
    if not data.get('cves_all') and data.get('vulnerabilities'):
        data['cves_all'] = data['vulnerabilities']

    # attack_vectors: scanner stores as markdown string (attack_vectors_md) OR list
    # Preserve the string; only default to [] if completely absent
    if 'attack_vectors' not in data:
        data['attack_vectors'] = []
    # If it's a non-empty string, keep it as-is (display function handles both)

    # apt_mapping: scanner stores as apt_mapping_md (markdown string)
    # Keep apt_mapping as-is; don't force to []
    if 'apt_mapping' not in data:
        data['apt_mapping'] = []
    # Only reset if it's an empty non-list (e.g. None or 0)
    elif data['apt_mapping'] is None:
        data['apt_mapping'] = []

    # Ensure issues_by_category exists
    if 'issues_by_category' not in data:
        data['issues_by_category'] = {}

    # ── Normalize CVE severity to Title Case so display comparisons work ──
    # Scanner produces "CRITICAL", "HIGH", etc. — display uses "Critical", "High"
    sev_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
    for vuln in data.get('cves_all', []):
        if isinstance(vuln, dict) and 'severity' in vuln:
            vuln['severity'] = sev_map.get(str(vuln['severity']).upper(), vuln['severity'])
    for issue in data.get('security_issues', []):
        if isinstance(issue, dict) and 'severity' in issue:
            issue['severity'] = sev_map.get(str(issue['severity']).upper(), issue['severity'])

    logger.info("✅ Phase 4 data normalized")
    return data


def _normalize_phase5(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Phase 5 (Risk Assessment) data"""
    logger.info("🔍 Normalizing Phase 5 data...")
    
    # Ensure all expected keys exist
    required_keys = ['business_risk', 'infrastructure_risk', 'application_risk', 
                     'business_impact', 'risk_matrix', 'remediation_recommendations']
    for key in required_keys:
        if key not in data:
            if key == 'remediation_recommendations':
                data[key] = []
            else:
                data[key] = {}
    
    # Ensure risk_matrix has required structure
    if 'risk_matrix' not in data or not isinstance(data['risk_matrix'], dict):
        data['risk_matrix'] = {
            'composite_risk_score': 0,
            'risk_level': 'Unknown',
            'dimensions': {}
        }
    
    # Ensure dimensions exist
    if 'dimensions' not in data['risk_matrix']:
        data['risk_matrix']['dimensions'] = {}
    
    # Ensure multidimensional_score exists
    if 'multidimensional_score' not in data:
        data['multidimensional_score'] = {
            'overall_risk_score': 0,
            'risk_rating': 'Unknown'
        }
    
    logger.info("✅ Phase 5 data normalized")
    return data


def safe_get_nested(data: Dict[str, Any], *keys, default=None):
    """Safely get nested dictionary values"""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
            if current is None:
                return default
        else:
            return default
    return current
