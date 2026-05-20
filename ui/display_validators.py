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
    
    # Ensure all expected keys exist
    required_keys = ['cves_all', 'security_issues', 'technologies', 'attack_vectors', 'apt_mapping']
    for key in required_keys:
        if key not in data:
            if key in ['cves_all', 'security_issues', 'technologies', 'attack_vectors', 'apt_mapping']:
                data[key] = []
    
    # Ensure lists are lists
    for key in ['cves_all', 'security_issues', 'technologies', 'attack_vectors', 'apt_mapping']:
        if not isinstance(data.get(key), list):
            data[key] = []
    
    # Ensure issues_by_category exists
    if 'issues_by_category' not in data:
        data['issues_by_category'] = {}
    
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
