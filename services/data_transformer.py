#!/usr/bin/env python3
"""
Data Transformer - Uses LLM to restructure phase output for display templates
Transforms raw phase data into template-compatible format
"""

import json
import logging
from typing import Dict, Any
from config.gemini_config import call_gemini

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataTransformer:
    """Transforms raw phase data using LLM for template compatibility"""
    
    def __init__(self):
        """Initialize data transformer"""
        self.transformations = {}
    
    def transform_phase_data(self, phase_num: int, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform raw phase data using LLM"""
        
        if not raw_data or 'error' in raw_data:
            return raw_data
        
        try:
            if phase_num == 1:
                return self._transform_phase1(raw_data)
            elif phase_num == 2:
                return self._transform_phase2(raw_data)
            elif phase_num == 3:
                return self._transform_phase3(raw_data)
            elif phase_num == 4:
                return self._transform_phase4(raw_data)
            elif phase_num == 5:
                return self._transform_phase5(raw_data)
        except Exception as e:
            logger.error(f"❌ Error transforming Phase {phase_num}: {e}")
            return raw_data
        
        return raw_data
    
    def _transform_phase1(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Phase 1 data"""
        logger.info("🔄 Transforming Phase 1 data...")
        
        # Map actual keys to expected keys
        transformed = {
            "company_name": raw_data.get('name') or raw_data.get('company_name', 'Unknown'),
            "domain": raw_data.get('domain', 'Unknown'),
            "analysis_timestamp": raw_data.get('analysis_timestamp', ''),
            "hunter_io": raw_data.get('hunter_io', {}),
            "host_io": raw_data.get('host_io', {}),
            "abstractapi_company": raw_data.get('abstractapi_company', {}),
            "whois_data": raw_data.get('whois_data', {}),
            "scraped_data": raw_data.get('scraped_data', {}),
            "search_data": raw_data.get('search_data', {}),
            "ai_analysis": raw_data.get('ai_analysis', {})
        }
        
        logger.info("✅ Phase 1 data transformed")
        return transformed
    
    def _transform_phase2(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Phase 2 data"""
        logger.info("🔄 Transforming Phase 2 data...")
        
        prompt = f"""
        Transform this raw infrastructure discovery data into a clean, structured format.
        
        Raw data:
        {json.dumps(raw_data, indent=2, default=str)}
        
        Return ONLY valid JSON with this structure:
        {{
            "subdomains": ["subdomain1.com", "subdomain2.com"],
            "ip_addresses": ["1.2.3.4", "5.6.7.8"],
            "ssl_analysis": {{
                "certificate_info": {{}},
                "tls_versions_supported": ["TLSv1.2", "TLSv1.3"],
                "tls_versions_rejected": [],
                "vulnerabilities": []
            }},
            "asn_info": {{
                "ip": "string",
                "asn": "string",
                "organization": "string",
                "country": "string"
            }}
        }}
        """
        
        try:
            response = call_gemini(prompt)
            transformed = json.loads(response)
            logger.info("✅ Phase 2 data transformed")
            return transformed
        except Exception as e:
            logger.error(f"❌ Phase 2 transformation failed: {e}")
            return raw_data
    
    def _transform_phase3(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Phase 3 data"""
        logger.info("🔄 Transforming Phase 3 data...")
        
        prompt = f"""
        Transform this raw application landscape data into a clean, structured format.
        
        Raw data:
        {json.dumps(raw_data, indent=2, default=str)}
        
        Return ONLY valid JSON with this structure:
        {{
            "1_application_discovery": {{
                "status": "Active/Inactive",
                "server": "string",
                "response_time_ms": 0,
                "content_length": 0
            }},
            "2_web_server_stack": {{
                "cms": ["WordPress", "Drupal"],
                "frameworks": ["Django", "Flask"],
                "javascript_libraries": ["jQuery", "React"]
            }},
            "7_security_posture": {{
                "security_headers": {{
                    "X-Frame-Options": "string or null",
                    "X-Content-Type-Options": "string or null",
                    "Content-Security-Policy": "string or null",
                    "Strict-Transport-Security": "string or null"
                }},
                "admin_panels": [
                    {{"path": "/admin", "status": 200, "access": "OPEN"}}
                ],
                "cookie_security": []
            }},
            "8_api_discovery": {{
                "api_endpoints": [
                    {{"path": "/api", "status": 200}}
                ],
                "graphql_endpoints": []
            }}
        }}
        """
        
        try:
            response = call_gemini(prompt)
            transformed = json.loads(response)
            logger.info("✅ Phase 3 data transformed")
            return transformed
        except Exception as e:
            logger.error(f"❌ Phase 3 transformation failed: {e}")
            return raw_data
    
    def _transform_phase4(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Phase 4 data"""
        logger.info("🔄 Transforming Phase 4 data...")
        
        # Map actual keys to expected keys
        security_issues = raw_data.get('security_issues', [])
        
        # Extract vulnerabilities from security_issues
        vulnerabilities = []
        for issue in security_issues:
            vulnerabilities.append({
                "title": issue.get('title', issue.get('name', 'Unknown')),
                "severity": issue.get('severity', 'Medium'),
                "source": issue.get('source', 'Phase 3'),
                "description": issue.get('description', '')
            })
        
        # Calculate risk score from CVEs
        cves = raw_data.get('cves_all', [])
        risk_score = min(len(cves) * 5, 100)  # Simple scoring
        
        transformed = {
            "overall_risk_score": risk_score,
            "summary": raw_data.get('summary', {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "total": len(security_issues)
            }),
            "vulnerabilities": vulnerabilities,
            "threat_actors": [],  # Extract from apt_mapping_md if available
            "mitre_mapping": {},
            "domain": raw_data.get('domain', 'Unknown'),
            "cves": cves,
            "security_issues": security_issues
        }
        
        logger.info("✅ Phase 4 data transformed")
        return transformed
    
    def _transform_phase5(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Phase 5 data"""
        logger.info("🔄 Transforming Phase 5 data...")
        
        # Map actual keys to expected keys
        business_risk = raw_data.get('business_risk', {})
        infra_risk = raw_data.get('infrastructure_risk', {})
        app_risk = raw_data.get('application_risk', {})
        
        # Determine overall risk level
        risk_levels = [
            business_risk.get('risk_level', 'Medium'),
            infra_risk.get('risk_level', 'Medium'),
            app_risk.get('risk_level', 'Medium')
        ]
        
        # Map to numeric for comparison
        level_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        max_level = max([level_map.get(l, 2) for l in risk_levels])
        level_reverse = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low'}
        overall_level = level_reverse.get(max_level, 'Medium')
        
        # Calculate risk score
        multidim = raw_data.get('multidimensional_score', {})
        risk_score = multidim.get('overall_risk_score', 50)
        
        transformed = {
            "risk_overview": {
                "overall_risk_level": overall_level,
                "risk_score": risk_score,
                "exposure_level": "High" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low",
                "key_findings": [
                    f"Business Risk: {business_risk.get('risk_level', 'Unknown')}",
                    f"Infrastructure Risk: {infra_risk.get('risk_level', 'Unknown')}",
                    f"Application Risk: {app_risk.get('risk_level', 'Unknown')}"
                ]
            },
            "asset_risks": [],
            "business_impact": raw_data.get('business_impact', {}),
            "recommendations": raw_data.get('action_plan', {}).get('immediate_actions', []),
            "threat_landscape": raw_data.get('threat_actor_profile', {}),
            "compliance_status": {},
            "assessment_date": raw_data.get('assessment_date', ''),
            "executive_summary": raw_data.get('executive_summary', '')
        }
        
        logger.info("✅ Phase 5 data transformed")
        return transformed


def transform_all_phases(results: Dict[str, Any]) -> Dict[str, Any]:
    """Transform all phase results"""
    transformer = DataTransformer()
    
    phase_map = {
        1: 'business_domain',
        2: 'infrastructure',
        3: 'application_landscape',
        4: 'correlation_analysis',
        5: 'risk_assessment'
    }
    
    transformed_results = results.copy()
    
    for phase_num, key in phase_map.items():
        if results.get(key):
            logger.info(f"Transforming Phase {phase_num}...")
            transformed_results[key] = transformer.transform_phase_data(phase_num, results[key])
    
    return transformed_results
