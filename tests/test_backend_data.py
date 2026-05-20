#!/usr/bin/env python3
"""
Test Script - Fetch all backend data for a domain
Verifies what data is actually stored and what's missing
"""

import json
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.database import get_db_manager
from core.orchestrator_bsi import BSIOrchestrator


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)


def print_subsection(title: str):
    """Print a formatted subsection header"""
    print(f"\n--- {title} ---")


def fetch_all_data(domain: str):
    """Fetch all data for a domain from backend"""
    
    print_section(f"BACKEND DATA VERIFICATION FOR: {domain}")
    
    # Initialize database
    db = get_db_manager()
    
    # 1. Check if domain exists in database
    print_subsection("1. DATABASE LOOKUP")
    analysis = db.get_analysis(domain)
    
    if not analysis:
        print(f"❌ Domain '{domain}' not found in database")
        print("   Run analysis first: streamlit run app.py")
        return
    
    print(f"✅ Domain found in database")
    print(f"   Analysis ID: {analysis['id']}")
    print(f"   Status: {analysis['status']}")
    print(f"   Created: {analysis['created_at']}")
    print(f"   Updated: {analysis['updated_at']}")
    
    # 2. Fetch all phase results
    print_subsection("2. PHASE RESULTS")
    phases = db.get_all_phase_results(analysis['id'])
    
    if not phases:
        print(f"❌ No phase results found for analysis ID {analysis['id']}")
        return
    
    print(f"✅ Found {len(phases)} phase results")
    
    phase_data = {}
    for phase in phases:
        phase_num = phase['phase_number']
        phase_name = phase['phase_name']
        result_data = phase['result_data']
        
        print(f"\n   Phase {phase_num}: {phase_name}")
        completed_at = phase.get('completed_at', 'N/A')
        print(f"   - Completed at: {completed_at}")
        print(f"   - Data size: {len(json.dumps(result_data, default=str))} bytes")
        
        if result_data:
            if isinstance(result_data, dict):
                keys = list(result_data.keys())
                print(f"   - Top-level keys ({len(keys)}): {', '.join(keys[:5])}")
                if len(keys) > 5:
                    print(f"     ... and {len(keys) - 5} more keys")
            else:
                print(f"   - Data type: {type(result_data).__name__}")
        else:
            print(f"   ❌ No data stored")
        
        phase_data[phase_num] = result_data
    
    # 3. Detailed phase breakdown
    print_subsection("3. DETAILED PHASE DATA")
    
    for phase_num in sorted(phase_data.keys()):
        data = phase_data[phase_num]
        phase_names = {
            1: "Business Domain Understanding",
            2: "Infrastructure Discovery",
            3: "Application Landscape",
            4: "Vulnerability Correlation",
            5: "Risk Assessment"
        }
        
        print(f"\n📊 PHASE {phase_num}: {phase_names.get(phase_num, 'Unknown')}")
        print("-" * 80)
        
        if not data:
            print("❌ No data")
            continue
        
        if isinstance(data, dict):
            print(f"✅ Data type: Dictionary with {len(data)} keys")
            
            # Show all keys and their types
            for key, value in data.items():
                if isinstance(value, dict):
                    print(f"   📦 {key}: dict ({len(value)} items)")
                elif isinstance(value, list):
                    print(f"   📋 {key}: list ({len(value)} items)")
                elif isinstance(value, str):
                    preview = value[:50] + "..." if len(value) > 50 else value
                    print(f"   📝 {key}: str - {preview}")
                elif isinstance(value, (int, float)):
                    print(f"   🔢 {key}: {type(value).__name__} - {value}")
                elif isinstance(value, bool):
                    print(f"   ✓ {key}: bool - {value}")
                else:
                    print(f"   ❓ {key}: {type(value).__name__}")
        else:
            print(f"✅ Data type: {type(data).__name__}")
            print(f"   Content: {str(data)[:200]}")
    
    # 4. Data completeness check
    print_subsection("4. DATA COMPLETENESS CHECK")
    
    completeness = {
        1: {
            'name': 'Business Domain',
            'required_keys': ['company_name', 'domain', 'hunter_io', 'whois_data', 'ai_analysis'],
            'data': phase_data.get(1, {})
        },
        2: {
            'name': 'Infrastructure',
            'required_keys': ['subdomains', 'ip_addresses', 'ssl_analysis'],
            'data': phase_data.get(2, {})
        },
        3: {
            'name': 'Application',
            'required_keys': ['1_application_discovery', '2_web_server_stack', '7_security_posture', '8_api_discovery'],
            'data': phase_data.get(3, {})
        },
        4: {
            'name': 'Correlation',
            'required_keys': ['overall_risk_score', 'summary', 'vulnerabilities'],
            'data': phase_data.get(4, {})
        },
        5: {
            'name': 'Risk Assessment',
            'required_keys': ['risk_overview', 'business_impact', 'recommendations'],
            'data': phase_data.get(5, {})
        }
    }
    
    for phase_num, check in completeness.items():
        data = check['data']
        required = check['required_keys']
        
        if not data:
            print(f"\n❌ Phase {phase_num} ({check['name']}): NO DATA")
            continue
        
        found_keys = [k for k in required if k in data]
        missing_keys = [k for k in required if k not in data]
        
        completeness_pct = (len(found_keys) / len(required)) * 100
        
        print(f"\n✅ Phase {phase_num} ({check['name']}): {completeness_pct:.0f}% complete")
        print(f"   Found: {len(found_keys)}/{len(required)} required keys")
        
        if found_keys:
            print(f"   ✓ {', '.join(found_keys)}")
        
        if missing_keys:
            print(f"   ❌ Missing: {', '.join(missing_keys)}")
    
    # 5. Export raw data for inspection
    print_subsection("5. RAW DATA EXPORT")
    
    export_file = f"backend_data_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    export_data = {
        'domain': domain,
        'analysis_id': analysis['id'],
        'status': analysis['status'],
        'created_at': str(analysis['created_at']),
        'updated_at': str(analysis['updated_at']),
        'phases': {}
    }
    
    for phase_num, data in phase_data.items():
        export_data['phases'][f'phase_{phase_num}'] = data
    
    try:
        with open(export_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        print(f"✅ Raw data exported to: {export_file}")
    except Exception as e:
        print(f"❌ Failed to export data: {e}")
    
    # 6. Summary
    print_subsection("6. SUMMARY")
    
    total_phases = len([p for p in phase_data.values() if p])
    print(f"Total phases with data: {total_phases}/5")
    
    if total_phases == 5:
        print("✅ All phases have data")
    elif total_phases > 0:
        print(f"⚠️  Only {total_phases} phases have data")
    else:
        print("❌ No phase data found")
    
    print("\n" + "="*80)


def main():
    """Main function"""
    
    if len(sys.argv) < 2:
        print("Usage: python test_backend_data.py <domain>")
        print("Example: python test_backend_data.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1].strip().lower()
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
    
    fetch_all_data(domain)


if __name__ == "__main__":
    main()
