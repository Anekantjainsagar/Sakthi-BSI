#!/usr/bin/env python3
"""
Data Completeness Checker - Verifies if all data for a domain has been displayed
Compares database records with what's shown in the UI
"""

import json
from typing import Dict, Any, List, Tuple
from data.database import get_db_manager


class DataCompletenessChecker:
    """Checks if all stored data for a domain is being displayed"""
    
    def __init__(self):
        self.db = get_db_manager()
    
    def get_stored_data_summary(self, domain: str) -> Dict[str, Any]:
        """Get summary of all data stored in database for a domain"""
        analysis = self.db.get_analysis(domain)
        
        if not analysis:
            return {
                'domain': domain,
                'exists': False,
                'total_records': 0,
                'phases': {}
            }
        
        analysis_id = analysis['id']
        phases = self.db.get_all_phase_results(analysis_id)
        
        summary = {
            'domain': domain,
            'exists': True,
            'analysis_id': analysis_id,
            'created_at': analysis['created_at'],
            'updated_at': analysis['updated_at'],
            'status': analysis['status'],
            'completion_percentage': analysis['completion_percentage'],
            'total_records': len(phases),
            'phases': {}
        }
        
        # Analyze each phase
        for phase in phases:
            phase_num = phase['phase_number']
            phase_name = phase['phase_name']
            
            if phase['result_data']:
                try:
                    data = json.loads(phase['result_data'])
                    summary['phases'][phase_num] = {
                        'name': phase_name,
                        'status': phase['status'],
                        'has_data': True,
                        'data_size': len(json.dumps(data)),
                        'keys': list(data.keys()) if isinstance(data, dict) else [],
                        'record_count': self._count_records(data)
                    }
                except:
                    summary['phases'][phase_num] = {
                        'name': phase_name,
                        'status': phase['status'],
                        'has_data': False,
                        'error': 'Failed to parse data'
                    }
            else:
                summary['phases'][phase_num] = {
                    'name': phase_name,
                    'status': phase['status'],
                    'has_data': False
                }
        
        return summary
    
    def _count_records(self, data: Any) -> int:
        """Count total records in data structure"""
        if isinstance(data, dict):
            count = 0
            for v in data.values():
                if isinstance(v, (list, dict)):
                    count += self._count_records(v)
                else:
                    count += 1
            return count
        elif isinstance(data, list):
            return len(data)
        else:
            return 1
    
    def get_displayed_data_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary of data currently displayed in UI"""
        summary = {
            'phases': {}
        }
        
        phase_keys = {
            1: 'business_domain',
            2: 'infrastructure',
            3: 'application_landscape',
            4: 'correlation_analysis',
            5: 'risk_assessment'
        }
        
        for phase_num, key in phase_keys.items():
            data = results.get(key)
            
            if data and 'error' not in data:
                summary['phases'][phase_num] = {
                    'name': self._get_phase_name(phase_num),
                    'displayed': True,
                    'data_size': len(json.dumps(data, default=str)),
                    'keys': list(data.keys()) if isinstance(data, dict) else [],
                    'record_count': self._count_records(data)
                }
            else:
                summary['phases'][phase_num] = {
                    'name': self._get_phase_name(phase_num),
                    'displayed': False
                }
        
        return summary
    
    def _get_phase_name(self, phase_num: int) -> str:
        """Get phase name from number"""
        names = {
            1: 'Business Domain',
            2: 'Infrastructure',
            3: 'Application Landscape',
            4: 'Correlation Analysis',
            5: 'Risk Assessment'
        }
        return names.get(phase_num, f'Phase {phase_num}')
    
    def compare_data(self, domain: str, displayed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compare stored data with displayed data"""
        stored = self.get_stored_data_summary(domain)
        displayed = self.get_displayed_data_summary(displayed_results)
        
        comparison = {
            'domain': domain,
            'stored_phases': len(stored.get('phases', {})),
            'displayed_phases': len([p for p in displayed['phases'].values() if p.get('displayed')]),
            'completeness_percentage': 0,
            'missing_phases': [],
            'incomplete_phases': [],
            'phase_details': {}
        }
        
        # Compare each phase
        for phase_num in range(1, 6):
            stored_phase = stored.get('phases', {}).get(phase_num, {})
            displayed_phase = displayed['phases'].get(phase_num, {})
            
            phase_name = self._get_phase_name(phase_num)
            
            if stored_phase.get('has_data') and not displayed_phase.get('displayed'):
                comparison['missing_phases'].append(phase_name)
                comparison['phase_details'][phase_num] = {
                    'name': phase_name,
                    'status': 'MISSING',
                    'stored_records': stored_phase.get('record_count', 0),
                    'displayed_records': 0,
                    'stored_keys': stored_phase.get('keys', []),
                    'displayed_keys': []
                }
            elif stored_phase.get('has_data') and displayed_phase.get('displayed'):
                stored_count = stored_phase.get('record_count', 0)
                displayed_count = displayed_phase.get('record_count', 0)
                
                if stored_count > displayed_count:
                    comparison['incomplete_phases'].append(phase_name)
                    status = 'INCOMPLETE'
                else:
                    status = 'COMPLETE'
                
                comparison['phase_details'][phase_num] = {
                    'name': phase_name,
                    'status': status,
                    'stored_records': stored_count,
                    'displayed_records': displayed_count,
                    'stored_keys': stored_phase.get('keys', []),
                    'displayed_keys': displayed_phase.get('keys', []),
                    'missing_keys': list(set(stored_phase.get('keys', [])) - set(displayed_phase.get('keys', [])))
                }
        
        # Calculate completeness
        if comparison['stored_phases'] > 0:
            comparison['completeness_percentage'] = int(
                (comparison['displayed_phases'] / comparison['stored_phases']) * 100
            )
        
        return comparison
    
    def get_completeness_report(self, domain: str, displayed_results: Dict[str, Any]) -> str:
        """Generate human-readable completeness report"""
        comparison = self.compare_data(domain, displayed_results)
        
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║           DATA COMPLETENESS REPORT - {domain}
╚════════════════════════════════════════════════════════════════╝

📊 OVERALL COMPLETENESS: {comparison['completeness_percentage']}%
   Displayed: {comparison['displayed_phases']}/{comparison['stored_phases']} phases

"""
        
        if comparison['missing_phases']:
            report += f"""⚠️  MISSING PHASES ({len(comparison['missing_phases'])})
   These phases have data in the database but are NOT displayed:
"""
            for phase in comparison['missing_phases']:
                report += f"   • {phase}\n"
            report += "\n"
        
        if comparison['incomplete_phases']:
            report += f"""⚠️  INCOMPLETE PHASES ({len(comparison['incomplete_phases'])})
   These phases are displayed but missing some data:
"""
            for phase in comparison['incomplete_phases']:
                report += f"   • {phase}\n"
            report += "\n"
        
        report += "📋 PHASE DETAILS:\n"
        for phase_num in range(1, 6):
            if phase_num in comparison['phase_details']:
                detail = comparison['phase_details'][phase_num]
                report += f"""
   Phase {phase_num}: {detail['name']} [{detail['status']}]
   ├─ Stored Records: {detail['stored_records']}
   ├─ Displayed Records: {detail['displayed_records']}
   └─ Missing Keys: {', '.join(detail['missing_keys']) if detail['missing_keys'] else 'None'}
"""
        
        return report
    
    def get_missing_data_details(self, domain: str, displayed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed information about missing data"""
        comparison = self.compare_data(domain, displayed_results)
        
        missing_details = {
            'domain': domain,
            'completeness_percentage': comparison['completeness_percentage'],
            'missing_phases': comparison['missing_phases'],
            'incomplete_phases': comparison['incomplete_phases'],
            'details': {}
        }
        
        for phase_num, detail in comparison['phase_details'].items():
            if detail['status'] in ['MISSING', 'INCOMPLETE']:
                missing_details['details'][detail['name']] = {
                    'status': detail['status'],
                    'stored_records': detail['stored_records'],
                    'displayed_records': detail['displayed_records'],
                    'missing_keys': detail['missing_keys'],
                    'stored_keys': detail['stored_keys']
                }
        
        return missing_details
