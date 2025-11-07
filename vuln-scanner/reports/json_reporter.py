"""
JSON report generator
"""

import json
from typing import Dict, Any
from pathlib import Path
from datetime import datetime


class JSONReporter:
    """Generate JSON reports from scan results"""
    
    def __init__(self):
        """Initialize JSON reporter"""
        pass
    
    def generate(self, scan_results: Dict[str, Any], output_file: Path) -> bool:
        """
        Generate JSON report from scan results
        
        Args:
            scan_results: Dictionary with scan results
            output_file: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add metadata
            report = {
                'report_metadata': {
                    'generator': 'VulnScanner',
                    'version': '1.0.0',
                    'generated_at': datetime.now().isoformat(),
                    'format': 'json'
                },
                'scan_data': scan_results
            }
            
            # Write JSON file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"[!] Error generating JSON report: {e}")
            return False
    
    def generate_compact(self, scan_results: Dict[str, Any], output_file: Path) -> bool:
        """
        Generate compact JSON report (minified)
        
        Args:
            scan_results: Dictionary with scan results
            output_file: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"[!] Error generating compact JSON report: {e}")
            return False
    
    @staticmethod
    def load_report(file_path: Path) -> Dict[str, Any]:
        """
        Load JSON report from file
        
        Args:
            file_path: Path to JSON report
            
        Returns:
            Dictionary with report data
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading JSON report: {e}")
            return {}
    
    @staticmethod
    def merge_reports(report_files: list, output_file: Path) -> bool:
        """
        Merge multiple JSON reports into one
        
        Args:
            report_files: List of paths to JSON reports
            output_file: Path to merged output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            merged_data = {
                'report_metadata': {
                    'generator': 'VulnScanner',
                    'version': '1.0.0',
                    'generated_at': datetime.now().isoformat(),
                    'format': 'json',
                    'type': 'merged',
                    'source_reports': len(report_files)
                },
                'scans': []
            }
            
            for report_file in report_files:
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        merged_data['scans'].append(data)
                except Exception as e:
                    print(f"[!] Error loading {report_file}: {e}")
                    continue
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(merged_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"[!] Error merging reports: {e}")
            return False
