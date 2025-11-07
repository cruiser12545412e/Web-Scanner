"""
Nmap scanner module for port scanning and service detection
"""

import nmap
import subprocess
from typing import Dict, List, Any, Optional


class NmapScanner:
    """Wrapper for nmap port scanning"""
    
    def __init__(self, nmap_opts: Optional[str] = None):
        """
        Initialize nmap scanner
        
        Args:
            nmap_opts: Custom nmap options (e.g., '-sV -sC -T4')
        """
        self.nmap_opts = nmap_opts or '-sV -sC -T4'
        self.nm = None
        
        # Check if nmap is installed
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[!] Nmap not found. Please install nmap.")
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with nmap
        
        Args:
            target: Target IP or domain
            target_type: 'ip' or 'domain'
            
        Returns:
            Dictionary with scan results
        """
        if not self.nm:
            return {
                'status': 'error',
                'error': 'Nmap not available',
                'open_ports': [],
                'services': []
            }
        
        try:
            # Run nmap scan
            self.nm.scan(target, arguments=self.nmap_opts)
            
            results = {
                'status': 'success',
                'scan_info': self.nm.scaninfo(),
                'command': self.nm.command_line(),
                'open_ports': [],
                'services': [],
                'os_detection': {},
                'hosts': []
            }
            
            # Parse results for each host
            for host in self.nm.all_hosts():
                host_info = {
                    'host': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': []
                }
                
                # Get protocols
                for proto in self.nm[host].all_protocols():
                    ports_info = []
                    lport = self.nm[host][proto].keys()
                    
                    for port in lport:
                        port_data = self.nm[host][proto][port]
                        
                        port_info = {
                            'port': port,
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'cpe': port_data.get('cpe', '')
                        }
                        
                        ports_info.append(port_info)
                        
                        # Add to open_ports list
                        if port_data['state'] == 'open':
                            results['open_ports'].append(port)
                            results['services'].append({
                                'port': port,
                                'service': port_data.get('name', 'unknown'),
                                'version': f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
                            })
                    
                    host_info['protocols'].append({
                        'protocol': proto,
                        'ports': ports_info
                    })
                
                # OS detection if available
                if 'osmatch' in self.nm[host]:
                    os_matches = []
                    for osmatch in self.nm[host]['osmatch']:
                        os_matches.append({
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy']
                        })
                    host_info['os_matches'] = os_matches
                    if os_matches:
                        results['os_detection'] = os_matches[0]
                
                results['hosts'].append(host_info)
            
            # Summary
            results['total_open_ports'] = len(results['open_ports'])
            results['total_services'] = len(results['services'])
            
            return results
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'open_ports': [],
                'services': []
            }
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Fast scan of most common ports"""
        original_opts = self.nmap_opts
        self.nmap_opts = '-F -T4'  # Fast scan
        result = self.scan(target, 'auto')
        self.nmap_opts = original_opts
        return result
    
    def full_scan(self, target: str) -> Dict[str, Any]:
        """Comprehensive scan with all features"""
        original_opts = self.nmap_opts
        self.nmap_opts = '-sV -sC -O -A -T4'  # Comprehensive scan
        result = self.scan(target, 'auto')
        self.nmap_opts = original_opts
        return result
    
    def scan_specific_ports(self, target: str, ports: str) -> Dict[str, Any]:
        """
        Scan specific ports
        
        Args:
            target: Target to scan
            ports: Port specification (e.g., '80,443' or '1-1000')
        """
        original_opts = self.nmap_opts
        self.nmap_opts = f'-p {ports} -sV -sC'
        result = self.scan(target, 'auto')
        self.nmap_opts = original_opts
        return result
    
    @staticmethod
    def check_nmap_installed() -> bool:
        """Check if nmap is installed on the system"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
