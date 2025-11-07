"""
HTTPX scanner module for HTTP probing and analysis
"""

import subprocess
import json
from typing import Dict, List, Any


class HTTPXScanner:
    """Wrapper for httpx tool"""
    
    def __init__(self):
        """Initialize HTTPX scanner"""
        self.tool_name = 'httpx'
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with httpx
        
        Args:
            target: Target domain or IP
            target_type: 'domain' or 'ip'
            
        Returns:
            Dictionary with scan results
        """
        if not self.check_tool_installed():
            return {
                'status': 'error',
                'error': f'{self.tool_name} not installed. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'live_hosts': [],
                'technologies': []
            }
        
        try:
            # Build httpx command with JSON output
            cmd = [
                'httpx',
                '-u', target,
                '-json',
                '-follow-redirects',
                '-status-code',
                '-tech-detect',
                '-title',
                '-web-server',
                '-content-length',
                '-response-time',
                '-timeout', '10'
            ]
            
            # Run httpx
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0 and not result.stdout:
                return {
                    'status': 'error',
                    'error': result.stderr or 'HTTPX scan failed',
                    'live_hosts': [],
                    'technologies': []
                }
            
            # Parse JSON output
            hosts = []
            technologies = set()
            
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    host_info = {
                        'url': data.get('url', ''),
                        'status_code': data.get('status_code', 0),
                        'title': data.get('title', ''),
                        'webserver': data.get('webserver', ''),
                        'content_length': data.get('content_length', 0),
                        'response_time': data.get('response_time', ''),
                        'tech': data.get('tech', []),
                        'scheme': data.get('scheme', ''),
                        'host': data.get('host', ''),
                        'port': data.get('port', '')
                    }
                    
                    hosts.append(host_info)
                    
                    # Collect technologies
                    if data.get('tech'):
                        technologies.update(data.get('tech', []))
                        
                except json.JSONDecodeError:
                    continue
            
            # Analyze results
            status_codes = {}
            web_servers = {}
            
            for host in hosts:
                # Count status codes
                code = host['status_code']
                status_codes[code] = status_codes.get(code, 0) + 1
                
                # Count web servers
                server = host['webserver'] or 'Unknown'
                web_servers[server] = web_servers.get(server, 0) + 1
            
            results = {
                'status': 'success',
                'total_hosts': len(hosts),
                'live_hosts': hosts,
                'technologies': sorted(list(technologies)),
                'status_codes': status_codes,
                'web_servers': web_servers,
                'statistics': {
                    'total_scanned': len(hosts),
                    'unique_technologies': len(technologies),
                    'unique_servers': len(web_servers)
                }
            }
            
            return results
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'error',
                'error': 'Scan timeout exceeded',
                'live_hosts': [],
                'technologies': []
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'live_hosts': [],
                'technologies': []
            }
    
    def scan_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Scan a list of URLs with httpx
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Dictionary with scan results
        """
        if not self.check_tool_installed():
            return {
                'status': 'error',
                'error': f'{self.tool_name} not installed',
                'live_hosts': []
            }
        
        try:
            # Create temporary file with URLs
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(f"{url}\n")
                temp_file = f.name
            
            # Run httpx with file input
            cmd = [
                'httpx',
                '-l', temp_file,
                '-json',
                '-follow-redirects',
                '-status-code',
                '-tech-detect',
                '-title',
                '-timeout', '10'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Clean up temp file
            import os
            try:
                os.unlink(temp_file)
            except:
                pass
            
            # Parse results (similar to scan method)
            hosts = []
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    hosts.append(data)
                except json.JSONDecodeError:
                    continue
            
            return {
                'status': 'success',
                'total_hosts': len(hosts),
                'live_hosts': hosts
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'live_hosts': []
            }
    
    @staticmethod
    def check_tool_installed() -> bool:
        """Check if httpx is installed"""
        try:
            result = subprocess.run(
                ['httpx', '-version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
