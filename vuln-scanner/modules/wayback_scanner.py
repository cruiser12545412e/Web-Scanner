"""
Wayback scanner module for historical URL discovery
"""

import subprocess
import re
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, parse_qs


class WaybackScanner:
    """Wrapper for waybackurls tool"""
    
    def __init__(self):
        """Initialize wayback scanner"""
        self.tool_name = 'waybackurls'
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with waybackurls
        
        Args:
            target: Target domain
            target_type: 'domain' or 'ip'
            
        Returns:
            Dictionary with scan results
        """
        if not self.check_tool_installed():
            return {
                'status': 'error',
                'error': f'{self.tool_name} not installed. Install with: go install github.com/tomnomnom/waybackurls@latest',
                'urls': [],
                'subdomains': [],
                'parameters': []
            }
        
        try:
            # Run waybackurls
            result = subprocess.run(
                ['waybackurls', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0 and result.stderr:
                return {
                    'status': 'error',
                    'error': result.stderr,
                    'urls': [],
                    'subdomains': [],
                    'parameters': []
                }
            
            # Parse URLs
            urls = [url.strip() for url in result.stdout.split('\n') if url.strip()]
            
            # Extract information
            subdomains = self._extract_subdomains(urls, target)
            parameters = self._extract_parameters(urls)
            endpoints = self._extract_endpoints(urls)
            file_extensions = self._count_extensions(urls)
            parameter_urls = self._extract_parameter_urls(urls)
            
            results = {
                'status': 'success',
                'total_urls': len(urls),
                'urls': urls[:1000],  # Limit to first 1000 for report size
                'subdomains': sorted(list(subdomains)),
                'parameters': sorted(list(parameters)),
                'parameter_urls': parameter_urls,  # NEW: URLs grouped by parameter
                'endpoints': sorted(list(endpoints))[:500],  # Top 500 endpoints
                'file_extensions': file_extensions,
                'statistics': {
                    'total_urls': len(urls),
                    'unique_subdomains': len(subdomains),
                    'unique_parameters': len(parameters),
                    'unique_endpoints': len(endpoints)
                }
            }
            
            return results
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'error',
                'error': 'Scan timeout exceeded',
                'urls': [],
                'subdomains': [],
                'parameters': []
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'urls': [],
                'subdomains': [],
                'parameters': []
            }
    
    def _extract_subdomains(self, urls: List[str], base_domain: str) -> Set[str]:
        """Extract unique subdomains from URLs"""
        subdomains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                if base_domain.lower() in domain:
                    subdomains.add(domain)
            except:
                continue
        
        return subdomains
    
    def _extract_parameters(self, urls: List[str]) -> Set[str]:
        """Extract unique parameter names from URLs"""
        parameters = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                parameters.update(params.keys())
            except:
                continue
        
        return parameters
    
    def _extract_parameter_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """Extract URLs grouped by parameter name"""
        parameter_urls = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # Group URLs by each parameter they contain
                for param_name in params.keys():
                    if param_name not in parameter_urls:
                        parameter_urls[param_name] = []
                    
                    # Limit to 20 URLs per parameter to avoid overwhelming output
                    if len(parameter_urls[param_name]) < 20:
                        parameter_urls[param_name].append(url)
            except:
                continue
        
        return parameter_urls
    
    def _extract_endpoints(self, urls: List[str]) -> Set[str]:
        """Extract unique endpoints (paths) from URLs"""
        endpoints = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                
                if path and path != '/':
                    # Remove file extensions for cleaner endpoint list
                    endpoint = re.sub(r'\.[^/.]+$', '', path)
                    endpoints.add(endpoint)
            except:
                continue
        
        return endpoints
    
    def _count_extensions(self, urls: List[str]) -> Dict[str, int]:
        """Count file extensions in URLs"""
        extensions = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                
                # Extract extension
                match = re.search(r'\.([^/.]+)$', path)
                if match:
                    ext = match.group(1).lower()
                    extensions[ext] = extensions.get(ext, 0) + 1
            except:
                continue
        
        # Sort by count and return top 20
        sorted_ext = sorted(extensions.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_ext[:20])
    
    @staticmethod
    def check_tool_installed() -> bool:
        """Check if waybackurls is installed"""
        try:
            result = subprocess.run(
                ['waybackurls', '-h'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0 or b'Usage' in result.stderr
        except:
            return False
