"""
GAU (GetAllURLs) scanner module for URL collection
"""

import subprocess
import re
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, parse_qs


class GAUScanner:
    """Wrapper for gau (GetAllURLs) tool"""
    
    def __init__(self):
        """Initialize GAU scanner"""
        self.tool_name = 'gau'
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with gau
        
        Args:
            target: Target domain
            target_type: 'domain' or 'ip'
            
        Returns:
            Dictionary with scan results
        """
        if not self.check_tool_installed():
            return {
                'status': 'error',
                'error': f'{self.tool_name} not installed. Install with: go install github.com/lc/gau/v2/cmd/gau@latest',
                'urls': [],
                'subdomains': [],
                'parameters': []
            }
        
        try:
            # Run gau with common options
            # --threads 5: Use 5 threads
            # --subs: Include subdomains
            result = subprocess.run(
                ['gau', '--threads', '5', '--subs', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0 and result.stderr:
                # GAU might still produce results even with non-zero exit code
                if not result.stdout:
                    return {
                        'status': 'error',
                        'error': result.stderr,
                        'urls': [],
                        'subdomains': [],
                        'parameters': []
                    }
            
            # Parse URLs
            urls = [url.strip() for url in result.stdout.split('\n') if url.strip()]
            
            # Filter and deduplicate
            urls = self._filter_urls(urls)
            
            # Extract information
            subdomains = self._extract_subdomains(urls, target)
            parameters = self._extract_parameters(urls)
            parameter_urls = self._extract_parameter_urls(urls)
            interesting_urls = self._find_interesting_urls(urls)
            file_types = self._categorize_by_type(urls)
            
            results = {
                'status': 'success',
                'total_urls': len(urls),
                'urls': urls[:1000],  # Limit to first 1000
                'subdomains': sorted(list(subdomains)),
                'parameters': sorted(list(parameters)),
                'parameter_urls': parameter_urls,  # NEW: URLs grouped by parameter
                'interesting_urls': interesting_urls,
                'file_types': file_types,
                'statistics': {
                    'total_urls': len(urls),
                    'unique_subdomains': len(subdomains),
                    'unique_parameters': len(parameters),
                    'interesting_count': len(interesting_urls)
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
    
    def _filter_urls(self, urls: List[str]) -> List[str]:
        """Filter and clean URLs"""
        filtered = []
        seen = set()
        
        # Extensions to exclude (images, fonts, etc.)
        exclude_ext = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'}
        
        for url in urls:
            # Skip if already seen
            if url in seen:
                continue
            
            # Skip non-http URLs
            if not url.startswith(('http://', 'https://')):
                continue
            
            # Check extension
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Skip if unwanted extension
            if any(path.endswith(ext) for ext in exclude_ext):
                continue
            
            filtered.append(url)
            seen.add(url)
        
        return filtered
    
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
    
    def _find_interesting_urls(self, urls: List[str]) -> List[str]:
        """Find potentially interesting URLs"""
        interesting = []
        
        # Patterns that might indicate interesting URLs
        patterns = [
            r'/admin',
            r'/api/',
            r'/v\d+/',
            r'/config',
            r'/backup',
            r'/test',
            r'/dev',
            r'/debug',
            r'\.env',
            r'\.git',
            r'\.sql',
            r'\.json',
            r'\.xml',
            r'/upload',
            r'/download',
            r'/swagger',
            r'/graphql',
            r'/login',
            r'/auth'
        ]
        
        for url in urls:
            url_lower = url.lower()
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    interesting.append(url)
                    break
        
        return interesting[:100]  # Limit to 100
    
    def _categorize_by_type(self, urls: List[str]) -> Dict[str, int]:
        """Categorize URLs by file type/endpoint type"""
        categories = {
            'api': 0,
            'admin': 0,
            'static': 0,
            'dynamic': 0,
            'other': 0
        }
        
        for url in urls:
            url_lower = url.lower()
            
            if '/api/' in url_lower or url_lower.endswith('/api'):
                categories['api'] += 1
            elif '/admin' in url_lower:
                categories['admin'] += 1
            elif re.search(r'\.(css|js)$', url_lower):
                categories['static'] += 1
            elif '?' in url:
                categories['dynamic'] += 1
            else:
                categories['other'] += 1
        
        return categories
    
    @staticmethod
    def check_tool_installed() -> bool:
        """Check if gau is installed"""
        try:
            result = subprocess.run(
                ['gau', '--help'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
