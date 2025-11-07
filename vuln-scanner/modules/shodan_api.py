"""
Shodan API integration module
"""

import requests
from typing import Dict, List, Any, Optional


class ShodanAPI:
    """Shodan API client for vulnerability and device scanning"""
    
    def __init__(self, api_key: str):
        """
        Initialize Shodan API client
        
        Args:
            api_key: Shodan API key
        """
        self.api_key = api_key
        self.base_url = 'https://api.shodan.io'
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with Shodan
        
        Args:
            target: Target IP or domain
            target_type: 'ip' or 'domain'
            
        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            return {
                'status': 'error',
                'error': 'Shodan API key not configured',
                'results': []
            }
        
        try:
            if target_type == 'ip':
                return self.host_lookup(target)
            elif target_type == 'domain':
                return self.domain_lookup(target)
            else:
                return self.search(target)
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': []
            }
    
    def host_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Look up information about a specific IP address
        
        Args:
            ip: IP address to look up
            
        Returns:
            Dictionary with host information
        """
        try:
            url = f'{self.base_url}/shodan/host/{ip}?key={self.api_key}'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract key information
                results = {
                    'status': 'success',
                    'ip': data.get('ip_str', ip),
                    'hostnames': data.get('hostnames', []),
                    'organization': data.get('org', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'asn': data.get('asn', 'Unknown'),
                    'ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', []),
                    'tags': data.get('tags', []),
                    'services': [],
                    'last_update': data.get('last_update', '')
                }
                
                # Parse services
                for service in data.get('data', []):
                    service_info = {
                        'port': service.get('port'),
                        'transport': service.get('transport', 'tcp'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'banner': service.get('data', '')[:200],  # Truncate banner
                        'module': service.get('_shodan', {}).get('module', '')
                    }
                    results['services'].append(service_info)
                
                # Statistics
                results['statistics'] = {
                    'total_ports': len(results['ports']),
                    'total_vulnerabilities': len(results['vulnerabilities']),
                    'total_services': len(results['services'])
                }
                
                return results
            
            elif response.status_code == 404:
                return {
                    'status': 'not_found',
                    'error': 'IP address not found in Shodan database',
                    'results': []
                }
            else:
                return {
                    'status': 'error',
                    'error': f'API returned status {response.status_code}: {response.text}',
                    'results': []
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'error': 'Request timeout',
                'results': []
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': []
            }
    
    def domain_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Look up information about a domain
        
        Args:
            domain: Domain to look up
            
        Returns:
            Dictionary with domain information
        """
        try:
            # Get DNS information
            url = f'{self.base_url}/dns/domain/{domain}?key={self.api_key}'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                results = {
                    'status': 'success',
                    'domain': domain,
                    'subdomains': data.get('subdomains', []),
                    'data': data.get('data', []),
                    'statistics': {
                        'total_subdomains': len(data.get('subdomains', []))
                    }
                }
                
                return results
            else:
                return {
                    'status': 'error',
                    'error': f'API returned status {response.status_code}',
                    'results': []
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': []
            }
    
    def search(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """
        Search Shodan for devices matching query
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            Dictionary with search results
        """
        try:
            url = f'{self.base_url}/shodan/host/search?key={self.api_key}&query={query}'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                matches = []
                for match in data.get('matches', [])[:limit]:
                    match_info = {
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'organization': match.get('org', ''),
                        'hostnames': match.get('hostnames', []),
                        'location': f"{match.get('location', {}).get('city', '')}, {match.get('location', {}).get('country_name', '')}",
                        'banner': match.get('data', '')[:100]
                    }
                    matches.append(match_info)
                
                results = {
                    'status': 'success',
                    'total': data.get('total', 0),
                    'matches': matches,
                    'statistics': {
                        'total_results': data.get('total', 0),
                        'returned_results': len(matches)
                    }
                }
                
                return results
            else:
                return {
                    'status': 'error',
                    'error': f'API returned status {response.status_code}',
                    'results': []
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': []
            }
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get information about the API key"""
        try:
            url = f'{self.base_url}/api-info?key={self.api_key}'
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return {
                    'status': 'success',
                    'data': response.json()
                }
            else:
                return {
                    'status': 'error',
                    'error': 'Invalid API key or request failed'
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
