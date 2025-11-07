"""
Censys API integration module
"""

import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, List, Any, Optional


class CensysAPI:
    """Censys API client for internet-wide scanning and certificate search"""
    
    def __init__(self, api_id: str, api_secret: str):
        """
        Initialize Censys API client
        
        Args:
            api_id: Censys API ID
            api_secret: Censys API Secret
        """
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = 'https://search.censys.io/api/v2'
        self.auth = HTTPBasicAuth(api_id, api_secret)
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with Censys
        
        Args:
            target: Target IP or domain
            target_type: 'ip' or 'domain'
            
        Returns:
            Dictionary with scan results
        """
        if not self.api_id or not self.api_secret:
            return {
                'status': 'error',
                'error': 'Censys API credentials not configured',
                'results': []
            }
        
        try:
            if target_type == 'ip':
                return self.host_lookup(target)
            elif target_type == 'domain':
                return self.certificate_search(target)
            else:
                return self.search_hosts(target)
                
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
            url = f'{self.base_url}/hosts/{ip}'
            response = requests.get(url, auth=self.auth, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                result = data.get('result', {})
                
                # Extract services
                services = []
                for service in result.get('services', []):
                    service_info = {
                        'port': service.get('port'),
                        'service_name': service.get('service_name', ''),
                        'transport_protocol': service.get('transport_protocol', ''),
                        'certificate': service.get('certificate', ''),
                        'banner': str(service.get('banner', ''))[:200]
                    }
                    services.append(service_info)
                
                # Extract location
                location = result.get('location', {})
                
                results = {
                    'status': 'success',
                    'ip': result.get('ip', ip),
                    'autonomous_system': result.get('autonomous_system', {}),
                    'location': {
                        'country': location.get('country', 'Unknown'),
                        'city': location.get('city', 'Unknown'),
                        'coordinates': location.get('coordinates', {})
                    },
                    'services': services,
                    'protocols': result.get('protocols', []),
                    'last_updated': result.get('last_updated_at', ''),
                    'statistics': {
                        'total_services': len(services),
                        'total_protocols': len(result.get('protocols', []))
                    }
                }
                
                return results
            
            elif response.status_code == 404:
                return {
                    'status': 'not_found',
                    'error': 'IP address not found in Censys database',
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
    
    def certificate_search(self, domain: str) -> Dict[str, Any]:
        """
        Search for certificates associated with a domain
        
        Args:
            domain: Domain to search
            
        Returns:
            Dictionary with certificate information
        """
        try:
            url = f'{self.base_url}/certificates/search'
            query = f'names: {domain}'
            
            params = {
                'q': query,
                'per_page': 50
            }
            
            response = requests.get(url, auth=self.auth, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                certificates = []
                for cert in data.get('result', {}).get('hits', []):
                    cert_info = {
                        'fingerprint': cert.get('fingerprint_sha256', ''),
                        'names': cert.get('names', [])[:10],  # Limit names
                        'issuer': cert.get('parsed', {}).get('issuer', {}),
                        'validity': cert.get('parsed', {}).get('validity', {}),
                        'subject': cert.get('parsed', {}).get('subject', {})
                    }
                    certificates.append(cert_info)
                
                # Extract unique domains/subdomains
                all_names = set()
                for cert in data.get('result', {}).get('hits', []):
                    all_names.update(cert.get('names', []))
                
                results = {
                    'status': 'success',
                    'domain': domain,
                    'total_certificates': data.get('result', {}).get('total', 0),
                    'certificates': certificates,
                    'discovered_names': sorted(list(all_names))[:100],  # Top 100
                    'statistics': {
                        'total_certificates': data.get('result', {}).get('total', 0),
                        'returned_certificates': len(certificates),
                        'unique_names': len(all_names)
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
    
    def search_hosts(self, query: str, max_results: int = 50) -> Dict[str, Any]:
        """
        Search for hosts matching query
        
        Args:
            query: Search query
            max_results: Maximum number of results
            
        Returns:
            Dictionary with search results
        """
        try:
            url = f'{self.base_url}/hosts/search'
            
            params = {
                'q': query,
                'per_page': max_results
            }
            
            response = requests.get(url, auth=self.auth, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                hosts = []
                for host in data.get('result', {}).get('hits', []):
                    host_info = {
                        'ip': host.get('ip', ''),
                        'services': host.get('services', []),
                        'location': host.get('location', {}),
                        'autonomous_system': host.get('autonomous_system', {})
                    }
                    hosts.append(host_info)
                
                results = {
                    'status': 'success',
                    'total': data.get('result', {}).get('total', 0),
                    'hosts': hosts,
                    'statistics': {
                        'total_results': data.get('result', {}).get('total', 0),
                        'returned_results': len(hosts)
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
    
    def get_account_info(self) -> Dict[str, Any]:
        """Get information about the API account"""
        try:
            url = f'{self.base_url}/account'
            response = requests.get(url, auth=self.auth, timeout=10)
            
            if response.status_code == 200:
                return {
                    'status': 'success',
                    'data': response.json()
                }
            else:
                return {
                    'status': 'error',
                    'error': 'Invalid API credentials or request failed'
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
