"""
Wayback Machine API integration module
"""

import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import quote


class WaybackAPI:
    """Wayback Machine API client for historical data"""
    
    def __init__(self):
        """Initialize Wayback Machine API client"""
        self.base_url = 'https://web.archive.org'
        self.cdx_api = f'{self.base_url}/cdx/search/cdx'
        self.availability_api = f'{self.base_url}/wayback/available'
    
    def scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Scan target with Wayback Machine API
        
        Args:
            target: Target domain or URL
            target_type: 'domain' or 'ip'
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Get availability information
            availability = self.check_availability(target)
            
            # Get snapshot timeline
            snapshots = self.get_snapshots(target, limit=100)
            
            # Get URL collection
            urls = self.get_urls(target, limit=1000)
            
            results = {
                'status': 'success',
                'target': target,
                'availability': availability,
                'total_snapshots': len(snapshots),
                'snapshots': snapshots[:50],  # Limit to 50 most recent
                'total_urls': len(urls),
                'urls': urls[:500],  # Limit to 500
                'statistics': {
                    'total_snapshots': len(snapshots),
                    'total_urls': len(urls),
                    'first_snapshot': snapshots[0] if snapshots else None,
                    'last_snapshot': snapshots[-1] if snapshots else None
                }
            }
            
            return results
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'snapshots': [],
                'urls': []
            }
    
    def check_availability(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is available in Wayback Machine
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with availability information
        """
        try:
            params = {'url': url}
            response = requests.get(self.availability_api, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('archived_snapshots'):
                    closest = data['archived_snapshots'].get('closest', {})
                    return {
                        'available': closest.get('available', False),
                        'url': closest.get('url', ''),
                        'timestamp': closest.get('timestamp', ''),
                        'status': closest.get('status', '')
                    }
                else:
                    return {
                        'available': False,
                        'url': '',
                        'timestamp': '',
                        'status': ''
                    }
            else:
                return {
                    'available': False,
                    'error': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
    
    def get_snapshots(self, url: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get list of snapshots for a URL
        
        Args:
            url: URL to search
            limit: Maximum number of snapshots
            
        Returns:
            List of snapshot information
        """
        try:
            params = {
                'url': url,
                'output': 'json',
                'limit': limit,
                'fl': 'timestamp,original,statuscode,mimetype',
                'collapse': 'timestamp:8'  # Group by date
            }
            
            response = requests.get(self.cdx_api, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Skip header row
                if data and len(data) > 1:
                    snapshots = []
                    for row in data[1:]:
                        if len(row) >= 4:
                            snapshot = {
                                'timestamp': row[0],
                                'url': row[1],
                                'status_code': row[2],
                                'mimetype': row[3],
                                'date': self._parse_timestamp(row[0])
                            }
                            snapshots.append(snapshot)
                    return snapshots
                else:
                    return []
            else:
                return []
                
        except Exception as e:
            print(f"[!] Error getting snapshots: {e}")
            return []
    
    def get_urls(self, domain: str, limit: int = 1000) -> List[str]:
        """
        Get list of archived URLs for a domain
        
        Args:
            domain: Domain to search
            limit: Maximum number of URLs
            
        Returns:
            List of URLs
        """
        try:
            # Use matchType=domain to get all URLs under domain
            params = {
                'url': domain,
                'output': 'json',
                'limit': limit,
                'fl': 'original',
                'matchType': 'domain',
                'collapse': 'urlkey'  # Deduplicate
            }
            
            response = requests.get(self.cdx_api, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Skip header row and extract URLs
                if data and len(data) > 1:
                    urls = []
                    for row in data[1:]:
                        if row and len(row) > 0:
                            urls.append(row[0])
                    return urls
                else:
                    return []
            else:
                return []
                
        except Exception as e:
            print(f"[!] Error getting URLs: {e}")
            return []
    
    def search_by_date_range(
        self,
        url: str,
        from_date: str,
        to_date: str
    ) -> List[Dict[str, Any]]:
        """
        Search for snapshots within a date range
        
        Args:
            url: URL to search
            from_date: Start date (YYYYMMDD)
            to_date: End date (YYYYMMDD)
            
        Returns:
            List of snapshots
        """
        try:
            params = {
                'url': url,
                'output': 'json',
                'from': from_date,
                'to': to_date,
                'fl': 'timestamp,original,statuscode'
            }
            
            response = requests.get(self.cdx_api, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data and len(data) > 1:
                    snapshots = []
                    for row in data[1:]:
                        if len(row) >= 3:
                            snapshots.append({
                                'timestamp': row[0],
                                'url': row[1],
                                'status_code': row[2]
                            })
                    return snapshots
                else:
                    return []
            else:
                return []
                
        except Exception as e:
            print(f"[!] Error searching by date: {e}")
            return []
    
    @staticmethod
    def _parse_timestamp(timestamp: str) -> str:
        """
        Parse Wayback timestamp to readable date
        
        Args:
            timestamp: Wayback timestamp (YYYYMMDDhhmmss)
            
        Returns:
            Formatted date string
        """
        try:
            if len(timestamp) >= 14:
                dt = datetime.strptime(timestamp[:14], '%Y%m%d%H%M%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            else:
                return timestamp
        except:
            return timestamp
