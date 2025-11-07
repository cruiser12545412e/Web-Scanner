"""
Configuration management for vulnerability scanner
"""

import os
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, Any, Optional

load_dotenv()


class Config:
    """Centralized configuration management"""
    
    # API Keys
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
    WAYBACK_API_KEY = os.getenv('WAYBACK_API_KEY', '')
    
    # User Agent
    USER_AGENT = os.getenv('USER_AGENT', 'VulnScanner/1.0 (https://github.com/your-repo)')
    
    # Rate Limiting
    RATE_LIMIT = int(os.getenv('RATE_LIMIT', '5'))
    
    # Timeout Settings
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '300'))
    
    # Thread Settings
    MAX_THREADS = int(os.getenv('MAX_THREADS', '10'))
    
    # Proxy Settings
    HTTP_PROXY = os.getenv('HTTP_PROXY', '')
    HTTPS_PROXY = os.getenv('HTTPS_PROXY', '')
    
    # Scan Profiles
    SCAN_PROFILES = {
        'quick': {
            'modules': ['httpx', 'wayback'],
            'nmap_opts': '-F -T4',  # Fast scan, common ports
            'timeout': 60,
            'threads': 10
        },
        'standard': {
            'modules': ['nmap', 'httpx', 'wayback', 'gau', 'shodan'],
            'nmap_opts': '-sV -sC',  # Service version, default scripts
            'timeout': 300,
            'threads': 5
        },
        'comprehensive': {
            'modules': ['nmap', 'httpx', 'wayback', 'gau', 'shodan', 'censys'],
            'nmap_opts': '-sV -sC -O -A',  # Full scan
            'timeout': 600,
            'threads': 3
        }
    }
    
    # Module Configurations
    NMAP_DEFAULT_OPTS = '-sV -sC -T4'
    HTTPX_DEFAULT_OPTS = [
        '-follow-redirects',
        '-status-code',
        '-tech-detect',
        '-title'
    ]
    
    # Output Directories
    BASE_DIR = Path(__file__).parent.parent
    REPORTS_DIR = BASE_DIR / 'reports'
    LOGS_DIR = BASE_DIR / 'logs'
    
    # Ensure directories exist
    REPORTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def get_proxies(cls) -> Optional[Dict[str, str]]:
        """Get proxy configuration"""
        proxies = {}
        if cls.HTTP_PROXY:
            proxies['http'] = cls.HTTP_PROXY
        if cls.HTTPS_PROXY:
            proxies['https'] = cls.HTTPS_PROXY
        return proxies if proxies else None
    
    @classmethod
    def get_profile(cls, profile_name: str) -> Dict[str, Any]:
        """Get scan profile configuration"""
        return cls.SCAN_PROFILES.get(profile_name, cls.SCAN_PROFILES['standard'])
    
    @classmethod
    def has_shodan_key(cls) -> bool:
        """Check if Shodan API key is configured"""
        return bool(cls.SHODAN_API_KEY)
    
    @classmethod
    def has_censys_keys(cls) -> bool:
        """Check if Censys API credentials are configured"""
        return bool(cls.CENSYS_API_ID and cls.CENSYS_API_SECRET)
    
    @classmethod
    def get_headers(cls) -> Dict[str, str]:
        """Get default HTTP headers"""
        return {
            'User-Agent': cls.USER_AGENT,
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9'
        }
    
    @classmethod
    def validate_config(cls) -> Dict[str, bool]:
        """Validate configuration and return status"""
        return {
            'shodan_configured': cls.has_shodan_key(),
            'censys_configured': cls.has_censys_keys(),
            'proxies_configured': bool(cls.get_proxies()),
            'directories_ready': cls.REPORTS_DIR.exists() and cls.LOGS_DIR.exists()
        }
    
    @classmethod
    def get_output_path(cls, filename: str, report_type: str = 'json') -> Path:
        """Get full output path for a report"""
        if not filename.endswith(f'.{report_type}'):
            filename = f'{filename}.{report_type}'
        return cls.REPORTS_DIR / filename
