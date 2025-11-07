"""
Utility functions for vulnerability scanner
"""

import re
import socket
import validators
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlparse
import ipaddress


def validate_target(target: str) -> Tuple[bool, str, str]:
    """
    Validate and classify target (domain or IP)
    
    Returns:
        (is_valid, target_type, normalized_target)
    """
    target = target.strip().lower()
    
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Remove port if present
    if ':' in target and not target.count(':') > 1:  # Not IPv6
        target = target.split(':')[0]
    
    # Check if it's an IP address
    try:
        ipaddress.ip_address(target)
        return (True, 'ip', target)
    except ValueError:
        pass
    
    # Check if it's a valid domain
    if validators.domain(target):
        return (True, 'domain', target)
    
    # Check if it's a hostname (less strict)
    hostname_pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$'
    if re.match(hostname_pattern, target):
        return (True, 'hostname', target)
    
    return (False, 'unknown', target)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    """
    # Remove invalid filename characters
    invalid_chars = r'[<>:"/\\|?*]'
    filename = re.sub(invalid_chars, '_', filename)
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


def format_timestamp(dt: Optional[datetime] = None, format_type: str = 'iso') -> str:
    """
    Format timestamp for reports
    """
    if dt is None:
        dt = datetime.now()
    
    if format_type == 'iso':
        return dt.isoformat()
    elif format_type == 'readable':
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    elif format_type == 'filename':
        return dt.strftime('%Y%m%d_%H%M%S')
    else:
        return str(dt)


def parse_targets(target_input: str, target_file: Optional[str] = None) -> List[str]:
    """
    Parse targets from string or file
    """
    targets = []
    
    # Parse from string input
    if target_input:
        # Split by comma
        for target in target_input.split(','):
            target = target.strip()
            if target:
                targets.append(target)
    
    # Parse from file
    if target_file:
        try:
            with open(target_file, 'r') as f:
                for line in f:
                    target = line.strip()
                    if target and not target.startswith('#'):
                        targets.append(target)
        except FileNotFoundError:
            print(f"[!] Target file not found: {target_file}")
        except Exception as e:
            print(f"[!] Error reading target file: {e}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    return unique_targets


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_port_open(host: str, port: int, timeout: int = 2) -> bool:
    """
    Check if a port is open on a host
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except:
        return url


def format_size(size_bytes: int) -> str:
    """
    Format bytes to human-readable size
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def deduplicate_list(items: List[str]) -> List[str]:
    """
    Remove duplicates from list while preserving order
    """
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_subdomains_from_urls(urls: List[str], base_domain: str) -> List[str]:
    """
    Extract unique subdomains from list of URLs
    """
    subdomains = set()
    for url in urls:
        domain = extract_domain_from_url(url)
        if base_domain in domain:
            subdomains.add(domain)
    return sorted(list(subdomains))


def color_text(text: str, color: str) -> str:
    """
    Add color to text for terminal output
    """
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m'
    }
    
    color_code = colors.get(color.lower(), colors['reset'])
    reset_code = colors['reset']
    return f"{color_code}{text}{reset_code}"


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to max length
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix
