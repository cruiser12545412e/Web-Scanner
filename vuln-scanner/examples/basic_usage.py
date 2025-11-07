#!/usr/bin/env python3
"""
Basic usage examples for Vulnerability Scanner programmatic API
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config
from core.scanner import ScanOrchestrator
from modules import NmapScanner, HTTPXScanner, WaybackScanner, ShodanAPI
from reports import JSONReporter, HTMLReporter


def example_simple_scan():
    """Example 1: Simple single-module scan"""
    print("=" * 60)
    print("Example 1: Simple HTTP Scan")
    print("=" * 60)
    
    # Initialize scanner
    httpx = HTTPXScanner()
    
    # Scan target
    result = httpx.scan('example.com', 'domain')
    
    # Display results
    if result['status'] == 'success':
        print(f"✓ Found {result['total_hosts']} live hosts")
        print(f"✓ Detected technologies: {', '.join(result['technologies'])}")
    else:
        print(f"✗ Scan failed: {result.get('error')}")
    
    print()


def example_full_scan():
    """Example 2: Full scan with orchestrator"""
    print("=" * 60)
    print("Example 2: Full Orchestrated Scan")
    print("=" * 60)
    
    # Initialize configuration
    config = Config()
    
    # Create orchestrator
    orchestrator = ScanOrchestrator(config)
    
    # Register modules
    orchestrator.register_module('nmap', NmapScanner())
    orchestrator.register_module('httpx', HTTPXScanner())
    orchestrator.register_module('wayback', WaybackScanner())
    
    # Run scan
    results = orchestrator.run_scan(
        target='scanme.nmap.org',
        modules=['nmap', 'httpx'],
        profile='quick',
        verbose=True
    )
    
    # Display summary
    print("\nScan Summary:")
    print(f"  Target: {results['target']}")
    print(f"  Duration: {results['scan_duration']:.2f}s")
    print(f"  Modules: {', '.join(results['modules_run'])}")
    print(f"  Findings: {results['summary'].get('total_findings', 0)}")
    
    print()


def example_with_reports():
    """Example 3: Scan with report generation"""
    print("=" * 60)
    print("Example 3: Scan with Report Generation")
    print("=" * 60)
    
    # Setup
    config = Config()
    orchestrator = ScanOrchestrator(config)
    orchestrator.register_module('httpx', HTTPXScanner())
    
    # Run scan
    results = orchestrator.run_scan(
        target='example.com',
        modules=['httpx'],
        profile='quick'
    )
    
    # Generate JSON report
    json_reporter = JSONReporter()
    json_file = config.REPORTS_DIR / 'example_scan.json'
    json_reporter.generate(results, json_file)
    print(f"✓ JSON report saved: {json_file}")
    
    # Generate HTML report
    html_reporter = HTMLReporter()
    html_file = config.REPORTS_DIR / 'example_scan.html'
    html_reporter.generate(results, html_file)
    print(f"✓ HTML report saved: {html_file}")
    
    print()


def example_api_scan():
    """Example 4: Using Shodan API"""
    print("=" * 60)
    print("Example 4: Shodan API Scan")
    print("=" * 60)
    
    config = Config()
    
    if not config.has_shodan_key():
        print("✗ Shodan API key not configured")
        print("  Set SHODAN_API_KEY in .env file")
        return
    
    # Initialize Shodan API
    shodan = ShodanAPI(config.SHODAN_API_KEY)
    
    # Lookup an IP
    result = shodan.host_lookup('8.8.8.8')
    
    if result['status'] == 'success':
        print(f"✓ IP: {result['ip']}")
        print(f"✓ Organization: {result['organization']}")
        print(f"✓ Country: {result['country']}")
        print(f"✓ Open Ports: {', '.join(map(str, result['ports']))}")
        print(f"✓ Vulnerabilities: {len(result['vulnerabilities'])}")
    else:
        print(f"✗ Lookup failed: {result.get('error')}")
    
    print()


def example_batch_scan():
    """Example 5: Batch scanning multiple targets"""
    print("=" * 60)
    print("Example 5: Batch Scan")
    print("=" * 60)
    
    config = Config()
    orchestrator = ScanOrchestrator(config)
    orchestrator.register_module('httpx', HTTPXScanner())
    
    # Multiple targets
    targets = ['example.com', 'google.com', 'github.com']
    
    # Run batch scan
    results = orchestrator.run_batch_scan(
        targets=targets,
        modules=['httpx'],
        profile='quick',
        max_workers=3
    )
    
    # Display results
    print(f"\n✓ Completed scanning {len(results)} targets")
    for i, result in enumerate(results):
        target = targets[i]
        status = "✓" if result.get('status') != 'failed' else "✗"
        print(f"  {status} {target}")
    
    print()


def example_custom_module():
    """Example 6: Using individual modules with custom options"""
    print("=" * 60)
    print("Example 6: Custom Module Configuration")
    print("=" * 60)
    
    # Initialize nmap with custom options
    nmap = NmapScanner(nmap_opts='-F -T4')  # Fast scan
    
    # Run quick scan
    result = nmap.quick_scan('scanme.nmap.org')
    
    if result['status'] == 'success':
        print(f"✓ Scanned {result['total_open_ports']} open ports")
        
        if result['open_ports']:
            print("\nOpen Ports:")
            for service in result['services'][:5]:  # Show first 5
                print(f"  - Port {service['port']}: {service['service']} {service['version']}")
    else:
        print(f"✗ Scan failed: {result.get('error')}")
    
    print()


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("VULNERABILITY SCANNER - PROGRAMMATIC API EXAMPLES")
    print("=" * 60 + "\n")
    
    examples = [
        ("Simple HTTP Scan", example_simple_scan),
        ("Full Orchestrated Scan", example_full_scan),
        ("Scan with Reports", example_with_reports),
        ("Shodan API Usage", example_api_scan),
        ("Batch Scanning", example_batch_scan),
        ("Custom Module Config", example_custom_module)
    ]
    
    for i, (name, func) in enumerate(examples, 1):
        print(f"\n[{i}/{len(examples)}] Running: {name}")
        try:
            func()
        except KeyboardInterrupt:
            print("\n\n✗ Interrupted by user")
            break
        except Exception as e:
            print(f"\n✗ Error: {e}")
            continue
    
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    main()
