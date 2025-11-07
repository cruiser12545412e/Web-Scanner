#!/usr/bin/env python3
"""
Vulnerability Scanner & Recon Framework
Main CLI entry point
"""

import argparse
import sys
from pathlib import Path
from rich.console import Console
from rich import print as rprint
import pyfiglet

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.scanner import ScanOrchestrator
from core.utils import parse_targets, format_timestamp, sanitize_filename
from modules import (
    NmapScanner,
    WaybackScanner,
    GAUScanner,
    HTTPXScanner,
    ShodanAPI,
    CensysAPI,
    WaybackAPI
)
from reports import JSONReporter, HTMLReporter

console = Console()


def print_banner():
    """Print application banner"""
    banner = pyfiglet.figlet_format("VulnScanner", font="slant")
    console.print(f"[cyan]{banner}[/cyan]")
    console.print("[bold]Vulnerability Scanner & Recon Framework v1.0[/bold]")
    console.print("[dim]For educational and authorized security research only[/dim]\n")


def check_dependencies():
    """Check if required tools are installed"""
    console.print("[cyan]→[/cyan] Checking dependencies...")
    
    checks = {
        'nmap': NmapScanner.check_nmap_installed(),
        'waybackurls': WaybackScanner().check_tool_installed(),
        'gau': GAUScanner().check_tool_installed(),
        'httpx': HTTPXScanner().check_tool_installed()
    }
    
    all_ok = True
    for tool, installed in checks.items():
        status = "[green]✓[/green]" if installed else "[red]✗[/red]"
        console.print(f"  {status} {tool}")
        if not installed:
            all_ok = False
    
    if not all_ok:
        console.print("\n[yellow]⚠[/yellow] Some tools are missing. Install them for full functionality.")
        console.print("See README.md for installation instructions.\n")
    else:
        console.print("[green]✓[/green] All dependencies available\n")
    
    # Check API keys
    config_status = Config.validate_config()
    if config_status['shodan_configured']:
        console.print("[green]✓[/green] Shodan API configured")
    if config_status['censys_configured']:
        console.print("[green]✓[/green] Censys API configured")
    
    if not config_status['shodan_configured'] and not config_status['censys_configured']:
        console.print("[dim]No API keys configured (optional)[/dim]")
    
    console.print()


def setup_scanner(args) -> ScanOrchestrator:
    """Setup scanner with modules"""
    config = Config()
    
    # Update config based on args
    if args.nmap_opts:
        config.NMAP_DEFAULT_OPTS = args.nmap_opts
    
    if args.timeout:
        config.REQUEST_TIMEOUT = args.timeout
    
    if args.threads:
        config.MAX_THREADS = args.threads
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator(config)
    
    # Register modules
    orchestrator.register_module('nmap', NmapScanner(config.NMAP_DEFAULT_OPTS))
    orchestrator.register_module('wayback', WaybackScanner())
    orchestrator.register_module('gau', GAUScanner())
    orchestrator.register_module('httpx', HTTPXScanner())
    
    # Register API modules if keys are available
    if config.has_shodan_key():
        orchestrator.register_module('shodan', ShodanAPI(config.SHODAN_API_KEY))
    
    if config.has_censys_keys():
        orchestrator.register_module('censys', CensysAPI(config.CENSYS_API_ID, config.CENSYS_API_SECRET))
    
    orchestrator.register_module('wayback_api', WaybackAPI())
    
    return orchestrator


def generate_reports(scan_results, output_format, output_file, target):
    """Generate reports in specified formats"""
    
    # Prepare output filename
    if not output_file:
        timestamp = format_timestamp(format_type='filename')
        safe_target = sanitize_filename(target)
        output_file = f"scan_{safe_target}_{timestamp}"
    
    # Remove extension if present
    output_file = str(output_file).rsplit('.', 1)[0]
    
    formats = output_format.split(',')
    generated_files = []
    
    for fmt in formats:
        fmt = fmt.strip().lower()
        
        if fmt == 'json':
            json_file = Config.get_output_path(output_file, 'json')
            reporter = JSONReporter()
            if reporter.generate(scan_results, json_file):
                console.print(f"[green]✓[/green] JSON report saved: {json_file}")
                generated_files.append(json_file)
            else:
                console.print(f"[red]✗[/red] Failed to generate JSON report")
        
        elif fmt == 'html':
            html_file = Config.get_output_path(output_file, 'html')
            reporter = HTMLReporter()
            if reporter.generate(scan_results, html_file):
                console.print(f"[green]✓[/green] HTML report saved: {html_file}")
                generated_files.append(html_file)
            else:
                console.print(f"[red]✗[/red] Failed to generate HTML report")
        
        elif fmt == 'both':
            # Generate both formats
            json_file = Config.get_output_path(output_file, 'json')
            html_file = Config.get_output_path(output_file, 'html')
            
            json_reporter = JSONReporter()
            html_reporter = HTMLReporter()
            
            if json_reporter.generate(scan_results, json_file):
                console.print(f"[green]✓[/green] JSON report saved: {json_file}")
                generated_files.append(json_file)
            
            if html_reporter.generate(scan_results, html_file):
                console.print(f"[green]✓[/green] HTML report saved: {html_file}")
                generated_files.append(html_file)
    
    return generated_files


def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(
        description='Vulnerability Scanner & Recon Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scanner.py -t example.com
  
  # Full scan with all modules
  python scanner.py -t example.com --full
  
  # Specific modules
  python scanner.py -t example.com -m nmap,httpx,shodan
  
  # Custom profile
  python scanner.py -t example.com -p comprehensive
  
  # Generate HTML report
  python scanner.py -t example.com -o html -f report.html
  
  # Multiple targets from file
  python scanner.py -tl targets.txt --full -o both
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Target domain or IP address')
    target_group.add_argument('-tl', '--target-list', help='File containing list of targets (one per line)')
    
    # Scan options
    parser.add_argument('-m', '--modules', help='Comma-separated modules: nmap,wayback,gau,httpx,shodan,censys')
    parser.add_argument('-p', '--profile', default='standard', 
                       choices=['quick', 'standard', 'comprehensive'],
                       help='Scan profile (default: standard)')
    parser.add_argument('--full', action='store_true', help='Run all available modules')
    
    # Output options
    parser.add_argument('-o', '--output', default='json', 
                       help='Output format: json, html, both (default: json)')
    parser.add_argument('-f', '--file', help='Output filename (without extension)')
    
    # Advanced options
    parser.add_argument('--nmap-opts', help='Custom nmap options (e.g., "-sV -sC -O")')
    parser.add_argument('--threads', type=int, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    
    # Display options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies and exit')
    
    args = parser.parse_args()
    
    # Print banner (unless quiet)
    if not args.quiet:
        print_banner()
    
    # Check dependencies
    if args.check_deps:
        check_dependencies()
        sys.exit(0)
    
    if not args.quiet:
        check_dependencies()
    
    # Parse targets
    targets = parse_targets(args.target or '', args.target_list)
    
    if not targets:
        console.print("[red]✗[/red] No valid targets specified")
        sys.exit(1)
    
    # Setup scanner
    orchestrator = setup_scanner(args)
    
    # Determine modules to run
    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(',')]
    elif args.full:
        modules = list(orchestrator.modules.keys())
    
    # Run scans
    if len(targets) == 1:
        # Single target
        console.print(f"\n[bold cyan]Starting scan...[/bold cyan]\n")
        
        results = orchestrator.run_scan(
            targets[0],
            modules=modules,
            profile=args.profile,
            verbose=args.verbose
        )
        
        # Generate reports
        if not results.get('error'):
            console.print(f"\n[bold green]Scan completed successfully![/bold green]\n")
            generate_reports(results, args.output, args.file, targets[0])
        else:
            console.print(f"\n[bold red]Scan failed: {results['error']}[/bold red]\n")
            sys.exit(1)
    
    else:
        # Multiple targets
        console.print(f"\n[bold cyan]Starting batch scan for {len(targets)} targets...[/bold cyan]\n")
        
        all_results = orchestrator.run_batch_scan(
            targets,
            modules=modules,
            profile=args.profile,
            verbose=args.verbose,
            max_workers=args.threads or 3
        )
        
        # Generate reports for each target
        console.print(f"\n[bold green]Batch scan completed![/bold green]\n")
        
        for i, result in enumerate(all_results):
            if not result.get('error'):
                target = targets[i]
                output_file = f"{args.file or 'scan'}_{i+1}" if args.file else None
                generate_reports(result, args.output, output_file, target)
    
    console.print("\n[bold]Done![/bold] 🎉\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠[/yellow] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]✗[/red] Fatal error: {e}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
