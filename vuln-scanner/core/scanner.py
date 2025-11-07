"""
Core scanner orchestrator that manages all scanning modules
"""

import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from .config import Config
from .utils import validate_target, format_timestamp


console = Console()


class ScanOrchestrator:
    """Orchestrates and manages all scanning modules"""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.modules = {}
        
    def register_module(self, name: str, module_instance):
        """Register a scanning module"""
        self.modules[name] = module_instance
        
    def run_scan(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        profile: str = 'standard',
        verbose: bool = False
    ) -> Dict[str, Any]:
        """
        Run scan on target with specified modules
        
        Args:
            target: Target domain or IP
            modules: List of module names to run (None = use profile)
            profile: Scan profile (quick, standard, comprehensive)
            verbose: Enable verbose output
            
        Returns:
            Dictionary containing scan results
        """
        self.start_time = datetime.now()
        
        # Validate target
        is_valid, target_type, normalized_target = validate_target(target)
        if not is_valid:
            console.print(f"[red]✗[/red] Invalid target: {target}")
            return {'error': 'Invalid target', 'target': target}
        
        console.print(f"[cyan]→[/cyan] Target: {normalized_target} ({target_type})")
        
        # Determine modules to run
        if modules is None:
            profile_config = self.config.get_profile(profile)
            modules = profile_config['modules']
        
        # Filter modules based on availability
        available_modules = self._get_available_modules(modules)
        
        if not available_modules:
            console.print("[red]✗[/red] No modules available to run")
            return {'error': 'No modules available', 'target': normalized_target}
        
        console.print(f"[cyan]→[/cyan] Running modules: {', '.join(available_modules)}")
        
        # Initialize results structure
        self.results = {
            'target': normalized_target,
            'target_type': target_type,
            'scan_date': format_timestamp(self.start_time),
            'profile': profile,
            'modules_run': available_modules,
            'results': {},
            'summary': {},
            'errors': []
        }
        
        # Run modules
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(available_modules))
            
            for module_name in available_modules:
                progress.update(task, description=f"[cyan]Running {module_name}...")
                
                try:
                    module_result = self._run_module(
                        module_name,
                        normalized_target,
                        target_type,
                        verbose
                    )
                    self.results['results'][module_name] = module_result
                    
                    # Show module completion
                    if module_result.get('status') == 'success':
                        console.print(f"[green]✓[/green] {module_name} completed")
                    else:
                        console.print(f"[yellow]⚠[/yellow] {module_name} completed with warnings")
                        
                except Exception as e:
                    error_msg = f"{module_name}: {str(e)}"
                    self.results['errors'].append(error_msg)
                    console.print(f"[red]✗[/red] {module_name} failed: {str(e)}")
                
                progress.advance(task)
        
        # Generate summary
        self.end_time = datetime.now()
        self.results['scan_duration'] = (self.end_time - self.start_time).total_seconds()
        self.results['summary'] = self._generate_summary()
        
        # Display results summary
        self._display_summary()
        
        return self.results
    
    def _get_available_modules(self, requested_modules: List[str]) -> List[str]:
        """Filter modules based on availability and API keys"""
        available = []
        
        for module_name in requested_modules:
            # Check if module is registered
            if module_name not in self.modules:
                console.print(f"[yellow]⚠[/yellow] Module '{module_name}' not registered, skipping")
                continue
            
            # Check API requirements
            if module_name == 'shodan' and not self.config.has_shodan_key():
                console.print(f"[yellow]⚠[/yellow] Shodan API key not configured, skipping")
                continue
            
            if module_name == 'censys' and not self.config.has_censys_keys():
                console.print(f"[yellow]⚠[/yellow] Censys API credentials not configured, skipping")
                continue
            
            available.append(module_name)
        
        return available
    
    def _run_module(
        self,
        module_name: str,
        target: str,
        target_type: str,
        verbose: bool
    ) -> Dict[str, Any]:
        """Run a single scanning module"""
        module = self.modules[module_name]
        
        start_time = time.time()
        
        try:
            # Call module's scan method
            result = module.scan(target, target_type)
            
            # Add timing information
            result['execution_time'] = time.time() - start_time
            result['status'] = result.get('status', 'success')
            
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics from all module results"""
        summary = {
            'total_modules_run': len(self.results['results']),
            'successful_modules': 0,
            'failed_modules': 0,
            'total_findings': 0
        }
        
        for module_name, result in self.results['results'].items():
            if result.get('status') == 'success':
                summary['successful_modules'] += 1
                
                # Count findings based on module type
                if module_name == 'nmap':
                    summary['open_ports'] = len(result.get('open_ports', []))
                    summary['total_findings'] += summary['open_ports']
                
                elif module_name in ['wayback', 'gau']:
                    url_count = len(result.get('urls', []))
                    summary[f'{module_name}_urls'] = url_count
                    summary['total_findings'] += url_count
                
                elif module_name == 'httpx':
                    summary['live_hosts'] = len(result.get('live_hosts', []))
                    summary['total_findings'] += summary['live_hosts']
                
                elif module_name == 'shodan':
                    summary['shodan_results'] = len(result.get('results', []))
                    summary['total_findings'] += summary['shodan_results']
                
                elif module_name == 'censys':
                    summary['censys_results'] = len(result.get('results', []))
                    summary['total_findings'] += summary['censys_results']
            else:
                summary['failed_modules'] += 1
        
        return summary
    
    def _display_summary(self):
        """Display scan results summary in terminal"""
        console.print("\n" + "="*60)
        console.print("[bold cyan]Scan Summary[/bold cyan]")
        console.print("="*60)
        
        # Create summary table
        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target", self.results['target'])
        table.add_row("Duration", f"{self.results['scan_duration']:.2f}s")
        table.add_row("Modules Run", str(self.results['summary']['total_modules_run']))
        table.add_row("Successful", str(self.results['summary']['successful_modules']))
        table.add_row("Failed", str(self.results['summary']['failed_modules']))
        table.add_row("Total Findings", str(self.results['summary']['total_findings']))
        
        # Add specific findings
        summary = self.results['summary']
        if 'open_ports' in summary:
            table.add_row("Open Ports", str(summary['open_ports']))
        if 'wayback_urls' in summary:
            table.add_row("Wayback URLs", str(summary['wayback_urls']))
        if 'gau_urls' in summary:
            table.add_row("GAU URLs", str(summary['gau_urls']))
        if 'live_hosts' in summary:
            table.add_row("Live Hosts", str(summary['live_hosts']))
        
        console.print(table)
        console.print("="*60 + "\n")
    
    def run_batch_scan(
        self,
        targets: List[str],
        modules: Optional[List[str]] = None,
        profile: str = 'standard',
        verbose: bool = False,
        max_workers: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Run scans on multiple targets concurrently
        
        Args:
            targets: List of target domains/IPs
            modules: List of module names to run
            profile: Scan profile
            verbose: Enable verbose output
            max_workers: Maximum concurrent scans
            
        Returns:
            List of scan results for each target
        """
        console.print(f"[cyan]→[/cyan] Batch scanning {len(targets)} targets...")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self.run_scan,
                    target,
                    modules,
                    profile,
                    verbose
                ): target for target in targets
            }
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    console.print(f"[red]✗[/red] Scan failed for {target}: {str(e)}")
                    results.append({
                        'target': target,
                        'error': str(e),
                        'status': 'failed'
                    })
        
        console.print(f"[green]✓[/green] Batch scan completed: {len(results)}/{len(targets)} targets")
        
        return results
