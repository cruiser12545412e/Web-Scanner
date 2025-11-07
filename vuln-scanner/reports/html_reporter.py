"""
HTML report generator
"""

from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
from jinja2 import Template


class HTMLReporter:
    """Generate HTML reports from scan results"""
    
    def __init__(self):
        """Initialize HTML reporter"""
        self.template = self._get_template()
    
    def generate(self, scan_results: Dict[str, Any], output_file: Path) -> bool:
        """
        Generate HTML report from scan results
        
        Args:
            scan_results: Dictionary with scan results
            output_file: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Prepare data for template
            template_data = self._prepare_template_data(scan_results)
            
            # Render template
            html_content = self.template.render(**template_data)
            
            # Write HTML file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return True
            
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")
            return False
    
    def _prepare_template_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template"""
        
        results = scan_results.get('results', {})
        summary = scan_results.get('summary', {})
        
        # Extract key findings
        open_ports = []
        services = []
        technologies = []
        vulnerabilities = []
        urls_found = 0
        subdomains = []
        
        # Process nmap results
        if 'nmap' in results and results['nmap'].get('status') == 'success':
            nmap_data = results['nmap']
            open_ports = nmap_data.get('open_ports', [])
            services = nmap_data.get('services', [])
        
        # Process httpx results
        if 'httpx' in results and results['httpx'].get('status') == 'success':
            httpx_data = results['httpx']
            technologies = httpx_data.get('technologies', [])
        
        # Process wayback results
        if 'wayback' in results and results['wayback'].get('status') == 'success':
            wayback_data = results['wayback']
            urls_found += wayback_data.get('total_urls', 0)
            subdomains.extend(wayback_data.get('subdomains', []))
        
        # Process gau results
        if 'gau' in results and results['gau'].get('status') == 'success':
            gau_data = results['gau']
            urls_found += gau_data.get('total_urls', 0)
            subdomains.extend(gau_data.get('subdomains', []))
        
        # Process shodan results
        if 'shodan' in results and results['shodan'].get('status') == 'success':
            shodan_data = results['shodan']
            vulnerabilities = shodan_data.get('vulnerabilities', [])
        
        # Deduplicate subdomains
        subdomains = sorted(list(set(subdomains)))
        
        # Calculate severity
        severity = self._calculate_severity(
            len(open_ports),
            len(vulnerabilities),
            len(subdomains)
        )
        
        return {
            'target': scan_results.get('target', 'Unknown'),
            'scan_date': scan_results.get('scan_date', datetime.now().isoformat()),
            'scan_duration': scan_results.get('scan_duration', 0),
            'profile': scan_results.get('profile', 'standard'),
            'modules_run': scan_results.get('modules_run', []),
            'severity': severity,
            'summary': summary,
            'open_ports': open_ports,
            'services': services,
            'technologies': technologies,
            'vulnerabilities': vulnerabilities,
            'urls_found': urls_found,
            'subdomains': subdomains[:50],  # Limit to 50
            'total_subdomains': len(subdomains),
            'results': results,
            'errors': scan_results.get('errors', []),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _calculate_severity(self, ports: int, vulns: int, subdomains: int) -> str:
        """Calculate overall severity level"""
        score = 0
        
        if ports > 10:
            score += 2
        elif ports > 5:
            score += 1
        
        if vulns > 5:
            score += 3
        elif vulns > 0:
            score += 2
        
        if subdomains > 20:
            score += 1
        
        if score >= 4:
            return 'high'
        elif score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _get_template(self) -> Template:
        """Get HTML template"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .target {
            font-size: 1.5em;
            color: #3498db;
            font-weight: bold;
        }
        
        .severity {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 15px;
            text-transform: uppercase;
        }
        
        .severity.low { background: #2ecc71; color: white; }
        .severity.medium { background: #f39c12; color: white; }
        .severity.high { background: #e74c3c; color: white; }
        
        .meta {
            background: #ecf0f1;
            padding: 20px 40px;
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
        }
        
        .meta-item {
            text-align: center;
            padding: 10px 20px;
        }
        
        .meta-item .label {
            font-size: 0.9em;
            color: #7f8c8d;
            text-transform: uppercase;
        }
        
        .meta-item .value {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .card {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        
        .card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #34495e;
            color: white;
            font-weight: bold;
        }
        
        tr:hover {
            background: #f5f5f5;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }
        
        .badge.success { background: #2ecc71; color: white; }
        .badge.warning { background: #f39c12; color: white; }
        .badge.danger { background: #e74c3c; color: white; }
        .badge.info { background: #3498db; color: white; }
        
        .url-list {
            max-height: 300px;
            overflow-y: auto;
            background: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
        }
        
        .url-list ul {
            list-style: none;
        }
        
        .url-list li {
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .no-data {
            color: #95a5a6;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Vulnerability Scan Report</h1>
            <div class="target">{{ target }}</div>
            <div class="severity {{ severity }}">Severity: {{ severity }}</div>
        </div>
        
        <div class="meta">
            <div class="meta-item">
                <div class="label">Scan Date</div>
                <div class="value">{{ scan_date[:10] }}</div>
            </div>
            <div class="meta-item">
                <div class="label">Duration</div>
                <div class="value">{{ "%.2f"|format(scan_duration) }}s</div>
            </div>
            <div class="meta-item">
                <div class="label">Modules</div>
                <div class="value">{{ modules_run|length }}</div>
            </div>
            <div class="meta-item">
                <div class="label">Open Ports</div>
                <div class="value">{{ open_ports|length }}</div>
            </div>
            <div class="meta-item">
                <div class="label">Subdomains</div>
                <div class="value">{{ total_subdomains }}</div>
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Section -->
            <div class="section">
                <h2>📊 Summary</h2>
                <div class="card">
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Profile:</strong> {{ profile }}</p>
                    <p><strong>Modules Used:</strong> {{ modules_run|join(', ') }}</p>
                    <p><strong>Total Findings:</strong> {{ summary.get('total_findings', 0) }}</p>
                    <p><strong>Generated:</strong> {{ generated_at }}</p>
                </div>
            </div>
            
            <!-- Open Ports Section -->
            {% if open_ports %}
            <div class="section">
                <h2>🔓 Open Ports & Services</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>State</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for service in services %}
                        <tr>
                            <td><strong>{{ service.port }}</strong></td>
                            <td>{{ service.service }}</td>
                            <td>{{ service.version or 'N/A' }}</td>
                            <td><span class="badge success">Open</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            <!-- Technologies Section -->
            {% if technologies %}
            <div class="section">
                <h2>💻 Detected Technologies</h2>
                <div class="card">
                    {% for tech in technologies %}
                    <span class="badge info">{{ tech }}</span>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            
            <!-- Vulnerabilities Section -->
            {% if vulnerabilities %}
            <div class="section">
                <h2>⚠️ Vulnerabilities</h2>
                {% for vuln in vulnerabilities %}
                <div class="card">
                    <h3>{{ vuln }}</h3>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <!-- Subdomains Section -->
            {% if subdomains %}
            <div class="section">
                <h2>🌐 Discovered Subdomains (Top 50)</h2>
                <div class="url-list">
                    <ul>
                        {% for subdomain in subdomains %}
                        <li>{{ subdomain }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
            {% endif %}
            
            <!-- URLs Found Section -->
            {% if urls_found > 0 %}
            <div class="section">
                <h2>🔗 URLs Discovered</h2>
                <div class="card">
                    <p><strong>Total URLs Found:</strong> {{ urls_found }}</p>
                    <p>URLs from Wayback Machine, GAU, and other sources</p>
                </div>
            </div>
            {% endif %}
            
            <!-- Errors Section -->
            {% if errors %}
            <div class="section">
                <h2>❌ Errors</h2>
                {% for error in errors %}
                <div class="card">
                    <span class="badge danger">Error</span> {{ error }}
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if not open_ports and not technologies and not vulnerabilities and not subdomains %}
            <div class="no-data">
                No significant findings to display. This may indicate the target is secure or not responding.
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>VulnScanner v1.0</strong> | {{ generated_at }}</p>
            <p>For educational and authorized security research only</p>
        </div>
    </div>
</body>
</html>
        """
        
        return Template(html_template)
