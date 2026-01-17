#!/usr/bin/env python3
"""
Plugin Fingerprinting Engine - Advanced Jenkins Plugin Detection with CVE Correlation
Identifies installed plugins, versions, and correlates with known vulnerabilities
"""

import requests
import json
import re
from typing import Dict, List, Optional, Tuple
from packaging import version
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

console = Console()

CVE_DATABASE = {
    "script-security": [
        {"cve": "CVE-2019-1003029", "affected": "<1.54", "severity": "critical", "description": "Groovy sandbox bypass RCE"},
        {"cve": "CVE-2019-1003030", "affected": "<1.54", "severity": "critical", "description": "Script security sandbox bypass"},
        {"cve": "CVE-2019-1003040", "affected": "<1.56", "severity": "high", "description": "Sandbox protection bypass"},
    ],
    "git": [
        {"cve": "CVE-2019-10392", "affected": "<3.10.1", "severity": "critical", "description": "Git plugin credential disclosure"},
        {"cve": "CVE-2018-1000182", "affected": "<3.9.0", "severity": "high", "description": "Path traversal vulnerability"},
        {"cve": "CVE-2020-2136", "affected": "<4.2.0", "severity": "high", "description": "Missing SSH host key validation"},
    ],
    "credentials": [
        {"cve": "CVE-2019-10320", "affected": "<2.1.19", "severity": "medium", "description": "Credentials stored in plain text"},
        {"cve": "CVE-2020-2100", "affected": "<2.3.0", "severity": "high", "description": "Credentials disclosure"},
    ],
    "pipeline-groovy": [
        {"cve": "CVE-2019-1003001", "affected": "<2.61", "severity": "critical", "description": "Sandbox bypass via default parameter expression"},
        {"cve": "CVE-2019-1003002", "affected": "<2.61", "severity": "critical", "description": "Pipeline sandbox bypass"},
    ],
    "workflow-cps": [
        {"cve": "CVE-2019-1003029", "affected": "<2.64", "severity": "critical", "description": "Groovy sandbox bypass"},
        {"cve": "CVE-2019-1003030", "affected": "<2.64", "severity": "critical", "description": "Script security bypass"},
    ],
    "jenkins-cli": [
        {"cve": "CVE-2024-23897", "affected": "<2.442", "severity": "high", "description": "Arbitrary file read via CLI"},
        {"cve": "CVE-2019-1003000", "affected": "<2.150.2", "severity": "critical", "description": "SECURITY-218 RCE"},
    ],
    "matrix-auth": [
        {"cve": "CVE-2020-2286", "affected": "<2.6.4", "severity": "medium", "description": "Stored XSS vulnerability"},
        {"cve": "CVE-2017-1000353", "affected": "<1.5", "severity": "critical", "description": "Java deserialization RCE"},
    ],
    "cloudbees-folder": [
        {"cve": "CVE-2020-2222", "affected": "<6.14", "severity": "medium", "description": "Missing permission check"},
        {"cve": "CVE-2018-1000601", "affected": "<6.4", "severity": "high", "description": "CSRF vulnerability"},
    ],
    "github": [
        {"cve": "CVE-2018-1000600", "affected": "<1.29.3", "severity": "medium", "description": "GitHub plugin SSRF"},
        {"cve": "CVE-2020-2110", "affected": "<1.29.5", "severity": "high", "description": "Credentials stored in plain text"},
    ],
    "kubernetes": [
        {"cve": "CVE-2020-2235", "affected": "<1.27.0", "severity": "high", "description": "XXE vulnerability"},
        {"cve": "CVE-2019-10445", "affected": "<1.18.2", "severity": "critical", "description": "Missing permission checks"},
    ],
    "docker-plugin": [
        {"cve": "CVE-2019-10399", "affected": "<1.1.7", "severity": "critical", "description": "Arbitrary code execution"},
        {"cve": "CVE-2019-10432", "affected": "<1.1.9", "severity": "high", "description": "Missing permission check"},
    ],
    "aws-credentials": [
        {"cve": "CVE-2018-1000402", "affected": "<1.23", "severity": "high", "description": "AWS credentials exposure"},
        {"cve": "CVE-2020-2096", "affected": "<1.27", "severity": "medium", "description": "Plain text credential storage"},
    ],
    "ssh-slaves": [
        {"cve": "CVE-2017-2648", "affected": "<1.20", "severity": "high", "description": "Missing SSH host key validation"},
        {"cve": "CVE-2018-1000149", "affected": "<1.26", "severity": "medium", "description": "Information disclosure"},
    ],
    "ansible": [
        {"cve": "CVE-2020-2304", "affected": "<1.1", "severity": "high", "description": "Missing permission checks"},
        {"cve": "CVE-2018-1000861", "affected": "<0.8", "severity": "critical", "description": "Arbitrary file read"},
    ],
    "parameterized-trigger": [
        {"cve": "CVE-2017-1000084", "affected": "<2.35.2", "severity": "medium", "description": "CSRF vulnerability"},
        {"cve": "CVE-2020-2249", "affected": "<2.37", "severity": "high", "description": "Missing permission check"},
    ],
    "emailext": [
        {"cve": "CVE-2020-2253", "affected": "<2.75", "severity": "medium", "description": "Stored XSS vulnerability"},
        {"cve": "CVE-2018-1000176", "affected": "<2.61", "severity": "high", "description": "SSRF vulnerability"},
    ]
}

class PluginFingerprint:
    """Advanced plugin fingerprinting with CVE correlation"""
    
    def __init__(self, jenkins_url: str, username: str = None, password: str = None, proxy: str = None):
        self.jenkins_url = jenkins_url.rstrip('/')
        self.username = username
        self.password = password
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        if username and password:
            self.session.auth = (username, password)
        
        self.plugins = []
        self.vulnerabilities = []
        self.fingerprint_methods = []
    
    def enumerate_plugins(self) -> List[Dict]:
        """Enumerate all installed plugins via API"""
        console.print("[cyan][*] Enumerating installed plugins via API[/cyan]")
        
        try:
            resp = self.session.get(
                f"{self.jenkins_url}/pluginManager/api/json?depth=1",
                proxies=self.proxy,
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                plugins = data.get("plugins", [])
                
                for plugin in plugins:
                    plugin_info = {
                        "short_name": plugin.get("shortName"),
                        "long_name": plugin.get("longName"),
                        "version": plugin.get("version"),
                        "enabled": plugin.get("enabled"),
                        "active": plugin.get("active"),
                        "has_update": plugin.get("hasUpdate"),
                        "url": plugin.get("url"),
                        "detection_method": "api"
                    }
                    self.plugins.append(plugin_info)
                
                console.print(f"[green][PASS] Enumerated {len(self.plugins)} plugins via API[/green]")
                return self.plugins
            else:
                console.print(f"[yellow][WARN] API returned status {resp.status_code}[/yellow]")
                
        except Exception as e:
            console.print(f"[red][FAIL] API enumeration failed: {e}[/red]")
        
        return self.plugins
    
    def passive_fingerprint(self) -> List[Dict]:
        """Passive fingerprinting via HTTP headers and responses"""
        console.print("[cyan][*] Performing passive plugin fingerprinting[/cyan]")
        
        detected = []
        
        try:
            resp = self.session.get(self.jenkins_url, proxies=self.proxy, timeout=10)
            
            headers = resp.headers
            for header, value in headers.items():
                if 'plugin' in header.lower():
                    console.print(f"[cyan][*] Plugin header detected: {header}: {value}[/cyan]")
                    detected.append({"method": "http_header", "header": header, "value": value})
            
            script_pattern = r'/plugin/([a-z0-9\-]+)/([0-9\.]+)/'
            matches = re.findall(script_pattern, resp.text)
            
            for plugin_name, plugin_version in matches:
                plugin_info = {
                    "short_name": plugin_name,
                    "version": plugin_version,
                    "detection_method": "html_resources"
                }
                
                if not any(p.get("short_name") == plugin_name for p in self.plugins):
                    self.plugins.append(plugin_info)
                    detected.append(plugin_info)
            
            console.print(f"[green][PASS] Passive fingerprinting detected {len(detected)} plugin indicators[/green]")
            
        except Exception as e:
            console.print(f"[red][FAIL] Passive fingerprinting failed: {e}[/red]")
        
        return detected
    
    def active_fingerprint(self) -> List[Dict]:
        """Active fingerprinting by probing plugin endpoints"""
        console.print("[cyan][*] Performing active plugin fingerprinting[/cyan]")
        
        plugin_probes = [
            ("script-security", "/scriptApproval/"),
            ("git", "/git/notifyCommit"),
            ("credentials", "/credentials/"),
            ("pipeline-groovy", "/pipeline-syntax/"),
            ("workflow-cps", "/job/test/pipeline-syntax/"),
            ("github", "/github-webhook/"),
            ("cloudbees-folder", "/job/folder/"),
            ("kubernetes", "/cloud/kubernetes/"),
            ("docker-plugin", "/docker-plugin/"),
            ("ansible", "/ansible/"),
            ("matrix-auth", "/configureSecurity/"),
            ("parameterized-trigger", "/build/parameterized/"),
        ]
        
        detected = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Probing endpoints...", total=len(plugin_probes))
            
            for plugin_name, endpoint in plugin_probes:
                try:
                    url = f"{self.jenkins_url}{endpoint}"
                    resp = self.session.get(url, proxies=self.proxy, timeout=5, allow_redirects=False)
                    
                    if resp.status_code in [200, 302, 403]:
                        plugin_info = {
                            "short_name": plugin_name,
                            "version": "unknown",
                            "detection_method": "active_probe",
                            "endpoint": endpoint,
                            "status_code": resp.status_code
                        }
                        
                        if not any(p.get("short_name") == plugin_name for p in self.plugins):
                            self.plugins.append(plugin_info)
                            detected.append(plugin_info)
                            console.print(f"[green][PASS] Detected {plugin_name} via {endpoint}[/green]")
                
                except Exception:
                    pass
                
                progress.update(task, advance=1)
        
        console.print(f"[green][PASS] Active fingerprinting detected {len(detected)} plugins[/green]")
        return detected
    
    def correlate_cves(self) -> List[Dict]:
        """Correlate installed plugins with known CVEs"""
        console.print("[cyan][*] Correlating plugins with CVE database[/cyan]")
        
        vulnerabilities = []
        
        for plugin in self.plugins:
            plugin_name = plugin.get("short_name")
            plugin_version = plugin.get("version", "unknown")
            
            if plugin_name in CVE_DATABASE:
                cves = CVE_DATABASE[plugin_name]
                
                for cve_entry in cves:
                    affected_version = cve_entry["affected"]
                    
                    if plugin_version != "unknown":
                        try:
                            is_vulnerable = self._check_version_vulnerable(
                                plugin_version,
                                affected_version
                            )
                            
                            if is_vulnerable:
                                vuln = {
                                    "plugin": plugin_name,
                                    "plugin_version": plugin_version,
                                    "cve": cve_entry["cve"],
                                    "severity": cve_entry["severity"],
                                    "description": cve_entry["description"],
                                    "affected_versions": affected_version
                                }
                                vulnerabilities.append(vuln)
                                console.print(f"[red][FAIL] {plugin_name} {plugin_version} vulnerable to {cve_entry['cve']}[/red]")
                        
                        except Exception as e:
                            console.print(f"[yellow][WARN] Version comparison failed for {plugin_name}: {e}[/yellow]")
                    else:
                        vuln = {
                            "plugin": plugin_name,
                            "plugin_version": "unknown",
                            "cve": cve_entry["cve"],
                            "severity": cve_entry["severity"],
                            "description": cve_entry["description"],
                            "affected_versions": affected_version,
                            "note": "Version unknown - potential vulnerability"
                        }
                        vulnerabilities.append(vuln)
        
        self.vulnerabilities = vulnerabilities
        console.print(f"[green][PASS] Found {len(vulnerabilities)} potential vulnerabilities[/green]")
        
        return vulnerabilities
    
    def _check_version_vulnerable(self, current_version: str, affected_spec: str) -> bool:
        """Check if current version matches vulnerability specification"""
        current_version = current_version.strip()
        affected_spec = affected_spec.strip()
        
        try:
            if affected_spec.startswith('<'):
                threshold = affected_spec[1:].strip()
                return version.parse(current_version) < version.parse(threshold)
            
            elif affected_spec.startswith('<='):
                threshold = affected_spec[2:].strip()
                return version.parse(current_version) <= version.parse(threshold)
            
            elif affected_spec.startswith('>'):
                threshold = affected_spec[1:].strip()
                return version.parse(current_version) > version.parse(threshold)
            
            elif affected_spec.startswith('>='):
                threshold = affected_spec[2:].strip()
                return version.parse(current_version) >= version.parse(threshold)
            
            elif ',' in affected_spec:
                ranges = [r.strip() for r in affected_spec.split(',')]
                return all(self._check_version_vulnerable(current_version, r) for r in ranges)
            
            else:
                return current_version == affected_spec
        
        except Exception:
            return False
    
    def generate_exploit_recommendations(self) -> List[Dict]:
        """Generate prioritized exploit recommendations"""
        console.print("[cyan][*] Generating exploit recommendations[/cyan]")
        
        recommendations = []
        severity_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        
        for vuln in self.vulnerabilities:
            cve = vuln["cve"]
            exploit_info = self._get_exploit_info(cve)
            
            recommendation = {
                **vuln,
                "priority": severity_priority.get(vuln["severity"], 5),
                "exploit_available": exploit_info.get("available", False),
                "exploit_module": exploit_info.get("module"),
                "remediation": exploit_info.get("remediation"),
            }
            recommendations.append(recommendation)
        
        recommendations.sort(key=lambda x: x["priority"])
        
        console.print(f"[green][PASS] Generated {len(recommendations)} exploit recommendations[/green]")
        return recommendations
    
    def _get_exploit_info(self, cve: str) -> Dict:
        """Get exploit information for specific CVE"""
        exploit_map = {
            "CVE-2024-23897": {
                "available": True,
                "module": "exploits/cve_2024_23897.py",
                "remediation": "Upgrade Jenkins to >= 2.442 or disable CLI"
            },
            "CVE-2019-1003029": {
                "available": True,
                "module": "exploits/cve_2019_1003029.py",
                "remediation": "Upgrade script-security plugin to >= 1.54"
            },
            "CVE-2019-1003030": {
                "available": True,
                "module": "exploits/cve_2019_1003030.py",
                "remediation": "Upgrade script-security plugin to >= 1.54"
            },
            "CVE-2018-1000861": {
                "available": True,
                "module": "exploits/cve_2018_1000861.py",
                "remediation": "Upgrade Jenkins to >= 2.154 and LTS >= 2.138.4"
            },
        }
        
        return exploit_map.get(cve, {
            "available": False,
            "module": None,
            "remediation": f"Check vendor advisory for {cve}"
        })
    
    def print_plugin_table(self):
        """Display installed plugins in formatted table"""
        table = Table(title="Installed Jenkins Plugins", show_header=True, header_style="bold magenta")
        table.add_column("Plugin Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Detection Method", style="blue")
        
        for plugin in self.plugins[:50]:
            status = "Active" if plugin.get("active") else "Inactive"
            if not plugin.get("enabled"):
                status = "Disabled"
            
            table.add_row(
                plugin.get("short_name", "unknown"),
                plugin.get("version", "unknown"),
                status,
                plugin.get("detection_method", "unknown")
            )
        
        console.print(table)
        
        if len(self.plugins) > 50:
            console.print(f"[yellow][*] Showing 50 of {len(self.plugins)} total plugins[/yellow]")
    
    def print_vulnerability_table(self):
        """Display vulnerabilities in formatted table"""
        table = Table(title="Plugin Vulnerabilities", show_header=True, header_style="bold red")
        table.add_column("Plugin", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("CVE", style="red")
        table.add_column("Severity", style="magenta")
        table.add_column("Description", style="white")
        
        for vuln in self.vulnerabilities[:30]:
            severity_color = {
                "critical": "[red]",
                "high": "[orange1]",
                "medium": "[yellow]",
                "low": "[green]"
            }.get(vuln["severity"], "[white]")
            
            table.add_row(
                vuln["plugin"],
                vuln["plugin_version"],
                vuln["cve"],
                f"{severity_color}{vuln['severity'].upper()}[/]",
                vuln["description"][:60] + "..." if len(vuln["description"]) > 60 else vuln["description"]
            )
        
        console.print(table)
        
        if len(self.vulnerabilities) > 30:
            console.print(f"[yellow][*] Showing 30 of {len(self.vulnerabilities)} total vulnerabilities[/yellow]")
    
    def export_results(self, filename: str = "plugin_fingerprint.json"):
        """Export results to JSON file"""
        output = {
            "jenkins_url": self.jenkins_url,
            "total_plugins": len(self.plugins),
            "total_vulnerabilities": len(self.vulnerabilities),
            "plugins": self.plugins,
            "vulnerabilities": self.vulnerabilities,
            "severity_breakdown": {
                "critical": len([v for v in self.vulnerabilities if v["severity"] == "critical"]),
                "high": len([v for v in self.vulnerabilities if v["severity"] == "high"]),
                "medium": len([v for v in self.vulnerabilities if v["severity"] == "medium"]),
                "low": len([v for v in self.vulnerabilities if v["severity"] == "low"]),
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        console.print(f"[green][PASS] Results exported to {filename}[/green]")
    
    def print_summary(self):
        """Print summary statistics"""
        table = Table(title="Fingerprinting Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Plugins Detected", str(len(self.plugins)))
        table.add_row("Total Vulnerabilities", str(len(self.vulnerabilities)))
        
        severity_counts = {
            "critical": len([v for v in self.vulnerabilities if v["severity"] == "critical"]),
            "high": len([v for v in self.vulnerabilities if v["severity"] == "high"]),
            "medium": len([v for v in self.vulnerabilities if v["severity"] == "medium"]),
            "low": len([v for v in self.vulnerabilities if v["severity"] == "low"]),
        }
        
        table.add_row("Critical Severity", f"[red]{severity_counts['critical']}[/red]")
        table.add_row("High Severity", f"[orange1]{severity_counts['high']}[/orange1]")
        table.add_row("Medium Severity", f"[yellow]{severity_counts['medium']}[/yellow]")
        table.add_row("Low Severity", f"[green]{severity_counts['low']}[/green]")
        
        console.print(table)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Plugin Fingerprinting Engine - CVE Correlation")
    parser.add_argument("--url", required=True, help="Jenkins URL")
    parser.add_argument("--username", help="Jenkins username")
    parser.add_argument("--password", help="Jenkins password")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--output", default="plugin_fingerprint.json", help="Output file")
    parser.add_argument("--no-active", action="store_true", help="Skip active fingerprinting")
    
    args = parser.parse_args()
    
    fp = PluginFingerprint(args.url, args.username, args.password, args.proxy)
    
    console.print("\n[bold cyan]===== Plugin Enumeration =====[/bold cyan]\n")
    fp.enumerate_plugins()
    
    console.print("\n[bold cyan]===== Passive Fingerprinting =====[/bold cyan]\n")
    fp.passive_fingerprint()
    
    if not args.no_active:
        console.print("\n[bold cyan]===== Active Fingerprinting =====[/bold cyan]\n")
        fp.active_fingerprint()
    
    console.print("\n[bold cyan]===== CVE Correlation =====[/bold cyan]\n")
    fp.correlate_cves()
    
    console.print("\n[bold cyan]===== Exploit Recommendations =====[/bold cyan]\n")
    recommendations = fp.generate_exploit_recommendations()
    
    console.print("\n[bold cyan]===== Installed Plugins =====[/bold cyan]\n")
    fp.print_plugin_table()
    
    console.print("\n[bold cyan]===== Detected Vulnerabilities =====[/bold cyan]\n")
    fp.print_vulnerability_table()
    
    console.print("\n[bold cyan]===== Summary =====[/bold cyan]\n")
    fp.print_summary()
    fp.export_results(args.output)
