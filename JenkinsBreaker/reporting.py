"""
JenkinsBreaker Reporting System

Comprehensive reporting functionality for JenkinsBreaker exploit runs.
Generates structured JSON logs, MITRE ATT&CK matrices, and formatted reports.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

console = Console()

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False


MITRE_ATTACK_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
}


class ReportManager:
    """
    Manages report generation for JenkinsBreaker exploit runs.
    """
    
    def __init__(self, base_dir: str = "reports"):
        """
        Initialize the report manager.
        
        Args:
            base_dir: Base directory for all reports
        """
        self.base_dir = Path(base_dir)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.base_dir / self.session_id
        self._create_directory_structure()
        
        self.exploit_logs: List[Dict[str, Any]] = []
        self.target_info: Dict[str, Any] = {}
        self.mitre_techniques: set = set()
        
    def _create_directory_structure(self):
        """Create the reports directory structure."""
        (self.session_dir / "json").mkdir(parents=True, exist_ok=True)
        (self.session_dir / "markdown").mkdir(parents=True, exist_ok=True)
        (self.session_dir / "pdf").mkdir(parents=True, exist_ok=True)
        (self.session_dir / "attack_matrix").mkdir(parents=True, exist_ok=True)
        
    def log_exploit(self, exploit_name: str, cve_id: str, status: str, 
                   details: str, mitre_ids: List[str] = None, 
                   data: Optional[Dict[str, Any]] = None):
        """
        Log an individual exploit attempt.
        
        Args:
            exploit_name: Name of the exploit
            cve_id: CVE identifier
            status: Status (success, failed, error)
            details: Detailed description of the result
            mitre_ids: List of MITRE ATT&CK technique IDs
            data: Additional data captured during the exploit
        """
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "exploit": exploit_name,
            "cve_id": cve_id,
            "status": status,
            "details": details,
            "mitre_attack": mitre_ids or [],
            "data": data or {}
        }
        
        self.exploit_logs.append(log_entry)
        
        if mitre_ids:
            self.mitre_techniques.update(mitre_ids)
        
        log_filename = self.session_dir / "json" / f"{cve_id}_{status}_{timestamp.replace(':', '-')}.json"
        with open(log_filename, 'w', encoding='utf-8') as f:
            json.dump(log_entry, f, indent=2)
            
        console.print(f"[dim][*] Logged {cve_id} to {log_filename}[/dim]")
        
    def set_target_info(self, url: str, version: str = None, plugins: List[str] = None, 
                       vulnerabilities: List[str] = None):
        """
        Set information about the target Jenkins instance.
        
        Args:
            url: Target Jenkins URL
            version: Jenkins version
            plugins: List of installed plugins
            vulnerabilities: List of detected vulnerabilities
        """
        self.target_info = {
            "url": url,
            "version": version or "Unknown",
            "plugins": plugins or [],
            "vulnerabilities": vulnerabilities or [],
            "scan_timestamp": datetime.now().isoformat()
        }
        
    def generate_mitre_matrix(self) -> str:
        """
        Generate a MITRE ATT&CK matrix visualization.
        
        Returns:
            str: Markdown formatted MITRE ATT&CK matrix
        """
        matrix_md = "# MITRE ATT&CK Matrix\n\n"
        matrix_md += f"**Session**: {self.session_id}\n\n"
        matrix_md += "## Techniques Used\n\n"
        
        tactic_groups = {}
        for tech_id in self.mitre_techniques:
            if tech_id in MITRE_ATTACK_TECHNIQUES:
                tech_info = MITRE_ATTACK_TECHNIQUES[tech_id]
                tactics = tech_info["tactic"].split(", ")
                for tactic in tactics:
                    if tactic not in tactic_groups:
                        tactic_groups[tactic] = []
                    tactic_groups[tactic].append((tech_id, tech_info["name"]))
        
        for tactic, techniques in sorted(tactic_groups.items()):
            matrix_md += f"### {tactic}\n\n"
            for tech_id, tech_name in techniques:
                matrix_md += f"- **{tech_id}**: {tech_name}\n"
            matrix_md += "\n"
        
        matrix_filename = self.session_dir / "attack_matrix" / f"mitre_matrix_{self.session_id}.md"
        with open(matrix_filename, 'w', encoding='utf-8') as f:
            f.write(matrix_md)
            
        console.print(f"[green][+] MITRE ATT&CK matrix saved to {matrix_filename}[/green]")
        return matrix_md
        
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """
        Generate a comprehensive JSON report.
        
        Args:
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            str: Path to the generated report
        """
        if filename is None:
            filename = self.session_dir / "json" / f"full_report_{self.session_id}.json"
        else:
            filename = self.session_dir / "json" / filename
            
        report = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "target": self.target_info,
            "exploits": self.exploit_logs,
            "mitre_techniques": sorted(list(self.mitre_techniques)),
            "summary": {
                "total_exploits": len(self.exploit_logs),
                "successful": sum(1 for e in self.exploit_logs if e["status"] == "success"),
                "failed": sum(1 for e in self.exploit_logs if e["status"] == "failed"),
                "errors": sum(1 for e in self.exploit_logs if e["status"] == "error")
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
            
        console.print(f"[green][+] JSON report saved to {filename}[/green]")
        return str(filename)
        
    def generate_markdown_report(self, filename: Optional[str] = None) -> str:
        """
        Generate a comprehensive Markdown report.
        
        Args:
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            str: Path to the generated report
        """
        if filename is None:
            filename = self.session_dir / "markdown" / f"report_{self.session_id}.md"
        else:
            filename = self.session_dir / "markdown" / filename
            
        md = f"# JenkinsBreaker Exploit Report\n\n"
        md += f"**Session ID**: `{self.session_id}`\n\n"
        md += f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md += "---\n\n"
        
        md += "## Target Information\n\n"
        md += f"- **URL**: `{self.target_info.get('url', 'N/A')}`\n"
        md += f"- **Version**: `{self.target_info.get('version', 'Unknown')}`\n"
        md += f"- **Vulnerabilities Detected**: {len(self.target_info.get('vulnerabilities', []))}\n"
        md += f"- **Plugins**: {len(self.target_info.get('plugins', []))}\n\n"
        
        md += "## Executive Summary\n\n"
        total = len(self.exploit_logs)
        successful = sum(1 for e in self.exploit_logs if e["status"] == "success")
        failed = sum(1 for e in self.exploit_logs if e["status"] == "failed")
        errors = sum(1 for e in self.exploit_logs if e["status"] == "error")
        
        md += f"- **Total Exploits Attempted**: {total}\n"
        md += f"- **Successful**: {successful}\n"
        md += f"- **Failed**: {failed}\n"
        md += f"- **Errors**: {errors}\n\n"
        
        if successful > 0:
            md += "**Risk Assessment**: HIGH - One or more exploits succeeded\n\n"
        elif total > 0:
            md += "**Risk Assessment**: MEDIUM - Exploits attempted but none succeeded\n\n"
        else:
            md += "**Risk Assessment**: LOW - No exploits attempted\n\n"
            
        md += "## MITRE ATT&CK Techniques\n\n"
        if self.mitre_techniques:
            for tech_id in sorted(self.mitre_techniques):
                if tech_id in MITRE_ATTACK_TECHNIQUES:
                    tech_info = MITRE_ATTACK_TECHNIQUES[tech_id]
                    md += f"- **{tech_id}**: {tech_info['name']} ({tech_info['tactic']})\n"
        else:
            md += "*No MITRE ATT&CK techniques recorded*\n"
        md += "\n"
        
        md += "## Exploit Details\n\n"
        for i, exploit in enumerate(self.exploit_logs, 1):
            status_icon = "[SUCCESS]" if exploit["status"] == "success" else "[FAILED]"
            md += f"### {i}. {exploit['exploit']} ({exploit['cve_id']}) {status_icon}\n\n"
            md += f"- **Status**: {exploit['status'].upper()}\n"
            md += f"- **Timestamp**: {exploit['timestamp']}\n"
            md += f"- **Details**: {exploit['details']}\n"
            if exploit.get("mitre_attack"):
                md += f"- **MITRE ATT&CK**: {', '.join(exploit['mitre_attack'])}\n"
            md += "\n"
            
        md += "---\n\n"
        md += "*Report generated by JenkinsBreaker - Professional CI/CD Exploitation Suite*\n"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md)
            
        console.print(f"[green][+] Markdown report saved to {filename}[/green]")
        return str(filename)
        
    def generate_pdf_report(self, filename: Optional[str] = None) -> Optional[str]:
        """
        Generate a PDF report from the Markdown report.
        
        Args:
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Optional[str]: Path to the generated PDF, or None if WeasyPrint unavailable
        """
        if not WEASYPRINT_AVAILABLE:
            console.print("[yellow][!] PDF generation unavailable (WeasyPrint not installed)[/yellow]")
            return None
            
        if filename is None:
            filename = self.session_dir / "pdf" / f"report_{self.session_id}.pdf"
        else:
            filename = self.session_dir / "pdf" / filename
            
        md_file = self.generate_markdown_report()
        
        with open(md_file, 'r') as f:
            md_content = f.read()
            
        html_content = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    max-width: 800px;
                    margin: 40px auto;
                    padding: 20px;
                }}
                h1 {{
                    color: #c02020;
                    border-bottom: 3px solid #c02020;
                    padding-bottom: 10px;
                }}
                h2 {{
                    color: #333;
                    border-bottom: 1px solid #ccc;
                    padding-bottom: 5px;
                    margin-top: 30px;
                }}
                h3 {{
                    color: #555;
                }}
                code {{
                    background-color: #f4f4f4;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: monospace;
                }}
                ul {{
                    margin-left: 20px;
                }}
                hr {{
                    border: none;
                    border-top: 1px solid #ccc;
                    margin: 30px 0;
                }}
            </style>
        </head>
        <body>
        """
        
        lines = md_content.split('\n')
        for line in lines:
            if line.startswith('# '):
                html_content += f"<h1>{line[2:]}</h1>\n"
            elif line.startswith('## '):
                html_content += f"<h2>{line[3:]}</h2>\n"
            elif line.startswith('### '):
                html_content += f"<h3>{line[4:]}</h3>\n"
            elif line.startswith('- '):
                if '**' in line:
                    line = line.replace('**', '<strong>').replace('**', '</strong>')
                if '`' in line:
                    line = line.replace('`', '<code>').replace('`', '</code>')
                html_content += f"<ul><li>{line[2:]}</li></ul>\n"
            elif line.startswith('*') and line.endswith('*'):
                html_content += f"<p><em>{line[1:-1]}</em></p>\n"
            elif line == '---':
                html_content += "<hr/>\n"
            elif line.strip():
                if '**' in line:
                    line = line.replace('**', '<strong>').replace('**', '</strong>')
                if '`' in line:
                    line = line.replace('`', '<code>').replace('`', '</code>')
                html_content += f"<p>{line}</p>\n"
                
        html_content += "</body></html>"
        
        try:
            HTML(string=html_content).write_pdf(filename)
            console.print(f"[green][+] PDF report saved to {filename}[/green]")
            return str(filename)
        except Exception as e:
            console.print(f"[red][-] PDF generation failed: {e}[/red]")
            return None
            
    def generate_all_reports(self, formats: List[str] = None) -> Dict[str, str]:
        """
        Generate all requested report formats.
        
        Args:
            formats: List of formats to generate ('json', 'md', 'pdf')
                    Defaults to ['json', 'md']
                    
        Returns:
            Dict[str, str]: Dictionary mapping format to file path
        """
        if formats is None:
            formats = ['json', 'md']
            
        results = {}
        
        if 'json' in formats:
            results['json'] = self.generate_json_report()
            
        if 'md' in formats or 'markdown' in formats:
            results['markdown'] = self.generate_markdown_report()
            
        if 'pdf' in formats:
            pdf_path = self.generate_pdf_report()
            if pdf_path:
                results['pdf'] = pdf_path
                
        if 'mitre' in formats or 'attack' in formats:
            self.generate_mitre_matrix()
            
        return results
        
    def print_summary(self):
        """Print a summary of the session to console."""
        table = Table(title=f"JenkinsBreaker Session {self.session_id}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Target", self.target_info.get('url', 'N/A'))
        table.add_row("Jenkins Version", self.target_info.get('version', 'Unknown'))
        table.add_row("Total Exploits", str(len(self.exploit_logs)))
        table.add_row("Successful", str(sum(1 for e in self.exploit_logs if e["status"] == "success")))
        table.add_row("Failed", str(sum(1 for e in self.exploit_logs if e["status"] == "failed")))
        table.add_row("MITRE Techniques", str(len(self.mitre_techniques)))
        table.add_row("Report Directory", str(self.session_dir))
        
        console.print(table)
