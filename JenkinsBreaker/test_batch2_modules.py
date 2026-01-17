#!/usr/bin/env python3
"""
Test script for CVE Batch 2 modules.
Tests CVE-2020-2100, CVE-2020-2249, CVE-2021-21686, and CVE-2018-1000600.

This script verifies that each module:
1. Loads correctly
2. Has proper metadata
3. Can execute check_vulnerable()
4. Can execute run() without crashing
5. Returns proper ExploitResult objects

Run against Jenkins Lab:
    python test_batch2_modules.py --url http://localhost:8080 --username admin --password admin
    
Run module checks only (no live target):
    python test_batch2_modules.py --check-only
"""

import sys
import argparse
from rich.console import Console
from rich.table import Table
from exploits import ExploitRegistry, ExploitResult

console = Console()

BATCH_2_MODULES = [
    "cve_2020_2100",
    "cve_2020_2249",
    "cve_2021_21686",
    "cve_2018_1000600"
]

BATCH_2_CVES = [
    "CVE-2020-2100",
    "CVE-2020-2249",
    "CVE-2021-21686",
    "CVE-2018-1000600"
]


class MockTool:
    """Mock JenkinsBreaker tool for testing without live target."""
    
    def __init__(self, url="http://localhost:8080", username="admin", password="admin"):
        self.jenkins_url = url
        self.auth = (username, password) if username and password else None
        self.custom_headers = {}
        self.proxies = {}
        self.crumb = None


def test_module_structure(registry, module_name):
    """Test that a module has proper structure and metadata."""
    console.print(f"\n[cyan][*] Testing module structure: {module_name}[/cyan]")
    
    module = registry.get_module(module_name)
    if not module:
        console.print(f"[red][-] Module {module_name} not loaded![/red]")
        return False
    
    tests_passed = 0
    tests_total = 0
    
    tests_total += 1
    if hasattr(module, 'CVE_ID') or hasattr(module, 'cve'):
        console.print(f"[green][+] Has CVE_ID/cve attribute[/green]")
        tests_passed += 1
    else:
        console.print(f"[red][-] Missing CVE_ID/cve attribute[/red]")
    
    tests_total += 1
    if hasattr(module, 'METADATA'):
        console.print(f"[green][+] Has METADATA[/green]")
        tests_passed += 1
        
        metadata = module.METADATA
        
        tests_total += 1
        if hasattr(metadata, 'cve_id') and metadata.cve_id:
            console.print(f"[green][+] Metadata has cve_id: {metadata.cve_id}[/green]")
            tests_passed += 1
        else:
            console.print(f"[red][-] Metadata missing cve_id[/red]")
        
        tests_total += 1
        if hasattr(metadata, 'mitre_attack') and metadata.mitre_attack:
            console.print(f"[green][+] Has MITRE ATT&CK mapping: {', '.join(metadata.mitre_attack)}[/green]")
            tests_passed += 1
        else:
            console.print(f"[yellow][!] Missing MITRE ATT&CK mapping[/yellow]")
    else:
        console.print(f"[red][-] Missing METADATA[/red]")
    
    tests_total += 1
    if hasattr(module, 'check_vulnerable') and callable(module.check_vulnerable):
        console.print(f"[green][+] Has check_vulnerable() function[/green]")
        tests_passed += 1
    else:
        console.print(f"[yellow][!] Missing check_vulnerable() function[/yellow]")
    
    tests_total += 1
    if hasattr(module, 'run') and callable(module.run):
        console.print(f"[green][+] Has run() function[/green]")
        tests_passed += 1
    else:
        console.print(f"[red][-] Missing run() function[/red]")
    
    console.print(f"[cyan][*] Structure tests: {tests_passed}/{tests_total} passed[/cyan]")
    
    return tests_passed == tests_total


def test_module_execution(registry, module_name, tool):
    """Test that a module can execute without crashing."""
    console.print(f"\n[cyan][*] Testing module execution: {module_name}[/cyan]")
    
    module = registry.get_module(module_name)
    if not module:
        console.print(f"[red][-] Module {module_name} not loaded![/red]")
        return False
    
    try:
        console.print(f"[cyan][*] Running check_vulnerable()...[/cyan]")
        if hasattr(module, 'check_vulnerable'):
            result = module.check_vulnerable(tool)
            console.print(f"[green][+] check_vulnerable() returned: {result}[/green]")
    except Exception as e:
        console.print(f"[yellow][!] check_vulnerable() error (non-fatal): {e}[/yellow]")
    
    try:
        console.print(f"[cyan][*] Running exploit (dry-run mode)...[/cyan]")
        result = module.run(tool, lhost="127.0.0.1", lport=9001)
        
        if isinstance(result, ExploitResult):
            console.print(f"[green][+] Returns ExploitResult object[/green]")
            console.print(f"[cyan]    Status: {result.status}[/cyan]")
            console.print(f"[cyan]    Details: {result.details[:100]}...[/cyan]" if len(result.details) > 100 else f"[cyan]    Details: {result.details}[/cyan]")
            return True
        elif isinstance(result, dict):
            console.print(f"[yellow][!] Returns dict (should be ExploitResult)[/yellow]")
            console.print(f"[cyan]    Keys: {result.keys()}[/cyan]")
            return True
        else:
            console.print(f"[red][-] Unexpected return type: {type(result)}[/red]")
            return False
            
    except Exception as e:
        console.print(f"[red][-] Execution error: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(description="Test CVE Batch 2 modules")
    parser.add_argument('--url', default='http://localhost:8080', help='Jenkins URL')
    parser.add_argument('--username', default='admin', help='Jenkins username')
    parser.add_argument('--password', default='admin', help='Jenkins password')
    parser.add_argument('--check-only', action='store_true', help='Only check module structure, no execution')
    args = parser.parse_args()
    
    console.print("[bold cyan]JenkinsBreaker - CVE Batch 2 Module Tests[/bold cyan]\n")
    
    console.print("[cyan][*] Initializing ExploitRegistry...[/cyan]")
    registry = ExploitRegistry()
    loaded = registry.load_all_modules()
    
    if loaded == 0:
        console.print("[red][!] No modules loaded! Check exploits directory.[/red]")
        sys.exit(1)
    
    console.print(f"\n[cyan][*] Testing Batch 2 modules specifically...[/cyan]")
    
    results_table = Table(title="Batch 2 Module Test Results")
    results_table.add_column("Module", style="cyan")
    results_table.add_column("CVE ID", style="yellow")
    results_table.add_column("Structure", style="green")
    results_table.add_column("Execution", style="blue")
    results_table.add_column("Status", style="bold")
    
    all_passed = True
    tool = MockTool(url=args.url, username=args.username, password=args.password)
    
    for module_name in BATCH_2_MODULES:
        console.print(f"\n{'=' * 70}")
        console.print(f"[bold]Testing: {module_name}[/bold]")
        console.print('=' * 70)
        
        structure_ok = test_module_structure(registry, module_name)
        
        if args.check_only:
            execution_ok = "SKIPPED"
            status = "[+] PASS" if structure_ok else "[-] FAIL"
        else:
            execution_ok = test_module_execution(registry, module_name, tool)
            status = "[+] PASS" if (structure_ok and execution_ok) else "[-] FAIL"
            execution_ok = "[+]" if execution_ok else "[-]"
        
        if not structure_ok:
            all_passed = False
        
        cve_id = registry.get_cve_id(module_name)
        
        results_table.add_row(
            module_name,
            cve_id,
            "[+]" if structure_ok else "[-]",
            execution_ok,
            status
        )
    
    console.print(f"\n{'=' * 70}")
    console.print(results_table)
    console.print('=' * 70)
    
    if all_passed:
        console.print("\n[bold green][[+]] All Batch 2 modules passed tests![/bold green]")
        sys.exit(0)
    else:
        console.print("\n[bold red][[-]] Some modules failed tests[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
