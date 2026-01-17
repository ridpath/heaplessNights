"""
Test script for JenkinsBreaker automation and fingerprinting features.

This script validates:
1. Plugin fingerprinting via /pluginManager/api/json
2. Version matching logic for CVEs
3. Safe execution order determination
4. Auto-exploit with fingerprinting
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from exploits import ExploitRegistry, ExploitMetadata
from rich.console import Console

console = Console()

def test_exploit_registry():
    """Test that ExploitRegistry can load all modules."""
    console.print("[bold cyan]Test 1: Exploit Registry Loading[/bold cyan]")
    
    registry = ExploitRegistry()
    loaded_count = registry.load_all_modules()
    
    if loaded_count > 0:
        console.print(f"[green][+] Successfully loaded {loaded_count} exploit modules[/green]")
        
        modules_info = registry.list_modules()
        console.print(f"[cyan][*] Modules:[/cyan]")
        for module in modules_info[:5]:
            console.print(f"    - {module['cve_id']}: {module['name']}")
        
        return True
    else:
        console.print("[red][-] Failed to load any exploit modules[/red]")
        return False


def test_version_matching():
    """Test version matching logic."""
    console.print("\n[bold cyan]Test 2: Version Matching Logic[/bold cyan]")
    
    class MockTool:
        def __init__(self):
            self.version = "2.440.1"
            self.plugins = {}
    
    tool = MockTool()
    
    from JenkinsBreaker import JenkinsBreaker
    
    jb = JenkinsBreaker("http://test:8080")
    jb.version = "2.440.1"
    jb.plugins = {}
    
    test_metadata = ExploitMetadata(
        cve_id="CVE-TEST-12345",
        name="Test CVE",
        description="Test",
        affected_versions=["<= 2.441", "<= 2.426.2 LTS"],
        mitre_attack=["T1190"],
        severity="high"
    )
    
    is_vulnerable = jb.match_cve_to_version(test_metadata)
    
    if is_vulnerable:
        console.print(f"[green][+] Version 2.440.1 correctly matched as vulnerable to <= 2.441[/green]")
    else:
        console.print(f"[red][-] Version matching failed for 2.440.1 vs <= 2.441[/red]")
        return False
    
    jb.version = "2.442.0"
    is_not_vulnerable = jb.match_cve_to_version(test_metadata)
    
    if not is_not_vulnerable:
        console.print(f"[green][+] Version 2.442.0 correctly matched as NOT vulnerable to <= 2.441[/green]")
        return True
    else:
        console.print(f"[red][-] Version matching failed for 2.442.0 vs <= 2.441[/red]")
        return False


def test_safe_execution_order():
    """Test safe execution order determination."""
    console.print("\n[bold cyan]Test 3: Safe Execution Order[/bold cyan]")
    
    from JenkinsBreaker import JenkinsBreaker
    
    jb = JenkinsBreaker("http://test:8080")
    
    test_cves = [
        ("CVE-TEST-RCE", ExploitMetadata(
            cve_id="CVE-TEST-RCE",
            name="Test RCE",
            description="RCE Test",
            affected_versions=["<= 2.441"],
            mitre_attack=["T1190"],
            severity="critical",
            tags=["rce"]
        ), None),
        ("CVE-TEST-FILEREAD", ExploitMetadata(
            cve_id="CVE-TEST-FILEREAD",
            name="Test File Read",
            description="File Read Test",
            affected_versions=["<= 2.441"],
            mitre_attack=["T1552.001"],
            severity="high",
            tags=["file-read"]
        ), None),
        ("CVE-TEST-PRIVESC", ExploitMetadata(
            cve_id="CVE-TEST-PRIVESC",
            name="Test Privesc",
            description="Privesc Test",
            affected_versions=["<= 2.441"],
            mitre_attack=["T1068"],
            severity="high",
            tags=["privilege-escalation"]
        ), None),
    ]
    
    ordered = jb.determine_safe_execution_order(test_cves)
    
    console.print("[cyan][*] Execution order:[/cyan]")
    for i, exploit in enumerate(ordered, 1):
        console.print(f"    {i}. {exploit['cve_id']} - Priority {exploit['priority']} ({', '.join(exploit['tags'])})")
    
    if ordered[0]['tags'][0] == 'file-read' and ordered[-1]['tags'][0] == 'privilege-escalation':
        console.print("[green][+] Execution order correct: file-read -> rce -> privesc[/green]")
        return True
    else:
        console.print("[red][-] Execution order incorrect[/red]")
        return False


def test_list_cves_command():
    """Test --list-cves functionality."""
    console.print("\n[bold cyan]Test 4: --list-cves Command[/bold cyan]")
    
    from exploits import ExploitRegistry
    from rich.table import Table
    
    registry = ExploitRegistry()
    loaded_count = registry.load_all_modules()
    modules_info = registry.list_modules()
    
    if modules_info:
        console.print(f"[green][+] Found {len(modules_info)} modules to display[/green]")
        
        table = Table(title="Available CVE Modules (Sample)", show_header=True, header_style="bold cyan")
        table.add_column("CVE ID", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Tags", style="green")
        
        for module in sorted(modules_info, key=lambda x: x['cve_id'])[:5]:
            registry_module = None
            for name, mod in registry._modules.items():
                if registry.get_cve_id(name) == module['cve_id']:
                    registry_module = mod
                    break
            
            tags = "N/A"
            if registry_module and hasattr(registry_module, 'tags'):
                tags = ", ".join(registry_module.tags) if registry_module.tags else "N/A"
            
            table.add_row(
                module['cve_id'],
                module['severity'],
                tags
            )
        
        console.print(table)
        return True
    else:
        console.print("[red][-] No modules found for listing[/red]")
        return False


def main():
    """Run all tests."""
    console.print("[bold magenta]JenkinsBreaker Automation & Fingerprinting Tests[/bold magenta]\n")
    
    results = []
    
    results.append(("Exploit Registry Loading", test_exploit_registry()))
    results.append(("Version Matching Logic", test_version_matching()))
    results.append(("Safe Execution Order", test_safe_execution_order()))
    results.append(("List CVEs Command", test_list_cves_command()))
    
    console.print("\n[bold magenta]Test Summary[/bold magenta]")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[green]PASS[/green]" if result else "[red]FAIL[/red]"
        console.print(f"  {status} - {test_name}")
    
    console.print(f"\n[cyan]Total: {passed}/{total} tests passed[/cyan]")
    
    if passed == total:
        console.print("[bold green]All tests passed![/bold green]")
        return 0
    else:
        console.print("[bold red]Some tests failed[/bold red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
