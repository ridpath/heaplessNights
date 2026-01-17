#!/usr/bin/env python3
"""
Test script to validate Batch 3 CVE modules load successfully.
"""

from exploits import ExploitRegistry
from rich.console import Console

console = Console()

def test_batch3_modules():
    """Test loading of batch 3 CVE modules."""
    console.print("\n[cyan]Testing Batch 3 CVE Module Loading...[/cyan]\n")
    
    reg = ExploitRegistry()
    count = reg.load_all_modules()
    
    console.print(f"\n[green]=== SUMMARY ===[/green]")
    console.print(f"Total modules loaded: {count}")
    
    batch3_cves = [
        'cve_2018_1000402',
        'cve_2023_24422',
        'cve_2023_3519'
    ]
    
    console.print(f"\n[cyan]Batch 3 Modules Status:[/cyan]")
    for cve in batch3_cves:
        if cve in reg._modules:
            metadata = reg.get_metadata(cve)
            console.print(f"[green][+] {cve}[/green]")
            if metadata:
                console.print(f"  CVE ID: {metadata.cve_id}")
                console.print(f"  Name: {metadata.name}")
                console.print(f"  Severity: {metadata.severity}")
                console.print(f"  MITRE ATT&CK: {', '.join(metadata.mitre_attack)}")
        else:
            console.print(f"[red][-] {cve} - NOT LOADED[/red]")
    
    console.print(f"\n[cyan]All Loaded Modules:[/cyan]")
    for module_name in sorted(reg._modules.keys()):
        cve_id = reg.get_cve_id(module_name)
        console.print(f"  - {module_name} ({cve_id})")
    
    if count >= 11:
        console.print(f"\n[green][+] All 11+ CVE modules loaded successfully![/green]")
        return True
    else:
        console.print(f"\n[yellow][!] Only {count} modules loaded (expected 11+)[/yellow]")
        return False

if __name__ == '__main__':
    success = test_batch3_modules()
    exit(0 if success else 1)
