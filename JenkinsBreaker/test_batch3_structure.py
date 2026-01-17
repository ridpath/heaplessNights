#!/usr/bin/env python3
"""
Validate Batch 3 CVE modules conform to exploit interface.
"""

import sys
from exploits import ExploitRegistry
from rich.console import Console

console = Console()

def test_module_structure(module_name, module, metadata):
    """Test a single module's structure."""
    issues = []
    
    if not hasattr(module, 'run'):
        issues.append("Missing 'run' function")
    elif not callable(module.run):
        issues.append("'run' is not callable")
    
    if not hasattr(module, 'cve') and not hasattr(module, 'CVE_ID'):
        issues.append("Missing CVE identifier")
    
    if not hasattr(module, 'check_vulnerable'):
        issues.append("Missing 'check_vulnerable' function (optional but recommended)")
    
    if not metadata:
        issues.append("Missing METADATA")
    else:
        if not metadata.cve_id:
            issues.append("METADATA missing cve_id")
        if not metadata.name:
            issues.append("METADATA missing name")
        if not metadata.description:
            issues.append("METADATA missing description")
        if not metadata.mitre_attack or len(metadata.mitre_attack) == 0:
            issues.append("METADATA missing MITRE ATT&CK mappings")
        if not metadata.severity:
            issues.append("METADATA missing severity")
    
    return issues

def main():
    """Test all batch 3 modules."""
    console.print("\n[cyan]Testing Batch 3 Module Structure Compliance...[/cyan]\n")
    
    reg = ExploitRegistry()
    reg.load_all_modules()
    
    batch3_modules = [
        'cve_2018_1000402',
        'cve_2023_24422',
        'cve_2023_3519'
    ]
    
    all_passed = True
    
    for module_name in batch3_modules:
        console.print(f"[cyan]Testing {module_name}...[/cyan]")
        
        module = reg.get_module(module_name)
        if not module:
            console.print(f"[red]  FAIL: Module not loaded[/red]")
            all_passed = False
            continue
        
        metadata = reg.get_metadata(module_name)
        issues = test_module_structure(module_name, module, metadata)
        
        if issues:
            console.print(f"[red]  FAIL: Issues found:[/red]")
            for issue in issues:
                console.print(f"    - {issue}")
            all_passed = False
        else:
            console.print(f"[green]  PASS: All checks passed[/green]")
            if metadata:
                console.print(f"    CVE ID: {metadata.cve_id}")
                console.print(f"    Severity: {metadata.severity}")
                console.print(f"    MITRE: {', '.join(metadata.mitre_attack)}")
    
    console.print()
    if all_passed:
        console.print("[green][+] All Batch 3 modules passed structure validation![/green]")
        return 0
    else:
        console.print("[red][-] Some modules failed structure validation[/red]")
        return 1

if __name__ == '__main__':
    sys.exit(main())
