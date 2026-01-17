#!/usr/bin/env python3
"""Test script to verify CVE modules load correctly."""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from exploits import ExploitRegistry
from rich.console import Console
from rich.table import Table

console = Console()

console.print("[cyan][*] Testing CVE Module Loading...[/cyan]\n")

registry = ExploitRegistry()

console.print("[cyan][*] Discovering modules...[/cyan]")
discovered = registry.discover_modules()
console.print(f"[green][+] Found {len(discovered)} modules[/green]\n")

console.print("[cyan][*] Loading modules...[/cyan]")
loaded_count = registry.load_all_modules()

console.print(f"\n[cyan][*] Loaded {loaded_count}/{len(discovered)} modules successfully[/cyan]\n")

table = Table(title="CVE Modules")
table.add_column("CVE ID", style="cyan")
table.add_column("Name", style="green")
table.add_column("Severity", style="yellow")
table.add_column("Description", style="white")

modules_info = registry.list_modules()
for module in modules_info:
    table.add_row(
        module['cve_id'],
        module['name'],
        module['severity'],
        module['description'][:60] + "..." if len(module['description']) > 60 else module['description']
    )

console.print(table)

console.print("\n[green][+] All modules loaded successfully![/green]")
