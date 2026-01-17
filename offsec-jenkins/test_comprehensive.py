#!/usr/bin/env python3
"""
Comprehensive test suite for offsec-jenkins Jenkins Credential Decryptor.
Validates all CLI flags, usage scenarios, and JenkinsBreaker integration.
"""

import subprocess
import sys
import json
import csv
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def run_test(name, cmd, expect_success=True, expect_output=None):
    """Run a single test command."""
    print(f"\n{Colors.BLUE}[TEST]{Colors.END} {name}")
    print(f"  Command: {cmd}")
    
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    success = (result.returncode == 0) if expect_success else (result.returncode != 0)
    
    if expect_output:
        for expected in expect_output:
            if expected not in result.stdout and expected not in result.stderr:
                success = False
                print(f"  {Colors.RED}[X] Missing expected output: {expected}{Colors.END}")
    
    if success:
        print(f"  {Colors.GREEN}[PASS]{Colors.END}")
    else:
        print(f"  {Colors.RED}[FAIL]{Colors.END}")
        if result.stdout:
            print(f"  STDOUT: {result.stdout[:200]}")
        if result.stderr:
            print(f"  STDERR: {result.stderr[:200]}")
    
    return success

def test_help_and_usage():
    """Test all help and usage flags."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing Help and Usage{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("--help flag", "python decrypt.py --help", True, 
         ["usage:", "Jenkins Credential Decryptor", "--path", "--export-json", "--reveal-secrets"]),
        
        ("-h flag", "python decrypt.py -h", True, 
         ["usage:", "Jenkins Credential Decryptor"]),
        
        ("No arguments shows help", "python decrypt.py", False, 
         ["Error:", "Must specify"]),
    ]
    
    results = []
    for test in tests:
        results.append(run_test(*test))
    
    return results

def test_basic_decryption():
    """Test basic decryption functionality."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing Basic Decryption{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("Decrypt with --path (redacted)", 
         "python decrypt.py --path test_fixtures", True,
         ["Loading confidentiality key", "***REDACTED***", "Found 3 secrets"]),
        
        ("Decrypt with --path (revealed)", 
         "python decrypt.py --path test_fixtures --reveal-secrets", True,
         ["admin", "AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefghijklmnopqrstuv"]),
        
        ("Decrypt with explicit files", 
         "python decrypt.py --key test_fixtures/secrets/master.key --secret test_fixtures/secrets/hudson.util.Secret --xml test_fixtures/credentials.xml --reveal-secrets", True,
         ["admin", "AKIAIOSFODNN7EXAMPLE"]),
        
        ("Dry-run mode", 
         "python decrypt.py --path test_fixtures --dry-run", True,
         ["[DRY RUN]", "not decrypted"]),
    ]
    
    results = []
    for test in tests:
        results.append(run_test(*test))
    
    return results

def test_export_functionality():
    """Test JSON and CSV export."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing Export Functionality{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("Export to JSON (redacted)", 
         "python decrypt.py --path test_fixtures --export-json outputs/test_redacted.json --force", True,
         ["Exported", "test_redacted.json"]),
        
        ("Export to JSON (revealed)", 
         "python decrypt.py --path test_fixtures --export-json outputs/test_revealed.json --reveal-secrets --force", True,
         ["Exported", "test_revealed.json"]),
        
        ("Export to CSV", 
         "python decrypt.py --path test_fixtures --export-csv outputs/test.csv --reveal-secrets --force", True,
         ["Exported", "test.csv"]),
        
        ("JSON format validation", 
         "", True, None),  # Custom validation below
        
        ("CSV format validation", 
         "", True, None),  # Custom validation below
    ]
    
    results = []
    for i, test in enumerate(tests):
        if i == 3:  # JSON validation
            try:
                with open("outputs/test_revealed.json", 'r') as f:
                    data = json.load(f)
                assert isinstance(data, list)
                assert len(data) > 0
                assert 'file' in data[0]
                assert 'encrypted' in data[0]
                assert 'decrypted' in data[0]
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} JSON format validation")
                print(f"  {Colors.GREEN}[PASS]{Colors.END}")
                results.append(True)
            except Exception as e:
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} JSON format validation")
                print(f"  {Colors.RED}[FAIL]: {e}{Colors.END}")
                results.append(False)
        elif i == 4:  # CSV validation
            try:
                with open("outputs/test.csv", 'r') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                assert len(rows) > 0
                assert 'file' in rows[0]
                assert 'encrypted' in rows[0]
                assert 'decrypted' in rows[0]
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} CSV format validation")
                print(f"  {Colors.GREEN}[PASS]{Colors.END}")
                results.append(True)
            except Exception as e:
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} CSV format validation")
                print(f"  {Colors.RED}[FAIL]: {e}{Colors.END}")
                results.append(False)
        else:
            results.append(run_test(*test))
    
    return results

def test_security_controls():
    """Test security and redaction controls."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing Security Controls{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("Default redaction active", 
         "python decrypt.py --path test_fixtures", True,
         ["***REDACTED***", "Secrets are redacted by default"]),
        
        ("Sensitive credential detection (AWS)", 
         "python decrypt.py --path test_fixtures --reveal-secrets", True,
         ["AKIAIOSFODNN7EXAMPLE"]),
        
        ("Sensitive credential detection (GitHub)", 
         "python decrypt.py --path test_fixtures --reveal-secrets", True,
         ["ghp_1234567890abcdefghijklmnopqrstuv"]),
        
        ("File overwrite protection", 
         "python decrypt.py --path test_fixtures --export-json outputs/test.json", False,
         ["already exists", "Use --force"]),
        
        ("Force overwrite", 
         "python decrypt.py --path test_fixtures --export-json outputs/test.json --force", True,
         ["Exported"]),
    ]
    
    results = []
    for test in tests:
        results.append(run_test(*test))
    
    return results

def test_error_handling():
    """Test error handling and edge cases."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing Error Handling{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("Missing master.key", 
         "python decrypt.py --key nonexistent.key --secret test_fixtures/secrets/hudson.util.Secret", False,
         ["Error", "not found"]),
        
        ("Missing hudson.util.Secret", 
         "python decrypt.py --key test_fixtures/secrets/master.key --secret nonexistent", False,
         ["Error", "not found"]),
        
        ("Invalid path", 
         "python decrypt.py --path /nonexistent/path", False,
         ["Error", "not found"]),
        
        ("Empty directory", 
         "python decrypt.py --scan-dir outputs --key test_fixtures/secrets/master.key --secret test_fixtures/secrets/hudson.util.Secret", True,
         ["Found 0 credential files"]),
    ]
    
    results = []
    for test in tests:
        results.append(run_test(*test))
    
    return results

def test_jenkinsbreaker_integration():
    """Test JenkinsBreaker workflow integration."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing JenkinsBreaker Integration{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    print("\n  Scenario: Post-exploitation after CVE-2024-23897")
    print("  1. CVE extracts master.key and hudson.util.Secret")
    print("  2. CVE extracts credentials.xml")
    print("  3. offsec-jenkins decrypts credentials")
    
    tests = [
        ("Decrypt credentials.xml with keys", 
         "python decrypt.py --key test_fixtures/secrets/master.key --secret test_fixtures/secrets/hudson.util.Secret --xml test_fixtures/credentials.xml --reveal-secrets", True,
         ["admin", "AKIAIOSFODNN7EXAMPLE", "ghp_"]),
        
        ("Export for JenkinsBreaker consumption", 
         "python decrypt.py --path test_fixtures --export-json outputs/jenkins_secrets.json --reveal-secrets --force", True,
         ["Exported", "jenkins_secrets.json"]),
        
        ("Validate JSON structure matches JenkinsBreaker expectations", 
         "", True, None),  # Custom validation
    ]
    
    results = []
    for i, test in enumerate(tests):
        if i == 2:  # JenkinsBreaker format validation
            try:
                with open("outputs/jenkins_secrets.json", 'r') as f:
                    data = json.load(f)
                
                # Validate structure matches JenkinsBreaker expectations
                assert isinstance(data, list), "Should be a list of secrets"
                assert len(data) > 0, "Should have secrets"
                
                for secret in data:
                    assert 'file' in secret, "Should have 'file' field"
                    assert 'encrypted' in secret, "Should have 'encrypted' field"
                    assert 'decrypted' in secret, "Should have 'decrypted' field"
                    assert 'display' in secret, "Should have 'display' field"
                
                # Check for sensitive credentials
                decrypted_values = [s['decrypted'] for s in data]
                has_aws = any('AKIA' in v for v in decrypted_values)
                has_github = any('ghp_' in v for v in decrypted_values)
                
                assert has_aws, "Should extract AWS credentials"
                assert has_github, "Should extract GitHub tokens"
                
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} Validate JSON structure matches JenkinsBreaker expectations")
                print(f"  {Colors.GREEN}[PASS]{Colors.END}")
                print(f"    - Found {len(data)} secrets")
                print(f"    - AWS credentials: {'Yes' if has_aws else 'No'}")
                print(f"    - GitHub tokens: {'Yes' if has_github else 'No'}")
                results.append(True)
            except Exception as e:
                print(f"\n{Colors.BLUE}[TEST]{Colors.END} Validate JSON structure")
                print(f"  {Colors.RED}[FAIL]: {e}{Colors.END}")
                results.append(False)
        else:
            results.append(run_test(*test))
    
    return results

def test_all_cli_flags():
    """Test all CLI flags and combinations."""
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Testing All CLI Flags{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    
    tests = [
        ("--path", "python decrypt.py --path test_fixtures", True, ["Loading"]),
        ("--key + --secret + --xml", "python decrypt.py --key test_fixtures/secrets/master.key --secret test_fixtures/secrets/hudson.util.Secret --xml test_fixtures/credentials.xml", True, ["Loading"]),
        ("--scan-dir", "python decrypt.py --scan-dir test_fixtures --key test_fixtures/secrets/master.key --secret test_fixtures/secrets/hudson.util.Secret", True, ["Scanning"]),
        ("--export-json", "python decrypt.py --path test_fixtures --export-json outputs/test_flag.json --force", True, ["Exported"]),
        ("--export-csv", "python decrypt.py --path test_fixtures --export-csv outputs/test_flag.csv --force", True, ["Exported"]),
        ("--dry-run", "python decrypt.py --path test_fixtures --dry-run", True, ["[DRY RUN]"]),
        ("--reveal-secrets", "python decrypt.py --path test_fixtures --reveal-secrets", True, ["admin"]),
        ("--force", "python decrypt.py --path test_fixtures --export-json outputs/test_flag.json --force", True, ["Exported"]),
        ("Multiple flags combined", "python decrypt.py --path test_fixtures --export-json outputs/combined.json --reveal-secrets --force", True, ["Exported"]),
    ]
    
    results = []
    for test in tests:
        results.append(run_test(*test))
    
    return results

def print_summary(all_results):
    """Print test summary."""
    total = sum(len(r) for r in all_results)
    passed = sum(sum(r) for r in all_results)
    failed = total - passed
    
    print(f"\n{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}TEST SUMMARY{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"\nTotal tests: {total}")
    print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
    print(f"{Colors.RED}Failed: {failed}{Colors.END}")
    print(f"Success rate: {(passed/total*100):.1f}%")
    
    if failed == 0:
        print(f"\n{Colors.GREEN}[SUCCESS] ALL TESTS PASSED!{Colors.END}")
        print(f"\n{Colors.GREEN}offsec-jenkins is production-ready for:{Colors.END}")
        print(f"  - Post-exploitation after Jenkins CVE exploitation")
        print(f"  - JenkinsBreaker integration")
        print(f"  - CTF competitions")
        print(f"  - Red team engagements")
        return 0
    else:
        print(f"\n{Colors.RED}[FAILED] SOME TESTS FAILED{Colors.END}")
        return 1

if __name__ == "__main__":
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}COMPREHENSIVE TEST SUITE - offsec-jenkins{Colors.END}")
    print(f"{Colors.YELLOW}{'='*80}{Colors.END}")
    print("\nThis test suite validates:")
    print("  - All CLI flags and usage patterns")
    print("  - JenkinsBreaker workflow integration")
    print("  - Security controls and redaction")
    print("  - Export functionality (JSON/CSV)")
    print("  - Error handling")
    
    all_results = []
    
    try:
        all_results.append(test_help_and_usage())
        all_results.append(test_basic_decryption())
        all_results.append(test_export_functionality())
        all_results.append(test_security_controls())
        all_results.append(test_error_handling())
        all_results.append(test_jenkinsbreaker_integration())
        all_results.append(test_all_cli_flags())
        
        exit_code = print_summary(all_results)
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Tests interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n{Colors.RED}Test suite error: {e}{Colors.END}")
        sys.exit(1)
