#!/usr/bin/env python3
"""Test CLI functionality without bootstrap"""
import os
import sys

os.environ["INSIDE_VENV"] = "1"

sys.path.insert(0, os.path.dirname(__file__))

from pathlib import Path
from decrypt import (
    scan_directory_recursive,
    parse_arguments,
    check_elevated_privileges,
    redact_secret,
    is_sensitive_credential
)

def test_cli_parsing():
    """Test argparse functionality"""
    print("[*] Testing CLI argument parsing...")
    
    test_args = [
        "decrypt.py",
        "--path", "/var/lib/jenkins",
        "--export-json", "output.json",
        "--reveal-secrets"
    ]
    
    original_argv = sys.argv
    sys.argv = test_args
    
    try:
        args = parse_arguments()
        assert args.path == "/var/lib/jenkins"
        assert args.export_json == "output.json"
        assert args.reveal_secrets == True
        print("[+] CLI parsing: PASS")
        return True
    except Exception as e:
        print(f"[-] CLI parsing: FAIL - {e}")
        return False
    finally:
        sys.argv = original_argv

def test_redaction():
    """Test secret redaction"""
    print("[*] Testing secret redaction...")
    
    test_secret = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(test_secret)
    
    if "***REDACTED***" in redacted and redacted != test_secret:
        print(f"[+] Redaction: PASS ({test_secret} -> {redacted})")
        return True
    else:
        print(f"[-] Redaction: FAIL")
        return False

def test_sensitive_detection():
    """Test sensitive credential detection"""
    print("[*] Testing sensitive credential detection...")
    
    test_cases = [
        ("AKIAIOSFODNN7EXAMPLE", True),
        ("my_secret_password", True),
        ("ghp_1234567890123456789012345678901234567890", True),
        ("regularvalue123", False),
    ]
    
    all_pass = True
    for secret, should_detect in test_cases:
        detected = is_sensitive_credential(secret)
        if detected == should_detect:
            print(f"  [+] '{secret[:20]}...' -> {detected} (correct)")
        else:
            print(f"  [-] '{secret[:20]}...' -> {detected} (expected {should_detect})")
            all_pass = False
    
    if all_pass:
        print("[+] Sensitive detection: PASS")
    else:
        print("[-] Sensitive detection: FAIL")
    
    return all_pass

def test_path_handling():
    """Test cross-platform path handling"""
    print("[*] Testing cross-platform path handling...")
    
    if sys.platform == "win32":
        test_path = Path("C:\\Windows\\System32")
        print(f"  Windows path: {test_path}")
    else:
        test_path = Path("/var/lib/jenkins")
        print(f"  Unix path: {test_path}")
    
    print(f"[+] Path handling: PASS (platform: {sys.platform})")
    return True

def main():
    print("=" * 60)
    print("Jenkins Credential Decryptor - CLI Test Suite")
    print("=" * 60)
    
    results = []
    results.append(("CLI Parsing", test_cli_parsing()))
    results.append(("Redaction", test_redaction()))
    results.append(("Sensitive Detection", test_sensitive_detection()))
    results.append(("Path Handling", test_path_handling()))
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {name:.<40} {status}")
    
    print("=" * 60)
    print(f"Total: {passed}/{total} tests passed")
    print("=" * 60)
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
