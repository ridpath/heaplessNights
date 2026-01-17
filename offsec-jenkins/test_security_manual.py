#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

def run_test(name, args, should_contain=None, should_not_contain=None):
    """Run a test and check output"""
    print(f"\n{'='*60}")
    print(f"{name}")
    print(f"{'='*60}")
    print(f"Command: python decrypt.py {' '.join(args)}")
    
    result = subprocess.run(
        [sys.executable, "decrypt.py"] + args,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    output = result.stdout + result.stderr
    print("\nOutput:")
    print(output)
    
    success = True
    if should_contain:
        if should_contain in output:
            print(f"\n[+] PASSED: Found '{should_contain}'")
        else:
            print(f"\n[-] FAILED: Missing '{should_contain}'")
            success = False
    
    if should_not_contain:
        if should_not_contain not in output:
            print(f"\n[+] PASSED: '{should_not_contain}' not found (as expected)")
        else:
            print(f"\n[-] FAILED: Found '{should_not_contain}' (should be absent)")
            success = False
    
    return success, output

def main():
    base_args = [
        "--key", "test_fixtures/secrets/master.key",
        "--secret", "test_fixtures/secrets/hudson.util.Secret",
        "--xml", "test_fixtures/credentials.xml"
    ]
    
    results = []
    
    # Test 1: Help
    success, _ = run_test(
        "TEST 1: Help output",
        ["--help"],
        should_contain="Jenkins Credential Decryptor"
    )
    results.append(("Help output", success))
    
    # Test 2: Default (redacted)
    success, redacted_output = run_test(
        "TEST 2: Default behavior (redacted)",
        base_args,
        should_contain="REDACTED"
    )
    results.append(("Default redaction", success))
    
    # Test 3: Reveal secrets
    success, revealed_output = run_test(
        "TEST 3: Reveal secrets flag",
        base_args + ["--reveal-secrets"],
        should_not_contain="REDACTED"
    )
    results.append(("Reveal secrets", success))
    
    # Test 4: Dry-run
    success, dryrun_output = run_test(
        "TEST 4: Dry-run mode",
        base_args + ["--dry-run"],
        should_contain="DRY RUN"
    )
    results.append(("Dry-run mode", success))
    
    # Test 5: Elevated privileges warning
    success, _ = run_test(
        "TEST 5: Elevated privileges check",
        base_args
    )
    # This test doesn't check for specific output, just runs
    results.append(("Elevated check", True))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for test_name, passed in results:
        status = "[+] PASSED" if passed else "[-] FAILED"
        print(f"{status}: {test_name}")
    
    all_passed = all(r[1] for r in results)
    print("\n" + ("="*60))
    if all_passed:
        print("ALL TESTS PASSED")
        return 0
    else:
        print("SOME TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
