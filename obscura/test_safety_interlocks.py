#!/usr/bin/env python3
"""
Test script for Obscura safety interlocks.
Validates:
- OBSCURA_RF_LOCK environment variable enforcement
- --override-safety flag functionality  
- --dry-run mode activation
- Faraday cage warnings
- Exit behavior without RF_LOCK
"""

import os
import sys
import subprocess
from pathlib import Path

def run_obscura_test(description, env_vars=None, args=None, expect_exit_code=0):
    """Run obscura CLI with given environment and arguments."""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"{'='*60}")
    
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)
        print(f"Environment: {env_vars}")
    
    cmd = [sys.executable, "-m", "obscura.cli"]
    if args:
        cmd.extend(args)
        print(f"Arguments: {' '.join(args)}")
    
    print(f"Command: {' '.join(cmd)}")
    print("-" * 60)
    
    result = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True
    )
    
    print("STDOUT:")
    print(result.stdout)
    
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    print(f"\nExit Code: {result.returncode} (expected: {expect_exit_code})")
    
    success = result.returncode == expect_exit_code
    status = "[PASS]" if success else "[FAIL]"
    print(f"\n{status}")
    
    return success, result

def main():
    """Run all safety interlock tests."""
    print("=" * 60)
    print("Obscura Safety Interlock Test Suite")
    print("=" * 60)
    
    tests = []
    
    # Test 1: No RF_LOCK, should fail with exit code 1
    success, result = run_obscura_test(
        "No RF_LOCK environment variable (should fail)",
        env_vars={"OBSCURA_RF_LOCK": "0"},
        args=["--list-attacks"],
        expect_exit_code=1
    )
    tests.append(("No RF_LOCK enforcement", success))
    assert "[ERROR] RF safety interlock not set" in result.stdout, "Missing RF_LOCK error message"
    assert "Faraday cage" in result.stdout, "Missing Faraday cage warning"
    
    # Test 2: RF_LOCK not set in env (implicitly 0), should fail
    success, result = run_obscura_test(
        "RF_LOCK not in environment (should fail)",
        env_vars={k: v for k, v in os.environ.items() if k != "OBSCURA_RF_LOCK"},
        args=["--list-attacks"],
        expect_exit_code=1
    )
    tests.append(("RF_LOCK unset enforcement", success))
    
    # Test 3: RF_LOCK=1, should succeed
    success, result = run_obscura_test(
        "RF_LOCK=1 (should succeed)",
        env_vars={"OBSCURA_RF_LOCK": "1"},
        args=["--list-attacks"],
        expect_exit_code=0
    )
    tests.append(("RF_LOCK=1 allows execution", success))
    
    # Test 4: No RF_LOCK but --override-safety, should succeed with warning
    success, result = run_obscura_test(
        "No RF_LOCK but --override-safety (should succeed)",
        env_vars={"OBSCURA_RF_LOCK": "0"},
        args=["--override-safety", "--list-attacks"],
        expect_exit_code=0
    )
    tests.append(("--override-safety bypass", success))
    assert "[WARNING] Safety interlock bypassed" in result.stdout, "Missing override warning"
    
    # Test 5: --dry-run mode (verify it doesn't break with list-attacks)
    success, result = run_obscura_test(
        "--dry-run mode with --list-attacks (should succeed)",
        env_vars={"OBSCURA_RF_LOCK": "1"},
        args=["--dry-run", "--list-attacks"],
        expect_exit_code=0
    )
    tests.append(("--dry-run mode compatibility", success))
    
    # Test 6: Export mode (does not require RF_LOCK check bypass)
    success, result = run_obscura_test(
        "--export without RF_LOCK (should fail)",
        env_vars={"OBSCURA_RF_LOCK": "0"},
        args=["--export", "test_graph.json"],
        expect_exit_code=1
    )
    tests.append(("Export without RF_LOCK fails", success))
    
    # Test 7: Export with RF_LOCK
    success, result = run_obscura_test(
        "--export with RF_LOCK=1 (should succeed)",
        env_vars={"OBSCURA_RF_LOCK": "1"},
        args=["--export", "test_graph.json"],
        expect_exit_code=0
    )
    tests.append(("Export with RF_LOCK", success))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, success in tests if success)
    total = len(tests)
    
    for test_name, success in tests:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status}: {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    # Cleanup
    if os.path.exists("test_graph.json"):
        os.remove("test_graph.json")
        print("\n[*] Cleaned up test artifacts")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
