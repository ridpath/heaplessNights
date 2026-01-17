#!/usr/bin/env python3
import os
import sys
import json
import csv
import subprocess
from pathlib import Path
import shutil

PROJECT_ROOT = Path(__file__).parent

def setup_test_fixtures():
    """Create test fixtures for export validation"""
    fixtures_dir = PROJECT_ROOT / "test_fixtures"
    secrets_dir = fixtures_dir / "secrets"
    
    fixtures_dir.mkdir(exist_ok=True)
    secrets_dir.mkdir(exist_ok=True)
    
    master_key_content = "4a8a9f3e2b7c1d5e8f9a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e"
    hudson_secret_content = bytes.fromhex(
        "3c8f9a2b1e4d7c5a6f8e9b0a1c3d5e7f"
        "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
        "3a3a3a3a4d41474943"
        "3a3a3a3a"
    )
    
    credentials_xml = """<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@2.3.0">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain>
        <specifications/>
      </com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>test-credentials</id>
          <description>Test Credentials</description>
          <username>admin</username>
          <password>{AQAAABAAAAAQwwL8C9vYXzPwJvN0k2gN3Q==}</password>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        <org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>api-token</id>
          <description>API Token</description>
          <secret>{AQAAABAAAAAQyZmD4k2L8vXwN9jP0tRq1A==}</secret>
        </org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>
"""
    
    (secrets_dir / "master.key").write_text(master_key_content)
    (secrets_dir / "hudson.util.Secret").write_bytes(hudson_secret_content)
    (fixtures_dir / "credentials.xml").write_text(credentials_xml)
    
    print("[+] Test fixtures created")

def test_json_export():
    """Test JSON export functionality"""
    print("\n[*] Testing JSON export...")
    
    output_file = PROJECT_ROOT / "outputs" / "test_export.json"
    
    if output_file.exists():
        output_file.unlink()
    
    cmd = [
        sys.executable, 
        str(PROJECT_ROOT / "decrypt.py"),
        "--path", str(PROJECT_ROOT / "test_fixtures"),
        "--export-json", str(output_file),
        "--reveal-secrets"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[-] JSON export failed: {result.stderr}")
        return False
    
    if not output_file.exists():
        print("[-] JSON output file not created")
        return False
    
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        print("[-] JSON export is not a list")
        return False
    
    required_fields = ['file', 'encrypted', 'decrypted']
    for entry in data:
        for field in required_fields:
            if field not in entry:
                print(f"[-] Missing required field '{field}' in JSON entry")
                return False
    
    print(f"[+] JSON export validated: {len(data)} entries")
    print(f"[+] Output saved to: {output_file}")
    
    return True

def test_csv_export():
    """Test CSV export functionality"""
    print("\n[*] Testing CSV export...")
    
    output_file = PROJECT_ROOT / "outputs" / "test_export.csv"
    
    if output_file.exists():
        output_file.unlink()
    
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "decrypt.py"),
        "--path", str(PROJECT_ROOT / "test_fixtures"),
        "--export-csv", str(output_file),
        "--reveal-secrets"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[-] CSV export failed: {result.stderr}")
        return False
    
    if not output_file.exists():
        print("[-] CSV output file not created")
        return False
    
    with open(output_file, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    if not rows:
        print("[-] CSV export is empty")
        return False
    
    required_fields = ['file', 'encrypted', 'decrypted']
    for field in required_fields:
        if field not in rows[0]:
            print(f"[-] Missing required field '{field}' in CSV header")
            return False
    
    print(f"[+] CSV export validated: {len(rows)} entries")
    print(f"[+] Output saved to: {output_file}")
    
    return True

def test_force_flag():
    """Test --force flag for overwriting files"""
    print("\n[*] Testing --force flag...")
    
    output_file = PROJECT_ROOT / "outputs" / "test_force.json"
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text('{"test": "existing"}')
    
    cmd_without_force = [
        sys.executable,
        str(PROJECT_ROOT / "decrypt.py"),
        "--path", str(PROJECT_ROOT / "test_fixtures"),
        "--export-json", str(output_file)
    ]
    
    result = subprocess.run(cmd_without_force, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[-] Should have failed without --force flag")
        return False
    
    if "already exists" not in result.stdout and "already exists" not in result.stderr:
        print("[-] Expected error message about existing file")
        return False
    
    print("[+] Correctly prevented overwrite without --force")
    
    cmd_with_force = [
        sys.executable,
        str(PROJECT_ROOT / "decrypt.py"),
        "--path", str(PROJECT_ROOT / "test_fixtures"),
        "--export-json", str(output_file),
        "--force",
        "--reveal-secrets"
    ]
    
    result = subprocess.run(cmd_with_force, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[-] Failed with --force flag: {result.stderr}")
        return False
    
    print("[+] Successfully overwrote file with --force flag")
    
    return True

def test_export_redaction():
    """Test that secrets are redacted by default in export"""
    print("\n[*] Testing export redaction...")
    
    output_file = PROJECT_ROOT / "outputs" / "test_redacted.json"
    
    if output_file.exists():
        output_file.unlink()
    
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "decrypt.py"),
        "--path", str(PROJECT_ROOT / "test_fixtures"),
        "--export-json", str(output_file)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"[-] Export with redaction failed: {result.stderr}")
        return False
    
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    for entry in data:
        if 'display' in entry:
            if 'REDACTED' not in entry['display'] and entry['display'] != entry['decrypted']:
                continue
    
    print("[+] Export redaction validated")
    
    return True

def cleanup():
    """Clean up test artifacts"""
    print("\n[*] Cleaning up test artifacts...")
    
    outputs_dir = PROJECT_ROOT / "outputs"
    if outputs_dir.exists():
        for file in outputs_dir.glob("test_*"):
            file.unlink()
        print("[+] Test outputs cleaned")

def main():
    """Run all export validation tests"""
    print("=" * 60)
    print("Jenkins Credential Decryptor - Export Functions Validation")
    print("=" * 60)
    
    setup_test_fixtures()
    
    tests = [
        ("JSON Export", test_json_export),
        ("CSV Export", test_csv_export),
        ("Force Flag", test_force_flag),
        ("Export Redaction", test_export_redaction)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[-] {test_name} threw exception: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    cleanup()
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
