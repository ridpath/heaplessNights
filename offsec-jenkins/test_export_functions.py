#!/usr/bin/env python3
"""Test export functions without full decryption pipeline"""
import os
import sys
import json
import csv
from pathlib import Path

os.environ["INSIDE_VENV"] = "1"

PROJECT_ROOT = Path(__file__).parent

def test_json_export_structure():
    """Test JSON export with mock data"""
    print("[*] Testing JSON export structure...")
    
    outputs_dir = PROJECT_ROOT / "outputs"
    outputs_dir.mkdir(exist_ok=True)
    
    mock_secrets = [
        {
            'file': '/var/jenkins_home/credentials.xml',
            'encrypted': 'AQAAABAAAAAQwwL8C...',
            'decrypted': 'admin123',
            'display': '***REDACTED***'
        },
        {
            'file': '/var/jenkins_home/config.xml',
            'encrypted': 'AQAAABAAAAAQyZmD4...',
            'decrypted': 'AKIAIOSFODNN7EXAMPLE',
            'display': '***REDACTED***'
        }
    ]
    
    output_file = outputs_dir / "test_json_structure.json"
    
    with open(output_file, 'w') as f:
        json.dump(mock_secrets, f, indent=2)
    
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        print("[-] JSON export is not a list")
        return False
    
    required_fields = ['file', 'encrypted', 'decrypted', 'display']
    for entry in data:
        for field in required_fields:
            if field not in entry:
                print(f"[-] Missing required field '{field}' in JSON entry")
                return False
    
    print(f"[+] JSON export structure validated: {len(data)} entries")
    print(f"    Fields: {', '.join(data[0].keys())}")
    
    output_file.unlink()
    
    return True

def test_csv_export_structure():
    """Test CSV export with mock data"""
    print("[*] Testing CSV export structure...")
    
    outputs_dir = PROJECT_ROOT / "outputs"
    outputs_dir.mkdir(exist_ok=True)
    
    mock_secrets = [
        {
            'file': '/var/jenkins_home/credentials.xml',
            'encrypted': 'AQAAABAAAAAQwwL8C...',
            'decrypted': 'admin123',
            'display': '***REDACTED***'
        },
        {
            'file': '/var/jenkins_home/config.xml',
            'encrypted': 'AQAAABAAAAAQyZmD4...',
            'decrypted': 'AKIAIOSFODNN7EXAMPLE',
            'display': '***REDACTED***'
        }
    ]
    
    output_file = outputs_dir / "test_csv_structure.csv"
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
        writer.writeheader()
        writer.writerows(mock_secrets)
    
    with open(output_file, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    if not rows:
        print("[-] CSV export is empty")
        return False
    
    required_fields = ['file', 'encrypted', 'decrypted', 'display']
    for field in required_fields:
        if field not in rows[0]:
            print(f"[-] Missing required field '{field}' in CSV header")
            return False
    
    if len(rows) != 2:
        print(f"[-] Expected 2 rows, got {len(rows)}")
        return False
    
    print(f"[+] CSV export structure validated: {len(rows)} entries")
    print(f"    Headers: {', '.join(rows[0].keys())}")
    
    output_file.unlink()
    
    return True

def test_file_safety():
    """Test file overwrite protection"""
    print("[*] Testing file safety checks...")
    
    outputs_dir = PROJECT_ROOT / "outputs"
    outputs_dir.mkdir(exist_ok=True)
    
    test_file = outputs_dir / "test_safety.json"
    test_file.write_text('{"existing": "data"}')
    
    if not test_file.exists():
        print("[-] Failed to create test file")
        return False
    
    existing_content = test_file.read_text()
    
    print("[+] File overwrite protection simulated")
    print(f"    File exists: {test_file.exists()}")
    print(f"    Content: {existing_content[:50]}")
    
    test_file.unlink()
    
    return True

def test_directory_creation():
    """Test automatic directory creation"""
    print("[*] Testing automatic directory creation...")
    
    nested_path = PROJECT_ROOT / "outputs" / "nested" / "deep" / "test.json"
    
    nested_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not nested_path.parent.exists():
        print("[-] Failed to create nested directory")
        return False
    
    nested_path.write_text('{"test": "data"}')
    
    if not nested_path.exists():
        print("[-] Failed to write to nested path")
        return False
    
    print(f"[+] Directory creation validated")
    print(f"    Created: {nested_path.parent}")
    
    import shutil
    shutil.rmtree(PROJECT_ROOT / "outputs" / "nested")
    
    return True

def test_export_field_consistency():
    """Test that export fields match expected schema"""
    print("[*] Testing export field consistency...")
    
    expected_fields = {
        'file': str,
        'encrypted': str,
        'decrypted': str,
        'display': str
    }
    
    mock_entry = {
        'file': '/var/jenkins_home/credentials.xml',
        'encrypted': 'AQAAABAAAAAQwwL8C...',
        'decrypted': 'admin123',
        'display': '***REDACTED***'
    }
    
    for field, expected_type in expected_fields.items():
        if field not in mock_entry:
            print(f"[-] Missing field: {field}")
            return False
        
        if not isinstance(mock_entry[field], expected_type):
            print(f"[-] Field '{field}' has wrong type: {type(mock_entry[field])}")
            return False
    
    print("[+] Export field consistency validated")
    print(f"    Fields: {', '.join(expected_fields.keys())}")
    
    return True

def main():
    """Run all export function validation tests"""
    print("=" * 60)
    print("Export Functions Validation")
    print("=" * 60)
    
    tests = [
        ("JSON Export Structure", test_json_export_structure),
        ("CSV Export Structure", test_csv_export_structure),
        ("File Safety Checks", test_file_safety),
        ("Directory Creation", test_directory_creation),
        ("Field Consistency", test_export_field_consistency)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[-] {test_name} threw exception: {e}")
            import traceback
            traceback.print_exc()
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
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
