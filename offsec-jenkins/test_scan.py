#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

os.environ["INSIDE_VENV"] = "1"

from pathlib import Path
import tempfile
import shutil

def test_recursive_scan():
    """Test the recursive directory scanning function"""
    
    from decrypt import scan_directory_recursive
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        (tmppath / "credentials.xml").touch()
        (tmppath / "config.xml").touch()
        (tmppath / "jobs" / "test-job").mkdir(parents=True)
        (tmppath / "jobs" / "test-job" / "config.xml").touch()
        (tmppath / "users" / "admin").mkdir(parents=True)
        (tmppath / "users" / "admin" / "credentials.xml").touch()
        (tmppath / "random.xml").touch()
        (tmppath / "not-relevant.txt").touch()
        
        print(f"[*] Created test directory structure in {tmppath}")
        
        found_files = scan_directory_recursive(tmppath)
        
        print(f"[+] Found {len(found_files)} credential files:")
        for f in found_files:
            print(f"    - {f.relative_to(tmppath)}")
        
        expected_count = 4
        if len(found_files) == expected_count:
            print(f"\n[+] PASS: Found expected {expected_count} files")
            return True
        else:
            print(f"\n[-] FAIL: Expected {expected_count} files, found {len(found_files)}")
            return False

if __name__ == "__main__":
    success = test_recursive_scan()
    sys.exit(0 if success else 1)
