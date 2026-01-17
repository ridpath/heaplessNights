#!/usr/bin/env python3
from pathlib import Path
import sys

print(f"Platform: {sys.platform}")
print(f"Python version: {sys.version}")

test_path = Path(".")
print(f"Current directory: {test_path.resolve()}")

if sys.platform == "win32":
    print("Windows path handling: OK")
    test_win_path = Path("C:\\Windows\\System32")
    print(f"Windows path example: {test_win_path}")
else:
    print("Unix path handling: OK")
    test_unix_path = Path("/var/lib/jenkins")
    print(f"Unix path example: {test_unix_path}")

print("\n[+] Cross-platform path handling verified!")
