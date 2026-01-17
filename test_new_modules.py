#!/usr/bin/env python3
"""Test script for new JenkinsBreaker modules"""

import sys
sys.path.insert(0, 'JenkinsBreaker')

print("[*] Testing module imports...")

try:
    import jwt_breaker
    print("[PASS] jwt_breaker imported successfully")
except Exception as e:
    print(f"[FAIL] jwt_breaker import failed: {e}")

try:
    import plugin_fingerprint
    print("[PASS] plugin_fingerprint imported successfully")
except Exception as e:
    print(f"[FAIL] plugin_fingerprint import failed: {e}")

try:
    import persistence
    print("[PASS] persistence imported successfully")
except Exception as e:
    print(f"[FAIL] persistence import failed: {e}")

try:
    import tui
    print("[PASS] tui imported successfully")
except Exception as e:
    print(f"[FAIL] tui import failed: {e}")

try:
    import web_ui
    print("[PASS] web_ui imported successfully")
except Exception as e:
    print(f"[FAIL] web_ui import failed: {e}")

try:
    import jenkinsfuzzer
    print("[PASS] jenkinsfuzzer imported successfully")
except Exception as e:
    print(f"[FAIL] jenkinsfuzzer import failed: {e}")

print("\n[*] Testing basic module functionality...")

try:
    jb = jwt_breaker.JWTBreaker("http://localhost:8080")
    print("[PASS] JWTBreaker instance created")
except Exception as e:
    print(f"[FAIL] JWTBreaker instantiation failed: {e}")

try:
    pf = plugin_fingerprint.PluginFingerprint("http://localhost:8080")
    print("[PASS] PluginFingerprint instance created")
except Exception as e:
    print(f"[FAIL] PluginFingerprint instantiation failed: {e}")

try:
    pm = persistence.PersistenceManager("http://localhost:8080")
    print("[PASS] PersistenceManager instance created")
except Exception as e:
    print(f"[FAIL] PersistenceManager instantiation failed: {e}")

try:
    jf = jenkinsfuzzer.JenkinsFuzzer("http://localhost:8080")
    print("[PASS] JenkinsFuzzer instance created")
except Exception as e:
    print(f"[FAIL] JenkinsFuzzer instantiation failed: {e}")

print("\n[*] All tests completed")
