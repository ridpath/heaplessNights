#!/usr/bin/env python3
from pathlib import Path

fixtures_dir = Path(__file__).parent / "test_fixtures" / "secrets"

master_key_file = fixtures_dir / "master.key"
hudson_secret_file = fixtures_dir / "hudson.util.Secret"

print("Master Key:")
with open(master_key_file, 'rb') as f:
    mk = f.read()
    print(f"  Length: {len(mk)} bytes")
    print(f"  Hex: {mk.hex()}")
    print(f"  ASCII: {mk}")

print("\nHudson Secret:")
with open(hudson_secret_file, 'rb') as f:
    hs = f.read()
    print(f"  Length: {len(hs)} bytes")
    print(f"  Hex: {hs.hex()}")
    print(f"  Is multiple of 16: {len(hs) % 16 == 0}")
