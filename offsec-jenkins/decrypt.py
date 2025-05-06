#!/usr/bin/env python3
import os
import sys
import subprocess

# --- Auto Virtualenv Bootstrapping ---
def bootstrap_virtualenv():
    venv_path = os.path.join(os.path.dirname(__file__), ".venv")  # Path to local virtualenv
    python_bin = os.path.join(venv_path, "bin", "python")         # Python binary inside venv

    # Re-launch inside venv if not already inside
    if sys.executable != python_bin and not os.environ.get("INSIDE_VENV"):
        if not os.path.exists(python_bin):
            print("[*] Setting up virtualenv...")
            subprocess.check_call(["python3", "-m", "venv", venv_path])
        print("[*] Installing pycryptodome...")
        subprocess.check_call([python_bin, "-m", "pip", "install", "--upgrade", "pip", "pycryptodome"])
        print("[*] Re-launching script inside virtualenv...")
        os.execve(python_bin, [python_bin] + sys.argv, dict(os.environ, INSIDE_VENV="1"))

bootstrap_virtualenv()

# --- Jenkins Decryption Logic ---
import re
import base64
from hashlib import sha256
from Crypto.Cipher import AES
import os.path

# Fields in Jenkins XML likely to contain encrypted secrets
secret_title_list = [
    'apiToken', 'password', 'privateKey', 'passphrase',
    'secret', 'secretId', 'value', 'defaultValue'
]

# Magic byte marker used to validate decrypted output
decryption_magic = b'::::MAGIC::::'

# Print usage instructions
def usage():
    print('Usage:')
    print('\t' + os.path.basename(sys.argv[0]) + ' <jenkins_base_path>')
    print('\t' + os.path.basename(sys.argv[0]) + ' <master.key> <hudson.util.Secret> [credentials.xml]')
    print('\t' + os.path.basename(sys.argv[0]) + ' -i <path> (interactive mode)')
    sys.exit(1)

# Load and return Jenkins confidentiality key from master.key and hudson.util.Secret
def get_confidentiality_key(master_key_path, hudson_secret_path):
    with open(master_key_path, 'r') as f:
        master_key = f.read().encode('utf-8')
    with open(hudson_secret_path, 'rb') as f:
        hudson_secret = f.read()
    # Sanitize potential trailing newlines
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

# Decrypt all secrets found in a Jenkins credentials.xml file
def decrypt_credentials_file(credentials_file, confidentiality_key):
    with open(credentials_file, 'r') as f:
        data = f.read()
    secrets = []
    for secret_title in secret_title_list:
        secrets += re.findall(secret_title + r'>\{?(.*?)\}?<\/' + secret_title, data)
    secrets += re.findall(r'>{([a-zA-Z0-9=+/]*)}<\/', data)  # fallback catch-all
    secrets = list(set(secrets))  # remove duplicates
    for secret in secrets:
        try:
            decrypted_secret = decrypt_secret(secret, confidentiality_key)
            if decrypted_secret != b'':
                print(decrypted_secret.decode('utf-8'))
        except Exception as e:
            print("Error:", e)

# Prompt user for secrets and decrypt them interactively
def run_interactive_mode(confidentiality_key):
    while True:
        secret = input('Encrypted secret: ').strip()
        if not secret:
            continue
        try:
            decrypted_secret = decrypt_secret(secret, confidentiality_key)
            print(decrypted_secret.decode('utf-8'))
        except Exception as e:
            print(e)

# --- Argument Handling ---
credentials_file = ''

# Check argument structure
if len(sys.argv) > 4 or len(sys.argv) < 2:
    usage()

# Interactive mode: derive paths from base
if sys.argv[1] == '-i':
    base_path = sys.argv[2]
    master_key_file = base_path + '/secrets/master.key'
    hudson_secret_file = base_path + '/secrets/hudson.util.Secret'
# Directory mode: derive files from standard structure
elif len(sys.argv) == 2:
    base_path = sys.argv[1]
    credentials_file = base_path + '/credentials.xml'
    master_key_file = base_path + '/secrets/master.key'
    hudson_secret_file = base_path + '/secrets/hudson.util.Secret'
# Explicit file mode
else:
    master_key_file = sys.argv[1]
    hudson_secret_file = sys.argv[2]
    if len(sys.argv) == 4:
        credentials_file = sys.argv[3]

# Validate required files exist
if not os.path.exists(master_key_file) or not os.path.exists(hudson_secret_file):
    print("Error: Could not find key files.")
    sys.exit(1)

# Perform decryption logic
confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
if not confidentiality_key:
    print('Failed to decrypt confidentiality key')
    sys.exit(1)

# Run in file or interactive mode
if credentials_file:
    decrypt_credentials_file(credentials_file, confidentiality_key)
else:
    run_interactive_mode(confidentiality_key)
