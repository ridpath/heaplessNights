#!/usr/bin/env python3
"""Generate valid test fixtures for Jenkins credential decryptor"""
import os
from pathlib import Path
from hashlib import sha256
from Crypto.Cipher import AES

# Test master key (hex string, 64 chars = 32 bytes when interpreted as hex ASCII)
MASTER_KEY_HEX = "4a8a9f3e2b7c1d5e8f9a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e"

# Magic marker used by Jenkins
MAGIC = b'::::MAGIC::::'

def generate_hudson_secret(master_key_hex):
    """Generate a valid hudson.util.Secret file"""
    # Master key as bytes (ASCII hex string)
    master_key = master_key_hex.encode('utf-8')
    
    # Derive AES-128 key from master key
    derived_key = sha256(master_key).digest()[:16]
    
    # Create the confidentiality key (16 bytes) + MAGIC marker
    confidentiality_key = os.urandom(16)
    plaintext = confidentiality_key + MAGIC
    
    # Pad to 16-byte boundary for AES ECB
    padding_needed = 16 - (len(plaintext) % 16)
    if padding_needed < 16:
        plaintext += b'\x00' * padding_needed
    
    # Encrypt with AES ECB
    cipher = AES.new(derived_key, AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext)
    
    return encrypted, confidentiality_key

def generate_encrypted_secret(confidentiality_key, plaintext_secret):
    """Generate an encrypted secret using old format (AES ECB)"""
    # Create plaintext with MAGIC marker
    plaintext = plaintext_secret.encode('utf-8') + MAGIC
    
    # Pad to 16-byte boundary
    padding_needed = 16 - (len(plaintext) % 16)
    if padding_needed < 16:
        plaintext += b'\x00' * padding_needed
    
    # Encrypt with AES ECB
    cipher = AES.new(confidentiality_key, AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext)
    
    import base64
    return base64.b64encode(encrypted).decode('ascii')

def main():
    fixtures_dir = Path(__file__).parent / "test_fixtures"
    secrets_dir = fixtures_dir / "secrets"
    
    # Create directories
    fixtures_dir.mkdir(exist_ok=True)
    secrets_dir.mkdir(exist_ok=True)
    
    # Generate hudson.util.Secret
    hudson_secret, confidentiality_key = generate_hudson_secret(MASTER_KEY_HEX)
    
    # Write master.key
    master_key_file = secrets_dir / "master.key"
    with open(master_key_file, 'w') as f:
        f.write(MASTER_KEY_HEX)
    print(f"[+] Generated {master_key_file}")
    print(f"    Length: {len(MASTER_KEY_HEX)} bytes")
    
    # Write hudson.util.Secret
    hudson_secret_file = secrets_dir / "hudson.util.Secret"
    with open(hudson_secret_file, 'wb') as f:
        f.write(hudson_secret)
    print(f"[+] Generated {hudson_secret_file}")
    print(f"    Length: {len(hudson_secret)} bytes (should be multiple of 16: {len(hudson_secret) % 16 == 0})")
    print(f"    Hex: {hudson_secret.hex()}")
    
    # Generate test encrypted secrets
    test_password = "admin"
    test_token = "ghp_1234567890abcdefghijklmnopqrstuv"
    test_api_key = "AKIAIOSFODNN7EXAMPLE"
    
    encrypted_password = generate_encrypted_secret(confidentiality_key, test_password)
    encrypted_token = generate_encrypted_secret(confidentiality_key, test_token)
    encrypted_api_key = generate_encrypted_secret(confidentiality_key, test_api_key)
    
    print(f"\n[+] Generated encrypted secrets:")
    print(f"    Password 'admin': {encrypted_password}")
    print(f"    Token: {encrypted_token}")
    print(f"    API Key: {encrypted_api_key}")
    
    # Write credentials.xml
    credentials_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
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
          <password>{{{encrypted_password}}}</password>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
        <org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>api-token</id>
          <description>API Token</description>
          <secret>{{{encrypted_token}}}</secret>
        </org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
        <org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>aws-key</id>
          <description>AWS Access Key</description>
          <secret>{{{encrypted_api_key}}}</secret>
        </org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>
"""
    
    credentials_file = fixtures_dir / "credentials.xml"
    with open(credentials_file, 'w', encoding='utf-8') as f:
        f.write(credentials_xml)
    print(f"\n[+] Generated {credentials_file}")
    
    print("\n[+] Test fixtures generated successfully!")
    print(f"\nExpected decrypted values:")
    print(f"  - Password: {test_password}")
    print(f"  - Token: {test_token}")
    print(f"  - API Key: {test_api_key}")

if __name__ == "__main__":
    main()
