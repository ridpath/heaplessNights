#!/usr/bin/env python3
import os
import sys
import pytest
from pathlib import Path
from hashlib import sha256
from Crypto.Cipher import AES

os.environ["INSIDE_VENV"] = "1"

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

MAGIC = b'::::MAGIC::::'

TEST_MASTER_KEY_HEX = "4a8a9f3e2b7c1d5e8f9a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e"

@pytest.fixture
def test_fixtures_dir(tmp_path):
    """Create temporary test fixtures directory"""
    fixtures_dir = tmp_path / "fixtures"
    secrets_dir = fixtures_dir / "secrets"
    
    fixtures_dir.mkdir()
    secrets_dir.mkdir()
    
    return fixtures_dir

@pytest.fixture
def master_key_file(test_fixtures_dir):
    """Create test master.key file"""
    key_file = test_fixtures_dir / "secrets" / "master.key"
    key_file.write_text(TEST_MASTER_KEY_HEX)
    return key_file

@pytest.fixture
def confidentiality_key():
    """Generate a test confidentiality key"""
    return os.urandom(16)

@pytest.fixture
def hudson_secret_file(test_fixtures_dir, confidentiality_key):
    """Create test hudson.util.Secret file"""
    master_key = TEST_MASTER_KEY_HEX.encode('utf-8')
    derived_key = sha256(master_key).digest()[:16]
    
    plaintext = confidentiality_key + MAGIC
    padding_needed = 16 - (len(plaintext) % 16)
    if padding_needed < 16:
        plaintext += b'\x00' * padding_needed
    
    cipher = AES.new(derived_key, AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext)
    
    secret_file = test_fixtures_dir / "secrets" / "hudson.util.Secret"
    secret_file.write_bytes(encrypted)
    
    return secret_file

@pytest.fixture
def credentials_xml_file(test_fixtures_dir, confidentiality_key):
    """Create test credentials.xml with encrypted secrets"""
    import base64
    
    def encrypt_secret_ecb(plaintext):
        plaintext_bytes = plaintext.encode('utf-8') + MAGIC
        padding_needed = 16 - (len(plaintext_bytes) % 16)
        if padding_needed < 16:
            plaintext_bytes += b'\x00' * padding_needed
        
        cipher = AES.new(confidentiality_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(plaintext_bytes)
        return base64.b64encode(encrypted).decode('ascii')
    
    test_password = "admin"
    test_token = "ghp_1234567890abcdefghijklmnopqrstuv"
    test_api_key = "AKIAIOSFODNN7EXAMPLE"
    
    encrypted_password = encrypt_secret_ecb(test_password)
    encrypted_token = encrypt_secret_ecb(test_token)
    encrypted_api_key = encrypt_secret_ecb(test_api_key)
    
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
    
    creds_file = test_fixtures_dir / "credentials.xml"
    creds_file.write_text(credentials_xml)
    
    return creds_file, {
        'password': test_password,
        'token': test_token,
        'api_key': test_api_key
    }
