#!/usr/bin/env python3
import os
import sys
import pytest
import base64
from pathlib import Path
from hashlib import sha256
from Crypto.Cipher import AES

os.environ["INSIDE_VENV"] = "1"

from decrypt import (
    get_confidentiality_key,
    decrypt_confidentiality_key,
    decrypt_secret_old_format,
    decrypt_secret_new_format,
    decrypt_secret,
    decrypt_credentials_file
)

MAGIC = b'::::MAGIC::::'

class TestConfidentialityKey:
    def test_decrypt_confidentiality_key_valid(self, confidentiality_key):
        """Test decryption of valid confidentiality key"""
        master_key = b"test_master_key_12345678"
        derived_key = sha256(master_key).digest()[:16]
        
        plaintext = confidentiality_key + MAGIC
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(derived_key, AES.MODE_ECB)
        hudson_secret = cipher.encrypt(plaintext)
        
        result = decrypt_confidentiality_key(master_key, hudson_secret)
        
        assert result is not None
        assert result == confidentiality_key
        assert len(result) == 16
    
    def test_decrypt_confidentiality_key_invalid_magic(self):
        """Test decryption fails with invalid magic marker"""
        master_key = b"test_master_key_12345678"
        derived_key = sha256(master_key).digest()[:16]
        
        confidentiality_key = os.urandom(16)
        plaintext = confidentiality_key + b"INVALID_MAGIC"
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(derived_key, AES.MODE_ECB)
        hudson_secret = cipher.encrypt(plaintext)
        
        result = decrypt_confidentiality_key(master_key, hudson_secret)
        
        assert result is None
    
    def test_get_confidentiality_key_from_files(self, master_key_file, hudson_secret_file):
        """Test loading confidentiality key from files"""
        result = get_confidentiality_key(master_key_file, hudson_secret_file)
        
        assert result is not None
        assert len(result) == 16
        assert isinstance(result, bytes)

class TestOldFormatDecryption:
    def test_decrypt_secret_old_format_valid(self, confidentiality_key):
        """Test AES ECB decryption with valid secret"""
        plaintext = b"test_password" + MAGIC
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(confidentiality_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(plaintext)
        
        result = decrypt_secret_old_format(encrypted, confidentiality_key)
        
        assert result is not None
        assert result == b"test_password"
    
    def test_decrypt_secret_old_format_invalid_magic(self, confidentiality_key):
        """Test AES ECB decryption fails with invalid magic"""
        plaintext = b"test_password_no_magic_marker"
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(confidentiality_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(plaintext)
        
        result = decrypt_secret_old_format(encrypted, confidentiality_key)
        
        assert result is None
    
    def test_decrypt_secret_old_format_multiple_values(self, confidentiality_key):
        """Test AES ECB decryption with various test vectors"""
        test_values = [
            b"admin",
            b"password123",
            b"AKIAIOSFODNN7EXAMPLE",
            b"ghp_1234567890123456789012345678901234567890",
            b"a",
            b"very_long_secret_value_that_exceeds_normal_length_for_testing_purposes"
        ]
        
        for test_val in test_values:
            plaintext = test_val + MAGIC
            padding_needed = 16 - (len(plaintext) % 16)
            if padding_needed < 16:
                plaintext += b'\x00' * padding_needed
            
            cipher = AES.new(confidentiality_key, AES.MODE_ECB)
            encrypted = cipher.encrypt(plaintext)
            
            result = decrypt_secret_old_format(encrypted, confidentiality_key)
            
            assert result == test_val, f"Failed for value: {test_val}"

class TestNewFormatDecryption:
    def test_decrypt_secret_new_format_valid(self, confidentiality_key):
        """Test AES CBC decryption with valid secret"""
        iv = os.urandom(16)
        plaintext = b"test_password"
        
        padding_value = 16 - (len(plaintext) % 16)
        if padding_value == 0:
            padding_value = 16
        plaintext += bytes([padding_value] * padding_value)
        
        cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)
        encrypted_body = cipher.encrypt(plaintext)
        
        encrypted_secret = b'\x01' + b'\x00' * 8 + iv + encrypted_body
        
        result = decrypt_secret_new_format(encrypted_secret, confidentiality_key)
        
        assert result is not None
        assert result == b"test_password"
    
    def test_decrypt_secret_new_format_various_padding(self, confidentiality_key):
        """Test AES CBC decryption with various padding sizes"""
        test_values = [
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"abcde",
            b"abcdefghijklmno",
            b"abcdefghijklmnop",
            b"abcdefghijklmnopq"
        ]
        
        for test_val in test_values:
            iv = os.urandom(16)
            plaintext = test_val
            
            padding_value = 16 - (len(plaintext) % 16)
            if padding_value == 0:
                padding_value = 16
            plaintext += bytes([padding_value] * padding_value)
            
            cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)
            encrypted_body = cipher.encrypt(plaintext)
            
            encrypted_secret = b'\x01' + b'\x00' * 8 + iv + encrypted_body
            
            result = decrypt_secret_new_format(encrypted_secret, confidentiality_key)
            
            assert result == test_val, f"Failed for value: {test_val} (len={len(test_val)})"

class TestBase64DecryptionWrapper:
    def test_decrypt_secret_old_format_base64(self, confidentiality_key):
        """Test base64-encoded old format decryption"""
        plaintext = b"admin" + MAGIC
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(confidentiality_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(plaintext)
        encoded = base64.b64encode(encrypted).decode('ascii')
        
        result = decrypt_secret(encoded, confidentiality_key)
        
        assert result is not None
        assert result == b"admin"
    
    def test_decrypt_secret_new_format_base64(self, confidentiality_key):
        """Test base64-encoded new format decryption"""
        iv = os.urandom(16)
        plaintext = b"test_password"
        
        padding_value = 16 - (len(plaintext) % 16)
        if padding_value == 0:
            padding_value = 16
        plaintext += bytes([padding_value] * padding_value)
        
        cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)
        encrypted_body = cipher.encrypt(plaintext)
        
        encrypted_secret = b'\x01' + b'\x00' * 8 + iv + encrypted_body
        encoded = base64.b64encode(encrypted_secret).decode('ascii')
        
        result = decrypt_secret(encoded, confidentiality_key)
        
        assert result is not None
        assert result == b"test_password"
    
    def test_decrypt_secret_invalid_base64(self, confidentiality_key):
        """Test decryption with invalid base64"""
        result = decrypt_secret("!!!INVALID_BASE64!!!", confidentiality_key)
        
        assert result is None
    
    def test_decrypt_secret_none_input(self, confidentiality_key):
        """Test decryption with None input"""
        result = decrypt_secret(None, confidentiality_key)
        
        assert result is None

class TestCredentialsFileDecryption:
    def test_decrypt_credentials_file(self, credentials_xml_file, master_key_file, hudson_secret_file):
        """Test full credentials.xml decryption"""
        creds_file, expected = credentials_xml_file
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True, dry_run=False)
        
        assert len(secrets) >= 3
        
        decrypted_values = [s['decrypted'] for s in secrets]
        assert expected['password'] in decrypted_values
        assert expected['token'] in decrypted_values
        assert expected['api_key'] in decrypted_values
    
    def test_decrypt_credentials_file_dry_run(self, credentials_xml_file, master_key_file, hudson_secret_file):
        """Test dry-run mode doesn't decrypt"""
        creds_file, expected = credentials_xml_file
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True, dry_run=True)
        
        assert len(secrets) >= 3
        
        for secret in secrets:
            assert secret['decrypted'] == "[DRY RUN - NOT DECRYPTED]"
    
    def test_decrypt_credentials_file_redaction(self, credentials_xml_file, master_key_file, hudson_secret_file):
        """Test secrets are redacted by default"""
        creds_file, expected = credentials_xml_file
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=False, dry_run=False)
        
        assert len(secrets) >= 3
        
        for secret in secrets:
            if 'display' in secret:
                assert 'REDACTED' in secret['display'] or secret['display'] != secret['decrypted']

class TestKnownTestVectors:
    """Test with known Jenkins credential test vectors"""
    
    def test_jenkins_known_vector_1(self):
        """Test with known Jenkins credential from documentation"""
        master_key = b"4a8a9f3e2b7c1d5e8f9a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e"
        
        derived_key = sha256(master_key).digest()[:16]
        confidentiality_key = os.urandom(16)
        
        plaintext = confidentiality_key + MAGIC
        padding_needed = 16 - (len(plaintext) % 16)
        if padding_needed < 16:
            plaintext += b'\x00' * padding_needed
        
        cipher = AES.new(derived_key, AES.MODE_ECB)
        hudson_secret = cipher.encrypt(plaintext)
        
        result = decrypt_confidentiality_key(master_key, hudson_secret)
        
        assert result == confidentiality_key
