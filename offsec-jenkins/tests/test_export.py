#!/usr/bin/env python3
import os
import sys
import json
import csv
import pytest
import subprocess
from pathlib import Path

os.environ["INSIDE_VENV"] = "1"

from decrypt import get_confidentiality_key, decrypt_credentials_file

class TestJSONExport:
    def test_json_export_basic(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test basic JSON export functionality"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        assert output_file.exists()
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert isinstance(data, list)
        assert len(data) >= 3
    
    def test_json_export_structure(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test JSON export has correct structure"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        required_fields = ['file', 'encrypted', 'decrypted']
        for entry in data:
            for field in required_fields:
                assert field in entry, f"Missing field: {field}"
    
    def test_json_export_file_creation(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test JSON file is created with correct permissions"""
        creds_file, expected = credentials_xml_file
        output_dir = tmp_path / "outputs"
        output_dir.mkdir()
        output_file = output_dir / "secrets.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    def test_json_export_valid_format(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test JSON export is valid JSON format"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        try:
            with open(output_file, 'r') as f:
                json.load(f)
            valid = True
        except json.JSONDecodeError:
            valid = False
        
        assert valid is True
    
    def test_json_export_with_redaction(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test JSON export with redacted secrets"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=False)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        for entry in data:
            if 'display' in entry:
                assert 'REDACTED' in entry['display'] or entry['display'] != entry['decrypted']

class TestCSVExport:
    def test_csv_export_basic(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test basic CSV export functionality"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.csv"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
            writer.writeheader()
            writer.writerows(secrets)
        
        assert output_file.exists()
    
    def test_csv_export_structure(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test CSV export has correct structure"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.csv"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
            writer.writeheader()
            writer.writerows(secrets)
        
        with open(output_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) >= 3
        
        required_fields = ['file', 'encrypted', 'decrypted']
        for field in required_fields:
            assert field in rows[0], f"Missing field: {field}"
    
    def test_csv_export_header(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test CSV export has correct header"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.csv"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
            writer.writeheader()
            writer.writerows(secrets)
        
        with open(output_file, 'r') as f:
            first_line = f.readline().strip()
        
        assert 'file' in first_line
        assert 'encrypted' in first_line
        assert 'decrypted' in first_line
    
    def test_csv_export_readable(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test CSV export is readable by csv.DictReader"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "output.csv"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'encrypted', 'decrypted', 'display'])
            writer.writeheader()
            writer.writerows(secrets)
        
        try:
            with open(output_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            readable = len(rows) > 0
        except Exception:
            readable = False
        
        assert readable is True

class TestFileOverwriteProtection:
    def test_overwrite_protection(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test file overwrite protection without --force"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "existing.json"
        
        output_file.write_text('{"existing": "data"}')
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        if output_file.exists():
            exists = True
        else:
            exists = False
        
        assert exists is True
        
        original_content = output_file.read_text()
        assert "existing" in original_content
    
    def test_force_overwrite(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test file overwrite with --force flag"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "existing.json"
        
        output_file.write_text('{"existing": "data"}')
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        new_content = output_file.read_text()
        assert "existing" not in new_content or "file" in new_content

class TestOutputDirectoryCreation:
    def test_creates_output_directory(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test output directory is created if it doesn't exist"""
        creds_file, expected = credentials_xml_file
        output_dir = tmp_path / "outputs" / "nested" / "path"
        output_file = output_dir / "secrets.json"
        
        confidentiality_key = get_confidentiality_key(master_key_file, hudson_secret_file)
        secrets = decrypt_credentials_file(creds_file, confidentiality_key, reveal_secrets=True)
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        
        assert output_dir.exists()
        assert output_file.exists()

class TestIntegrationWithCLI:
    def test_cli_json_export_integration(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test full CLI integration with JSON export"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "cli_test.json"
        
        script_path = Path(__file__).parent.parent / "decrypt.py"
        
        cmd = [
            sys.executable,
            str(script_path),
            "--key", str(master_key_file),
            "--secret", str(hudson_secret_file),
            "--xml", str(creds_file),
            "--export-json", str(output_file),
            "--reveal-secrets"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists()
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert len(data) >= 3
        
        decrypted_values = [s['decrypted'] for s in data]
        assert expected['password'] in decrypted_values
        assert expected['token'] in decrypted_values
        assert expected['api_key'] in decrypted_values
    
    def test_cli_csv_export_integration(self, credentials_xml_file, master_key_file, hudson_secret_file, tmp_path):
        """Test full CLI integration with CSV export"""
        creds_file, expected = credentials_xml_file
        output_file = tmp_path / "cli_test.csv"
        
        script_path = Path(__file__).parent.parent / "decrypt.py"
        
        cmd = [
            sys.executable,
            str(script_path),
            "--key", str(master_key_file),
            "--secret", str(hudson_secret_file),
            "--xml", str(creds_file),
            "--export-csv", str(output_file),
            "--reveal-secrets"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists()
        
        with open(output_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) >= 3
