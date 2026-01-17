#!/usr/bin/env python3
import os
import sys
import pytest

os.environ["INSIDE_VENV"] = "1"

from decrypt import (
    parse_arguments,
    redact_secret,
    is_sensitive_credential,
    scan_directory_recursive
)
from pathlib import Path

class TestArgumentParsing:
    def test_parse_path_argument(self, monkeypatch):
        """Test --path argument parsing"""
        test_args = ["decrypt.py", "--path", "/var/lib/jenkins"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.path == "/var/lib/jenkins"
        assert args.export_json is None
        assert args.reveal_secrets is False
    
    def test_parse_export_json_argument(self, monkeypatch):
        """Test --export-json argument"""
        test_args = ["decrypt.py", "--path", "/test", "--export-json", "output.json"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.export_json == "output.json"
    
    def test_parse_export_csv_argument(self, monkeypatch):
        """Test --export-csv argument"""
        test_args = ["decrypt.py", "--path", "/test", "--export-csv", "output.csv"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.export_csv == "output.csv"
    
    def test_parse_reveal_secrets_flag(self, monkeypatch):
        """Test --reveal-secrets flag"""
        test_args = ["decrypt.py", "--path", "/test", "--reveal-secrets"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.reveal_secrets is True
    
    def test_parse_dry_run_flag(self, monkeypatch):
        """Test --dry-run flag"""
        test_args = ["decrypt.py", "--path", "/test", "--dry-run"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.dry_run is True
    
    def test_parse_force_flag(self, monkeypatch):
        """Test --force flag"""
        test_args = ["decrypt.py", "--path", "/test", "--force"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.force is True
    
    def test_parse_interactive_flag(self, monkeypatch):
        """Test --interactive flag"""
        test_args = ["decrypt.py", "--key", "master.key", "--secret", "hudson.util.Secret", "--interactive"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.interactive is True
    
    def test_parse_scan_dir_argument(self, monkeypatch):
        """Test --scan-dir argument"""
        test_args = ["decrypt.py", "--key", "master.key", "--secret", "hudson.util.Secret", "--scan-dir", "/jenkins_backup"]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.scan_dir == "/jenkins_backup"
    
    def test_parse_multiple_flags(self, monkeypatch):
        """Test multiple flags together"""
        test_args = [
            "decrypt.py",
            "--path", "/var/lib/jenkins",
            "--export-json", "secrets.json",
            "--reveal-secrets",
            "--force"
        ]
        monkeypatch.setattr(sys, 'argv', test_args)
        
        args = parse_arguments()
        
        assert args.path == "/var/lib/jenkins"
        assert args.export_json == "secrets.json"
        assert args.reveal_secrets is True
        assert args.force is True

class TestSecretRedaction:
    def test_redact_short_secret(self):
        """Test redaction of short secrets"""
        secret = "abc"
        redacted = redact_secret(secret)
        
        assert redacted == "***REDACTED***"
    
    def test_redact_medium_secret(self):
        """Test redaction of medium-length secrets"""
        secret = "password123"
        redacted = redact_secret(secret)
        
        assert redacted.startswith("pass")
        assert redacted.endswith("123")
        assert "***REDACTED***" in redacted
        assert secret not in redacted
    
    def test_redact_long_secret(self):
        """Test redaction of long secrets"""
        secret = "AKIAIOSFODNN7EXAMPLEKEY1234567890"
        redacted = redact_secret(secret)
        
        assert redacted.startswith("AKIA")
        assert redacted.endswith("7890")
        assert "***REDACTED***" in redacted
        assert len(redacted) < len(secret)
    
    def test_redact_preserves_prefix_suffix(self):
        """Test redaction preserves first 4 and last 4 chars"""
        secret = "ghp_1234567890abcdefghijklmnopqrstuv"
        redacted = redact_secret(secret)
        
        assert redacted[:4] == "ghp_"
        assert redacted[-4:] == "stuv"

class TestSensitiveCredentialDetection:
    def test_detect_aws_key(self):
        """Test detection of AWS access key"""
        secret = "AKIAIOSFODNN7EXAMPLE"
        
        assert is_sensitive_credential(secret) is True
    
    def test_detect_github_token(self):
        """Test detection of GitHub token"""
        secret = "ghp_1234567890123456789012345678901234567890"
        
        assert is_sensitive_credential(secret) is True
    
    def test_detect_password_keyword(self):
        """Test detection of password keyword"""
        secret = "my_secret_password"
        
        assert is_sensitive_credential(secret) is True
    
    def test_detect_secret_keyword(self):
        """Test detection of secret keyword"""
        secret = "api_secret_key"
        
        assert is_sensitive_credential(secret) is True
    
    def test_detect_token_keyword(self):
        """Test detection of token keyword"""
        secret = "auth_token_123"
        
        assert is_sensitive_credential(secret) is True
    
    def test_detect_private_key(self):
        """Test detection of private key"""
        secret = "-----BEGIN RSA PRIVATE KEY-----"
        
        assert is_sensitive_credential(secret) is True
    
    def test_non_sensitive_value(self):
        """Test non-sensitive values are not detected"""
        secret = "regularvalue123"
        
        assert is_sensitive_credential(secret) is False
    
    def test_case_insensitive_detection(self):
        """Test case-insensitive keyword detection"""
        assert is_sensitive_credential("MY_PASSWORD") is True
        assert is_sensitive_credential("Secret_Key") is True
        assert is_sensitive_credential("API_TOKEN") is True

class TestDirectoryScanning:
    def test_scan_empty_directory(self, tmp_path):
        """Test scanning empty directory"""
        result = scan_directory_recursive(tmp_path)
        
        assert result == []
    
    def test_scan_with_credentials_xml(self, tmp_path):
        """Test scanning directory with credentials.xml"""
        (tmp_path / "credentials.xml").write_text("<credentials/>")
        
        result = scan_directory_recursive(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "credentials.xml"
    
    def test_scan_with_config_xml(self, tmp_path):
        """Test scanning directory with config.xml"""
        (tmp_path / "config.xml").write_text("<config/>")
        
        result = scan_directory_recursive(tmp_path)
        
        assert len(result) == 1
        assert result[0].name == "config.xml"
    
    def test_scan_recursive(self, tmp_path):
        """Test recursive scanning"""
        (tmp_path / "level1").mkdir()
        (tmp_path / "level1" / "level2").mkdir()
        (tmp_path / "level1" / "level2" / "credentials.xml").write_text("<creds/>")
        (tmp_path / "config.xml").write_text("<config/>")
        
        result = scan_directory_recursive(tmp_path)
        
        assert len(result) == 2
    
    def test_scan_jobs_directory(self, tmp_path):
        """Test scanning finds files in jobs/ directory"""
        jobs_dir = tmp_path / "jobs" / "test-job"
        jobs_dir.mkdir(parents=True)
        (jobs_dir / "config.xml").write_text("<job/>")
        
        result = scan_directory_recursive(tmp_path)
        
        assert len(result) == 1
        assert "jobs" in str(result[0])
    
    def test_scan_nonexistent_directory(self, tmp_path):
        """Test scanning non-existent directory"""
        result = scan_directory_recursive(tmp_path / "nonexistent")
        
        assert result == []
    
    def test_scan_ignores_other_xml_files(self, tmp_path):
        """Test scanning ignores non-credential XML files"""
        (tmp_path / "other.xml").write_text("<other/>")
        (tmp_path / "random.xml").write_text("<random/>")
        
        result = scan_directory_recursive(tmp_path)
        
        assert len(result) == 0

class TestCrossPlatformSupport:
    def test_path_handling_windows_style(self):
        """Test Windows-style path handling"""
        if sys.platform == "win32":
            path = Path("C:\\Jenkins\\secrets")
            assert path.is_absolute()
            assert str(path).startswith("C:")
    
    def test_path_handling_unix_style(self):
        """Test Unix-style path handling"""
        if sys.platform != "win32":
            path = Path("/var/lib/jenkins")
            assert path.is_absolute()
            assert str(path).startswith("/")
    
    def test_pathlib_normalization(self):
        """Test pathlib normalizes paths across platforms"""
        path = Path("test") / "directory" / "file.txt"
        
        assert "test" in str(path)
        assert "directory" in str(path)
        assert "file.txt" in str(path)
