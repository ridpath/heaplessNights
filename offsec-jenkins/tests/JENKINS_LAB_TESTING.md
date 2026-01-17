# Jenkins Lab Testing Instructions

This document describes how to test the decryptor against actual Jenkins Lab credentials once the Jenkins Lab is set up (see JenkinsBreaker project).

## Prerequisites

Jenkins Lab must be running (from JenkinsBreaker project):
```bash
cd ~/jenkins-lab
docker-compose up -d
```

## Extracting Jenkins Lab Credentials

### Method 1: Direct Docker Copy

```bash
# Create test directory
mkdir -p test_fixtures/jenkins_lab/secrets

# Extract master.key
docker cp $(docker ps -qf "name=jenkins"):/var/jenkins_home/secrets/master.key test_fixtures/jenkins_lab/secrets/

# Extract hudson.util.Secret
docker cp $(docker ps -qf "name=jenkins"):/var/jenkins_home/secrets/hudson.util.Secret test_fixtures/jenkins_lab/secrets/

# Extract credentials.xml
docker cp $(docker ps -qf "name=jenkins"):/var/jenkins_home/credentials.xml test_fixtures/jenkins_lab/
```

### Method 2: Docker Exec

```bash
# Create test directory
mkdir -p test_fixtures/jenkins_lab/secrets

# Extract files via docker exec
docker exec $(docker ps -qf "name=jenkins") cat /var/jenkins_home/secrets/master.key > test_fixtures/jenkins_lab/secrets/master.key
docker exec $(docker ps -qf "name=jenkins") cat /var/jenkins_home/secrets/hudson.util.Secret > test_fixtures/jenkins_lab/secrets/hudson.util.Secret
docker exec $(docker ps -qf "name=jenkins") cat /var/jenkins_home/credentials.xml > test_fixtures/jenkins_lab/credentials.xml
```

## Running Tests Against Jenkins Lab

### Test Decryption

```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --reveal-secrets
```

Expected output:
- AWS credentials from ~/.aws/credentials
- SSH keys metadata
- API tokens from credentials.xml
- Passwords and secrets

### Test JSON Export

```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --export-json outputs/jenkins_lab_secrets.json --reveal-secrets
```

Verify:
```bash
cat outputs/jenkins_lab_secrets.json
```

### Test CSV Export

```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --export-csv outputs/jenkins_lab_secrets.csv --reveal-secrets
```

Verify:
```bash
cat outputs/jenkins_lab_secrets.csv
```

### Test Recursive Scanning

```bash
# Copy entire Jenkins home
docker cp $(docker ps -qf "name=jenkins"):/var/jenkins_home test_fixtures/jenkins_lab_full/

# Scan recursively
python3 decrypt.py --scan-dir test_fixtures/jenkins_lab_full --export-json outputs/jenkins_lab_full.json --reveal-secrets
```

Expected: Should find credentials in:
- credentials.xml
- jobs/*/config.xml
- users/*/config.xml

## Expected Secrets in Jenkins Lab

Based on Jenkins Lab setup (see jenkins-lab/secrets/ directory):

### AWS Credentials
- AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
- AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

### SSH Keys
- Private key in ~/.ssh/id_rsa
- Key fingerprint should be detected

### API Tokens
- Jenkins API tokens from job configurations
- GitHub tokens (ghp_*)
- Docker registry credentials

### Build Artifacts
- .npmrc with auth tokens
- .m2/settings.xml with Maven credentials
- .docker/config.json with registry auth

## Validation Checklist

- [ ] master.key successfully loaded
- [ ] hudson.util.Secret successfully decrypted
- [ ] All planted secrets decrypted correctly
- [ ] AWS credentials extracted
- [ ] SSH keys detected
- [ ] API tokens extracted
- [ ] Secrets properly redacted by default
- [ ] --reveal-secrets shows plaintext
- [ ] JSON export works
- [ ] CSV export works
- [ ] Recursive scanning finds all credential files

## Integration with pytest

Create a pytest marker for Jenkins Lab tests:

```python
# tests/test_jenkins_lab.py
import pytest
from pathlib import Path

pytestmark = pytest.mark.skipif(
    not Path("test_fixtures/jenkins_lab/secrets/master.key").exists(),
    reason="Jenkins Lab credentials not available"
)

def test_jenkins_lab_decryption():
    # Test against actual Jenkins Lab
    pass
```

Run with:
```bash
pytest tests/test_jenkins_lab.py -v
```

## Troubleshooting

### Error: master.key not found
- Ensure Jenkins Lab is running
- Check Docker container name matches
- Verify file permissions

### Error: Decryption failed
- Verify hudson.util.Secret is binary file
- Check file wasn't corrupted during copy
- Ensure using correct Jenkins version

### No secrets found
- Check credentials.xml exists
- Verify XML contains encrypted values
- Ensure Jenkins had time to initialize

## Notes

This testing is essential for validating the decryptor works against real Jenkins instances, not just test fixtures. The Jenkins Lab contains intentionally vulnerable configurations and planted secrets for red team training.
