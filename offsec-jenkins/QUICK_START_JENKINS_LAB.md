# Quick Start: Jenkins Lab Testing

## Jenkins Lab Setup Status
- **WSL Path**: `\\wsl.localhost\parrot`
- **WSL User**: `over` / Password: `over`
- **Docker Credentials**: `admin` / `admin`
- **Expected Ready Time**: ~3 minutes from Docker start

## Prerequisites Check

### From Windows PowerShell
```powershell
# Check if Jenkins Lab container is running
docker ps -f "name=jenkins"

# Expected output: Container with jenkins in name should be running
```

### From WSL (\\wsl.localhost\parrot)
```bash
# Check Docker is running
docker ps

# Check Jenkins container
docker ps | grep jenkins
```

## Running Integration Tests

### Option 1: Windows PowerShell
```powershell
cd C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\offsec-jenkins
.\test_jenkins_lab.bat
```

### Option 2: WSL/Linux
```bash
cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/offsec-jenkins
chmod +x test_jenkins_lab.sh
./test_jenkins_lab.sh
```

## Manual Testing Steps

### 1. Extract Jenkins Lab Credentials
```bash
# Get Jenkins container ID
JENKINS_CONTAINER=$(docker ps -qf "name=jenkins")

# Create directory
mkdir -p test_fixtures/jenkins_lab/secrets

# Extract files
docker cp $JENKINS_CONTAINER:/var/jenkins_home/secrets/master.key test_fixtures/jenkins_lab/secrets/
docker cp $JENKINS_CONTAINER:/var/jenkins_home/secrets/hudson.util.Secret test_fixtures/jenkins_lab/secrets/
docker cp $JENKINS_CONTAINER:/var/jenkins_home/credentials.xml test_fixtures/jenkins_lab/
```

### 2. Test Decryption (Redacted)
```bash
python3 decrypt.py --path test_fixtures/jenkins_lab
```

Expected output:
```
[*] Loading confidentiality key...
[+] Confidentiality key loaded successfully
[*] Processing test_fixtures/jenkins_lab/credentials.xml
***REDACTED***
***REDACTED***
[!] Secrets are redacted by default. Use --reveal-secrets to show plaintext
```

### 3. Test Decryption (Revealed)
```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --reveal-secrets
```

Expected: Shows plaintext AWS keys, tokens, passwords

### 4. Test JSON Export
```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --export-json outputs/jenkins_lab_secrets.json --reveal-secrets --force
cat outputs/jenkins_lab_secrets.json
```

### 5. Test CSV Export
```bash
python3 decrypt.py --path test_fixtures/jenkins_lab --export-csv outputs/jenkins_lab_secrets.csv --reveal-secrets --force
cat outputs/jenkins_lab_secrets.csv
```

### 6. Test Recursive Scanning
```bash
python3 decrypt.py --scan-dir test_fixtures/jenkins_lab --export-json outputs/jenkins_lab_scan.json --reveal-secrets
```

## Expected Secrets in Jenkins Lab

Based on Jenkins Lab configuration (see jenkins-lab/secrets/ in JenkinsBreaker project):

### AWS Credentials
- Access Key: `AKIAIOSFODNN7EXAMPLE` (or similar)
- Secret Key: Base64-encoded secret

### API Tokens
- Jenkins API tokens
- GitHub tokens (ghp_*)
- Docker registry credentials

### Other Secrets
- Passwords
- SSH key metadata
- .npmrc tokens
- Maven settings

## Validation Checklist

- [ ] `decrypt.py --help` shows all flags
- [ ] Files extracted from Jenkins Lab container
- [ ] Decryption without --reveal-secrets shows redacted output
- [ ] Decryption with --reveal-secrets shows plaintext
- [ ] JSON export creates valid JSON file
- [ ] CSV export creates valid CSV file
- [ ] At least 3 secrets found in credentials.xml
- [ ] All unit tests pass: `pytest tests/ -v`

## Troubleshooting

### Error: Jenkins container not found
```bash
# Check if Jenkins Lab is running
docker ps -a | grep jenkins

# If not running, start it
cd ~/jenkins-lab
docker-compose up -d

# Wait 30-60 seconds for Jenkins to initialize
```

### Error: master.key not found
```bash
# Verify file exists in container
docker exec $(docker ps -qf "name=jenkins") ls -la /var/jenkins_home/secrets/

# If missing, Jenkins may still be initializing - wait longer
```

### Error: Decryption failed
```bash
# Verify hudson.util.Secret is binary
file test_fixtures/jenkins_lab/secrets/hudson.util.Secret
# Should show: data

# Check file sizes
ls -lh test_fixtures/jenkins_lab/secrets/
# master.key: ~64 bytes
# hudson.util.Secret: 32 or 48 bytes (multiple of 16)
```

### Error: No secrets found
```bash
# Check credentials.xml has content
cat test_fixtures/jenkins_lab/credentials.xml

# Verify it contains encrypted secrets (base64 strings in braces)
grep -o '{[A-Za-z0-9+/=]\{20,\}}' test_fixtures/jenkins_lab/credentials.xml
```

## Success Criteria

✓ All CLI flags work correctly  
✓ Credentials extracted from Jenkins Lab container  
✓ Secrets decrypted successfully  
✓ Redaction works by default  
✓ --reveal-secrets shows plaintext  
✓ JSON export validated  
✓ CSV export validated  
✓ 61/61 unit tests pass  
✓ Integration with actual Jenkins Lab verified

## Next Steps After Validation

Once all tests pass:
1. Document any found secrets for CTF/red team training
2. Test against additional Jenkins Lab scenarios (job configs, user credentials)
3. Validate cross-platform compatibility (Windows, WSL, Linux)
4. Update main README with Jenkins Lab testing results
