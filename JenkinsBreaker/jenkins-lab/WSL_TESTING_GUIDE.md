# WSL Testing Guide for Jenkins Lab

## Overview

This guide provides instructions for setting up and testing the Jenkins Lab in WSL2 environment on Windows.

## Prerequisites

- Windows 10/11 with WSL2 enabled
- WSL distribution installed (tested with Parrot, Ubuntu, Debian)
- At least 4GB RAM allocated to WSL
- Internet connection for Docker installation

## Quick Start

### 1. Access WSL

From Windows:
```powershell
wsl -d parrot
```

Or via network path:
```
\\wsl.localhost\parrot
```

### 2. Navigate to Jenkins Lab

```bash
cd /mnt/c/Users/<username>/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab
```

### 3. Install Docker (if not installed)

```bash
./scripts/install_docker_wsl.sh
```

After installation:
```bash
sudo service docker start
newgrp docker
```

### 4. Run Full Test Cycle

```bash
./scripts/test_wsl.sh
```

## Manual Testing Steps

### Step 1: Setup Jenkins Lab

```bash
./scripts/setup.sh
```

Expected output:
- Docker builds Jenkins vulnerable image
- Container starts on port 8080
- Waits for Jenkins to initialize
- Displays access credentials (admin:admin)

### Step 2: Verify Jenkins is Running

```bash
curl http://localhost:8080
```

Should return Jenkins homepage HTML.

### Step 3: Run Exploit Tests

```bash
./scripts/test_exploits.sh
```

Tests performed:
- Version fingerprinting (Jenkins 2.138.3)
- Plugin enumeration (50+ plugins)
- CVE-2024-23897 (CLI arbitrary file read)
- CVE-2019-1003029 (Groovy script RCE)
- Credentials enumeration (16 credentials)
- Job enumeration (5 vulnerable jobs)
- Secrets verification (AWS, SSH, NPM, Docker, Maven)

### Step 4: Test JenkinsBreaker Integration

```bash
cd ..
python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001
```

Expected behavior:
- Fingerprints Jenkins version
- Detects 11 applicable CVEs
- Attempts exploitation
- Extracts planted secrets
- Generates report

### Step 5: Cleanup

```bash
cd jenkins-lab
./scripts/cleanup.sh
```

Options:
- Keep volumes: Press N (default)
- Remove all data: Press Y

## Script Reference

### setup.sh
Initializes Jenkins Lab environment.

**Features:**
- Validates Docker installation
- Builds vulnerable Jenkins image
- Starts containers with docker-compose
- Waits for Jenkins initialization (max 2.5 minutes)
- Displays access information and CVE list

**Usage:**
```bash
./scripts/setup.sh
```

### cleanup.sh
Stops Jenkins Lab and optionally removes data.

**Features:**
- Stops all Jenkins containers
- Prompts for volume removal
- Preserves data by default

**Usage:**
```bash
./scripts/cleanup.sh
```

### generate_tokens.sh
Creates Jenkins API tokens for testing.

**Features:**
- Handles CSRF crumb
- Generates named API token
- Works with/without CSRF protection

**Usage:**
```bash
./scripts/generate_tokens.sh
```

### test_exploits.sh
Comprehensive CVE validation suite.

**Tests:**
1. Version fingerprinting
2. Plugin enumeration (vulnerable plugins)
3. CVE-2024-23897 (CLI file read)
4. CVE-2019-1003029 (Groovy RCE)
5. Credentials enumeration
6. Job enumeration
7. Secrets verification

**Usage:**
```bash
./scripts/test_exploits.sh
```

### verify_secrets.sh
Validates planted secrets in container.

**Checks:**
- File-based secrets (AWS, SSH, NPM, Docker, Maven)
- Jenkins credentials (16 credentials)
- Job configurations
- Environment variables
- Privilege escalation vectors

**Usage:**
```bash
./scripts/verify_secrets.sh
```

### install_docker_wsl.sh
Installs Docker Engine in WSL2.

**Features:**
- Adds Docker repository
- Installs Docker Engine and Compose
- Configures Docker daemon
- Adds user to docker group

**Usage:**
```bash
./scripts/install_docker_wsl.sh
sudo service docker start
newgrp docker
```

### test_wsl.sh
End-to-end WSL integration test.

**Validates:**
- WSL environment
- Docker installation
- Full lab setup → test → cleanup cycle

**Usage:**
```bash
./scripts/test_wsl.sh
```

## Troubleshooting

### Docker not found in WSL

**Solution:**
```bash
./scripts/install_docker_wsl.sh
sudo service docker start
```

### Docker daemon not running

**Solution:**
```bash
sudo service docker start
docker info
```

### Permission denied (docker)

**Solution:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Jenkins fails to start

**Check logs:**
```bash
docker-compose logs jenkins
```

**Common issues:**
- Port 8080 already in use
- Insufficient memory (need 2GB+)
- Volume mount permissions

**Solution:**
```bash
docker-compose down -v
docker-compose up -d
```

### Java not found for CLI testing

**Install Java:**
```bash
sudo apt-get update
sudo apt-get install -y openjdk-11-jre-headless
```

### curl: command not found

**Install curl:**
```bash
sudo apt-get update
sudo apt-get install -y curl
```

### python3 not found

**Install Python:**
```bash
sudo apt-get update
sudo apt-get install -y python3
```

## Testing Checklist

- [ ] WSL environment accessible
- [ ] Docker installed and running
- [ ] Jenkins Lab starts successfully
- [ ] Jenkins accessible at http://localhost:8080
- [ ] Login works (admin:admin)
- [ ] CVE-2024-23897 exploitable (file read)
- [ ] CVE-2019-1003029 exploitable (Groovy RCE)
- [ ] Credentials enumeration successful
- [ ] Jobs enumeration successful
- [ ] Secrets verification passed
- [ ] JenkinsBreaker detects vulnerabilities
- [ ] Cleanup works correctly

## Performance Notes

**Expected timings:**
- Docker build: 2-5 minutes (first time)
- Jenkins startup: 30-60 seconds
- Test suite: 15-30 seconds
- JenkinsBreaker full scan: 1-3 minutes

**Resource usage:**
- Disk: ~500MB for image
- RAM: ~1.5GB during operation
- CPU: Low (idle) to High (during exploits)

## Security Notes

**Lab is intentionally vulnerable:**
- CVE-2018-1000861 (Stapler RCE)
- CVE-2019-1003029/30 (Script Security)
- CVE-2024-23897 (CLI file read)
- CVE-2020-2100 (Git Plugin RCE)
- 7 more CVEs

**Do NOT expose to network:**
- Use only on localhost
- Do NOT port forward
- Do NOT use in production
- Test only in isolated environment

All credentials are TEST ONLY and publicly documented.

## Integration with JenkinsBreaker

After lab is running:

```bash
cd /mnt/c/Users/<username>/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker

python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001
```

**Expected results:**
- Detects Jenkins 2.138.3
- Identifies 11 CVEs
- Attempts exploitation
- Extracts secrets from:
  - credentials.xml
  - Job configurations
  - File system (~/.aws, ~/.ssh, etc.)
- Generates reports in reports/ directory

## Contact and Support

For issues specific to WSL integration:
1. Verify Docker is running: `docker info`
2. Check container logs: `docker-compose logs`
3. Test network: `curl http://localhost:8080`

For Jenkins Lab issues:
1. Check SECRETS_REFERENCE.md
2. Run verify_secrets.sh
3. Review docker-compose.yml

For JenkinsBreaker issues:
1. Check README.md in parent directory
2. Verify Python dependencies
3. Test individual CVE modules
