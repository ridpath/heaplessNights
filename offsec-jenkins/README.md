<!--
Jenkins credential decryptor, decrypt Jenkins master.key, decode hudson.util.Secret,
CI/CD security tools, DevOps post exploitation, cloud identity abuse detection,
pipeline credential recovery, decrypt Jenkins credentials.xml, AES CBC/ECB Jenkins decode,
secure DevOps assessment, supply chain security validation, cloud token extraction,
DevSecOps research utilities, IAM escalation via CI/CD, attack path from build server,
blue team Jenkins hardening, secure CI pipeline, infrastructure security research,
authorized penetration testing CI/CD, credential leak detection Jenkins,
build runner secret reconnaissance, DevOps lateral movement mapping, capture the flag, ctf hack the box, htb
-->

# Jenkins Credential Decryptor

Offline Jenkins credential decryption tool for red teams, researchers, and CTF players. Handles credentials.xml and master.key files with no Jenkins runtime required. Docker support included, works on Linux, macOS, and WSL.

## Overview

This tool extracts and decrypts stored Jenkins credentials using recovered encryption keys. It works with both legacy (AES-ECB) and modern (AES-CBC) encryption formats and is designed for use after CI infrastructure compromise.

### Highlights

- No hardcoded credentials or paths — everything is configurable via environment variables  
- Automatically locates Jenkins directories and key files  
- Works in Docker for clean, repeatable execution  
- Can also run natively with Python and virtualenv  
- Warns on unsafe defaults like `admin/admin` or root execution  
- Tested on Linux, macOS, Windows 10/11, and WSL2  

## Use Case

Target files typically pulled from compromised Jenkins servers:

- `secrets/master.key` – Main encryption key  
- `secrets/hudson.util.Secret` – Secondary key used to generate confidentiality key  
- `credentials.xml` – Global secrets store  
- `jobs/*/config.xml` – Job-level secrets, often pipeline tokens  
- `users/*/config.xml` – User-level credentials (often more privileged)  

Recovered credentials may include:

- AWS access keys and secrets  
- GitHub Personal Access Tokens (PATs)  
- DockerHub/NPM/Maven API tokens  
- SSH private keys  
- Database passwords  
- Misc. cloud provider credentials  

## Features

### Core Capabilities

- **Virtualenv auto-setup** – Dependencies managed automatically  
- **Decrypt AES-ECB** – Legacy format from Jenkins < 2.0  
- **Decrypt AES-CBC** – Current format (Jenkins >= 2.0)  
- **Base64 decode + PKCS#7 unpad** – Full crypto stack built-in  
- **Recursive directory scan** – Handles large Jenkins home dirs  
- **Cross-platform support** – Works on Linux, Windows, macOS, and WSL2  

### Security-Safe Defaults

- **Secrets redacted by default** – No accidental credential dumps in logs  
- **Dry-run mode** – Run decryption safely without revealing anything  
- **Pattern detection** – Flags AWS keys, GitHub tokens, SSH material  
- **Root/admin detection** – Warns if running with unnecessary privileges  
- **Default credential warnings** – Active check for known weak creds  

### Output Options

- **JSON export** – Easy integration with tooling or automation  
- **CSV export** – Works well for reporting and quick triage  
- **Overwrite protection** – Won’t overwrite export files unless `--force` is set  

### Operator-Focused Features

- **Interactive mode** – Manually decrypt individual secrets  
- **Batch processing** – Supports large, automated decrypt runs  
- **Detailed error output** – Shows what failed and why  

### Run Modes

- **Dockerized** – Full isolation, zero local Python requirements  
- **Native Python** – Scripted usage with automatic `.venv` creation  
- **Volume mounts supported** – Keeps decrypted exports separate  
- **Jenkins Lab compatible** – Can be deployed in test labs with your own creds  

## Installation

### Requirements

**To run natively (no Docker):**

- Python 3.6 or newer (Python 3.11+ recommended)  
- `pycryptodome` (automatically installed via virtualenv on first run)  

**To run with Docker:**

- Docker Engine 20.10+  
- Docker Compose v1.29+ or Docker Compose v2+  


### Quick Start

**Clone the repository**:
```bash
git clone https://github.com/ridpath/heaplessNights.git
cd heaplessNights/offsec-jenkins
```

**Option 1: Native Python** (dependencies auto-install):
```bash
python3 decrypt.py --help
```

The script automatically creates a `.venv` and installs dependencies on first run. No manual setup required.

**Option 2: Docker** (zero local dependencies):
```bash
docker-compose build offsec-jenkins
docker-compose run --rm offsec-jenkins --help
```

Docker provides complete isolation and portability across any platform.

## Production Readiness

### Zero Hardcoded Values

**All credentials and paths are user-configurable**:
- No hardcoded admin/admin credentials in any component
- All Jenkins Lab credentials specified via environment variables
- Docker compose files contain commented examples, never actual secrets
- Test scripts use `${VARIABLE:-default}` pattern with active warnings
- Auto-discovery for directories (no hardcoded paths)

**Environment variable configuration**:
```bash
# Configure Jenkins Lab credentials
export JENKINS_USER=myuser
export JENKINS_PASS=strongpassword
export JENKINS_URL=http://target:8080

# Run any script - uses your credentials
./examples/full_workflow_example.sh
```

**Docker credential configuration**:
```yaml
# docker-compose.yml
environment:
  - JENKINS_ADMIN_USER=ctfuser
  - JENKINS_ADMIN_PASS=ctfpass123
```

All components emit warnings when default credentials are active:
```
[!] WARNING: Using default credentials (admin/admin)
[!] Set JENKINS_USER and JENKINS_PASS environment variables for custom credentials
```

### Red Team Deployment Standards

**Operational security**:
- Secrets redacted by default (no accidental leakage in logs or screenshots)
- Read-only volume mounts for forensic evidence preservation
- No credential storage in version control (`.env` files in `.gitignore`)
- Comprehensive error messages without exposing sensitive data

**Portability and reliability**:
- 61/61 unit tests passing (100% test coverage on core decryption)
- Validated across Windows 10/11, WSL2, Ubuntu, Debian, macOS
- Docker validation suite with 7 automated test scenarios
- Jenkins Lab integration testing with live vulnerable environment
- Automated virtualenv recovery on corruption

**Documentation completeness**:
- Main README with all usage patterns
- Dedicated Docker usage guide (DOCKER_USAGE.md)
- Jenkins Lab credential configuration guide (README_CREDENTIALS.md)
- Platform-specific troubleshooting (Windows virtualenv issues, etc.)
- CTF speedrun examples and red team workflow patterns

## Usage

### Command-Line Options

```
usage: decrypt.py [-h] [--path PATH] [--key FILE] [--secret FILE] [--xml FILE]
                  [--scan-dir DIR] [--interactive] [--export-json FILE]
                  [--export-csv FILE] [--dry-run] [--reveal-secrets] [--force]

Jenkins Credential Decryptor - Red Team Post-Exploitation Utility

options:
  -h, --help          show this help message and exit
  --path PATH         Jenkins base directory (auto-detects master.key,
                      hudson.util.Secret, credentials.xml)
  --key FILE          Path to master.key file
  --secret FILE       Path to hudson.util.Secret file
  --xml FILE          Path to credentials.xml file
  --scan-dir DIR      Recursively scan directory for all credential XMLs
  --interactive       Enter interactive mode (decrypt individual secrets)
  --export-json FILE  Export decrypted secrets to JSON file
  --export-csv FILE   Export decrypted secrets to CSV file
  --dry-run           Simulate decryption without printing secrets
  --reveal-secrets    Show plaintext secrets (default: redacted)
  --force             Overwrite output files without warning

Example: python3 decrypt.py --path /var/lib/jenkins --export-json secrets.json
```

### Basic Examples

#### Auto-detect Jenkins directory
```bash
python3 decrypt.py --path /var/lib/jenkins
```

#### Explicit file paths
```bash
python3 decrypt.py --key master.key --secret hudson.util.Secret --xml credentials.xml
```

#### Reveal plaintext secrets
```bash
python3 decrypt.py --path /var/lib/jenkins --reveal-secrets
```

#### Dry-run mode (test without decrypting)
```bash
python3 decrypt.py --path /var/lib/jenkins --dry-run
```

#### Recursive scan for all credential files
```bash
python3 decrypt.py --scan-dir /jenkins_backup
```

#### Export to JSON
```bash
python3 decrypt.py --path /var/lib/jenkins --export-json secrets.json --reveal-secrets
```

#### Export to CSV
```bash
python3 decrypt.py --path /var/lib/jenkins --export-csv secrets.csv --reveal-secrets
```

#### Interactive mode
```bash
python3 decrypt.py --key master.key --secret hudson.util.Secret --interactive
Encrypted secret: AQAAABAAAAAw...
[+] Decrypted: ghp_1234567890abcdef...
```

### Cross-Platform Usage

#### Windows PowerShell
```powershell
python decrypt.py --path C:\Jenkins --export-json secrets.json --reveal-secrets
```

**Note**: On Windows, always invoke with `python decrypt.py`, not `.\decrypt.py`. Direct execution may fail silently due to Windows file association handling.

If encountering issues, rebuild the virtualenv:
```powershell
rmdir /s /q .venv
python -m venv .venv
.venv\Scripts\python.exe -m pip install pycryptodome
python decrypt.py --help
```

#### WSL/Linux
```bash
python3 decrypt.py --path /var/lib/jenkins --export-json secrets.json --reveal-secrets
```

#### macOS
```bash
python3 decrypt.py --path /Users/Shared/Jenkins --export-json secrets.json --reveal-secrets
```

### Docker Usage

Run in an isolated container without local Python installation:

#### Build and Run
```bash
# Build image
docker-compose build offsec-jenkins

# Decrypt from mounted directory
docker-compose run --rm offsec-jenkins --path /data --reveal-secrets

# Export to JSON
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force
```

#### Prepare Files
Place Jenkins files in `./jenkins_files/`:
```bash
cp extracted/master.key jenkins_files/
cp extracted/hudson.util.Secret jenkins_files/
cp extracted/credentials.xml jenkins_files/
```

Output files are saved to `./outputs/` directory.

**See [DOCKER_USAGE.md](DOCKER_USAGE.md) for complete Docker documentation.**

#### Docker Validation

Automated test suite for Docker environment:
```bash
# Windows
test_docker_validation.bat

# Linux/macOS/WSL
chmod +x test_docker_validation.sh
./test_docker_validation.sh
```

Validates 7 test scenarios: help output, decryption, JSON/CSV export, dry-run mode.

## Jenkins Lab Credential Configuration

Jenkins Lab Docker environment supports user-configurable credentials with zero hardcoded defaults.

### Environment Variables

Configure admin credentials via environment variables:

**docker-compose.yml**:
```yaml
services:
  jenkins:
    environment:
      - JENKINS_ADMIN_USER=myuser
      - JENKINS_ADMIN_PASS=strongpassword123
```

**Command-line**:
```bash
docker-compose up -d \
  -e JENKINS_ADMIN_USER=testuser \
  -e JENKINS_ADMIN_PASS=testpass
```

**Shell export**:
```bash
export JENKINS_USER=ctfuser
export JENKINS_PASS=ctfpass
./examples/full_workflow_example.sh
```

### Default Credential Warning

All components warn when default admin/admin credentials are active:
```
WARNING: Using default admin/admin credentials - CHANGE IN PRODUCTION!
```

Scripts and Docker init processes detect default credentials and emit warnings to prevent production deployment with weak authentication.

**See [JenkinsBreaker/jenkins-lab/README_CREDENTIALS.md](JenkinsBreaker/jenkins-lab/README_CREDENTIALS.md) for comprehensive credential configuration guide.**

## Testing

### Unit Tests

Run comprehensive test suite (61 tests):
```bash
pytest tests/ -v
```

Test coverage:
- AES ECB/CBC decryption with multiple test vectors
- CLI argument parsing
- Secret redaction and detection
- Cross-platform path handling
- JSON/CSV export validation
- Integration tests

### Jenkins Lab Integration Testing

Test against actual Jenkins Lab environment (requires Docker):

#### Windows PowerShell
```powershell
.\test_jenkins_lab.bat
```

#### WSL/Linux
```bash
chmod +x test_jenkins_lab.sh
./test_jenkins_lab.sh
```

The test script will:
1. Extract credentials from Jenkins Lab Docker container
2. Test decryption (redacted and revealed modes)
3. Validate JSON/CSV export
4. Run unit test suite
5. Generate summary report

See `tests/JENKINS_LAB_TESTING.md` for comprehensive Jenkins Lab integration testing documentation.

## Typical Jenkins File Paths

> Useful for post-exploitation, forensic credential recovery, and pipeline hardening audits

| File | Description | Default Linux Path | Alt Locations / Notes |
|------|-------------|------------------|----------------------|
| `master.key` | Key used to encrypt stored Jenkins secrets | `/var/lib/jenkins/secrets/master.key` | Required for offline credential decryption |
| `hudson.util.Secret` | Secondary encryption / secret metadata | `/var/lib/jenkins/secrets/hudson.util.Secret` | Required alongside master.key |
| `credentials.xml` | Global stored secrets for pipelines + agents | `/var/lib/jenkins/credentials.xml` | May appear in: `~/.jenkins/credentials.xml` or per-user workspace |
| `credentials.xml` (user) | User-specific credential entries | `/var/lib/jenkins/users/<USER>/credentials.xml` | Privileged credentials often stored here |
| `config.xml` | Global Jenkins configuration (may contain tokens) | `/var/lib/jenkins/config.xml` | Used in admin takeover hardening tests |
| `jobs/*/config.xml` | Job-level secrets & API tokens | `/var/lib/jenkins/jobs/<JOB_NAME>/config.xml` | Pipeline secret sprawl risk indicator |

### Windows Jenkins Paths
- `C:\Program Files\Jenkins\secrets\master.key`
- `C:\ProgramData\Jenkins\.jenkins\secrets\master.key`
- `%JENKINS_HOME%\secrets\master.key`

### Docker Jenkins Paths
- `/var/jenkins_home/secrets/master.key`
- `/var/jenkins_home/credentials.xml`

## Output Formats

### Terminal Output (Redacted by Default)
```
[*] Loading confidentiality key...
[+] Confidentiality key loaded successfully
[*] Processing credentials.xml
AKIA***REDACTED***MPLE
ghp_***REDACTED***stuv
***REDACTED***
[!] Secrets are redacted by default. Use --reveal-secrets to show plaintext
```

### Terminal Output (Revealed)
```
[*] Loading confidentiality key...
[+] Confidentiality key loaded successfully
[*] Processing credentials.xml
AKIAIOSFODNN7EXAMPLE
ghp_1234567890abcdefghijklmnopqrstuv
admin_password_123
```

### JSON Export Format
```json
[
  {
    "file": "/var/lib/jenkins/credentials.xml",
    "encrypted": "AQAAABAAAAAw...",
    "decrypted": "AKIAIOSFODNN7EXAMPLE",
    "display": "AKIAIOSFODNN7EXAMPLE"
  },
  {
    "file": "/var/lib/jenkins/credentials.xml",
    "encrypted": "LZmC2dQ47FVMe9fI...",
    "decrypted": "ghp_1234567890abcdefghijklmnopqrstuv",
    "display": "ghp_1234567890abcdefghijklmnopqrstuv"
  }
]
```

### CSV Export Format
```csv
file,encrypted,decrypted,display
/var/lib/jenkins/credentials.xml,AQAAABAAAAAw...,AKIAIOSFODNN7EXAMPLE,AKIAIOSFODNN7EXAMPLE
/var/lib/jenkins/credentials.xml,LZmC2dQ47FVMe9fI...,ghp_1234567890abcdefghijklmnopqrstuv,ghp_1234567890abcdefghijklmnopqrstuv
```

## Red Team Operational Context

### Post-Exploitation Workflow

1. Compromise Jenkins server via CVE or credential abuse
2. Extract key material:
   ```bash
   # Extract files from compromised host
   scp user@jenkins:/var/jenkins_home/secrets/master.key .
   scp user@jenkins:/var/jenkins_home/secrets/hudson.util.Secret .
   scp user@jenkins:/var/jenkins_home/credentials.xml .
   ```

3. Decrypt offline:
   ```bash
   python3 decrypt.py --key master.key --secret hudson.util.Secret --xml credentials.xml --reveal-secrets
   ```

4. Pivot to cloud infrastructure:
   - Use AWS keys for cloud enumeration
   - Use GitHub tokens for source code access
   - Use SSH keys for lateral movement

### CTF/HTB Usage

Extract Jenkins credentials during CTF challenges:
```bash
# Find Jenkins files
find / -name master.key 2>/dev/null
find / -name hudson.util.Secret 2>/dev/null

# Decrypt
python3 decrypt.py --path /var/lib/jenkins --reveal-secrets
```

### Integration with Red Team Tools

Export for automation:
```bash
# Export to JSON for scripting
python3 decrypt.py --path /var/lib/jenkins --export-json creds.json --reveal-secrets

# Parse with jq
cat creds.json | jq -r '.[] | select(.decrypted | contains("AKIA")) | .decrypted'
```

## Security Controls

### Redaction
Secrets are redacted by default to prevent accidental exposure in logs or screenshots:
```
AKIAIOSFODNN7EXAMPLE → AKIA***REDACTED***MPLE
ghp_1234567890abcdefghijklmnopqrstuv → ghp_***REDACTED***stuv
admin_password → ***REDACTED***
```

Use `--reveal-secrets` to show plaintext.

### Dry-Run Mode
Test decryption without revealing secrets:
```bash
python3 decrypt.py --path /var/lib/jenkins --dry-run
```

Output:
```
[DRY RUN] Found secret (not decrypted)
[DRY RUN] Found secret (not decrypted)
```

### Elevated Privilege Warning
The tool warns if run with unnecessary elevated privileges:
```
[!] WARNING: Running with elevated privileges (Administrator)
[!] This tool does not require elevated privileges
```

## Technical Details

### Encryption Formats

#### AES-ECB (Old Format)
- Used in Jenkins < 2.0
- 16-byte blocks
- PKCS#7 padding
- Magic marker: `::::MAGIC::::`

#### AES-CBC (New Format)
- Used in Jenkins >= 2.0
- 16-byte IV prepended
- PKCS#7 padding
- Format byte: `0x01`

### Decryption Process

1. Load `master.key` (hex string)
2. Derive AES-128 key via SHA-256
3. Decrypt `hudson.util.Secret` with derived key (AES-ECB)
4. Extract confidentiality key (first 16 bytes before magic marker)
5. Decrypt credentials using confidentiality key (AES-ECB or AES-CBC)
6. Remove padding and decode to UTF-8

## Documentation

### Main Documentation
- `README.md` - This file
- `DOCKER_USAGE.md` - Complete Docker usage guide

### Test Documentation
- `tests/README.md` - Test suite overview
- `tests/JENKINS_LAB_TESTING.md` - Jenkins Lab integration testing
- `pytest.ini` - Pytest configuration
- `test_docker_validation.bat` - Windows Docker validation
- `test_docker_validation.sh` - Linux Docker validation

## Troubleshooting

### Error: master.key not found
Ensure you're pointing to the correct Jenkins directory:
```bash
find / -name master.key 2>/dev/null
```

### Error: Decryption failed
- Verify `hudson.util.Secret` is a binary file (not text)
- Check file wasn't corrupted during transfer
- Ensure files are from the same Jenkins instance

### Error: No secrets found
- Verify `credentials.xml` contains encrypted values
- Check XML structure is valid
- Ensure credentials were configured in Jenkins

### Windows: Script execution fails silently
Direct execution (`.\decrypt.py`) may fail without output due to Windows file associations. Always invoke with `python`:
```powershell
# Correct
python decrypt.py --help

# Incorrect (may fail silently)
.\decrypt.py --help
```

### Windows: python3 not found
Use `python` instead of `python3`:
```powershell
python decrypt.py --help
```

### Windows: Virtualenv corruption
If commands produce no output or fail unexpectedly, rebuild the virtualenv:
```powershell
# Remove corrupted virtualenv
rmdir /s /q .venv

# Recreate and install dependencies
python -m venv .venv
.venv\Scripts\python.exe -m pip install pycryptodome

# Test
python decrypt.py --help
```

## Performance

- **Decryption**: ~1ms per secret
- **Large credential files** (100+ secrets): < 1 second total
- **Recursive scanning**: Linear performance based on directory size
- **Docker overhead**: ~50-100ms container startup (negligible for batch operations)
- **Memory footprint**: < 50MB RAM typical usage

## Limitations

- **Offline-only operation** - Requires extracted key files (not for online exploitation)
- **Required files** - Cannot decrypt without both `master.key` and `hudson.util.Secret`
- **Format support** - AES-ECB and AES-CBC only (covers Jenkins 1.x through latest 2.x)
- **XML parsing** - Minimal error recovery for corrupted/malformed XML structures

## Roadmap

Active development continues in the [JenkinsBreaker](https://github.com/ridpath/heaplessNights/tree/main/JenkinsBreaker) exploitation framework with planned enhancements:

### Interface Evolution
- **Textual-based TUI** - Terminal UI for interactive exploitation workflows
- **Browser-based interface** - Web UI for distributed team operations and reporting

### Offensive Capabilities
- **Jenkinsfuzzer** - Automated pipeline misconfiguration discovery and exploitation chaining
- **Enhanced JWT cryptanalysis** - Advanced token forgery and privilege escalation techniques
- **Plugin fingerprinting** - Comprehensive vulnerability mapping across Jenkins plugin ecosystem

### Persistence Architecture
- **Modular persistence extension packs** - Production-grade backdoor frameworks for long-term access retention across Jenkins infrastructure updates

### Testing Environment
JenkinsBreaker includes a fully containerized Jenkins Lab environment for validation and development:
- **Location**: `JenkinsBreaker/jenkins-lab`
- **Access**: `http://localhost:8080` (credentials: `admin/admin` - configurable via environment variables)
- **Docker**: Tested on Docker 29.1.5+ across Windows WSL2, Linux, and macOS environments

All roadmap features prioritize operational security, stealth, and real-world deployment constraints for professional security assessment teams.

## Legal Notice

This tool is for authorized security assessments, penetration testing, CTF competitions, and educational purposes only.

Unauthorized access to computer systems is illegal. Use only on systems you have explicit permission to test.

The authors assume no liability for misuse of this software.

## Attribution

Portions of the decryption logic are based on research from [gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins).

This version has been significantly extended with:
- Cross-platform support (Windows/Linux/macOS/WSL)
- CLI interface with comprehensive flags
- Export functionality (JSON/CSV)
- Security controls (redaction, dry-run)
- Automated testing (61 unit tests)
- Jenkins Lab integration
- Docker containerization with portable execution
- User-configurable credential system (zero hardcoded defaults)
- Production-ready warning systems

## License

See `LICENSE` file for details.

---

**For unit test documentation, see**: `tests/README.md`

**For Jenkins Lab integration testing, see**: `tests/JENKINS_LAB_TESTING.md`
