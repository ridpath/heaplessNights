<!--
Jenkins credential decryptor, decrypt Jenkins master.key, decode hudson.util.Secret,
CI/CD security tools, DevOps post exploitation, cloud identity abuse detection,
pipeline credential recovery, decrypt Jenkins credentials.xml, AES CBC/ECB Jenkins decode,
secure DevOps assessment, supply chain security validation, cloud token extraction,
DevSecOps research utilities, IAM escalation via CI/CD, attack path from build server,
blue team Jenkins hardening, secure CI pipeline, infrastructure security research,
authorized penetration testing CI/CD, credential leak detection Jenkins,
build runner secret reconnaissance, DevOps lateral movement mapping, caputre the flag, ctf hack the box, htb
-->

# Jenkins Credential Decryptor

This Python script is a post-exploitation utility designed for penetration testers and red team operators to decrypt stored Jenkins credentials **offline**. It recovers plaintext secrets from Jenkins `credentials.xml` using the `master.key` and `hudson.util.Secret` files.

---

## Use Case

When Jenkins is compromised, attackers can access the following:

- `secrets/master.key`
- `secrets/hudson.util.Secret`
- `credentials.xml` (in user directories or global config)

This script decrypts those credential entries, including:

- API tokens  
- SSH keys  
- Stored passwords

---

## Features

- Automatically sets up a local Python virtual environment  
- Supports both old (ECB) and new (CBC) AES encryption formats  
- Interactive mode for manual decryption  
- Batch decryption of full `credentials.xml` files  
- Handles base64 decoding and PKCS#7 unpadding  

---

## Dependencies

- Python 3.6+  
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) *(auto-installed inside a `.venv`)*

---

## Example Usage

```bash
python3 decrypt.py /var/lib/jenkins/
# OR
python3 decrypt.py master.key hudson.util.Secret credentials.xml
# OR interactive mode
python3 decrypt.py -i /var/lib/jenkins/
```
## Typical Jenkins File Paths {#jenkins-paths}

> Useful for **post-exploitation**, **forensic credential recovery**, and **pipeline hardening audits**

| File | Description | Default Linux Path | Alt Locations / Notes |
|------|-------------|------------------|----------------------|
| `master.key` | Key used to encrypt stored Jenkins secrets | `/var/lib/jenkins/secrets/master.key` | Required for **offline credential decryption** |
| `hudson.util.Secret` | Secondary encryption / secret metadata | `/var/lib/jenkins/secrets/hudson.util.Secret` | Required alongside master.key |
| `credentials.xml` | Global stored secrets for pipelines + agents | `/var/lib/jenkins/credentials.xml` | May appear in: `~/.jenkins/credentials.xml` or per-user workspace |
| `credentials.xml` (folder form) | Folder containing credential entries | `/var/lib/jenkins/users/<USER>/credentials.xml` | **Privileged credentials** often stored here |
| `config.xml` | Global Jenkins configuration (may contain tokens) | `/var/lib/jenkins/config.xml` | Used in **admin takeover** hardening tests |
| `jobs/*/config.xml` | Job-level secrets & API tokens | `/var/lib/jenkins/jobs/<JOB_NAME>/config.xml` | Pipeline secret sprawl risk indicator |

<!--
SEO: Jenkins master.key location, hudson.util.Secret path, decrypt credentials.xml,
Jenkins credential exposure, CI/CD post exploitation, Jenkins forensics,
Linux Jenkins file storage, Jenkins token recovery path
-->


Pentesting Context
This tool is ideal for red team post-exploitation during:

CI/CD pipeline credential extraction

Lateral movement via build infrastructure

Reconnaissance on DevOps/infra assets

Token harvesting (e.g., AWS, GitHub, cloud APIs)

## Legal Notice
Use only on systems you have explicit permission to test.
This tool is for educational and authorized security assessments only.

## Attribution
Portions of the decryption logic are based on the excellent research and code from
gquere/pwn_jenkins.
This version has been significantly adapted and extended for modern post-exploitation workflows.

<!--
Long-tail indexing:
jenkins security, decrypt credentials pipeline, offline Jenkins password decode,
post-CI compromise research tools, DevSecOps credential exposure, build secret audit,
token recovery python, exploit Jenkins credential storage, cyber defense build systems,
cloud API token leakage from CI/CD, forensic Jenkins credential decode,
CI/CD zero-trust testing tools, exploit hudson.util.Secret, Jenkins AES decrypt script,
penetration testing DevOps pipelines, secure software supply chain research,
credential vault misconfigurations in CI, security assessment Jenkins credentials,
post-exploitation CI runner, secure developer workflow hardening

Tool classification:
- Domain: CI/CD infiltration & defense
- Audience: Red/Purple Teams, DevSecOps, Cloud Security Analysts, Incident Responders
- Ethics: Authorized environments only

Search anchors:
DevOps security toolkit, credential security automation, CI/CD defense engineering
-->


---
