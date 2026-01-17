# Jenkins Lab Credentials Configuration

## Overview

The Jenkins Lab Docker setup allows credential specification instead of using hardcoded defaults.

## Default Credentials (Testing Only)

Without custom configuration, the lab uses:
- **Username**: `admin`
- **Password**: `admin`

**WARNING**: These are insecure defaults for local testing only. Change credentials for any non-isolated usage.

---

## Setting Custom Credentials

### Method 1: Environment Variables (Recommended)

Edit `docker-compose.yml` and modify the environment variables:

```yaml
environment:
  - JENKINS_ADMIN_USER=myuser
  - JENKINS_ADMIN_PASS=strongpassword123
```

Start Jenkins:
```bash
docker-compose up -d
```

### Method 2: Command Line

Override environment variables at runtime:

```bash
docker-compose up -d \
  -e JENKINS_ADMIN_USER=myuser \
  -e JENKINS_ADMIN_PASS=strongpassword123
```

Or with plain Docker:
```bash
docker run -d \
  -p 8080:8080 \
  -e JENKINS_ADMIN_USER=myuser \
  -e JENKINS_ADMIN_PASS=strongpassword123 \
  jenkins-lab
```

### Method 3: .env File

Create `.env` file in the `jenkins-lab` directory:

```bash
JENKINS_ADMIN_USER=myuser
JENKINS_ADMIN_PASS=strongpassword123
```

Docker Compose automatically loads these variables.

---

## Verification

Check logs after starting Jenkins:

```bash
docker logs jenkins-lab
```

Expected output with custom credentials:
```
Jenkins configured with admin user: myuser
```

With default credentials:
```
WARNING: Using default admin/admin credentials - CHANGE IN PRODUCTION!
```

---

## Security Best Practices

1. Never use admin/admin in production environments
2. Use strong passwords (12+ characters, mixed case, numbers, symbols)
3. Change credentials after initial setup via Jenkins UI
4. Enable additional authentication (LDAP, SSO) for production
5. Restrict network access to Jenkins (firewall, VPN)

---

## Accessing Jenkins

Start the lab:
```bash
docker-compose up -d
```

Access Jenkins at http://localhost:8080

Log in with configured credentials (or admin/admin if using defaults)

Configure additional security in **Manage Jenkins** → **Configure Global Security**

---

## Credential Management for Testing

After login, add test credentials for decryption validation:

1. Navigate to **Manage Jenkins** → **Manage Credentials**
2. Click **(global)** domain
3. Click **Add Credentials**
4. Add credential types:
   - **Username with password** (basic auth)
   - **Secret text** (API tokens, AWS keys, GitHub PATs)
   - **SSH Username with private key** (SSH keys)

5. Extract files for decryption testing:
   ```bash
   docker cp jenkins-lab:/var/jenkins_home/secrets/master.key .
   docker cp jenkins-lab:/var/jenkins_home/secrets/hudson.util.Secret .
   docker cp jenkins-lab:/var/jenkins_home/credentials.xml .
   ```

6. Decrypt with offsec-jenkins:
   ```bash
   cd ../../offsec-jenkins
   python decrypt.py --key ../JenkinsBreaker/jenkins-lab/master.key \
                     --secret ../JenkinsBreaker/jenkins-lab/hudson.util.Secret \
                     --xml ../JenkinsBreaker/jenkins-lab/credentials.xml \
                     --reveal-secrets
   ```

---

## Troubleshooting

### Cannot Login with Custom Credentials

If `JENKINS_ADMIN_USER` is set but login fails:

1. Check logs: `docker logs jenkins-lab`
2. Verify variables in docker-compose.yml
3. Recreate container:
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### Reset to Default Credentials

```bash
docker-compose down -v
docker-compose up -d
```

Lab now uses admin/admin again.

---

## Example: CTF/Training Setup

Training environment with custom credentials:

**docker-compose.yml**:
```yaml
environment:
  - JENKINS_ADMIN_USER=ctfplayer
  - JENKINS_ADMIN_PASS=training2024!
```

**Start lab**:
```bash
docker-compose up -d
```

**Access**:
- URL: http://localhost:8080
- Username: `ctfplayer`
- Password: `training2024!`

**Exploit and decrypt**:
```bash
# Use JenkinsBreaker with credentials
python JenkinsBreaker.py --url http://localhost:8080 \
                         --username ctfplayer \
                         --password 'training2024!' \
                         --auto

# Decrypt extracted credentials
cd ../offsec-jenkins
python decrypt.py --path extracted_files --reveal-secrets
```

---

## Summary

- Credentials configurable via environment variables
- No hardcoded admin/admin enforcement
- Defaults provided for convenience with warnings
- Multiple configuration methods (compose, CLI, .env file)
- Security warnings when using weak defaults

Users have full control over credentials in the Jenkins lab environment.
