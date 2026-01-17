# Jenkins Lab Credentials Configuration

## Overview

The Jenkins Lab Docker setup allows you to **specify your own credentials** instead of using hardcoded defaults.

## Default Credentials (Testing Only)

If you don't specify custom credentials, the lab uses:
- **Username**: `admin`
- **Password**: `admin`

**⚠️ WARNING**: These are insecure defaults for testing purposes only. Always change them for any non-local usage.

---

## Setting Custom Credentials

### Method 1: Environment Variables (Recommended)

Edit `docker-compose.yml` and uncomment/modify the environment variables:

```yaml
environment:
  - JENKINS_ADMIN_USER=myuser
  - JENKINS_ADMIN_PASS=strongpassword123
```

Then start Jenkins:
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

Create a `.env` file in the `jenkins-lab` directory:

```bash
JENKINS_ADMIN_USER=myuser
JENKINS_ADMIN_PASS=strongpassword123
```

Docker Compose will automatically load these variables.

---

## Verification

After starting Jenkins, check the logs:

```bash
docker logs jenkins-lab
```

You should see:
```
Jenkins configured with admin user: myuser
```

If using default credentials, you'll also see:
```
WARNING: Using default admin/admin credentials - CHANGE IN PRODUCTION!
```

---

## Security Best Practices

1. **Never use admin/admin in production**
2. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. **Change credentials after initial setup** via Jenkins UI
4. **Enable additional authentication** (LDAP, SSO, etc.) for production
5. **Restrict network access** to Jenkins (firewall, VPN, etc.)

---

## Accessing Jenkins

1. Start the lab:
   ```bash
   docker-compose up -d
   ```

2. Access Jenkins at http://localhost:8080

3. Log in with your configured credentials (or admin/admin if defaults)

4. Configure additional security settings in **Manage Jenkins** → **Configure Global Security**

---

## Credential Management for Testing

Once logged in, you can add test credentials for decryption testing:

1. Go to **Manage Jenkins** → **Manage Credentials**
2. Click **(global)** domain
3. Click **Add Credentials**
4. Add various credential types:
   - **Username with password** (for basic auth)
   - **Secret text** (for API tokens, AWS keys, GitHub tokens)
   - **SSH Username with private key** (for SSH keys)

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

If you set `JENKINS_ADMIN_USER` but still can't log in:

1. Check logs: `docker logs jenkins-lab`
2. Ensure variables are set in docker-compose.yml
3. Recreate container:
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### Reset to Default Credentials

```bash
docker-compose down -v
docker-compose up -d
# Now uses admin/admin again
```

---

## Example: CTF/Training Setup

For a training environment with custom credentials:

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
# Use JenkinsBreaker with your credentials
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

✅ **Credentials are configurable** via environment variables  
✅ **No hardcoded admin/admin enforcement**  
✅ **Defaults exist for convenience** (with warnings)  
✅ **Multiple configuration methods** (compose, CLI, .env file)  
✅ **Security warnings** when using weak defaults  

Users have full control over credentials used in the Jenkins lab environment.
