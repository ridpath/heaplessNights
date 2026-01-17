# Jenkins Lab Secrets Reference

This document lists all planted secrets in the Jenkins Lab for testing exploitation and credential extraction capabilities.

## Credentials Configuration

### Jenkins System Credentials

The following credentials are configured via init.groovy.d/03-configure-credentials.groovy:

| ID | Type | Username | Password/Secret | Description |
|---|---|---|---|---|
| aws-credentials | UsernamePassword | AKIAIOSFODNN7EXAMPLE | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY | AWS Access Credentials |
| aws-secret-key | Secret String | - | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY | AWS Secret Access Key |
| github-token | Secret String | - | ghp_ExampleTokenString123456789ABC | GitHub API Token |
| docker-registry | UsernamePassword | dockeruser | dockerpassword123 | Docker Registry Credentials |
| npm-token | Secret String | - | npm_ExampleTokenString123456789 | NPM Registry Token |
| database-admin | UsernamePassword | dbadmin | DB_@dm1n_P@ssw0rd_2024! | Database Admin |
| heroku-api-key | Secret String | - | abcdef12-3456-7890-abcd-ef1234567890 | Heroku API Key |
| cloudflare-token | Secret String | - | CloudflareTokenExample123456789ABC | Cloudflare API Token |
| stripe-secret-key | Secret String | - | sk_live_51AbCd... | Stripe Secret Key |
| sendgrid-api-key | Secret String | - | SG.AbCdEfGh... | SendGrid API Key |
| twilio-auth-token | Secret String | - | abcdef1234567890abcdef1234567890 | Twilio Auth Token |
| slack-bot-token | Secret String | - | xoxb-0123456789-0123456789012-AbCd... | Slack Bot Token |
| datadog-api-key | Secret String | - | abcdef1234567890abcdef1234567890 | Datadog API Key |
| jwt-secret | Secret String | - | jwt-secret-key-256-bits-change-in-production-environment | JWT Secret |
| api-master-key | Secret String | - | sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 | API Master Key |
| prod-server-ssh | SSH Key | deploy | - | Production Server SSH Key |

## File-Based Secrets

### Home Directory Secrets

**Location**: /home/jenkins/

| Path | Content | Purpose |
|---|---|---|
| ~/.aws/credentials | AWS profiles (default, production) | AWS CLI configuration |
| ~/.ssh/id_rsa | RSA private key | SSH authentication |
| ~/.npmrc | NPM auth token | NPM package publishing |
| ~/.docker/config.json | Docker registry auth | Container registry access |
| ~/.m2/settings.xml | Maven repository credentials | Artifact repository |
| ~/.config/database.env | Database credentials | Multiple DB connections |
| ~/.config/api_keys.env | Third-party API keys | External service integration |

### Job-Embedded Secrets

#### vulnerable-pipeline (config.xml)
- AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
- AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
- DATABASE_URL: postgresql://admin:SuperSecret123@db.example.com:5432/production
- API_TOKEN: sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
- SLACK_WEBHOOK: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX

#### database-migration (config.xml)
- DB_PASSWORD: M1gr@t10n_P@ssw0rd_2024!
- REDIS_URL: redis://:SuperSecretRedisPass2024@...
- MONGODB_URI: mongodb://admin:MongoDBSecretPass123@...

#### api-deployment (config.xml)
- STRIPE_SECRET_KEY: sk_live_51AbCd...
- SENDGRID_API_KEY: SG.AbCdEf...
- TWILIO_AUTH_TOKEN: abcdef1234567890...
- GITHUB_OAUTH_TOKEN: ghp_AbCd...
- SLACK_BOT_TOKEN: xoxb-0123456789...
- DATADOG_API_KEY: abcdef1234567890...

#### build-artifacts (config.xml)
Creates build artifacts containing:
- .env file with multiple secrets
- config.json with API keys and DB credentials
- credentials.txt with production access details
- app.config with connection strings

## Privilege Escalation Vectors

### Sudo Configuration

**File**: /etc/sudoers and /etc/sudoers.d/jenkins-backup

```
jenkins ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/docker, /bin/systemctl, /usr/bin/tar, /usr/bin/find
jenkins ALL=(root) NOPASSWD: /opt/scripts/backup.sh
```

### Cronjobs

**File**: /etc/cron.d/jenkins-backup

```
0 2 * * * jenkins /opt/scripts/backup.sh >> /var/log/jenkins_backup.log 2>&1
```

The backup script (/opt/scripts/backup.sh) contains embedded AWS credentials.

### Writable Scripts

**Location**: /tmp/scripts/deploy.sh

World-writable script (chmod 777) containing AWS credentials that could be modified for privilege escalation.

## Environment Variables

Jenkins container runs with the following environment variables:

- JENKINS_USER=admin
- JENKINS_PASS=admin
- AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
- AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

## Extraction Testing

### Manual Verification

To manually verify secret placement after container start:

```bash
# Access container
docker exec -it jenkins-lab-jenkins-1 /bin/bash

# Check AWS credentials
cat /home/jenkins/.aws/credentials

# Check SSH key
cat /home/jenkins/.ssh/id_rsa

# Check environment files
cat /home/jenkins/.config/database.env
cat /home/jenkins/.config/api_keys.env

# Check backup script
cat /opt/scripts/backup.sh

# Check Jenkins secrets directory
ls -la /var/jenkins_home/secrets/

# Check sudo rights
sudo -l

# Check cronjobs
cat /etc/cron.d/jenkins-backup
```

### Automated Extraction (JenkinsBreaker)

JenkinsBreaker should be able to extract all these secrets via:
- Credential XML parsing
- Job configuration analysis
- File system traversal (post-exploitation)
- Environment variable enumeration

## Security Notes

All credentials are EXAMPLE/TEST credentials only. Never use these in production.

The intentional vulnerabilities include:
- Credentials hardcoded in job definitions
- Secrets in environment variables
- Overly permissive sudo configuration
- Writable scripts with elevated privileges
- Scheduled tasks with embedded credentials
- SSH keys with weak permissions
