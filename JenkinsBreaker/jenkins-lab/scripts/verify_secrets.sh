#!/bin/bash

set -e

# Detect Docker Compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    COMPOSE_CMD="docker compose"
fi

CONTAINER_NAME=$(docker ps --filter "name=jenkins" --format "{{.Names}}" | head -n 1)

if [ -z "$CONTAINER_NAME" ]; then
    CONTAINER_NAME="jenkins-lab-jenkins-1"
fi

echo "======================================"
echo "Jenkins Lab Secrets Verification"
echo "======================================"
echo ""

if ! docker ps | grep -q jenkins; then
    echo "ERROR: Jenkins container is not running"
    echo "Run: $COMPOSE_CMD up -d"
    exit 1
fi

echo "[*] Checking AWS credentials..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.aws/credentials 2>/dev/null | grep -q "AKIAIOSFODNN7EXAMPLE"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] AWS credentials found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] AWS credentials NOT found"
fi

echo ""
echo "[*] Checking SSH private key..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.ssh/id_rsa 2>/dev/null | grep -q "BEGIN RSA PRIVATE KEY"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] SSH private key found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] SSH private key NOT found"
fi

echo ""
echo "[*] Checking database credentials..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.config/database.env 2>/dev/null | grep -q "DB_PASSWORD"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Database credentials found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Database credentials NOT found"
fi

echo ""
echo "[*] Checking API keys..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.config/api_keys.env 2>/dev/null | grep -q "STRIPE_SECRET_KEY"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] API keys found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] API keys NOT found"
fi

echo ""
echo "[*] Checking cloud credentials..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.config/cloud.env 2>/dev/null | grep -q "AZURE_CLIENT_SECRET"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Cloud credentials found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Cloud credentials NOT found"
fi

echo ""
echo "[*] Checking NPM token..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.npmrc 2>/dev/null | grep -q "_authToken"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] NPM token found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] NPM token NOT found"
fi

echo ""
echo "[*] Checking Docker config..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.docker/config.json 2>/dev/null | grep -q "auths"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Docker config found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Docker config NOT found"
fi

echo ""
echo "[*] Checking Maven settings..."
if docker exec $CONTAINER_NAME cat /home/jenkins/.m2/settings.xml 2>/dev/null | grep -q "deployment123"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Maven settings found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Maven settings NOT found"
fi

echo ""
echo "[*] Checking backup script..."
if docker exec $CONTAINER_NAME cat /opt/scripts/backup.sh 2>/dev/null | grep -q "AWS_SECRET_ACCESS_KEY"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Backup script with secrets found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Backup script NOT found"
fi

echo ""
echo "[*] Checking Jenkins secrets directory..."
if docker exec $CONTAINER_NAME ls /var/jenkins_home/secrets/ 2>/dev/null | grep -q "aws_credentials"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Jenkins secrets directory populated"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Jenkins secrets directory NOT found"
fi

echo ""
echo "[*] Checking environment variables..."
if docker exec $CONTAINER_NAME printenv | grep -q "AWS_ACCESS_KEY_ID"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Environment variables with secrets found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Environment variables NOT found"
fi

echo ""
echo "[*] Checking sudo configuration..."
if docker exec $CONTAINER_NAME sudo -l 2>/dev/null | grep -q "NOPASSWD"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Sudo NOPASSWD configuration found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Sudo configuration NOT found"
fi

echo ""
echo "[*] Checking cronjob..."
if docker exec $CONTAINER_NAME cat /etc/cron.d/jenkins-backup 2>/dev/null | grep -q "backup.sh"; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Cronjob found"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Cronjob NOT found"
fi

echo ""
echo "[*] Checking Jenkins jobs..."
JOBS=$(docker exec $CONTAINER_NAME ls /usr/share/jenkins/ref/jobs/ 2>/dev/null || echo "")
if [ -n "$JOBS" ]; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Jobs found: $(echo $JOBS | tr '\n' ' ')"
else
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] No jobs found"
fi

echo ""
echo "[*] Checking Jenkins credentials..."
sleep 2
CREDS=$(docker exec $CONTAINER_NAME curl -s http://admin:admin@localhost:8080/credentials/ 2>/dev/null || echo "")
if [ -n "$CREDS" ]; then
    echo "    [ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Jenkins credentials accessible"
else
    echo "    [!] Jenkins may still be starting (credentials check failed)"
fi

echo ""
echo "======================================"
echo "Verification Complete"
echo "======================================"
echo ""
echo "To manually inspect secrets, run:"
echo "  docker exec -it $CONTAINER_NAME /bin/bash"
echo ""
echo "Then check:"
echo "  cat /home/jenkins/.aws/credentials"
echo "  cat /home/jenkins/.ssh/id_rsa"
echo "  cat /home/jenkins/.config/database.env"
echo "  cat /var/jenkins_home/secrets/*"
echo "  sudo -l"
echo ""
