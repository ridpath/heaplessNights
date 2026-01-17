#!/bin/bash

set -e

# Configuration - can be overridden with environment variables
JENKINS_URL="${JENKINS_URL:-http://localhost:8080}"
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-admin}"

# Warn if using default credentials
if [ "$JENKINS_USER" = "admin" ] && [ "$JENKINS_PASS" = "admin" ]; then
    echo "[!] WARNING: Using default credentials (admin/admin)"
    echo "[!] Set JENKINS_USER and JENKINS_PASS environment variables for custom credentials"
    echo ""
fi

echo "[*] Jenkins API Token Generator"
echo ""

if ! curl -s "$JENKINS_URL" > /dev/null 2>&1; then
    echo "[!] Jenkins is not running. Please start the lab first."
    echo "[*] Run: ./scripts/setup.sh"
    exit 1
fi

echo "[*] Generating API token for user: $JENKINS_USER"

CRUMB=$(curl -s -u "$JENKINS_USER:$JENKINS_PASS" \
    "$JENKINS_URL/crumbIssuer/api/json" | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['crumb'])" 2>/dev/null || echo "")

if [ -z "$CRUMB" ]; then
    echo "[!] Failed to get CSRF crumb. CSRF protection might be disabled."
    echo "[*] Trying without crumb..."
    
    TOKEN_RESPONSE=$(curl -s -X POST -u "$JENKINS_USER:$JENKINS_PASS" \
        "$JENKINS_URL/user/$JENKINS_USER/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken" \
        --data 'newTokenName=test-token')
else
    TOKEN_RESPONSE=$(curl -s -X POST -u "$JENKINS_USER:$JENKINS_PASS" \
        -H "Jenkins-Crumb: $CRUMB" \
        "$JENKINS_URL/user/$JENKINS_USER/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken" \
        --data 'newTokenName=test-token')
fi

echo ""
echo "[+] API Token Response:"
echo "$TOKEN_RESPONSE"
echo ""
echo "[*] Use this token for authenticated API access:"
echo "    curl -u $JENKINS_USER:<token> $JENKINS_URL/api/json"
