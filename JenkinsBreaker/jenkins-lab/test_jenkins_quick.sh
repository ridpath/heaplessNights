#!/bin/bash

# Configuration - can be overridden with environment variables
JENKINS_URL="${JENKINS_URL:-http://localhost:8080}"
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-admin}"

echo "[*] Quick Jenkins Lab Test"
echo ""

echo "[1] Docker containers:"
docker ps --filter name=jenkins

echo ""
echo "[2] Jenkins accessibility:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" "$JENKINS_URL"

echo ""
echo "[3] Jenkins version:"
curl -s -I "$JENKINS_URL" | grep X-Jenkins

echo ""
echo "[4] Jenkins API with auth:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/api/json"

echo ""
echo "[5] Script console access:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/script"

echo ""
echo "[6] Plugin manager:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/pluginManager/api/json"

echo ""
echo "[*] Quick test complete"
