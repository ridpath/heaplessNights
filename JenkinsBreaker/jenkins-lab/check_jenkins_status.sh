#!/bin/bash

# Configuration - can be overridden with environment variables
JENKINS_URL="${JENKINS_URL:-http://localhost:8080}"
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-admin}"

echo "Checking Jenkins status..."
echo ""

echo "[1] Container status:"
docker ps --filter name=jenkins-lab --format "  Status: {{.Status}}"

echo ""
echo "[2] Jenkins version:"
curl -s -I "$JENKINS_URL" | grep X-Jenkins || echo "  Not accessible"

echo ""
echo "[3] Plugin API:"
PLUGIN_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/pluginManager/api/json")
echo "  HTTP $PLUGIN_RESPONSE"

echo ""
echo "[4] Credentials API:"
CREDS_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/credentials/")
echo "  HTTP $CREDS_RESPONSE"

echo ""
echo "[5] Script console:"
SCRIPT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/script")
echo "  HTTP $SCRIPT_RESPONSE"

echo ""
echo "[6] Jobs:"
JOBS=$(curl -s -u "$JENKINS_USER:$JENKINS_PASS" "$JENKINS_URL/api/json?tree=jobs[name]" 2>/dev/null)
if echo "$JOBS" | grep -q "name"; then
    echo "$JOBS" | python3 -c 'import sys,json;[print(f"  - {j[\"name\"]}") for j in json.load(sys.stdin).get("jobs",[])]' 2>/dev/null || echo "  Parse error"
else
    echo "  No jobs found or API error"
fi

echo ""
echo "Done."
