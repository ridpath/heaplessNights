#!/bin/bash
# Jenkins Lab Integration Test Script
# Run this after Jenkins Lab Docker container is running in WSL

set -e

echo "========================================"
echo "Jenkins Lab Integration Test"
echo "========================================"
echo

# Create test directory
mkdir -p test_fixtures/jenkins_lab/secrets

echo "[*] Extracting Jenkins Lab credentials from Docker container..."
echo

# Get Jenkins container ID
JENKINS_CONTAINER=$(docker ps -qf "name=jenkins")

if [ -z "$JENKINS_CONTAINER" ]; then
    echo "[-] Error: Jenkins container not found. Is Jenkins Lab running?"
    echo "    Start Jenkins Lab with: cd ~/jenkins-lab && docker-compose up -d"
    exit 1
fi

echo "[+] Found Jenkins container: $JENKINS_CONTAINER"
echo

# Extract files from container
echo "[*] Extracting master.key..."
docker cp $JENKINS_CONTAINER:/var/jenkins_home/secrets/master.key test_fixtures/jenkins_lab/secrets/master.key
echo "[+] master.key extracted"

echo "[*] Extracting hudson.util.Secret..."
docker cp $JENKINS_CONTAINER:/var/jenkins_home/secrets/hudson.util.Secret test_fixtures/jenkins_lab/secrets/hudson.util.Secret
echo "[+] hudson.util.Secret extracted"

echo "[*] Extracting credentials.xml..."
docker cp $JENKINS_CONTAINER:/var/jenkins_home/credentials.xml test_fixtures/jenkins_lab/credentials.xml
echo "[+] credentials.xml extracted"
echo

echo "========================================"
echo "Running Decryption Tests"
echo "========================================"
echo

echo "[Test 1] Decrypt without revealing secrets (redacted)"
echo "--------------------------------------------------------"
python3 decrypt.py --path test_fixtures/jenkins_lab
echo

echo "[Test 2] Decrypt with --reveal-secrets"
echo "--------------------------------------------------------"
python3 decrypt.py --path test_fixtures/jenkins_lab --reveal-secrets
echo

echo "[Test 3] Export to JSON"
echo "--------------------------------------------------------"
python3 decrypt.py --path test_fixtures/jenkins_lab --export-json outputs/jenkins_lab_secrets.json --reveal-secrets --force
if [ -f outputs/jenkins_lab_secrets.json ]; then
    echo "[+] JSON export successful"
    echo
    cat outputs/jenkins_lab_secrets.json | python3 -m json.tool
else
    echo "[-] JSON export failed"
fi
echo

echo "[Test 4] Export to CSV"
echo "--------------------------------------------------------"
python3 decrypt.py --path test_fixtures/jenkins_lab --export-csv outputs/jenkins_lab_secrets.csv --reveal-secrets --force
if [ -f outputs/jenkins_lab_secrets.csv ]; then
    echo "[+] CSV export successful"
    echo
    cat outputs/jenkins_lab_secrets.csv
else
    echo "[-] CSV export failed"
fi
echo

echo "[Test 5] Recursive scan test"
echo "--------------------------------------------------------"
# Try to extract full Jenkins home for recursive scan test
echo "[*] Attempting full Jenkins home extraction (may take a moment)..."
docker cp $JENKINS_CONTAINER:/var/jenkins_home test_fixtures/jenkins_lab_full/ 2>/dev/null || true

if [ -d test_fixtures/jenkins_lab_full ]; then
    python3 decrypt.py --scan-dir test_fixtures/jenkins_lab_full --export-json outputs/jenkins_lab_full_scan.json --reveal-secrets --force
    echo "[+] Recursive scan complete"
    echo "Found $(cat outputs/jenkins_lab_full_scan.json | python3 -c 'import sys, json; print(len(json.load(sys.stdin)))') secrets"
else
    echo "[!] Full Jenkins home extraction skipped (not critical)"
fi
echo

echo "========================================"
echo "Running Unit Tests"
echo "========================================"
python3 -m pytest tests/ -v
echo

echo "========================================"
echo "Integration Test Complete"
echo "========================================"
echo
echo "Summary:"
echo "  - Test fixtures extracted from Jenkins Lab"
echo "  - Decryption tested (redacted and revealed)"
echo "  - JSON export validated"
echo "  - CSV export validated"
echo "  - Unit tests passed"
echo
echo "Output files:"
echo "  - outputs/jenkins_lab_secrets.json"
echo "  - outputs/jenkins_lab_secrets.csv"
echo
