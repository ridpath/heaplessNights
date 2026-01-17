#!/bin/bash
# Docker Validation Script for offsec-jenkins
# Tests that all functionality works with Docker

set -e

echo "========================================"
echo "Docker Validation for offsec-jenkins"
echo "========================================"
echo

cd "$(dirname "$0")"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[SKIP] Docker not installed. Install Docker to test containerized execution."
    echo
    echo "This is optional - the tool works without Docker using native Python."
    echo
    validate_native
    exit 0
fi

echo "[*] Docker detected. Running containerized tests..."
echo

# Build Docker image
echo "[TEST 1] Building Docker image..."
if docker-compose build offsec-jenkins > /dev/null 2>&1; then
    echo "[PASS] Docker image built successfully"
else
    echo "[FAIL] Docker build failed"
    validate_native
    exit 1
fi
echo

# Prepare test files
echo "[TEST 2] Preparing test files..."
mkdir -p jenkins_files
cp test_fixtures/secrets/master.key jenkins_files/
cp test_fixtures/secrets/hudson.util.Secret jenkins_files/
cp test_fixtures/credentials.xml jenkins_files/
echo "[PASS] Test files copied to jenkins_files/"
echo

# Test help command
echo "[TEST 3] Testing --help in Docker..."
if docker-compose run --rm offsec-jenkins --help 2>&1 | grep -q "usage:"; then
    echo "[PASS] Help command works in Docker"
else
    echo "[FAIL] Help command failed in Docker"
fi
echo

# Test decryption
echo "[TEST 4] Testing decryption in Docker..."
if docker-compose run --rm offsec-jenkins --path /data --reveal-secrets 2>&1 | grep -q "ghp_"; then
    echo "[PASS] Decryption works in Docker"
else
    echo "[FAIL] Decryption failed in Docker"
fi
echo

# Test JSON export
echo "[TEST 5] Testing JSON export in Docker..."
docker-compose run --rm offsec-jenkins --path /data --export-json /outputs/docker_test.json --reveal-secrets --force > /dev/null 2>&1
if [ -f "outputs/docker_test.json" ]; then
    echo "[PASS] JSON export works in Docker"
    rm outputs/docker_test.json
else
    echo "[FAIL] JSON export failed in Docker"
fi
echo

# Test CSV export
echo "[TEST 6] Testing CSV export in Docker..."
docker-compose run --rm offsec-jenkins --path /data --export-csv /outputs/docker_test.csv --reveal-secrets --force > /dev/null 2>&1
if [ -f "outputs/docker_test.csv" ]; then
    echo "[PASS] CSV export works in Docker"
    rm outputs/docker_test.csv
else
    echo "[FAIL] CSV export failed in Docker"
fi
echo

echo "========================================"
echo "Docker Validation Complete"
echo "========================================"
echo

validate_native() {
    echo
    echo "[*] Running native Python validation..."
    echo

    # Test native Python still works
    if python3 decrypt.py --path test_fixtures --reveal-secrets 2>&1 | grep -q "ghp_1234567890abcdefghijklmnopqrstuv"; then
        echo "[PASS] Native Python execution works"
    else
        echo "[FAIL] Native Python execution failed"
    fi
    echo

    # Run unit tests
    echo "[*] Running unit tests..."
    python3 -m pytest tests/ -q
    echo

    echo "========================================"
    echo "Validation Summary"
    echo "========================================"
    echo
    echo "Docker:  Optional (adds portability)"
    echo "Native:  Required (core functionality)"
    echo
    echo "Both Docker and native Python execution are supported."
    echo "Users can choose based on their environment."
    echo
}

validate_native
