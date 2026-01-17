#!/bin/bash

# Pre-flight check for WSL testing environment
# Validates all requirements are met before running tests

echo "[*] Pre-flight Check for Jenkins Lab WSL Testing"
echo "=================================================="
echo ""

CHECKS_PASSED=0
CHECKS_FAILED=0

# Check 1: WSL Environment
echo "[1/8] Checking WSL environment..."
if [[ -f /proc/version ]]; then
    echo "[+] Running in WSL/Linux"
    echo "    User: $(whoami)"
    echo "    Distro: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo 'Unknown')"
    echo "    Kernel: $(uname -r)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] Not running in WSL/Linux environment"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# Check 2: Docker installation
echo ""
echo "[2/8] Checking Docker..."
if command -v docker &> /dev/null; then
    echo "[+] Docker is installed: $(docker --version)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    
    # Check if Docker daemon is running
    if docker info &> /dev/null 2>&1; then
        echo "[+] Docker daemon is running"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        echo "[!] Docker daemon is not running"
        echo "    Start with: sudo service docker start"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    echo "[!] Docker is not installed"
    echo "    Install with: ./scripts/install_docker_wsl.sh"
    CHECKS_FAILED=$((CHECKS_FAILED + 2))
fi

# Check 3: Docker Compose
echo ""
echo "[3/8] Checking Docker Compose..."
if docker compose version &> /dev/null 2>&1; then
    echo "[+] Docker Compose plugin: $(docker compose version)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
elif command -v docker-compose &> /dev/null; then
    echo "[+] Docker Compose standalone: $(docker-compose --version)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] Docker Compose not found"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# Check 4: Python3
echo ""
echo "[4/8] Checking Python3..."
if command -v python3 &> /dev/null; then
    echo "[+] Python3: $(python3 --version)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] Python3 not found"
    echo "    Install with: sudo apt-get install -y python3 python3-pip python3-venv"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# Check 5: Java (for Jenkins CLI testing)
echo ""
echo "[5/8] Checking Java..."
if command -v java &> /dev/null; then
    echo "[+] Java: $(java --version 2>&1 | head -n 1)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] Java not found (optional, needed for CVE-2024-23897 testing)"
    echo "    Install with: sudo apt-get install -y openjdk-11-jre-headless"
    echo "    Note: Tests will skip CLI exploits without Java"
fi

# Check 6: curl
echo ""
echo "[6/8] Checking curl..."
if command -v curl &> /dev/null; then
    echo "[+] curl: $(curl --version | head -n 1)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] curl not found"
    echo "    Install with: sudo apt-get install -y curl"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# Check 7: JenkinsBreaker files
echo ""
echo "[7/8] Checking JenkinsBreaker files..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
JENKINS_BREAKER_DIR="$(dirname "$LAB_DIR")"

if [ -f "$JENKINS_BREAKER_DIR/JenkinsBreaker.py" ]; then
    echo "[+] JenkinsBreaker.py found"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] JenkinsBreaker.py not found at: $JENKINS_BREAKER_DIR"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# Check 8: offsec-jenkins
echo ""
echo "[8/8] Checking offsec-jenkins..."
OFFSEC_DIR="$(dirname "$LAB_DIR")/../offsec-jenkins"
if [ -f "$OFFSEC_DIR/decrypt.py" ]; then
    echo "[+] offsec-jenkins decrypt.py found"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    echo "[!] offsec-jenkins decrypt.py not found"
    echo "    Expected at: $OFFSEC_DIR"
fi

echo ""
echo "=================================================="
echo "                  SUMMARY                        "
echo "=================================================="
echo ""
echo "Checks Passed: $CHECKS_PASSED"
echo "Checks Failed: $CHECKS_FAILED"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    echo "[+] All pre-flight checks PASSED!"
    echo "[*] You can now run: ./scripts/test_wsl.sh"
    exit 0
else
    echo "[!] Some checks FAILED. Please address the issues above."
    echo ""
    echo "Quick setup commands:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y python3 python3-pip curl openjdk-11-jre-headless"
    echo "  ./scripts/install_docker_wsl.sh"
    echo "  sudo service docker start"
    echo ""
    exit 1
fi
