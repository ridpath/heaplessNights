#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================"
echo "  Jenkins Lab - Full Test Cycle"
echo "  Setup ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ Test ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ Cleanup"
echo "============================================"
echo ""

FAILURES=0

cd "$LAB_DIR"

echo "[PHASE 1/3] SETUP"
echo "----------------------------------------"

if ./scripts/setup.sh; then
    echo -e "${GREEN}[+] Setup completed successfully${NC}"
else
    echo -e "${RED}[!] Setup failed${NC}"
    exit 1
fi

echo ""
sleep 5

echo "[PHASE 2/3] TESTING"
echo "----------------------------------------"

if ./scripts/test_exploits.sh; then
    echo -e "${GREEN}[+] Exploit testing completed${NC}"
else
    echo -e "${YELLOW}[!] Some tests failed (expected for some CVEs)${NC}"
    FAILURES=$((FAILURES + 1))
fi

echo ""
sleep 2

echo "[*] Running secrets verification..."
if ./scripts/verify_secrets.sh > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Secrets verification passed${NC}"
else
    echo -e "${YELLOW}[!] Secrets verification had issues${NC}"
    FAILURES=$((FAILURES + 1))
fi

echo ""
sleep 2

echo "[PHASE 3/3] CLEANUP"
echo "----------------------------------------"

echo "[*] Stopping Jenkins Lab..."
docker-compose down 2>/dev/null || true

echo -e "${GREEN}[+] Cleanup completed${NC}"

echo ""
echo "============================================"
echo "  TEST CYCLE COMPLETE"
echo "============================================"
echo ""

if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}[+] All phases completed successfully!${NC}"
    echo ""
    echo "[*] Summary:"
    echo "    - Setup: SUCCESS"
    echo "    - Testing: SUCCESS"
    echo "    - Cleanup: SUCCESS"
    echo ""
    echo "[*] Jenkins Lab is ready for use"
    echo "[*] To start again: ./scripts/setup.sh"
    exit 0
else
    echo -e "${YELLOW}[!] Test cycle completed with $FAILURES warnings${NC}"
    echo ""
    echo "[*] This is normal if some CVEs require specific conditions"
    echo "[*] Review test_exploits.sh output for details"
    echo ""
    exit 0
fi
