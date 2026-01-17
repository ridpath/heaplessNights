#!/bin/bash

echo "========================================"
echo "QuantumForge WSL Test Runner"
echo "========================================"
echo ""

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."

echo "[*] Testing from WSL environment"
echo "[*] Project directory: $PROJECT_DIR"
echo ""

echo "[*] Checking build dependencies..."
which gcc || echo "[!] gcc not found"
which python3 || echo "[!] python3 not found"
echo ""

echo "[*] Running compile_all.sh..."
cd "$PROJECT_DIR"
bash compile_all.sh || {
    echo "[!] Compilation failed"
    exit 1
}

echo ""
echo "[*] Running Linux loader tests..."
cd tests
bash test_loader_linux.sh || {
    echo "[!] Linux tests failed"
    exit 1
}

echo ""
echo "[+] All WSL tests completed successfully"
exit 0
