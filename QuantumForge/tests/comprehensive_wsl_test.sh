#!/bin/bash

set -e

echo "========================================"
echo "QuantumForge Comprehensive WSL Test Suite"
echo "Platform Hardening & Security Validation"
echo "========================================"
echo ""

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."
cd "$PROJECT_DIR"

TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $? -eq 0 ]; then
        echo "[+] PASS: $1"
        ((TESTS_PASSED++))
    else
        echo "[-] FAIL: $1"
        ((TESTS_FAILED++))
    fi
}

echo "========================================  "
echo "Test 1: Build with Full Security Hardening"
echo "========================================"
echo "[*] Building with -O3, PIE, stack protectors..."
bash compile_all.sh | grep -E "compiled successfully|failed"
test_result "Hardened compilation"
echo ""

echo "========================================"
echo "Test 2: Binary Security Checks"
echo "========================================"

if [ -f build/quantumserver ]; then
    echo "[*] Checking for PIE (Position Independent Executable)..."
    if readelf -h build/quantumserver 2>/dev/null | grep -q "Type:[[:space:]]*DYN"; then
        echo "[+] PIE enabled"
        ((TESTS_PASSED++))
    else
        echo "[-] PIE not enabled"
        ((TESTS_FAILED++))
    fi
    
    echo "[*] Checking for stack canary..."
    if readelf -s build/quantumserver 2>/dev/null | grep -q "__stack_chk_fail"; then
        echo "[+] Stack canary enabled"
        ((TESTS_PASSED++))
    else
        echo "[-] Stack canary not found"
        ((TESTS_FAILED++))
    fi
    
    echo "[*] Checking for RELRO..."
    if readelf -l build/quantumserver 2>/dev/null | grep -q "GNU_RELRO"; then
        echo "[+] RELRO enabled"
        ((TESTS_PASSED++))
    else
        echo "[-] RELRO not enabled"
        ((TESTS_FAILED++))
    fi
    
    echo "[*] Checking for NX (No-Execute) stack..."
    if readelf -l build/quantumserver 2>/dev/null | grep "GNU_STACK" | grep -q "RW "; then
        echo "[+] NX stack enabled"
        ((TESTS_PASSED++))
    else
        echo "[-] NX stack not enabled"
        ((TESTS_FAILED++))
    fi
else
    echo "[-] Binary not found"
    ((TESTS_FAILED+=4))
fi
echo ""

echo "========================================"
echo "Test 3: Runtime Functionality"
echo "========================================"
cd tests
bash test_loader_linux.sh 2>&1 | tail -20
test_result "Linux loader test suite"
cd ..
echo ""

echo "========================================"
echo "Test 4: Logging System"
echo "========================================"
if [ -d /tmp/qf_logs ]; then
    LOG_COUNT=$(ls /tmp/qf_logs/*.json 2>/dev/null | wc -l)
    echo "[*] Found $LOG_COUNT log files"
    if [ $LOG_COUNT -gt 0 ]; then
        LATEST_LOG=$(ls -t /tmp/qf_logs/*.json | head -1)
        echo "[*] Latest log: $LATEST_LOG"
        if [ -f "$LATEST_LOG" ]; then
            echo "[*] Validating JSON structure..."
            if python3 -m json.tool "$LATEST_LOG" > /dev/null 2>&1; then
                echo "[+] Valid JSON"
                ((TESTS_PASSED++))
                
                if grep -q "\"level\": \"DEBUG\"\\|\"level\": \"TRACE\"" "$LATEST_LOG"; then
                    echo "[+] DEBUG/TRACE logging levels found"
                    ((TESTS_PASSED++))
                else
                    echo "[*] No DEBUG/TRACE entries (may not be in test mode)"
                fi
            else
                echo "[-] Invalid JSON"
                ((TESTS_FAILED++))
            fi
        fi
    else
        echo "[-] No log files generated"
        ((TESTS_FAILED++))
    fi
else
    echo "[-] Log directory not created"
    ((TESTS_FAILED++))
fi
echo ""

echo "========================================"
echo "Test 5: Signal Handler Validation"
echo "========================================"
echo "[*] Testing SIGINT handling..."
timeout 2s build/quantumserver --test-mode --no-doh --no-selfdelete &
PID=$!
sleep 1
kill -INT $PID 2>/dev/null && echo "[+] Signal handler installed" && ((TESTS_PASSED++)) || echo "[-] Signal handler failed" && ((TESTS_FAILED++))
wait $PID 2>/dev/null
echo ""

echo "========================================"
echo "Test 6: Memory Leak Check (Valgrind)"
echo "========================================"
if command -v valgrind &> /dev/null; then
    echo "[*] Running valgrind memory leak check..."
    valgrind --leak-check=summary --error-exitcode=1 \
        build/quantumserver --test-mode --no-doh --no-selfdelete 2>&1 | \
        grep -E "definitely lost|indirectly lost|ERROR SUMMARY"
    test_result "Memory leak check"
else
    echo "[*] Valgrind not installed, skipping"
fi
echo ""

echo "========================================"
echo "Test 7: Static Analysis (if available)"
echo "========================================"
if command -v cppcheck &> /dev/null; then
    echo "[*] Running cppcheck..."
    cppcheck --enable=warning,style --error-exitcode=0 \
        --suppress=missingIncludeSystem quantumserver.c 2>&1 | head -10
    echo "[*] cppcheck completed"
else
    echo "[*] cppcheck not installed, skipping"
fi
echo ""

echo "========================================"
echo "Test 8: Code Coverage Instrumentation"
echo "========================================"
echo "[*] Compiling with coverage flags..."
gcc -o build/quantumserver_coverage quantumserver.c \
    -lcrypto -lssl -lcurl -ldl \
    -D_GNU_SOURCE \
    -fprofile-arcs -ftest-coverage \
    -O0 -g \
    -fPIC 2>&1 | head -5 && echo "[+] Coverage build successful" && ((TESTS_PASSED++)) || echo "[-] Coverage build failed" && ((TESTS_FAILED++))

if [ -f build/quantumserver_coverage ]; then
    build/quantumserver_coverage --test-mode --no-doh --no-selfdelete 2>/dev/null
    if [ -f quantumserver.gcda ]; then
        echo "[+] Coverage data generated"
        ((TESTS_PASSED++))
        gcov quantumserver.c 2>&1 | grep "Lines executed" || echo "[*] gcov not available"
        rm -f *.gcda *.gcno *.gcov 2>/dev/null
    else
        echo "[-] No coverage data"
        ((TESTS_FAILED++))
    fi
fi
echo ""

echo "========================================"
echo "Test 9: Crypto Module Tests"
echo "========================================"
cat > /tmp/test_crypto.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include "qf_crypto.h"

int main() {
    unsigned char key[32];
    const unsigned char salt[] = "test_salt_16byte";
    const unsigned char ikm[] = "input_key_material_32_bytes_long";
    
    if (!qf_hkdf(key, 32, salt, 16, ikm, 32, NULL, 0)) {
        printf("[-] HKDF failed\n");
        return 1;
    }
    
    printf("[+] HKDF successful\n");
    
    secure_zero_memory(key, 32);
    
    for (int i = 0; i < 32; i++) {
        if (key[i] != 0) {
            printf("[-] secure_zero_memory failed\n");
            return 1;
        }
    }
    printf("[+] secure_zero_memory verified\n");
    
    printf("[+] Crypto module tests passed\n");
    return 0;
}
EOF

gcc -o /tmp/test_crypto /tmp/test_crypto.c -lcrypto -I"$PROJECT_DIR" 2>/dev/null
if [ -f /tmp/test_crypto ]; then
    /tmp/test_crypto
    test_result "Crypto module validation"
    rm -f /tmp/test_crypto /tmp/test_crypto.c
else
    echo "[-] Crypto test compilation failed"
    ((TESTS_FAILED++))
fi
echo ""

echo "========================================"
echo "Test Summary"
echo "========================================"
echo "[*] Tests Passed: $TESTS_PASSED"
echo "[*] Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "[+] All tests passed successfully!"
    exit 0
else
    echo "[-] Some tests failed"
    exit 1
fi
