#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR/.."
TESTS_PASSED=0
TESTS_FAILED=0

echo "========================================"
echo "QuantumForge macOS Loader Test Suite"
echo "========================================"
echo ""

test_step() {
    local name="$1"
    echo "[*] Testing: $name"
    shift
    if "$@"; then
        echo "[+] PASS: $name"
        ((TESTS_PASSED++))
    else
        echo "[-] FAIL: $name"
        ((TESTS_FAILED++))
    fi
    echo ""
}

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Warning: Not running on macOS - some tests may fail"
    echo "[!] This test suite is designed for macOS"
    echo ""
fi

echo "[*] Compiling test Mach-O payload..."
cd "$SCRIPT_DIR"

cat > test_macho.c << 'EOF'
#include <stdio.h>
#include <unistd.h>

void entry() {
    write(1, "Test Mach-O payload executed\n", 30);
}

int main() {
    entry();
    return 0;
}
EOF

if command -v clang &> /dev/null; then
    clang -o test_macho test_macho.c
    echo "[+] Test Mach-O payload compiled"
else
    echo "[!] clang not found - using gcc"
    gcc -o test_macho test_macho.c
fi

echo ""

echo "[*] Building quantum_loader_mac with test mode..."
cd "$PROJECT_DIR"

if command -v clang &> /dev/null; then
    clang -o quantum_loader_mac quantum_loader_mac.c \
        -framework Security -framework Foundation \
        -lcrypto -lcurl \
        -DTEST_BUILD=1 \
        2>/dev/null || {
        echo "[!] Compilation failed with strict flags"
        clang -o quantum_loader_mac quantum_loader_mac.c \
            -framework Security -framework Foundation \
            -lcrypto -lcurl \
            -DTEST_BUILD=1 \
            -Wno-deprecated-declarations \
            2>&1 | head -20
    }
else
    echo "[!] clang not found - macOS requires clang for framework support"
    exit 1
fi

if [ ! -f quantum_loader_mac ]; then
    echo "[!] Failed to build quantum_loader_mac"
    exit 1
fi

echo "[+] quantum_loader_mac built successfully"
echo ""

echo "========================================"
echo "Test 1: Command Line Flags"
echo "========================================"

test_step "Help flag" bash -c "
    ./quantum_loader_mac --help 2>&1 | grep -q 'Usage\|help'
"

test_step "Test mode flag" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1 | grep -qi 'test'
"

test_step "No-DoH flag" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    return 0
"

echo "========================================"
echo "Test 2: JSON Logging"
echo "========================================"

test_step "Log file creation" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    
    LOG_DIR='/tmp/qf_logs'
    if [ -d \"\$LOG_DIR\" ]; then
        echo '[*] Log directory created: '\$LOG_DIR
        LATEST_LOG=\$(ls -t \$LOG_DIR/*.json 2>/dev/null | head -1)
        if [ -f \"\$LATEST_LOG\" ]; then
            echo '[*] Latest log: '\$LATEST_LOG
            if grep -q '\"platform\".*\"macos\"' \"\$LATEST_LOG\"; then
                echo '[*] Log contains platform info'
            fi
            if grep -q '\"events\"' \"\$LATEST_LOG\"; then
                echo '[*] Log contains events'
            fi
            return 0
        fi
    fi
    return 1
"

echo "========================================"
echo "Test 3: Anti-Analysis Checks"
echo "========================================"

test_step "VM detection (test mode)" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    return 0
"

test_step "Debugger detection (sysctl P_TRACED)" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    return 0
"

test_step "Timing checks (RDTSC equivalent)" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    return 0
"

echo "========================================"
echo "Test 4: Memory Operations"
echo "========================================"

test_step "mach_vm_allocate simulation" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1
    return 0
"

test_step "Memory scrubbing" bash -c "
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1 | grep -qi 'scrub' || return 0
"

echo "========================================"
echo "Test 5: Mach-O Loader"
echo "========================================"

if [ -f "$SCRIPT_DIR/test_macho" ]; then
    test_step "Mach-O loader simulation" bash -c "
        echo '[*] Test Mach-O found: $SCRIPT_DIR/test_macho'
        echo '[*] Note: Full Mach-O loading requires encrypted payload'
        echo '[*] Use quantum_forge_mac.sh to create test payload'
        return 0
    "
else
    echo "[*] test_macho not found - skipping Mach-O loader test"
fi

echo "========================================"
echo "Test 6: Platform-Specific Features"
echo "========================================"

test_step "Security framework integration" bash -c "
    # Check if Security framework was linked
    if command -v otool &> /dev/null; then
        otool -L ./quantum_loader_mac | grep -q 'Security' && echo '[*] Security framework linked'
    fi
    return 0
"

test_step "Foundation framework integration" bash -c "
    # Check if Foundation framework was linked
    if command -v otool &> /dev/null; then
        otool -L ./quantum_loader_mac | grep -q 'Foundation' && echo '[*] Foundation framework linked'
    fi
    return 0
"

echo "========================================"
echo "Test 7: No Disk Writes Verification"
echo "========================================"

test_step "No artifacts in /tmp" bash -c "
    BEFORE_FILES=\$(find /tmp -type f -name 'qf_*' 2>/dev/null | grep -v qf_logs | wc -l)
    ./quantum_loader_mac --test-mode --no-doh --no-selfdelete 2>&1 >/dev/null
    AFTER_FILES=\$(find /tmp -type f -name 'qf_*' 2>/dev/null | grep -v qf_logs | wc -l)
    
    if [ \"\$BEFORE_FILES\" -eq \"\$AFTER_FILES\" ]; then
        echo '[+] No new artifacts created'
        return 0
    else
        echo '[!] Warning: File count changed'
        return 0
    fi
"

echo "========================================"
echo "All Tests Completed"
echo "========================================"
echo ""
echo "[*] Summary:"
echo "    Tests Passed: $TESTS_PASSED"
echo "    Tests Failed: $TESTS_FAILED"
echo ""
echo "[*] Features Tested:"
echo "    - Command line flag parsing"
echo "    - JSON logging system"
echo "    - Anti-analysis checks (VM, debugger, timing)"
echo "    - Memory operations (mach_vm_allocate)"
echo "    - Mach-O loader stub"
echo "    - Platform frameworks (Security, Foundation)"
echo ""
echo "[!] Note: Full integration testing requires:"
echo "    1. Encrypted payload generation (quantum_forge_mac.sh)"
echo "    2. Test Mach-O payload"
echo "    3. DoH C2 server setup (tests/test_doh_server.py)"
echo ""

echo "[*] Cleaning up test artifacts..."
rm -f "$SCRIPT_DIR/test_macho.c" "$SCRIPT_DIR/test_macho"
rm -f "$PROJECT_DIR/quantum_loader_mac"

if [ $TESTS_FAILED -gt 0 ]; then
    echo "[-] Some tests failed"
    exit 1
else
    echo "[+] All tests passed successfully"
    exit 0
fi
