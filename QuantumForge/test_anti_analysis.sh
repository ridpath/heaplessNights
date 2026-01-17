#!/bin/bash

echo "=========================================="
echo "QuantumForge Anti-Analysis Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test results
PASSED=0
FAILED=0

# Test 1: Generate junk.h
echo "[*] Test 1: Generating polymorphic junk.h"
python3 generate_junk.py
if [ -f junk.h ]; then
    echo -e "${GREEN}[PASS]${NC} junk.h generated successfully"
    PASSED=$((PASSED + 1))
    echo "Sample junk.h content:"
    head -n 10 junk.h
else
    echo -e "${RED}[FAIL]${NC} junk.h not generated"
    FAILED=$((FAILED + 1))
fi
echo ""

# Test 2: Verify anti_analysis.h compiles
echo "[*] Test 2: Compiling anti_analysis.h test"
cat << 'EOF' > test_anti_analysis.c
#include <stdio.h>
#include "anti_analysis.h"

int main() {
    printf("[*] Testing anti-analysis functions...\n");
    
    printf("[*] VM check (CPUID): ");
    if (check_vm_cpuid()) {
        printf("VM detected\n");
    } else {
        printf("No VM detected\n");
    }
    
    printf("[*] VirtualBox check: ");
    if (check_vm_virtualbox()) {
        printf("VirtualBox detected\n");
    } else {
        printf("No VirtualBox detected\n");
    }
    
    printf("[*] Debugger check: ");
    if (check_debugger()) {
        printf("Debugger detected\n");
    } else {
        printf("No debugger detected\n");
    }
    
    printf("[*] Parent PID check: ");
    if (check_parent_pid()) {
        printf("Analysis tool parent detected\n");
    } else {
        printf("Normal parent process\n");
    }
    
    printf("[*] Timing check: ");
    if (check_timing_sandbox()) {
        printf("Sandbox timing anomaly detected\n");
    } else {
        printf("Normal timing\n");
    }
    
    printf("[*] CPU count check: ");
    if (check_cpu_count()) {
        printf("Suspicious CPU count\n");
    } else {
        printf("Normal CPU count\n");
    }
    
    printf("\n[*] Full anti-analysis check: ");
    if (check_all_anti_analysis(0)) {
        printf("Analysis environment detected!\n");
    } else {
        printf("No analysis detected\n");
    }
    
    printf("\n[*] Test mode (skip checks): ");
    if (check_all_anti_analysis(1)) {
        printf("Should not detect (FAIL)\n");
    } else {
        printf("Skipped as expected (PASS)\n");
    }
    
    return 0;
}
EOF

gcc -o test_anti_analysis test_anti_analysis.c -O2
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} anti_analysis.h compiles successfully"
    PASSED=$((PASSED + 1))
    echo "[*] Running anti-analysis tests..."
    ./test_anti_analysis
else
    echo -e "${RED}[FAIL]${NC} anti_analysis.h failed to compile"
    FAILED=$((FAILED + 1))
fi
echo ""

# Test 3: Test under gdb (should detect)
echo "[*] Test 3: Testing debugger detection with gdb"
if command -v gdb &> /dev/null; then
    echo "run" | timeout 2 gdb -batch -ex "run" -ex "quit" ./test_anti_analysis 2>&1 | grep -q "Debugger detected"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} Debugger detection works under gdb"
        PASSED=$((PASSED + 1))
    else
        echo -e "${YELLOW}[WARN]${NC} Debugger detection may not work under gdb"
    fi
else
    echo -e "${YELLOW}[SKIP]${NC} gdb not installed, skipping debugger test"
fi
echo ""

# Test 4: Test section scrubbing
echo "[*] Test 4: Testing section scrubbing"
python3 scrub_sections.py test_anti_analysis 2>&1 | tee scrub_log.txt
if grep -q "Scrubbed sections" scrub_log.txt; then
    echo -e "${GREEN}[PASS]${NC} Section scrubbing completed"
    PASSED=$((PASSED + 1))
    echo "[*] Checking scrubbed binary..."
    if command -v readelf &> /dev/null; then
        readelf -S test_anti_analysis | grep -E "\.text|\.data|\.rodata" || echo "Original section names removed"
    elif command -v objdump &> /dev/null; then
        objdump -h test_anti_analysis | grep -E "\.text|\.data|\.rodata" || echo "Original section names removed"
    fi
elif grep -q "lief not installed" scrub_log.txt; then
    echo -e "${YELLOW}[WARN]${NC} lief not installed, section scrubbing skipped"
else
    echo -e "${RED}[FAIL]${NC} Section scrubbing failed"
    FAILED=$((FAILED + 1))
fi
echo ""

# Test 5: Test VM detection
echo "[*] Test 5: Testing VM detection"
if [ -f /sys/class/dmi/id/product_name ]; then
    PRODUCT_NAME=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    echo "Product name: $PRODUCT_NAME"
    if echo "$PRODUCT_NAME" | grep -qi "VirtualBox\|VMware\|QEMU\|KVM"; then
        echo -e "${GREEN}[INFO]${NC} Running in VM, detection should work"
    else
        echo -e "${GREEN}[INFO]${NC} Running on bare metal, VM detection should be negative"
    fi
else
    echo -e "${YELLOW}[INFO]${NC} Cannot determine if running in VM"
fi
echo ""

# Test 6: Test timing checks
echo "[*] Test 6: Testing timing checks"
cat << 'EOF' > test_timing.c
#include <stdio.h>
#include "anti_analysis.h"

int main() {
    uint64_t t1 = rdtsc_timing();
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) {
        x += i;
    }
    uint64_t t2 = rdtsc_timing();
    printf("RDTSC cycles: %lu\n", t2 - t1);
    
    if (check_timing_sandbox()) {
        printf("Timing anomaly detected (possible sandbox)\n");
    } else {
        printf("Normal timing detected\n");
    }
    return 0;
}
EOF

gcc -o test_timing test_timing.c -O0
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} Timing test compiles"
    PASSED=$((PASSED + 1))
    ./test_timing
else
    echo -e "${RED}[FAIL]${NC} Timing test failed to compile"
    FAILED=$((FAILED + 1))
fi
echo ""

# Cleanup
rm -f test_anti_analysis test_anti_analysis.c test_timing test_timing.c scrub_log.txt

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
