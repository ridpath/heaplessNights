#!/bin/bash
cd /home/over/projects/QuantumForge
export PATH="/home/over/.local/bin:$PATH"

echo "=== QuantumForge WSL Testing ==="
echo ""
echo "Test 1: Compile all loaders"
bash compile_all.sh 2>&1 | tail -50

echo ""
echo "Test 2: Run comprehensive WSL tests"
cd tests
bash comprehensive_wsl_test.sh 2>&1 | head -100

echo ""
echo "Test 3: Check build artifacts"
ls -lh /home/over/projects/QuantumForge/build/ 2>&1

echo ""
echo "Test 4: Check JSON logs"
ls -lh /home/over/projects/QuantumForge/logs/ 2>&1 | head -10

echo ""
echo "QuantumForge testing complete!"
