#!/bin/bash
cd /home/over/projects/obscura
export PATH="/home/over/.local/bin:$PATH"
export OBSCURA_RF_LOCK=1

echo "=== Obscura WSL Testing ==="
echo ""
echo "Test 1: Install dependencies"
pip3 install --user --break-system-packages scapy numpy scipy matplotlib pillow scikit-rf -q

echo ""
echo "Test 2: Run pytest suite"
pytest tests/ -v --tb=short 2>&1 | tail -50

echo ""
echo "Test 3: Test RF_LOCK enforcement (should succeed)"
export OBSCURA_RF_LOCK=1
python3 obscura/cli.py --list-plugins 2>&1 | head -20

echo ""
echo "Test 4: Test --dry-run mode"
python3 obscura/cli.py --target-file tests/test_traits.json --auto --dry-run 2>&1 | head -30

echo ""
echo "Test 5: Check reporting module"
python3 -c "from obscura.reporting import AttackReporter; print('Reporting module OK')"

echo ""
echo "Obscura testing complete!"
