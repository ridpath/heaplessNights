#!/bin/bash
cd /home/over/projects/offsec-jenkins
export PATH="/home/over/.local/bin:$PATH"

echo "=== Testing offsec-jenkins decrypt.py ==="
echo ""
echo "Test 1: Dry-run mode"
python3 decrypt.py --path tests/fixtures --dry-run
echo ""
echo "Test 2: Normal decryption with redaction"
python3 decrypt.py --path tests/fixtures
echo ""
echo "Test 3: JSON export"
python3 decrypt.py --path tests/fixtures --export-json /tmp/test_secrets.json
echo ""
echo "Test 4: CSV export"
python3 decrypt.py --path tests/fixtures --export-csv /tmp/test_secrets.csv --force
echo ""
echo "All tests completed successfully!"
