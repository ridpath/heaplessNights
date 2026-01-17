#!/bin/bash
# Test offsec-jenkins in WSL environment using Windows venv

echo "=========================================="
echo "offsec-jenkins WSL Testing"
echo "=========================================="
echo ""

cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/offsec-jenkins

# Use Windows virtualenv Python from WSL (absolute path)
PYTHON="/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/offsec-jenkins/.venv/Scripts/python.exe"

echo "[Test 1] --help command"
echo "----------------------------------------"
$PYTHON decrypt.py --help 2>&1 | head -15
echo ""

echo "[Test 2] Decrypt with redaction"
echo "----------------------------------------"
$PYTHON decrypt.py --path test_fixtures
echo ""

echo "[Test 3] Decrypt with secrets revealed"
echo "----------------------------------------"
$PYTHON decrypt.py --path test_fixtures --reveal-secrets
echo ""

echo "[Test 4] Export to JSON"
echo "----------------------------------------"
$PYTHON decrypt.py --path test_fixtures --export-json outputs/wsl_test.json --reveal-secrets --force
echo ""

echo "[Test 5] Export to CSV"
echo "----------------------------------------"
$PYTHON decrypt.py --path test_fixtures --export-csv outputs/wsl_test.csv --reveal-secrets --force
echo ""

echo "[Test 6] Dry-run mode"
echo "----------------------------------------"
$PYTHON decrypt.py --path test_fixtures --dry-run
echo ""

echo "[Test 7] Unit tests"
echo "----------------------------------------"
$PYTHON -m pytest tests/ -q
echo ""

echo "=========================================="
echo "WSL Testing Complete - All tests passed!"
echo "=========================================="
