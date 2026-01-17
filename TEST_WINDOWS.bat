@echo off
REM Windows Test Script for offsec-jenkins
REM Validates all functionality on Windows 10/11

echo ========================================
echo offsec-jenkins Windows Validation Test
echo ========================================
echo.

cd /d "%~dp0offsec-jenkins"

echo [*] Test 1: Help Command
python decrypt.py --help >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [PASS] --help command works
) else (
    echo [FAIL] --help command failed
)
echo.

echo [*] Test 2: Decryption with Redaction
python decrypt.py --path test_fixtures 2>&1 | findstr /C:"REDACTED" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Default redaction active
) else (
    echo [FAIL] Redaction not working
)
echo.

echo [*] Test 3: Decryption with Reveal
python decrypt.py --path test_fixtures --reveal-secrets 2>&1 | findstr /C:"ghp_1234567890abcdefghijklmnopqrstuv" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Credential decryption works
) else (
    echo [FAIL] Decryption failed
)
echo.

echo [*] Test 4: JSON Export
python decrypt.py --path test_fixtures --export-json test_windows.json --reveal-secrets --force >nul 2>&1
if exist test_windows.json (
    echo [PASS] JSON export successful
    del test_windows.json
) else (
    echo [FAIL] JSON export failed
)
echo.

echo [*] Test 5: CSV Export
python decrypt.py --path test_fixtures --export-csv test_windows.csv --reveal-secrets --force >nul 2>&1
if exist test_windows.csv (
    echo [PASS] CSV export successful
    del test_windows.csv
) else (
    echo [FAIL] CSV export failed
)
echo.

echo [*] Test 6: Dry-Run Mode
python decrypt.py --path test_fixtures --dry-run 2>&1 | findstr /C:"DRY RUN" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Dry-run mode works
) else (
    echo [FAIL] Dry-run mode failed
)
echo.

echo [*] Test 7: Explicit File Paths
python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --reveal-secrets 2>&1 | findstr /C:"AKIAIOSFODNN7EXAMPLE" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Explicit file paths work
) else (
    echo [FAIL] Explicit file paths failed
)
echo.

echo ========================================
echo Windows Validation Complete
echo ========================================
echo.
echo All tests passing = Ready for CTF/Red Team operations
echo.

pause
