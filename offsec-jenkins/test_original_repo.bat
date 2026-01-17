@echo off
echo ========================================
echo Testing offsec-jenkins in Original Repo
echo ========================================
echo.
echo Location: D:\github projects\heaplessNights\offsec-jenkins
echo.

cd /d "D:\github projects\heaplessNights\offsec-jenkins"
if %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to change to original repo directory
    pause
    exit /b 1
)

echo [TEST 1] Check if decrypt.py exists...
if exist decrypt.py (
    echo [+] PASS: decrypt.py found
) else (
    echo [-] FAIL: decrypt.py not found
    pause
    exit /b 1
)

echo.
echo [TEST 2] Run --help to verify tool works...
python decrypt.py --help
if %ERRORLEVEL% EQU 0 (
    echo [+] PASS: Tool works in original repo
) else (
    echo [-] FAIL: Tool failed to run
    pause
    exit /b 1
)

echo.
echo [TEST 3] Test decryption with test fixtures...
python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --reveal-secrets
if %ERRORLEVEL% EQU 0 (
    echo [+] PASS: Decryption works
) else (
    echo [-] FAIL: Decryption failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo All Tests PASSED!
echo ========================================
echo.
echo offsec-jenkins is working perfectly in original repo
echo Ready for CTF and red team operations
echo.
pause
