@echo off
echo ========================================
echo Syncing offsec-jenkins to Original Repo
echo ========================================
echo.
echo Source: C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\offsec-jenkins
echo Target: D:\github projects\heaplessNights\offsec-jenkins
echo.

set SOURCE=C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\offsec-jenkins
set TARGET=D:\github projects\heaplessNights\offsec-jenkins

echo [*] Copying decrypt.py...
copy /Y "%SOURCE%\decrypt.py" "%TARGET%\decrypt.py"
if %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to copy decrypt.py
    pause
    exit /b 1
)

echo [*] Creating test_fixtures directory...
if not exist "%TARGET%\test_fixtures\secrets" mkdir "%TARGET%\test_fixtures\secrets"

echo [*] Copying test fixtures...
copy /Y "%SOURCE%\test_fixtures\secrets\master.key" "%TARGET%\test_fixtures\secrets\master.key"
copy /Y "%SOURCE%\test_fixtures\secrets\hudson.util.Secret" "%TARGET%\test_fixtures\secrets\hudson.util.Secret"
copy /Y "%SOURCE%\test_fixtures\credentials.xml" "%TARGET%\test_fixtures\credentials.xml"

echo [*] Copying generate_test_fixtures.py...
copy /Y "%SOURCE%\generate_test_fixtures.py" "%TARGET%\generate_test_fixtures.py"

echo [*] Copying test scripts...
copy /Y "%SOURCE%\test_security_manual.py" "%TARGET%\test_security_manual.py"
copy /Y "%SOURCE%\test_ctf_scenario.py" "%TARGET%\test_ctf_scenario.py"

echo [*] Copying requirements.txt...
copy /Y "%SOURCE%\requirements.txt" "%TARGET%\requirements.txt"

echo.
echo ========================================
echo Sync Complete!
echo ========================================
echo.
echo You can now use the tool from the original repo:
echo   cd "D:\github projects\heaplessNights\offsec-jenkins"
echo   python decrypt.py --help
echo.
pause
