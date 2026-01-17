@echo off
REM Docker Validation Script for offsec-jenkins
REM Tests that all functionality works with Docker

echo ========================================
echo Docker Validation for offsec-jenkins
echo ========================================
echo.

cd /d "%~dp0"

REM Check if Docker is installed
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [SKIP] Docker not installed. Install Docker to test containerized execution.
    echo.
    echo This is optional - the tool works without Docker using native Python.
    goto :validate_native
)

echo [*] Docker detected. Running containerized tests...
echo.

REM Build Docker image
echo [TEST 1] Building Docker image...
docker-compose build offsec-jenkins >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Docker image built successfully
) else (
    echo [FAIL] Docker build failed
    goto :validate_native
)
echo.

REM Prepare test files
echo [TEST 2] Preparing test files...
if not exist jenkins_files mkdir jenkins_files
copy /Y test_fixtures\secrets\master.key jenkins_files\ >nul 2>&1
copy /Y test_fixtures\secrets\hudson.util.Secret jenkins_files\ >nul 2>&1
copy /Y test_fixtures\credentials.xml jenkins_files\ >nul 2>&1
echo [PASS] Test files copied to jenkins_files/
echo.

REM Test help command
echo [TEST 3] Testing --help in Docker...
docker-compose run --rm offsec-jenkins --help 2>&1 | findstr /C:"usage:" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Help command works in Docker
) else (
    echo [FAIL] Help command failed in Docker
)
echo.

REM Test decryption
echo [TEST 4] Testing decryption in Docker...
docker-compose run --rm offsec-jenkins --path /data --reveal-secrets 2>&1 | findstr /C:"ghp_" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Decryption works in Docker
) else (
    echo [FAIL] Decryption failed in Docker
)
echo.

REM Test JSON export
echo [TEST 5] Testing JSON export in Docker...
docker-compose run --rm offsec-jenkins --path /data --export-json /outputs/docker_test.json --reveal-secrets --force >nul 2>&1
if exist outputs\docker_test.json (
    echo [PASS] JSON export works in Docker
    del outputs\docker_test.json
) else (
    echo [FAIL] JSON export failed in Docker
)
echo.

REM Test CSV export
echo [TEST 6] Testing CSV export in Docker...
docker-compose run --rm offsec-jenkins --path /data --export-csv /outputs/docker_test.csv --reveal-secrets --force >nul 2>&1
if exist outputs\docker_test.csv (
    echo [PASS] CSV export works in Docker
    del outputs\docker_test.csv
) else (
    echo [FAIL] CSV export failed in Docker
)
echo.

echo ========================================
echo Docker Validation Complete
echo ========================================
echo.

:validate_native
echo.
echo [*] Running native Python validation...
echo.

REM Test native Python still works
python decrypt.py --path test_fixtures --reveal-secrets 2>&1 | findstr /C:"ghp_1234567890abcdefghijklmnopqrstuv" >nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Native Python execution works
) else (
    echo [FAIL] Native Python execution failed
)
echo.

REM Run unit tests
echo [*] Running unit tests...
.venv\Scripts\python.exe -m pytest tests/ -q
echo.

echo ========================================
echo Validation Summary
echo ========================================
echo.
echo Docker:  Optional (adds portability)
echo Native:  Required (core functionality)
echo.
echo Both Docker and native Python execution are supported.
echo Users can choose based on their environment.
echo.

pause
