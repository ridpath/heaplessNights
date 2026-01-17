@echo off
REM Jenkins Lab Integration Test Script
REM Run this after Jenkins Lab Docker container is running

echo ========================================
echo Jenkins Lab Integration Test
echo ========================================
echo.

REM Create test directory
if not exist "test_fixtures\jenkins_lab\secrets" mkdir test_fixtures\jenkins_lab\secrets

echo [*] Extracting Jenkins Lab credentials from Docker container...
echo.

REM Get Jenkins container ID
for /f "tokens=*" %%i in ('docker ps -qf "name=jenkins"') do set JENKINS_CONTAINER=%%i

if "%JENKINS_CONTAINER%"=="" (
    echo [-] Error: Jenkins container not found. Is Jenkins Lab running?
    echo     Start Jenkins Lab with: cd ~/jenkins-lab ^&^& docker-compose up -d
    exit /b 1
)

echo [+] Found Jenkins container: %JENKINS_CONTAINER%
echo.

REM Extract files from container
echo [*] Extracting master.key...
docker cp %JENKINS_CONTAINER%:/var/jenkins_home/secrets/master.key test_fixtures\jenkins_lab\secrets\master.key
if errorlevel 1 (
    echo [-] Failed to extract master.key
    exit /b 1
)
echo [+] master.key extracted

echo [*] Extracting hudson.util.Secret...
docker cp %JENKINS_CONTAINER%:/var/jenkins_home/secrets/hudson.util.Secret test_fixtures\jenkins_lab\secrets\hudson.util.Secret
if errorlevel 1 (
    echo [-] Failed to extract hudson.util.Secret
    exit /b 1
)
echo [+] hudson.util.Secret extracted

echo [*] Extracting credentials.xml...
docker cp %JENKINS_CONTAINER%:/var/jenkins_home/credentials.xml test_fixtures\jenkins_lab\credentials.xml
if errorlevel 1 (
    echo [-] Failed to extract credentials.xml
    exit /b 1
)
echo [+] credentials.xml extracted
echo.

echo ========================================
echo Running Decryption Tests
echo ========================================
echo.

echo [Test 1] Decrypt without revealing secrets (redacted)
echo --------------------------------------------------------
python decrypt.py --path test_fixtures\jenkins_lab
echo.

echo [Test 2] Decrypt with --reveal-secrets
echo --------------------------------------------------------
python decrypt.py --path test_fixtures\jenkins_lab --reveal-secrets
echo.

echo [Test 3] Export to JSON
echo --------------------------------------------------------
python decrypt.py --path test_fixtures\jenkins_lab --export-json outputs\jenkins_lab_secrets.json --reveal-secrets --force
if exist outputs\jenkins_lab_secrets.json (
    echo [+] JSON export successful
    echo.
    type outputs\jenkins_lab_secrets.json
) else (
    echo [-] JSON export failed
)
echo.

echo [Test 4] Export to CSV
echo --------------------------------------------------------
python decrypt.py --path test_fixtures\jenkins_lab --export-csv outputs\jenkins_lab_secrets.csv --reveal-secrets --force
if exist outputs\jenkins_lab_secrets.csv (
    echo [+] CSV export successful
    echo.
    type outputs\jenkins_lab_secrets.csv
) else (
    echo [-] CSV export failed
)
echo.

echo ========================================
echo Running Unit Tests
echo ========================================
.venv\Scripts\python.exe -m pytest tests/ -v
echo.

echo ========================================
echo Integration Test Complete
echo ========================================
