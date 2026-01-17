@echo off
REM Extract credentials from Jenkins Lab and test decryptor

echo ========================================
echo Extracting Jenkins Credentials
echo ========================================
echo.

REM Create directory
if not exist test_fixtures\jenkins_lab\secrets mkdir test_fixtures\jenkins_lab\secrets

echo [*] Extracting master.key...
wsl docker cp 2d514971da4d:/var/jenkins_home/secrets/master.key test_fixtures/jenkins_lab/secrets/master.key
if %errorlevel% neq 0 goto :error
echo [+] master.key extracted

echo [*] Extracting hudson.util.Secret...
wsl docker cp 2d514971da4d:/var/jenkins_home/secrets/hudson.util.Secret test_fixtures/jenkins_lab/secrets/hudson.util.Secret
if %errorlevel% neq 0 (
    echo [!] hudson.util.Secret not found - Jenkins may need initialization
    echo [!] Add credentials in Jenkins UI first: http://localhost:8080/credentials/
    goto :skiptest
)
echo [+] hudson.util.Secret extracted

echo [*] Extracting credentials.xml...
wsl docker cp 2d514971da4d:/var/jenkins_home/credentials.xml test_fixtures/jenkins_lab/credentials.xml
if %errorlevel% neq 0 (
    echo [!] credentials.xml not found
    echo [!] Add credentials in Jenkins UI: http://localhost:8080/credentials/
    goto :skiptest
)
echo [+] credentials.xml extracted
echo.

echo ========================================
echo Testing Decryption (Redacted)
echo ========================================
python decrypt.py --path test_fixtures/jenkins_lab
echo.

echo ========================================
echo Testing Decryption (Revealed)
echo ========================================
python decrypt.py --path test_fixtures/jenkins_lab --reveal-secrets
echo.

echo ========================================
echo Testing JSON Export
echo ========================================
python decrypt.py --path test_fixtures/jenkins_lab --export-json outputs/jenkins_lab.json --reveal-secrets --force
if %errorlevel% equ 0 (
    echo [+] JSON exported to outputs/jenkins_lab.json
    type outputs\jenkins_lab.json
)
echo.

echo [+] All tests completed!
goto :end

:skiptest
echo.
echo [!] Skipping tests - credentials not found
echo.
echo To add credentials:
echo 1. Go to http://localhost:8080/credentials/
echo 2. Login: admin / admin
echo 3. Add test credentials
echo 4. Run this script again
goto :end

:error
echo [-] Extraction failed
exit /b 1

:end
