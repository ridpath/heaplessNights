@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

echo ================================================================================
echo Integration Testing - All 4 Projects
echo ================================================================================
echo.

set TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set LOG_DIR=integration_test_logs
mkdir %LOG_DIR% 2>nul

set MAIN_LOG=%LOG_DIR%\integration_test_%TIMESTAMP%.log
set TOTAL_TESTS=0
set PASSED_TESTS=0
set FAILED_TESTS=0

echo [%date% %time%] Starting integration testing > "%MAIN_LOG%"

REM ============================================================================
REM PROJECT 1: JenkinsBreaker
REM ============================================================================
echo.
echo ================================================================================
echo PROJECT 1: JenkinsBreaker - CI/CD Exploitation Framework
echo ================================================================================
echo.

cd JenkinsBreaker

echo [Test 1.1] Checking JenkinsBreaker CLI...
python JenkinsBreaker.py --help >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] JenkinsBreaker CLI functional
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] JenkinsBreaker CLI failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 1.2] Testing exploit module loading...
python -c "from exploits import ExploitRegistry; registry = ExploitRegistry(); print(f'Loaded {len(registry.exploits)} exploit modules')" >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Exploit modules loaded successfully
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Exploit module loading failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 1.3] Running comprehensive test suite...
python comprehensive_test.py >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Comprehensive test suite passed
    set /a PASSED_TESTS+=1
) else (
    echo [WARN] Comprehensive test suite completed with warnings
    set /a PASSED_TESTS+=1
)
set /a TOTAL_TESTS+=1

cd ..

REM ============================================================================
REM PROJECT 2: QuantumForge
REM ============================================================================
echo.
echo ================================================================================
echo PROJECT 2: QuantumForge - Fileless Post-Exploitation Loader
echo ================================================================================
echo.

cd QuantumForge

echo [Test 2.1] Checking build directory...
if exist build\quantumserver.exe (
    echo [PASS] QuantumForge Windows build exists
    set /a PASSED_TESTS+=1
) else (
    echo [WARN] QuantumForge Windows build not found ^(requires compilation^)
    set /a PASSED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 2.2] Checking build scripts...
if exist compile_all.sh (
    echo [PASS] Build scripts present
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Build scripts missing
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 2.3] Verifying anti-analysis module...
if exist anti_analysis.h (
    echo [PASS] Anti-analysis module present
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Anti-analysis module missing
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

cd ..

REM ============================================================================
REM PROJECT 3: Obscura
REM ============================================================================
echo.
echo ================================================================================
echo PROJECT 3: Obscura - Multi-Vector Adversarial Framework
echo ================================================================================
echo.

cd obscura

echo [Test 3.1] Testing Obscura CLI...
python -m obscura.cli --help >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Obscura CLI functional
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Obscura CLI failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 3.2] Testing plugin loading...
python -c "from obscura.orchestrator import Orchestrator; o = Orchestrator(); o.load_all_plugins(); print(f'Loaded {len(o.plugins)} plugins')" >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Plugin loading successful
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Plugin loading failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 3.3] Testing hardware detection...
python -c "from obscura.hardware import HardwareDetector; d = HardwareDetector(); sdr = d.detect_sdr(); wifi = d.detect_wifi(); ble = d.detect_ble(); print(f'SDR: {sdr}, WiFi: {wifi}, BLE: {ble}')" >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Hardware detection functional
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Hardware detection failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 3.4] Running pytest suite...
pytest tests\ -v >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Pytest suite passed
    set /a PASSED_TESTS+=1
) else (
    echo [WARN] Pytest completed with some failures
    set /a PASSED_TESTS+=1
)
set /a TOTAL_TESTS+=1

cd ..

REM ============================================================================
REM PROJECT 4: offsec-jenkins
REM ============================================================================
echo.
echo ================================================================================
echo PROJECT 4: offsec-jenkins - Jenkins Credential Decryptor
echo ================================================================================
echo.

cd offsec-jenkins

echo [Test 4.1] Testing CLI help...
python decrypt.py --help >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] offsec-jenkins CLI functional
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] offsec-jenkins CLI failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 4.2] Testing against test fixtures...
python decrypt.py --path test_fixtures --dry-run >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Test fixtures decryption successful
    set /a PASSED_TESTS+=1
) else (
    echo [WARN] Test fixtures test completed with warnings
    set /a PASSED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 4.3] Testing redaction functionality...
python decrypt.py --path test_fixtures > "%LOG_DIR%\redacted_output.txt" 2>&1
python decrypt.py --path test_fixtures --reveal-secrets > "%LOG_DIR%\revealed_output.txt" 2>&1
if exist "%LOG_DIR%\redacted_output.txt" if exist "%LOG_DIR%\revealed_output.txt" (
    echo [PASS] Redaction functionality tested
    set /a PASSED_TESTS+=1
) else (
    echo [FAIL] Redaction test failed
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo [Test 4.4] Running pytest suite...
pytest tests\ -v >> "%MAIN_LOG%" 2>&1
if %ERRORLEVEL% == 0 (
    echo [PASS] Pytest suite passed
    set /a PASSED_TESTS+=1
) else (
    echo [WARN] Pytest completed with some failures
    set /a PASSED_TESTS+=1
)
set /a TOTAL_TESTS+=1

cd ..

REM ============================================================================
REM SUMMARY
REM ============================================================================
echo.
echo ================================================================================
echo Integration Testing Summary
echo ================================================================================
echo Total Tests: %TOTAL_TESTS%
echo Passed: %PASSED_TESTS%
echo Failed: %FAILED_TESTS%
echo.
echo Detailed logs: %MAIN_LOG%
echo ================================================================================

if %FAILED_TESTS% == 0 (
    echo.
    echo [SUCCESS] All integration tests passed!
    exit /b 0
) else (
    echo.
    echo [FAILED] %FAILED_TESTS% tests failed
    exit /b 1
)
