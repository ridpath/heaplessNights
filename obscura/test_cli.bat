@echo off
REM Test script for Obscura CLI implementation

echo ====================================
echo Obscura CLI Implementation Test
echo ====================================
echo.

echo Test 1: Help command
echo ---------------------
.venv\Scripts\python.exe -m obscura.cli --help
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Help command failed
    exit /b 1
)
echo [PASS] Help command works
echo.

echo Test 2: List attacks
echo ---------------------
.venv\Scripts\python.exe -m obscura.cli --list-attacks
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] List attacks failed
    exit /b 1
)
echo [PASS] List attacks works
echo.

echo Test 3: Export to JSON
echo -----------------------
if exist test_export.json del test_export.json
.venv\Scripts\python.exe -m obscura.cli --export test_export.json
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Export to JSON failed
    exit /b 1
)
if not exist test_export.json (
    echo [FAIL] JSON file not created
    exit /b 1
)
echo [PASS] Export to JSON works
del test_export.json
echo.

echo Test 4: Export to DOT
echo ----------------------
if exist test_export.dot del test_export.dot
.venv\Scripts\python.exe -m obscura.cli --export test_export.dot
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Export to DOT failed
    exit /b 1
)
if not exist test_export.dot (
    echo [FAIL] DOT file not created
    exit /b 1
)
echo [PASS] Export to DOT works
del test_export.dot
echo.

echo Test 5: RF_LOCK enforcement
echo ---------------------------
.venv\Scripts\python.exe -m obscura.cli --interactive --simulate 2>&1 | find "RF safety interlock not set" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] RF_LOCK enforcement not working
    exit /b 1
)
echo [PASS] RF_LOCK enforcement works
echo.

echo Test 6: Override safety flag
echo ----------------------------
echo exit | .venv\Scripts\python.exe -m obscura.cli --interactive --simulate --override-safety 2>&1 | find "Safety interlock bypassed" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Override safety flag not working
    exit /b 1
)
echo [PASS] Override safety flag works
echo.

echo ====================================
echo All CLI tests passed!
echo ====================================
