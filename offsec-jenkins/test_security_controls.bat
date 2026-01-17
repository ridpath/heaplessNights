@echo off
setlocal

echo ========================================
echo Testing Security Controls
echo ========================================

echo.
echo [TEST 1] Help output verification
echo.
python decrypt.py --help > nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo PASSED: Help command works
) else (
    echo FAILED: Help command failed
    exit /b 1
)

echo.
echo ========================================
echo [TEST 2] Default behavior (redacted)
echo ========================================
echo Running: python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml
python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml > test_output_redacted.txt 2>&1
echo.
echo Output:
type test_output_redacted.txt
echo.
findstr /C:"REDACTED" test_output_redacted.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo PASSED: Secrets are redacted by default
) else (
    echo FAILED: No redaction markers found
)

echo.
echo ========================================
echo [TEST 3] Reveal secrets flag
echo ========================================
echo Running: python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --reveal-secrets
python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --reveal-secrets > test_output_revealed.txt 2>&1
echo.
echo Output:
type test_output_revealed.txt
echo.
findstr /C:"REDACTED" test_output_revealed.txt >nul
if %ERRORLEVEL% NEQ 0 (
    echo PASSED: Secrets revealed with --reveal-secrets ^(no redaction^)
) else (
    echo WARNING: Redaction still present with --reveal-secrets
)

echo.
echo ========================================
echo [TEST 4] Dry-run mode
echo ========================================
echo Running: python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --dry-run
python decrypt.py --key test_fixtures\secrets\master.key --secret test_fixtures\secrets\hudson.util.Secret --xml test_fixtures\credentials.xml --dry-run > test_output_dryrun.txt 2>&1
echo.
echo Output:
type test_output_dryrun.txt
echo.
findstr /C:"DRY RUN" test_output_dryrun.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo PASSED: Dry-run mode working
) else (
    echo FAILED: Dry-run mode not working
)

echo.
echo ========================================
echo [TEST 5] Comparison Test
echo ========================================
echo Comparing redacted vs revealed output to verify difference:
echo.
echo Redacted output has REDACTED markers:
findstr /C:"REDACTED" test_output_redacted.txt >nul && echo   YES || echo   NO
echo.
echo Revealed output has NO REDACTED markers:
findstr /C:"REDACTED" test_output_revealed.txt >nul && echo   NO || echo   YES

echo.
echo ========================================
echo All Security Control Tests Complete
echo ========================================

del test_output_redacted.txt test_output_revealed.txt test_output_dryrun.txt 2>nul
