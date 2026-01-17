@echo off
echo ========================================
echo QuantumForge WSL Test Launcher
echo ========================================
echo.

set "WSL_PATH=/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge/tests"

echo [*] Launching tests in WSL...
echo.

wsl cd %WSL_PATH% ^&^& bash run_tests_wsl.sh

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] WSL tests completed successfully
    exit /b 0
) else (
    echo.
    echo [!] WSL tests failed
    exit /b 1
)
