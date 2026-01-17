@echo off
cd /d C:\Users\Chogyam\.zenflow\worktrees\new-task-e6e5\offsec-jenkins
echo ==============================
echo Step Verification Report
echo ==============================
echo.

echo [*] Testing --help flag...
.venv\Scripts\python.exe decrypt.py --help
echo.

echo [*] Testing recursive scan...
.venv\Scripts\python.exe test_scan.py
echo.

echo [*] Testing pathlib...
.venv\Scripts\python.exe test_pathlib.py
echo.

echo ==============================
echo Verification Complete
echo ==============================
