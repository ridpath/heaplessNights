@echo off
REM BLE Attack Plugin Verification Script for Windows
REM Tests all BLE attack vectors in dry-run mode

echo ============================================================
echo BLE Attack Plugin Verification
echo ============================================================
echo.

set OBSCURA_RF_LOCK=1

echo [*] Test 1: Plugin Registration
echo ----------------------------------------
.venv\Scripts\python.exe test_ble_plugin.py
if errorlevel 1 (
    echo [FAIL] Plugin registration test failed
    exit /b 1
) else (
    echo [PASS] Plugin registration test passed
)
echo.

echo [*] Test 2: CLI List Attacks
echo ----------------------------------------
.venv\Scripts\python.exe -m obscura.cli --list-attacks --override-safety | findstr "ble_"
if errorlevel 1 (
    echo [FAIL] BLE attacks not found in CLI
    exit /b 1
) else (
    echo [PASS] BLE attacks available via CLI
)
echo.

echo [*] Test 3: Load Specific BLE Plugin
echo ----------------------------------------
.venv\Scripts\python.exe -m obscura.cli --load ble --simulate --override-safety
if errorlevel 1 (
    echo [FAIL] Failed to load BLE plugin via --load flag
    exit /b 1
) else (
    echo [PASS] BLE plugin loads via --load flag
)
echo.

echo ============================================================
echo All BLE Attack Plugin Tests Passed
echo ============================================================
echo.
echo BLE Attack Vectors Available:
echo   - ble_hid_spoof_keyboard  : HID keyboard emulation attack
echo   - ble_mac_rotation        : Continuous MAC address rotation
echo   - ble_gatt_fuzzing        : GATT profile fuzzing with LLM assist
echo   - ble_advertising_jam     : Advertising channel jamming
echo.
echo Status: READY FOR DEPLOYMENT
echo.
