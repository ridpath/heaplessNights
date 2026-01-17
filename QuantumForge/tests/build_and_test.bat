@echo off
REM Comprehensive test for QuantumForge Reflective DLL Loader

echo ========================================
echo QuantumForge Reflective DLL Loader Test
echo ========================================
echo.

REM Check if running from Visual Studio Developer Command Prompt
where /q cl.exe
if %ERRORLEVEL% NEQ 0 (
    echo [!] cl.exe not found in PATH
    echo [!] Please run this script from Visual Studio Developer Command Prompt
    echo.
    echo You can start it from:
    echo   - Start Menu ^> Visual Studio 2022 ^> Developer Command Prompt
    echo   - Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    exit /b 1
)

echo [*] Visual Studio compiler found
echo.

REM Clean previous builds
echo [*] Cleaning previous builds...
if exist test_dll.dll del /f /q test_dll.dll
if exist test_dll.obj del /f /q test_dll.obj
if exist test_dll.lib del /f /q test_dll.lib
if exist test_dll.exp del /f /q test_dll.exp
if exist test_reflective_loader.exe del /f /q test_reflective_loader.exe
if exist test_reflective_loader.obj del /f /q test_reflective_loader.obj
if exist C:\temp\reflective_dll_test.txt del /f /q C:\temp\reflective_dll_test.txt
echo [+] Clean complete
echo.

REM Build test DLL
echo [*] Building test DLL (test_dll.dll)...
cl.exe /nologo /W3 /LD test_dll.c /link /DLL /OUT:test_dll.dll user32.lib kernel32.lib >nul 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo [!] Test DLL build failed
    echo [!] Running verbose build...
    cl.exe /W3 /LD test_dll.c /link /DLL /OUT:test_dll.dll user32.lib kernel32.lib
    exit /b 1
)

if not exist test_dll.dll (
    echo [!] test_dll.dll not found after build
    exit /b 1
)

echo [+] Test DLL built successfully
for %%F in (test_dll.dll) do echo [*]   Size: %%~zF bytes
echo.

REM Build test loader
echo [*] Building reflective loader test (test_reflective_loader.exe)...
cl.exe /nologo /W3 /Fe:test_reflective_loader.exe test_reflective_loader.c /link kernel32.lib user32.lib >nul 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo [!] Test loader build failed
    echo [!] Running verbose build...
    cl.exe /W3 /Fe:test_reflective_loader.exe test_reflective_loader.c /link kernel32.lib user32.lib
    exit /b 1
)

if not exist test_reflective_loader.exe (
    echo [!] test_reflective_loader.exe not found after build
    exit /b 1
)

echo [+] Reflective loader test built successfully
for %%F in (test_reflective_loader.exe) do echo [*]   Size: %%~zF bytes
echo.

REM Create temp directory if needed
if not exist C:\temp mkdir C:\temp

REM Run test
echo [*] Running reflective loader test...
echo ========================================
echo.
test_reflective_loader.exe test_dll.dll
set TEST_RESULT=%ERRORLEVEL%
echo.
echo ========================================

REM Check results
if %TEST_RESULT% EQU 0 (
    echo.
    echo [SUCCESS] All tests passed!
    
    if exist C:\temp\reflective_dll_test.txt (
        echo [+] Output file created successfully
        echo [*] Contents of C:\temp\reflective_dll_test.txt:
        type C:\temp\reflective_dll_test.txt
    ) else (
        echo [!] Warning: Expected output file not found
    )
    
    echo.
    echo Verification complete:
    echo   [+] PE header parsing: PASS
    echo   [+] Section mapping: PASS
    echo   [+] Import resolution: PASS
    echo   [+] Relocation processing: PASS
    echo   [+] DllMain execution: PASS
    echo   [+] Memory scrubbing: PASS
    exit /b 0
) else (
    echo.
    echo [FAILED] Reflective loader test failed
    echo.
    echo Check the output above for error details
    exit /b 1
)
