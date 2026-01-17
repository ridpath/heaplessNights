@echo off
REM Build test DLL for reflective loader verification

echo [*] Building test DLL...

cl.exe /LD /Fe:test_dll.dll test_dll.c /link /DLL /OUT:test_dll.dll user32.lib kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [!] Build failed - trying with Visual Studio environment
    where /q cl.exe
    if %ERRORLEVEL% NEQ 0 (
        echo [!] cl.exe not found. Please run from Visual Studio Developer Command Prompt
        exit /b 1
    )
)

if exist test_dll.dll (
    echo [+] Test DLL built successfully: test_dll.dll
    dir test_dll.dll
) else (
    echo [!] Test DLL build failed
    exit /b 1
)
