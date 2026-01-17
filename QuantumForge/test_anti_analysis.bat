@echo off
echo ==========================================
echo QuantumForge Anti-Analysis Test Suite
echo ==========================================
echo.

set PASSED=0
set FAILED=0

:: Test 1: Generate junk.h
echo [*] Test 1: Generating polymorphic junk.h
python generate_junk.py
if exist junk.h (
    echo [PASS] junk.h generated successfully
    set /a PASSED+=1
    echo Sample junk.h content:
    type junk.h | more /E +0 +10
) else (
    echo [FAIL] junk.h not generated
    set /a FAILED+=1
)
echo.

:: Test 2: Verify anti_analysis.h compiles
echo [*] Test 2: Compiling anti_analysis.h test
echo #include ^<stdio.h^> > test_anti_analysis.c
echo #include "anti_analysis.h" >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo int main() { >> test_anti_analysis.c
echo     printf("[*] Testing anti-analysis functions...\n"); >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("[*] VM check (CPUID): "); >> test_anti_analysis.c
echo     if (check_vm_cpuid()) { >> test_anti_analysis.c
echo         printf("VM detected\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("No VM detected\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("[*] VirtualBox check: "); >> test_anti_analysis.c
echo     if (check_vm_virtualbox()) { >> test_anti_analysis.c
echo         printf("VirtualBox detected\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("No VirtualBox detected\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("[*] Debugger check: "); >> test_anti_analysis.c
echo     if (check_debugger()) { >> test_anti_analysis.c
echo         printf("Debugger detected\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("No debugger detected\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("[*] Parent PID check: "); >> test_anti_analysis.c
echo     if (check_parent_pid()) { >> test_anti_analysis.c
echo         printf("Analysis tool parent detected\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("Normal parent process\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("[*] Timing check: "); >> test_anti_analysis.c
echo     if (check_timing_sandbox()) { >> test_anti_analysis.c
echo         printf("Sandbox timing anomaly detected\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("Normal timing\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("\n[*] Full anti-analysis check: "); >> test_anti_analysis.c
echo     if (check_all_anti_analysis(0)) { >> test_anti_analysis.c
echo         printf("Analysis environment detected!\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("No analysis detected\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     printf("\n[*] Test mode (skip checks): "); >> test_anti_analysis.c
echo     if (check_all_anti_analysis(1)) { >> test_anti_analysis.c
echo         printf("Should not detect (FAIL)\n"); >> test_anti_analysis.c
echo     } else { >> test_anti_analysis.c
echo         printf("Skipped as expected (PASS)\n"); >> test_anti_analysis.c
echo     } >> test_anti_analysis.c
echo. >> test_anti_analysis.c
echo     return 0; >> test_anti_analysis.c
echo } >> test_anti_analysis.c

where cl.exe >nul 2>&1
if %errorlevel% equ 0 (
    cl.exe /nologo /O2 test_anti_analysis.c >nul 2>&1
    if %errorlevel% equ 0 (
        echo [PASS] anti_analysis.h compiles successfully
        set /a PASSED+=1
        echo [*] Running anti-analysis tests...
        test_anti_analysis.exe
    ) else (
        echo [FAIL] anti_analysis.h failed to compile
        set /a FAILED+=1
    )
) else (
    echo [WARN] cl.exe not found, trying gcc
    where gcc >nul 2>&1
    if %errorlevel% equ 0 (
        gcc -o test_anti_analysis.exe test_anti_analysis.c -O2
        if %errorlevel% equ 0 (
            echo [PASS] anti_analysis.h compiles successfully
            set /a PASSED+=1
            echo [*] Running anti-analysis tests...
            test_anti_analysis.exe
        ) else (
            echo [FAIL] anti_analysis.h failed to compile
            set /a FAILED+=1
        )
    ) else (
        echo [SKIP] No C compiler found
    )
)
echo.

:: Test 3: Test section scrubbing
echo [*] Test 3: Testing section scrubbing
if exist test_anti_analysis.exe (
    python scrub_sections.py test_anti_analysis.exe >scrub_log.txt 2>&1
    findstr /C:"Scrubbed sections" scrub_log.txt >nul
    if %errorlevel% equ 0 (
        echo [PASS] Section scrubbing completed
        set /a PASSED+=1
    ) else (
        findstr /C:"lief not installed" scrub_log.txt >nul
        if %errorlevel% equ 0 (
            echo [WARN] lief not installed, section scrubbing skipped
        ) else (
            echo [FAIL] Section scrubbing failed
            set /a FAILED+=1
        )
    )
) else (
    echo [SKIP] No test binary to scrub
)
echo.

:: Test 4: Check if running in VM
echo [*] Test 4: Checking VM environment
systeminfo | findstr /C:"System Model" | findstr /I "VirtualBox VMware Hyper-V" >nul
if %errorlevel% equ 0 (
    echo [INFO] Running in VM, detection should work
) else (
    echo [INFO] Running on bare metal, VM detection should be negative
)
echo.

:: Cleanup
if exist test_anti_analysis.c del test_anti_analysis.c
if exist test_anti_analysis.exe del test_anti_analysis.exe
if exist test_anti_analysis.obj del test_anti_analysis.obj
if exist scrub_log.txt del scrub_log.txt

echo ==========================================
echo Test Summary
echo ==========================================
echo Passed: %PASSED%
echo Failed: %FAILED%
echo.

if %FAILED% equ 0 (
    echo All tests passed!
    exit /b 0
) else (
    echo Some tests failed
    exit /b 1
)
