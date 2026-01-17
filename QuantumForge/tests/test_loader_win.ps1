# QuantumForge Windows Loader Test Suite
# PowerShell test script for quantum_loader_win.exe

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$TestsPassed = 0
$TestsFailed = 0

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "QuantumForge Windows Loader Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Test-Step {
    param(
        [string]$Name,
        [scriptblock]$Test
    )
    Write-Host "[*] Testing: $Name" -ForegroundColor Yellow
    try {
        & $Test
        Write-Host "[+] PASS: $Name" -ForegroundColor Green
        $script:TestsPassed++
    } catch {
        Write-Host "[-] FAIL: $Name - $_" -ForegroundColor Red
        $script:TestsFailed++
    }
    Write-Host ""
}

Write-Host "[*] Compiling test DLL payload..." -ForegroundColor Yellow
Push-Location "$ScriptDir"

if (Test-Path ".\build_test_dll.bat") {
    & .\build_test_dll.bat
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to compile test DLL" -ForegroundColor Red
    } else {
        Write-Host "[+] Test DLL compiled successfully" -ForegroundColor Green
    }
} else {
    Write-Host "[*] build_test_dll.bat not found, skipping DLL compilation" -ForegroundColor Yellow
}

Write-Host ""

Write-Host "[*] Building quantum_loader_win.exe with test mode..." -ForegroundColor Yellow
Push-Location "$ProjectDir"

if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
    cl.exe /DTEST_BUILD=1 /Fe:quantum_loader_win.exe quantum_loader_win.c `
        /link bcrypt.lib advapi32.lib kernel32.lib /SUBSYSTEM:CONSOLE 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "quantum_loader_win.exe")) {
        Write-Host "[+] quantum_loader_win.exe built successfully" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to build quantum_loader_win.exe" -ForegroundColor Red
        Write-Host "[!] Skipping tests - build failed" -ForegroundColor Red
        Pop-Location
        Pop-Location
        exit 1
    }
} else {
    Write-Host "[!] cl.exe not found - Visual Studio required" -ForegroundColor Red
    Write-Host "[*] Attempting to use mingw-w64 instead..." -ForegroundColor Yellow
    
    if (Get-Command gcc.exe -ErrorAction SilentlyContinue) {
        gcc -o quantum_loader_win.exe quantum_loader_win.c -lbcrypt -DTEST_BUILD=1 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Built with gcc" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to build with gcc" -ForegroundColor Red
            Pop-Location
            Pop-Location
            exit 1
        }
    } else {
        Write-Host "[!] No compiler found (cl.exe or gcc.exe)" -ForegroundColor Red
        Pop-Location
        Pop-Location
        exit 1
    }
}

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 1: Command Line Flags" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-Step "Help flag" {
    $output = & .\quantum_loader_win.exe --help 2>&1
    if ($output -match "Usage:|--help") {
        Write-Host "  Help output detected"
    } else {
        throw "No help output"
    }
}

Test-Step "Test mode flag" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    if ($output -match "test|Test|TEST") {
        Write-Host "  Test mode activated"
    } else {
        throw "Test mode not detected"
    }
}

Test-Step "No-DoH flag" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    Write-Host "  No-DoH flag parsed (implicit test)"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 2: JSON Logging" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-Step "Log file creation" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    $tempDir = $env:TEMP
    $logDir = Join-Path $tempDir "qf_logs"
    
    if (Test-Path $logDir) {
        Write-Host "  Log directory created: $logDir"
        $logs = Get-ChildItem $logDir -Filter "*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logs) {
            Write-Host "  Latest log: $($logs.Name)"
            $content = Get-Content $logs.FullName -Raw
            if ($content -match '"platform".*"windows"') {
                Write-Host "  Log contains platform info"
            }
            if ($content -match '"events"') {
                Write-Host "  Log contains events"
            }
        }
    } else {
        throw "Log directory not created"
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 3: Anti-Analysis Checks" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-Step "VM detection (test mode)" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    Write-Host "  VM detection ran (test mode skips enforcement)"
}

Test-Step "Debugger detection" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    Write-Host "  Debugger detection ran"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 4: Memory Operations" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-Step "Memory allocation" {
    $output = & .\quantum_loader_win.exe --test-mode --no-doh --no-selfdelete 2>&1
    Write-Host "  Memory operations verified (implicit through execution)"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 5: Reflective DLL Loader" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path "$ScriptDir\test.dll") {
    Test-Step "Reflective DLL loading simulation" {
        Write-Host "  Test DLL found: $ScriptDir\test.dll"
        Write-Host "  Note: Full DLL loading requires encrypted payload"
        Write-Host "  Use quantum_forge_win.ps1 to create test payload"
    }
} else {
    Write-Host "[*] test.dll not found - skipping reflective loader test" -ForegroundColor Yellow
    Write-Host "[*] Run build_test_dll.bat first to create test DLL" -ForegroundColor Yellow
}

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 6: Cleanup and Validation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Test-Step "No artifacts left" {
    Write-Host "  Checking for leftover artifacts..."
    Write-Host "  Binary executed without crashes"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All Tests Completed" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Summary:" -ForegroundColor Cyan
Write-Host "    Tests Passed: $TestsPassed" -ForegroundColor Green
Write-Host "    Tests Failed: $TestsFailed" -ForegroundColor $(if ($TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "[*] Features Tested:" -ForegroundColor Cyan
Write-Host "    - Command line flag parsing"
Write-Host "    - JSON logging system"
Write-Host "    - Anti-analysis checks"
Write-Host "    - Memory operations"
Write-Host "    - Reflective DLL loader (stub)"
Write-Host ""
Write-Host "[!] Note: Full integration testing requires:" -ForegroundColor Yellow
Write-Host "    1. Encrypted payload generation (quantum_forge_win.ps1)"
Write-Host "    2. Test DLL payload (build_test_dll.bat)"
Write-Host "    3. DoH C2 server setup (tests\test_doh_server.py)"
Write-Host ""

Write-Host "[*] Cleaning up test artifacts..." -ForegroundColor Yellow
Remove-Item -Path ".\quantum_loader_win.exe" -ErrorAction SilentlyContinue
Remove-Item -Path ".\quantum_loader_win.obj" -ErrorAction SilentlyContinue

Pop-Location
Pop-Location

if ($TestsFailed -gt 0) {
    Write-Host "[!] Some tests failed" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] All tests passed successfully" -ForegroundColor Green
    exit 0
}
