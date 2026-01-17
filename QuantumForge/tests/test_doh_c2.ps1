param(
    [switch]$SkipCompile = $false
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir = Join-Path $ProjectDir "build"

Write-Host "[*] QuantumForge DoH C2 Test Suite (Windows)" -ForegroundColor Cyan
Write-Host "[*] =========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Write-Host "[*] Step 1: Starting DoH test server" -ForegroundColor Yellow
$ServerScript = Join-Path $ScriptDir "test_doh_server.py"

$ServerJob = Start-Job -ScriptBlock {
    param($Script)
    python $Script --port 8443
} -ArgumentList $ServerScript

Start-Sleep -Seconds 3

if ($ServerJob.State -ne "Running") {
    Write-Host "[!] DoH server failed to start" -ForegroundColor Red
    Receive-Job $ServerJob
    exit 1
}

Write-Host "[+] DoH server running (Job ID: $($ServerJob.Id))" -ForegroundColor Green
Write-Host ""

function Cleanup {
    Write-Host ""
    Write-Host "[*] Cleaning up..." -ForegroundColor Yellow
    if ($ServerJob) {
        Stop-Job $ServerJob -ErrorAction SilentlyContinue
        Remove-Job $ServerJob -ErrorAction SilentlyContinue
    }
}

Register-EngineEvent PowerShell.Exiting -Action { Cleanup } | Out-Null

try {
    Write-Host "[*] Step 2: Testing DoH query with curl" -ForegroundColor Yellow
    $Response = Invoke-RestMethod -Uri "http://localhost:8443/dns-query?name=c2.example.com&type=16" -Method Get
    Write-Host "[*] Response: $($Response | ConvertTo-Json -Compress)" -ForegroundColor Gray
    
    $ResponseJson = $Response | ConvertTo-Json
    if ($ResponseJson -match "C2_TRIGGER:1") {
        Write-Host "[+] DoH server returning correct trigger" -ForegroundColor Green
    } else {
        Write-Host "[!] DoH server not returning trigger" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    Write-Host "[*] Step 3: Testing beacon endpoint" -ForegroundColor Yellow
    $TestData = "test beacon data"
    $BeaconResponse = Invoke-RestMethod -Uri "http://localhost:8443/beacon" -Method Post -Body $TestData
    Write-Host "[+] Beacon endpoint responsive: $($BeaconResponse | ConvertTo-Json -Compress)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "[+] All DoH C2 tests passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Summary:" -ForegroundColor Cyan
    Write-Host "    - DoH query endpoint: OK" -ForegroundColor Gray
    Write-Host "    - JSON response parsing: OK" -ForegroundColor Gray
    Write-Host "    - C2 trigger detection: OK" -ForegroundColor Gray
    Write-Host "    - Beacon endpoint: OK" -ForegroundColor Gray
    Write-Host ""
    Write-Host "[*] For full C loader testing, compile in WSL with:" -ForegroundColor Yellow
    Write-Host "    cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge" -ForegroundColor Gray
    Write-Host "    gcc -o build/quantumserver quantumserver.c -lcrypto -lssl -lcurl -ldl" -ForegroundColor Gray
    Write-Host "    ./build/quantumserver --test-mode --doh-provider http://localhost:8443/dns-query" -ForegroundColor Gray
    Write-Host ""
    
} finally {
    Cleanup
}
