# QuantumForge WSL Test Runner - Copy to /tmp and test

Write-Host "========================================"  -ForegroundColor Cyan
Write-Host "QuantumForge WSL Test Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$src = "/mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/QuantumForge"
$dst = "/tmp/quantumforge_test"

Write-Host "[*] Copying QuantumForge to WSL /tmp..." -ForegroundColor Yellow
wsl bash -c "rm -rf $dst && mkdir -p $dst && cp -r $src/* $dst/"

Write-Host "[*] Fixing line endings..." -ForegroundColor Yellow
wsl bash -c "find $dst -type f -name '*.sh' -exec sed -i 's/\r$//' {} \;"

Write-Host "[*] Running compile_all.sh..." -ForegroundColor Yellow
wsl bash -c "cd $dst && bash compile_all.sh"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Compilation successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Running Linux loader tests..." -ForegroundColor Yellow
    wsl bash -c "cd $dst/tests && bash test_loader_linux.sh"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "[+] All WSL tests PASSED!" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "[*] Checking for log files..." -ForegroundColor Cyan
        wsl bash -c "ls -lh /tmp/qf_logs/ 2>/dev/null | head -10"
        
        Write-Host ""
        Write-Host "[*] Sample log contents..." -ForegroundColor Cyan
        wsl bash -c "cat /tmp/qf_logs/*.json 2>/dev/null | head -30"
        
        exit 0
    } else {
        Write-Host "[-] Tests FAILED" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[-] Compilation FAILED" -ForegroundColor Red
    exit 1
}
