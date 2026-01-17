$password = "over"
$command = "/tmp/fix_and_install.sh"

Write-Host "Running installation script in WSL..." -ForegroundColor Cyan
Write-Host "This will fix hostname and install dependencies..." -ForegroundColor Yellow
Write-Host ""

# Run with password piped to sudo
$output = & wsl bash -c "echo '$password' | sudo -S bash $command 2>&1"

Write-Output $output

Write-Host ""
Write-Host "Checking GCC installation..." -ForegroundColor Cyan
wsl gcc --version

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: GCC is now installed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "ERROR: GCC installation failed" -ForegroundColor Red
    exit 1
}
