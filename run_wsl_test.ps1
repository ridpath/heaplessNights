# WSL Test Runner for JenkinsBreaker
# Runs the comprehensive WSL integration test from Windows

Write-Host "[*] JenkinsBreaker WSL Integration Test Runner" -ForegroundColor Cyan
Write-Host "[*] This script will execute the test suite in WSL (Parrot distribution)" -ForegroundColor Cyan
Write-Host ""

# Get the current directory in WSL format
$currentDir = Get-Location
$wslPath = $currentDir.Path -replace '\\', '/' -replace 'C:', '/mnt/c'

Write-Host "[1/5] Converting Windows path to WSL path..." -ForegroundColor Yellow
Write-Host "    Windows: $currentDir" -ForegroundColor Gray
Write-Host "    WSL:     $wslPath" -ForegroundColor Gray
Write-Host ""

Write-Host "[2/5] Checking WSL distribution (Parrot)..." -ForegroundColor Yellow
$wslList = wsl --list --verbose
Write-Host $wslList -ForegroundColor Gray

if ($wslList -notmatch "parrot") {
    Write-Host "[!] Parrot WSL distribution not found!" -ForegroundColor Red
    Write-Host "[*] Available distributions:" -ForegroundColor Yellow
    Write-Host $wslList -ForegroundColor Gray
    exit 1
}

Write-Host "[+] Parrot WSL distribution found" -ForegroundColor Green
Write-Host ""

Write-Host "[3/5] Making test script executable..." -ForegroundColor Yellow
wsl -d parrot bash -c "cd '$wslPath/JenkinsBreaker/jenkins-lab' && chmod +x scripts/*.sh"
Write-Host "[+] Scripts are now executable" -ForegroundColor Green
Write-Host ""

Write-Host "[4/5] Checking Docker in WSL..." -ForegroundColor Yellow
$dockerCheck = wsl -d parrot bash -c "command -v docker"

if ([string]::IsNullOrEmpty($dockerCheck)) {
    Write-Host "[!] Docker not found in WSL. Installing Docker..." -ForegroundColor Yellow
    wsl -d parrot bash -c "cd '$wslPath/JenkinsBreaker/jenkins-lab' && ./scripts/install_docker_wsl.sh"
    
    Write-Host "[*] Starting Docker daemon..." -ForegroundColor Yellow
    wsl -d parrot bash -c "sudo service docker start"
    
    Start-Sleep -Seconds 3
} else {
    Write-Host "[+] Docker is installed: $dockerCheck" -ForegroundColor Green
    
    # Check if Docker daemon is running
    $dockerRunning = wsl -d parrot bash -c "docker info 2>&1"
    if ($dockerRunning -match "Cannot connect") {
        Write-Host "[*] Starting Docker daemon..." -ForegroundColor Yellow
        wsl -d parrot bash -c "sudo service docker start"
        Start-Sleep -Seconds 3
    } else {
        Write-Host "[+] Docker daemon is running" -ForegroundColor Green
    }
}
Write-Host ""

Write-Host "[5/5] Running WSL integration test..." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Run the test script
wsl -d parrot bash -c "cd '$wslPath/JenkinsBreaker/jenkins-lab' && ./scripts/test_wsl.sh"

$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan

if ($exitCode -eq 0) {
    Write-Host "[+] WSL Integration Test PASSED!" -ForegroundColor Green
} else {
    Write-Host "[!] WSL Integration Test FAILED with exit code: $exitCode" -ForegroundColor Red
}

Write-Host ""
Write-Host "[*] Test complete. Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

exit $exitCode
