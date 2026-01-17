# Install QuantumForge dependencies in WSL

Write-Host "Installing QuantumForge dependencies in WSL Parrot..." -ForegroundColor Cyan

# Create install script in WSL
$installScript = @'
#!/bin/bash
echo "Waiting for any apt locks to clear..."
while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 ; do
    echo "Waiting..."
    sleep 2
done

echo "Updating package lists..."
sudo apt-get update

echo "Installing build-essential..."
sudo apt-get install -y build-essential

echo "Installing libssl-dev..."
sudo apt-get install -y libssl-dev

echo "Installing libcurl4-openssl-dev..."
sudo apt-get install -y libcurl4-openssl-dev

echo ""
echo "Verifying installation..."
gcc --version
pkg-config --modversion libssl || echo "libssl version check failed"
pkg-config --modversion libcurl || echo "libcurl version check failed"

echo ""
echo "Dependencies installed successfully!"
'@

# Write script to WSL temp
$installScript | wsl bash -c "cat > /tmp/install_qf_deps.sh"

# Make executable
wsl chmod +x /tmp/install_qf_deps.sh

# Execute with password
Write-Host "Running installation (this may take a few minutes)..." -ForegroundColor Yellow
$result = echo "over" | wsl sudo -S bash /tmp/install_qf_deps.sh 2>&1

Write-Output $result

# Check if gcc is now available
Write-Host ""
Write-Host "Checking if GCC is now available..." -ForegroundColor Cyan
wsl which gcc

if ($LASTEXITCODE -eq 0) {
    Write-Host "GCC installed successfully!" -ForegroundColor Green
} else {
    Write-Host "GCC installation may have failed" -ForegroundColor Red
}
