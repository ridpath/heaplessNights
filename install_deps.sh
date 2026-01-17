#!/bin/bash
echo "Installing QuantumForge dependencies in WSL..."
echo "over" | sudo -S apt-get update -y
echo "over" | sudo -S apt-get install -y build-essential libssl-dev libcurl4-openssl-dev
echo "Verifying installation..."
gcc --version
pkg-config --modversion libssl libcurl
echo "Dependencies installed successfully"
