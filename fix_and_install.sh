#!/bin/bash
echo "Fixing hostname in /etc/hosts..."
echo "127.0.0.1 parrot" | sudo tee -a /etc/hosts

echo "Updating package lists..."
sudo apt-get update

echo "Installing build-essential..."
sudo apt-get install -y build-essential

echo "Installing libssl-dev..."
sudo apt-get install -y libssl-dev

echo "Installing libcurl4-openssl-dev..."
sudo apt-get install -y libcurl4-openssl-dev

echo "Verifying installation..."
gcc --version
echo "Installation complete!"
