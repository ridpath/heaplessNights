#!/bin/bash

set -e

echo "[*] Docker Installation Script for Parrot OS (WSL2)"
echo "[*] Using Debian repository (Parrot is Debian-based)"
echo ""

if command -v docker &> /dev/null; then
    echo "[+] Docker is already installed"
    docker --version
    exit 0
fi

echo "[*] Removing old Docker repository entries..."
sudo rm -f /etc/apt/sources.list.d/docker.list

echo "[*] Updating package lists..."
sudo apt-get update

echo "[*] Installing prerequisites..."
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

echo "[*] Adding Docker's official GPG key..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "[*] Setting up Docker repository (Debian-based)..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  bullseye stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[*] Installing Docker Engine..."
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "[*] Starting Docker service..."
sudo service docker start

echo "[*] Adding current user to docker group..."
sudo usermod -aG docker $USER

echo ""
echo "[+] Docker installation complete!"
echo ""
echo "    Docker version: $(docker --version)"
echo "    Docker Compose version: $(docker compose version)"
echo ""
echo "[!] IMPORTANT: Run these commands to complete setup:"
echo "    newgrp docker"
echo "    sudo service docker start"
echo ""
echo "[*] To start Docker automatically, add to ~/.bashrc:"
echo '    if ! pgrep -x dockerd > /dev/null 2>&1; then sudo service docker start 2>/dev/null; fi'
echo ""
