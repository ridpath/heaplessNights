#!/bin/bash

set -e

echo "[*] Docker Installation Script for WSL2"
echo "[*] This script installs Docker Engine on WSL2 (Debian/Ubuntu-based)"
echo ""

if command -v docker &> /dev/null; then
    echo "[+] Docker is already installed"
    docker --version
    exit 0
fi

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
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "[*] Setting up Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

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
echo "[!] IMPORTANT: You may need to log out and log back in for group changes to take effect"
echo "[*] Or run: newgrp docker"
echo ""
echo "[*] To start Docker automatically on WSL startup, add to ~/.bashrc:"
echo "    if ! pgrep -x docker > /dev/null; then sudo service docker start; fi"
