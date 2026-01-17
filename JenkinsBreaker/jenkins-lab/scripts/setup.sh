#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

echo "[*] Jenkins Lab Setup Script"
echo "[*] Lab directory: $LAB_DIR"
echo ""

cd "$LAB_DIR"

if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "[!] Docker daemon is not running. Please start Docker."
    exit 1
fi

# Detect Docker Compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "[!] docker-compose not found"
    exit 1
fi

echo "[*] Using: $COMPOSE_CMD"

echo "[*] Building Jenkins vulnerable image..."
$COMPOSE_CMD build

echo "[*] Starting Jenkins Lab..."
$COMPOSE_CMD up -d

echo "[*] Waiting for Jenkins to start..."
sleep 15

MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        echo "[+] Jenkins is up and running!"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "[*] Waiting for Jenkins... ($ATTEMPT/$MAX_ATTEMPTS)"
    sleep 5
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "[!] Jenkins failed to start within expected time"
    echo "[*] Check logs with: $COMPOSE_CMD logs jenkins"
    exit 1
fi

echo ""
echo "[+] Jenkins Lab is ready!"
echo ""
echo "    URL: http://localhost:8080"
echo "    Username: admin"
echo "    Password: admin"
echo ""
echo "[*] Available CVEs for testing:"
echo "    - CVE-2018-1000861 (Stapler RCE)"
echo "    - CVE-2019-1003029/1003030 (Script Security Groovy RCE)"
echo "    - CVE-2024-23897 (CLI Arbitrary File Read)"
echo "    - CVE-2020-2100 (Git Plugin RCE)"
echo "    - CVE-2018-1000402 (AWS CodeDeploy Plugin)"
echo ""
echo "[*] Planted secrets include:"
echo "    - 16 Jenkins credentials (AWS, GitHub, Docker, NPM, etc.)"
echo "    - File-based secrets in ~/.aws, ~/.ssh, ~/.docker, etc."
echo "    - Job-embedded environment variables"
echo "    - Privilege escalation vectors (sudo, cronjobs)"
echo ""
echo "[*] To verify secrets: ./scripts/verify_secrets.sh"
echo "[*] To stop the lab: ./scripts/cleanup.sh"
echo "[*] To view logs: $COMPOSE_CMD logs -f jenkins"
