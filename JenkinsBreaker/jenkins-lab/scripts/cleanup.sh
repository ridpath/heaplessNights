#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

echo "[*] Jenkins Lab Cleanup Script"
echo ""

cd "$LAB_DIR"

# Detect Docker Compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "[!] docker-compose not found"
    exit 1
fi

echo "[*] Stopping Jenkins containers..."
$COMPOSE_CMD down

echo -n "[?] Remove volumes and persistent data? (y/N): "
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "[*] Removing volumes..."
    $COMPOSE_CMD down -v
    echo "[+] All data removed"
else
    echo "[*] Volumes preserved for next run"
fi

echo ""
echo "[+] Jenkins Lab stopped"
echo ""
echo "[*] To start again: ./scripts/setup.sh"
