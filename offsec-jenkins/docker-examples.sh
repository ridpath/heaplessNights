#!/bin/bash
# Docker usage examples for offsec-jenkins

# Build the image
docker-compose build offsec-jenkins

# Example 1: Show help
docker-compose run --rm offsec-jenkins --help

# Example 2: Decrypt from mounted directory (redacted)
docker-compose run --rm offsec-jenkins --path /data

# Example 3: Decrypt and reveal secrets
docker-compose run --rm offsec-jenkins --path /data --reveal-secrets

# Example 4: Export to JSON
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-json /outputs/loot.json \
  --reveal-secrets \
  --force

# Example 5: Export to CSV
docker-compose run --rm offsec-jenkins \
  --path /data \
  --export-csv /outputs/loot.csv \
  --reveal-secrets \
  --force

# Example 6: Explicit file paths
docker-compose run --rm offsec-jenkins \
  --key /data/master.key \
  --secret /data/hudson.util.Secret \
  --xml /data/credentials.xml \
  --reveal-secrets

# Example 7: Dry-run mode
docker-compose run --rm offsec-jenkins \
  --path /data \
  --dry-run

# Example 8: Scan directory recursively
docker-compose run --rm offsec-jenkins \
  --scan-dir /data \
  --export-json /outputs/all_secrets.json \
  --reveal-secrets \
  --force

# ===================================
# Jenkins Lab (for testing only)
# ===================================

# Start Jenkins lab (user must configure credentials via UI)
docker-compose --profile lab up -d jenkins-lab

# Access Jenkins at http://localhost:8080
# Configure admin credentials via the web UI

# Stop Jenkins lab
docker-compose --profile lab down

# Remove all data (DESTRUCTIVE)
docker-compose --profile lab down -v
