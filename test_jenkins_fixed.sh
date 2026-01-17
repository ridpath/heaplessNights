#!/bin/bash
cd /home/over/projects/JenkinsBreaker/jenkins-lab
export PATH="/home/over/.local/bin:$PATH"

echo "=== Starting Jenkins Lab with Docker Compose ==="
docker compose up -d --build

echo ""
echo "=== Waiting for Jenkins to start (45 seconds) ==="
sleep 45

echo ""
echo "=== Checking Jenkins container status ==="
docker ps | grep jenkins

echo ""
echo "=== Testing JenkinsBreaker - List CVEs (simulated) ==="
cd /home/over/projects/JenkinsBreaker
export INSIDE_VENV=1
python3 JenkinsBreaker.py --url http://localhost:8080 --list-cves 2>&1 | head -50

echo ""
echo "=== Jenkins Lab is running ==="
echo "Jenkins URL: http://localhost:8080"
echo "Credentials: admin / admin (check README_CREDENTIALS.md for details)"
echo ""
echo "Container status:"
docker ps -a | grep jenkins
