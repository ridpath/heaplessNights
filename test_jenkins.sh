#!/bin/bash
cd /home/over/projects/JenkinsBreaker/jenkins-lab
export PATH="/home/over/.local/bin:$PATH"
export INSIDE_VENV=1

echo "=== Starting Jenkins Lab with Docker Compose ==="
docker-compose up -d

echo ""
echo "=== Waiting for Jenkins to start (30 seconds) ==="
sleep 30

echo ""
echo "=== Testing JenkinsBreaker - List CVEs ==="
cd /home/over/projects/JenkinsBreaker
python3 JenkinsBreaker.py --url http://localhost:8080 --list-cves

echo ""
echo "=== Jenkins Lab is running at http://localhost:8080 ==="
echo "Credentials: admin / admin123"
echo ""
echo "To test exploits manually, run:"
echo "python3 JenkinsBreaker.py --url http://localhost:8080 --auto --lhost 127.0.0.1 --lport 9001"
