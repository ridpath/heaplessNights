#!/bin/bash
# Start Jenkins Lab in WSL and test offsec-jenkins decryptor

set -e

echo "========================================"
echo "Starting Jenkins Lab"
echo "========================================"
echo

# Navigate to Jenkins Lab
cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/JenkinsBreaker/jenkins-lab

# Start Docker containers
echo "[*] Starting Jenkins Lab containers..."
docker-compose up -d

echo
echo "[*] Waiting for Jenkins to be ready (this may take 60-90 seconds)..."
sleep 10

# Check if container is running
JENKINS_CONTAINER=$(docker ps -qf "name=jenkins")

if [ -z "$JENKINS_CONTAINER" ]; then
    echo "[-] Error: Jenkins container failed to start"
    docker-compose logs
    exit 1
fi

echo "[+] Jenkins container is running: $JENKINS_CONTAINER"
echo

# Wait for Jenkins to fully initialize
echo "[*] Waiting for Jenkins web interface to be available..."
COUNTER=0
while [ $COUNTER -lt 30 ]; do
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        echo "[+] Jenkins is ready!"
        break
    fi
    echo "    Still waiting... ($COUNTER/30)"
    sleep 3
    COUNTER=$((COUNTER + 1))
done

if [ $COUNTER -eq 30 ]; then
    echo "[!] Warning: Jenkins may not be fully ready, but continuing..."
fi

echo
echo "========================================"
echo "Jenkins Lab Status"
echo "========================================"
docker ps -f "name=jenkins"
echo
echo "[+] Jenkins Lab is running!"
echo "    Access at: http://localhost:8080"
echo "    Username: admin"
echo "    Password: admin"
echo
echo "Now run the integration test:"
echo "    cd /mnt/c/Users/Chogyam/.zenflow/worktrees/new-task-e6e5/offsec-jenkins"
echo "    chmod +x test_jenkins_lab.sh"
echo "    ./test_jenkins_lab.sh"
