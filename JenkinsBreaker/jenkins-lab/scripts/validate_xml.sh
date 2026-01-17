#!/bin/bash

set -e

echo "=========================================="
echo "Jenkins Lab XML Validation"
echo "=========================================="
echo ""

JOBS_DIR="../jenkins/jobs"
VALID=0
INVALID=0

echo "[*] Validating job XML files..."
echo ""

for job_dir in "$JOBS_DIR"/*; do
    if [ -d "$job_dir" ]; then
        job_name=$(basename "$job_dir")
        config_file="$job_dir/config.xml"
        
        if [ -f "$config_file" ]; then
            echo -n "Checking $job_name ... "
            
            if xmllint --noout "$config_file" 2>/dev/null; then
                echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Valid XML"
                VALID=$((VALID + 1))
            else
                echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] INVALID XML"
                INVALID=$((INVALID + 1))
                xmllint "$config_file" 2>&1 | head -5
            fi
        else
            echo "[!] $job_name: config.xml not found"
        fi
    fi
done

echo ""
echo "=========================================="
echo "Results: $VALID valid, $INVALID invalid"
echo "=========================================="

if [ $INVALID -gt 0 ]; then
    echo ""
    echo "[!] XML validation failed. Fix errors before deploying."
    exit 1
fi

echo ""
echo "[+] All job XMLs are valid"
echo ""

echo "[*] Checking Groovy scripts syntax..."
echo ""

GROOVY_DIR="../jenkins/init.groovy.d"

for groovy_file in "$GROOVY_DIR"/*.groovy; do
    if [ -f "$groovy_file" ]; then
        filename=$(basename "$groovy_file")
        echo -n "Checking $filename ... "
        
        if grep -q '#!groovy' "$groovy_file"; then
            if grep -qE '(import|def|println)' "$groovy_file"; then
                echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Basic syntax OK"
            else
                echo "[!] Warning: Script may be empty or invalid"
            fi
        else
            echo "[!] Missing #!groovy shebang"
        fi
    fi
done

echo ""
echo "[*] Checking Dockerfile syntax..."
echo ""

DOCKERFILE="../jenkins/Dockerfile"

if [ -f "$DOCKERFILE" ]; then
    echo -n "Validating Dockerfile ... "
    
    if grep -q 'FROM jenkins/jenkins' "$DOCKERFILE"; then
        if grep -q 'COPY --chown=jenkins:jenkins' "$DOCKERFILE"; then
            echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Dockerfile structure OK"
        else
            echo "[!] Warning: Missing proper COPY commands"
        fi
    else
        echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] Invalid Dockerfile - missing FROM"
    fi
fi

echo ""
echo "[*] Checking required secret files..."
echo ""

SECRETS_DIR="../jenkins/secrets"
REQUIRED_SECRETS=(
    "aws_credentials"
    "id_rsa"
    "npmrc"
    "docker_config.json"
    "maven_settings.xml"
    "database_credentials.env"
    "api_keys.env"
    "cloud_credentials.env"
    "backup_script.sh"
)

MISSING=0

for secret in "${REQUIRED_SECRETS[@]}"; do
    secret_file="$SECRETS_DIR/$secret"
    echo -n "Checking $secret ... "
    
    if [ -f "$secret_file" ]; then
        echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“] Exists"
    else
        echo "[ÃƒÂ¢Ã…â€œÃ¢â‚¬â€] MISSING"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo "=========================================="
echo "Secret files: $((${#REQUIRED_SECRETS[@]} - MISSING))/${#REQUIRED_SECRETS[@]} present"
echo "=========================================="

if [ $MISSING -gt 0 ]; then
    echo ""
    echo "[!] Some secret files are missing"
    exit 1
fi

echo ""
echo "[+] All validation checks passed"
echo "[+] Jenkins Lab is ready for deployment"
echo ""
