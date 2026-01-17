#!/bin/bash

echo "========================================="
echo "  FINAL VALIDATION - JenkinsBreaker WSL"
echo "========================================="
echo ""

PASS=0
FAIL=0

echo "[1] Checking WSL environment..."
if [[ -f /proc/version ]]; then
    echo "    ✅ WSL/Linux: $(uname -r)"
    PASS=$((PASS+1))
else
    echo "    ❌ Not WSL"
    FAIL=$((FAIL+1))
fi

echo "[2] Checking Python3..."
if command -v python3 &> /dev/null; then
    echo "    ✅ Python3: $(python3 --version)"
    PASS=$((PASS+1))
else
    echo "    ❌ Python3 missing"
    FAIL=$((FAIL+1))
fi

echo "[3] Checking Docker..."
if command -v docker &> /dev/null; then
    echo "    ✅ Docker: $(docker --version)"
    PASS=$((PASS+1))
else
    echo "    ❌ Docker missing"
    FAIL=$((FAIL+1))
fi

echo "[4] Checking Docker Compose..."
if docker compose version &> /dev/null 2>&1; then
    echo "    ✅ Docker Compose: $(docker compose version)"
    PASS=$((PASS+1))
elif command -v docker-compose &> /dev/null; then
    echo "    ✅ Docker Compose: $(docker-compose --version)"
    PASS=$((PASS+1))
else
    echo "    ❌ Docker Compose missing"
    FAIL=$((FAIL+1))
fi

echo "[5] Checking scripts..."
for script in test_wsl.sh setup.sh cleanup.sh verify_secrets.sh preflight_check.sh test_exploits.sh; do
    if bash -n "scripts/$script" 2>/dev/null; then
        echo "    ✅ $script syntax valid"
        PASS=$((PASS+1))
    else
        echo "    ❌ $script syntax error"
        FAIL=$((FAIL+1))
    fi
done

echo "[6] Checking docker-compose.yml..."
if [[ -f docker-compose.yml ]]; then
    echo "    ✅ docker-compose.yml exists"
    PASS=$((PASS+1))
else
    echo "    ❌ docker-compose.yml missing"
    FAIL=$((FAIL+1))
fi

echo "[7] Checking Dockerfile..."
if [[ -f jenkins/Dockerfile ]]; then
    echo "    ✅ jenkins/Dockerfile exists"
    PASS=$((PASS+1))
else
    echo "    ❌ jenkins/Dockerfile missing"
    FAIL=$((FAIL+1))
fi

echo "[8] Checking plugins.txt..."
if [[ -f jenkins/plugins.txt ]]; then
    PLUGIN_COUNT=$(wc -l < jenkins/plugins.txt)
    echo "    ✅ jenkins/plugins.txt exists ($PLUGIN_COUNT plugins)"
    PASS=$((PASS+1))
else
    echo "    ❌ jenkins/plugins.txt missing"
    FAIL=$((FAIL+1))
fi

echo "[9] Checking init groovy scripts..."
GROOVY_COUNT=$(ls jenkins/init.groovy.d/*.groovy 2>/dev/null | wc -l)
if [[ $GROOVY_COUNT -gt 0 ]]; then
    echo "    ✅ Init scripts: $GROOVY_COUNT files"
    PASS=$((PASS+1))
else
    echo "    ❌ Init scripts missing"
    FAIL=$((FAIL+1))
fi

echo "[10] Checking secrets..."
SECRET_COUNT=$(ls jenkins/secrets/ 2>/dev/null | wc -l)
if [[ $SECRET_COUNT -gt 0 ]]; then
    echo "    ✅ Secrets: $SECRET_COUNT files"
    PASS=$((PASS+1))
else
    echo "    ❌ Secrets missing"
    FAIL=$((FAIL+1))
fi

echo "[11] Checking jobs..."
JOB_COUNT=$(ls jenkins/jobs/ 2>/dev/null | wc -l)
if [[ $JOB_COUNT -gt 0 ]]; then
    echo "    ✅ Jobs: $JOB_COUNT configured"
    PASS=$((PASS+1))
else
    echo "    ❌ Jobs missing"
    FAIL=$((FAIL+1))
fi

echo "[12] Checking JenkinsBreaker.py..."
if [[ -f ../JenkinsBreaker.py ]]; then
    echo "    ✅ JenkinsBreaker.py exists"
    PASS=$((PASS+1))
else
    echo "    ❌ JenkinsBreaker.py missing"
    FAIL=$((FAIL+1))
fi

echo "[13] Checking offsec-jenkins..."
if [[ -f ../../offsec-jenkins/decrypt.py ]]; then
    echo "    ✅ offsec-jenkins/decrypt.py exists"
    PASS=$((PASS+1))
else
    echo "    ❌ offsec-jenkins/decrypt.py missing"
    FAIL=$((FAIL+1))
fi

echo ""
echo "========================================="
echo "           VALIDATION SUMMARY"
echo "========================================="
echo "✅ Passed: $PASS"
echo "❌ Failed: $FAIL"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo "🎉 ALL CHECKS PASSED! Ready to run:"
    echo ""
    echo "    bash scripts/test_wsl.sh"
    echo ""
    exit 0
else
    echo "⚠️  Some checks failed. Review above."
    exit 1
fi
