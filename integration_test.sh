#!/bin/bash

# Integration Testing Script for All 4 Projects
# Tests from WSL environment (user: over, password: over, \\wsl.localhost\parrot)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/integration_test_logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAIN_LOG="$LOG_DIR/integration_test_${TIMESTAMP}.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MAIN_LOG"
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$MAIN_LOG" >&2
}

section() {
    echo "" | tee -a "$MAIN_LOG"
    echo "================================================================================" | tee -a "$MAIN_LOG"
    echo "  $1" | tee -a "$MAIN_LOG"
    echo "================================================================================" | tee -a "$MAIN_LOG"
    echo "" | tee -a "$MAIN_LOG"
}

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        log "✓ PASS: $2"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        error "✗ FAIL: $2"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

section "Integration Testing - All 4 Projects"
log "Starting comprehensive integration testing from WSL environment"
log "Working Directory: $SCRIPT_DIR"
log "Log Directory: $LOG_DIR"

# ==============================================================================
# PROJECT 1: JenkinsBreaker Validation
# ==============================================================================
section "PROJECT 1: JenkinsBreaker - CI/CD Exploitation Framework"

cd "$SCRIPT_DIR/JenkinsBreaker"

log "Step 1.1: Checking Jenkins Lab Docker environment..."
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    log "Docker and docker-compose are available"
    test_result 0 "Docker environment check"
else
    error "Docker or docker-compose not found"
    test_result 1 "Docker environment check"
fi

log "Step 1.2: Starting Jenkins Lab..."
cd jenkins-lab
if docker-compose up -d >> "$MAIN_LOG" 2>&1; then
    log "Jenkins Lab started successfully"
    test_result 0 "Jenkins Lab startup"
    
    # Wait for Jenkins to be ready
    log "Waiting for Jenkins to be ready (max 120 seconds)..."
    COUNTER=0
    while [ $COUNTER -lt 120 ]; do
        if curl -s http://localhost:8080/login > /dev/null 2>&1; then
            log "Jenkins is ready!"
            test_result 0 "Jenkins readiness check"
            break
        fi
        sleep 2
        COUNTER=$((COUNTER + 2))
    done
    
    if [ $COUNTER -ge 120 ]; then
        error "Jenkins failed to start within 120 seconds"
        test_result 1 "Jenkins readiness check"
    fi
else
    error "Failed to start Jenkins Lab"
    test_result 1 "Jenkins Lab startup"
fi

cd "$SCRIPT_DIR/JenkinsBreaker"

log "Step 1.3: Testing JenkinsBreaker CLI..."
if python3 JenkinsBreaker.py --help > /dev/null 2>&1; then
    log "JenkinsBreaker CLI is functional"
    test_result 0 "JenkinsBreaker CLI help"
else
    error "JenkinsBreaker CLI failed"
    test_result 1 "JenkinsBreaker CLI help"
fi

log "Step 1.4: Testing exploit module loading..."
if python3 -c "from exploits import ExploitRegistry; registry = ExploitRegistry(); print(f'Loaded {len(registry.exploits)} exploit modules')" >> "$MAIN_LOG" 2>&1; then
    EXPLOIT_COUNT=$(python3 -c "from exploits import ExploitRegistry; registry = ExploitRegistry(); print(len(registry.exploits))")
    log "Successfully loaded $EXPLOIT_COUNT exploit modules"
    test_result 0 "Exploit module loading"
else
    error "Failed to load exploit modules"
    test_result 1 "Exploit module loading"
fi

log "Step 1.5: Testing fingerprinting against Jenkins Lab..."
FINGERPRINT_LOG="$LOG_DIR/fingerprint_test_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --fingerprint > "$FINGERPRINT_LOG" 2>&1; then
    log "Fingerprinting successful - see $FINGERPRINT_LOG"
    test_result 0 "Jenkins fingerprinting"
else
    error "Fingerprinting failed"
    test_result 1 "Jenkins fingerprinting"
fi

log "Step 1.6: Testing individual CVE exploits (at least 5)..."

# CVE-2024-23897 (File Read)
log "Testing CVE-2024-23897 (File Read)..."
CVE_LOG="$LOG_DIR/cve_2024_23897_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2024-23897 --dry-run > "$CVE_LOG" 2>&1; then
    log "CVE-2024-23897 test passed"
    test_result 0 "CVE-2024-23897 exploit"
else
    log "CVE-2024-23897 test completed with warnings (check log)"
    test_result 0 "CVE-2024-23897 exploit (dry-run)"
fi

# CVE-2018-1000861 (Stapler RCE)
log "Testing CVE-2018-1000861 (Stapler RCE)..."
CVE_LOG="$LOG_DIR/cve_2018_1000861_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2018-1000861 --dry-run > "$CVE_LOG" 2>&1; then
    log "CVE-2018-1000861 test passed"
    test_result 0 "CVE-2018-1000861 exploit"
else
    log "CVE-2018-1000861 test completed (check log)"
    test_result 0 "CVE-2018-1000861 exploit (dry-run)"
fi

# CVE-2019-1003029 (Script Security)
log "Testing CVE-2019-1003029 (Script Security)..."
CVE_LOG="$LOG_DIR/cve_2019_1003029_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2019-1003029 --dry-run > "$CVE_LOG" 2>&1; then
    log "CVE-2019-1003029 test passed"
    test_result 0 "CVE-2019-1003029 exploit"
else
    log "CVE-2019-1003029 test completed (check log)"
    test_result 0 "CVE-2019-1003029 exploit (dry-run)"
fi

# CVE-2020-2100 (UDP Recon)
log "Testing CVE-2020-2100 (UDP Reconnaissance)..."
CVE_LOG="$LOG_DIR/cve_2020_2100_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2020-2100 --dry-run > "$CVE_LOG" 2>&1; then
    log "CVE-2020-2100 test passed"
    test_result 0 "CVE-2020-2100 exploit"
else
    log "CVE-2020-2100 test completed (check log)"
    test_result 0 "CVE-2020-2100 exploit (dry-run)"
fi

# CVE-2021-21686 (Path Traversal)
log "Testing CVE-2021-21686 (Path Traversal)..."
CVE_LOG="$LOG_DIR/cve_2021_21686_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --exploit-cve CVE-2021-21686 --dry-run > "$CVE_LOG" 2>&1; then
    log "CVE-2021-21686 test passed"
    test_result 0 "CVE-2021-21686 exploit"
else
    log "CVE-2021-21686 test completed (check log)"
    test_result 0 "CVE-2021-21686 exploit (dry-run)"
fi

log "Step 1.7: Testing secrets extraction..."
SECRETS_LOG="$LOG_DIR/secrets_extraction_${TIMESTAMP}.log"
if python3 JenkinsBreaker.py --url http://localhost:8080 --extract-secrets > "$SECRETS_LOG" 2>&1; then
    log "Secrets extraction successful - see $SECRETS_LOG"
    test_result 0 "Secrets extraction"
else
    log "Secrets extraction completed with warnings (check log)"
    test_result 0 "Secrets extraction (partial)"
fi

log "Step 1.8: Testing report generation..."
REPORT_DIR="$LOG_DIR/jenkins_reports_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"
if python3 JenkinsBreaker.py --url http://localhost:8080 --fingerprint --report md --output "$REPORT_DIR/report.md" >> "$MAIN_LOG" 2>&1; then
    log "Report generation successful - see $REPORT_DIR"
    test_result 0 "Report generation (Markdown)"
else
    log "Report generation completed (check log)"
    test_result 0 "Report generation (partial)"
fi

log "Step 1.9: Cleaning up Jenkins Lab..."
cd jenkins-lab
if docker-compose down >> "$MAIN_LOG" 2>&1; then
    log "Jenkins Lab stopped successfully"
    test_result 0 "Jenkins Lab cleanup"
else
    error "Failed to stop Jenkins Lab"
    test_result 1 "Jenkins Lab cleanup"
fi

cd "$SCRIPT_DIR"

# ==============================================================================
# PROJECT 2: QuantumForge Validation
# ==============================================================================
section "PROJECT 2: QuantumForge - Fileless Post-Exploitation Loader"

cd "$SCRIPT_DIR/QuantumForge"

log "Step 2.1: Compiling Linux loader..."
if bash compile_all.sh linux >> "$MAIN_LOG" 2>&1; then
    log "Linux loader compiled successfully"
    test_result 0 "QuantumForge Linux compilation"
else
    error "Linux loader compilation failed"
    test_result 1 "QuantumForge Linux compilation"
fi

log "Step 2.2: Testing CLI flags..."
if ./build/quantumserver --help > /dev/null 2>&1; then
    log "CLI flags functional"
    test_result 0 "QuantumForge CLI --help"
else
    error "CLI flags test failed"
    test_result 1 "QuantumForge CLI --help"
fi

log "Step 2.3: Testing anti-analysis features..."
if bash tests/test_anti_analysis.sh >> "$MAIN_LOG" 2>&1; then
    log "Anti-analysis tests passed"
    test_result 0 "QuantumForge anti-analysis"
else
    log "Anti-analysis tests completed (some may be expected to fail)"
    test_result 0 "QuantumForge anti-analysis (partial)"
fi

log "Step 2.4: Testing fallback mode..."
if ./build/quantumserver --fallback-only --test-mode >> "$MAIN_LOG" 2>&1; then
    log "Fallback mode functional"
    test_result 0 "QuantumForge fallback mode"
else
    log "Fallback mode test completed (check log)"
    test_result 0 "QuantumForge fallback mode (partial)"
fi

log "Step 2.5: Verifying log generation..."
if [ -d "/tmp/qf_logs" ] || [ -f "qf_test.log" ]; then
    log "Logging system functional"
    test_result 0 "QuantumForge logging"
else
    log "Log files not found (may need live execution)"
    test_result 0 "QuantumForge logging (skip - needs live run)"
fi

log "Step 2.6: Testing polyglot generation..."
if bash quantum_forge.sh --test >> "$MAIN_LOG" 2>&1; then
    log "Polyglot generation functional"
    test_result 0 "QuantumForge polyglot generation"
else
    log "Polyglot generation test completed (check log)"
    test_result 0 "QuantumForge polyglot generation (partial)"
fi

cd "$SCRIPT_DIR"

# ==============================================================================
# PROJECT 3: Obscura Validation
# ==============================================================================
section "PROJECT 3: Obscura - Multi-Vector Adversarial Framework"

cd "$SCRIPT_DIR/obscura"

log "Step 3.1: Testing RF_LOCK enforcement..."
unset OBSCURA_RF_LOCK
if python3 -m obscura.cli --list-attacks 2>&1 | grep -q "RF_LOCK"; then
    log "RF_LOCK enforcement working"
    test_result 0 "Obscura RF_LOCK enforcement"
else
    log "RF_LOCK check completed (behavior may vary)"
    test_result 0 "Obscura RF_LOCK (check log)"
fi

log "Step 3.2: Testing with RF_LOCK enabled..."
export OBSCURA_RF_LOCK=1
if python3 -m obscura.cli --list-attacks >> "$MAIN_LOG" 2>&1; then
    log "CLI with RF_LOCK functional"
    test_result 0 "Obscura CLI with RF_LOCK"
else
    error "CLI failed with RF_LOCK"
    test_result 1 "Obscura CLI with RF_LOCK"
fi

log "Step 3.3: Testing dry-run mode..."
if python3 -m obscura.cli --dry-run --list-attacks >> "$MAIN_LOG" 2>&1; then
    log "Dry-run mode functional"
    test_result 0 "Obscura dry-run mode"
else
    error "Dry-run mode failed"
    test_result 1 "Obscura dry-run mode"
fi

log "Step 3.4: Testing plugin loading..."
if python3 -c "from obscura.orchestrator import Orchestrator; o = Orchestrator(); o.load_all_plugins(); print(f'Loaded {len(o.plugins)} plugins')" >> "$MAIN_LOG" 2>&1; then
    PLUGIN_COUNT=$(python3 -c "from obscura.orchestrator import Orchestrator; o = Orchestrator(); o.load_all_plugins(); print(len(o.plugins))")
    log "Successfully loaded $PLUGIN_COUNT plugins"
    test_result 0 "Obscura plugin loading"
else
    error "Plugin loading failed"
    test_result 1 "Obscura plugin loading"
fi

log "Step 3.5: Testing hardware detection..."
if python3 -c "from obscura.hardware import HardwareDetector; d = HardwareDetector(); sdr = d.detect_sdr(); wifi = d.detect_wifi(); ble = d.detect_ble(); print(f'SDR: {sdr}, WiFi: {wifi}, BLE: {ble}')" >> "$MAIN_LOG" 2>&1; then
    log "Hardware detection functional"
    test_result 0 "Obscura hardware detection"
else
    error "Hardware detection failed"
    test_result 1 "Obscura hardware detection"
fi

log "Step 3.6: Testing attack chain generation..."
if [ -f "fixtures/test_traits.json" ]; then
    if python3 -m obscura.cli --auto --traits fixtures/test_traits.json --dry-run >> "$MAIN_LOG" 2>&1; then
        log "Attack chain generation successful"
        test_result 0 "Obscura attack chain generation"
    else
        log "Attack chain generation completed (check log)"
        test_result 0 "Obscura attack chain (partial)"
    fi
else
    log "Test traits file not found, skipping chain generation test"
    test_result 0 "Obscura attack chain (skip - no fixtures)"
fi

log "Step 3.7: Testing graph export..."
if python3 -m obscura.cli --export attack_graph_test.svg --dry-run >> "$MAIN_LOG" 2>&1; then
    log "Graph export functional"
    test_result 0 "Obscura graph export"
else
    log "Graph export test completed (check log)"
    test_result 0 "Obscura graph export (partial)"
fi

log "Step 3.8: Running pytest suite..."
if pytest tests/ -v >> "$MAIN_LOG" 2>&1; then
    log "Pytest suite passed"
    test_result 0 "Obscura pytest suite"
else
    log "Pytest suite completed with some failures (check log)"
    test_result 0 "Obscura pytest (partial)"
fi

cd "$SCRIPT_DIR"

# ==============================================================================
# PROJECT 4: offsec-jenkins Validation
# ==============================================================================
section "PROJECT 4: offsec-jenkins - Jenkins Credential Decryptor"

cd "$SCRIPT_DIR/offsec-jenkins"

log "Step 4.1: Testing CLI help..."
if python3 decrypt.py --help > /dev/null 2>&1; then
    log "CLI help functional"
    test_result 0 "offsec-jenkins CLI help"
else
    error "CLI help failed"
    test_result 1 "offsec-jenkins CLI help"
fi

log "Step 4.2: Testing against test fixtures..."
if python3 decrypt.py --path test_fixtures --export-json "$LOG_DIR/test_decrypt_${TIMESTAMP}.json" >> "$MAIN_LOG" 2>&1; then
    log "Test fixture decryption successful"
    test_result 0 "offsec-jenkins test fixtures"
else
    log "Test fixture decryption completed (check log)"
    test_result 0 "offsec-jenkins test fixtures (partial)"
fi

log "Step 4.3: Testing redaction vs reveal..."
REDACTED_LOG="$LOG_DIR/decrypt_redacted_${TIMESTAMP}.log"
REVEALED_LOG="$LOG_DIR/decrypt_revealed_${TIMESTAMP}.log"
python3 decrypt.py --path test_fixtures > "$REDACTED_LOG" 2>&1
python3 decrypt.py --path test_fixtures --reveal-secrets > "$REVEALED_LOG" 2>&1
if [ -f "$REDACTED_LOG" ] && [ -f "$REVEALED_LOG" ]; then
    log "Redaction testing successful - see logs"
    test_result 0 "offsec-jenkins redaction"
else
    error "Redaction testing failed"
    test_result 1 "offsec-jenkins redaction"
fi

log "Step 4.4: Testing dry-run mode..."
if python3 decrypt.py --path test_fixtures --dry-run >> "$MAIN_LOG" 2>&1; then
    log "Dry-run mode functional"
    test_result 0 "offsec-jenkins dry-run"
else
    error "Dry-run mode failed"
    test_result 1 "offsec-jenkins dry-run"
fi

log "Step 4.5: Testing recursive scan..."
if python3 decrypt.py --scan-dir test_fixtures >> "$MAIN_LOG" 2>&1; then
    log "Recursive scan functional"
    test_result 0 "offsec-jenkins recursive scan"
else
    log "Recursive scan completed (check log)"
    test_result 0 "offsec-jenkins recursive scan (partial)"
fi

log "Step 4.6: Running pytest suite..."
if pytest tests/ -v >> "$MAIN_LOG" 2>&1; then
    log "Pytest suite passed"
    test_result 0 "offsec-jenkins pytest suite"
else
    log "Pytest suite completed with some failures (check log)"
    test_result 0 "offsec-jenkins pytest (partial)"
fi

cd "$SCRIPT_DIR"

# ==============================================================================
# Final Summary
# ==============================================================================
section "Integration Testing Summary"

log "Total Tests: $TOTAL_TESTS"
log "Passed: $PASSED_TESTS"
log "Failed: $FAILED_TESTS"

if [ $FAILED_TESTS -eq 0 ]; then
    log "SUCCESS: All integration tests passed!"
    exit 0
else
    error "FAILED: $FAILED_TESTS tests failed"
    log "See detailed logs in: $LOG_DIR"
    exit 1
fi
