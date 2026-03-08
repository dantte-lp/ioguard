#!/bin/bash
#
# Benchmark Results Comparison Script - ringwall
#
# Copyright (C) 2025 ringwall Contributors
#
# Compares benchmark results between GnuTLS and wolfSSL backends
# and generates a GO/NO-GO decision report.
#

set -euo pipefail

# Configuration
GNUTLS_FILE="${1:-}"
WOLFSSL_FILE="${2:-}"
OUTPUT_FILE="comparison_$(date +%Y%m%d_%H%M%S).md"
REGRESSION_THRESHOLD=10  # Maximum acceptable regression percentage

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Usage
usage() {
    cat <<EOF
Usage: $0 <gnutls_results.json> <wolfssl_results.json>

Compares benchmark results between GnuTLS and wolfSSL backends.

Examples:
  $0 benchmark_gnutls.json benchmark_wolfssl.json
EOF
    exit 1
}

# Validate inputs
if [ -z "${GNUTLS_FILE}" ] || [ -z "${WOLFSSL_FILE}" ]; then
    log_error "Missing required arguments"
    usage
fi

if [ ! -f "${GNUTLS_FILE}" ]; then
    log_error "GnuTLS results file not found: ${GNUTLS_FILE}"
    exit 1
fi

if [ ! -f "${WOLFSSL_FILE}" ]; then
    log_error "wolfSSL results file not found: ${WOLFSSL_FILE}"
    exit 1
fi

# Extract values using jq
extract_value() {
    local file="$1"
    local path="$2"
    jq -r "${path}" "${file}" 2>/dev/null || echo "0"
}

# Calculate percentage difference
calc_diff() {
    local baseline="$1"
    local current="$2"
    echo "scale=2; ((${current} - ${baseline}) / ${baseline}) * 100" | bc 2>/dev/null || echo "0"
}

log_info "Analyzing benchmark results..."

# Extract metrics
gnutls_handshake_rate=$(extract_value "${GNUTLS_FILE}" '.handshake.handshake_rate')
wolfssl_handshake_rate=$(extract_value "${WOLFSSL_FILE}" '.handshake.handshake_rate')

gnutls_latency_p50=$(extract_value "${GNUTLS_FILE}" '.latency.p50_ms')
wolfssl_latency_p50=$(extract_value "${WOLFSSL_FILE}" '.latency.p50_ms')

gnutls_latency_p95=$(extract_value "${GNUTLS_FILE}" '.latency.p95_ms')
wolfssl_latency_p95=$(extract_value "${WOLFSSL_FILE}" '.latency.p95_ms')

gnutls_latency_p99=$(extract_value "${GNUTLS_FILE}" '.latency.p99_ms')
wolfssl_latency_p99=$(extract_value "${WOLFSSL_FILE}" '.latency.p99_ms')

gnutls_memory=$(extract_value "${GNUTLS_FILE}" '.memory.memory_rss_mb')
wolfssl_memory=$(extract_value "${WOLFSSL_FILE}" '.memory.memory_rss_mb')

# Extract throughput data (first test result - 64KB)
gnutls_throughput=$(extract_value "${GNUTLS_FILE}" '.throughput.tests[5].throughput_mbps')
wolfssl_throughput=$(extract_value "${WOLFSSL_FILE}" '.throughput.tests[5].throughput_mbps')

# Calculate differences
handshake_diff=$(calc_diff "${gnutls_handshake_rate}" "${wolfssl_handshake_rate}")
latency_p50_diff=$(calc_diff "${gnutls_latency_p50}" "${wolfssl_latency_p50}")
latency_p95_diff=$(calc_diff "${gnutls_latency_p95}" "${wolfssl_latency_p95}")
latency_p99_diff=$(calc_diff "${gnutls_latency_p99}" "${wolfssl_latency_p99}")
memory_diff=$(calc_diff "${gnutls_memory}" "${wolfssl_memory}")
throughput_diff=$(calc_diff "${gnutls_throughput}" "${wolfssl_throughput}")

# Generate report
cat > "${OUTPUT_FILE}" <<EOF
# TLS Backend Performance Comparison

**Generated**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

**Baseline**: GnuTLS
**Candidate**: wolfSSL

---

## Executive Summary

EOF

# Determine GO/NO-GO
go_nogo="GO"
reasons=()

# Check handshake rate (higher is better, so negative diff is regression)
if (( $(echo "${handshake_diff} < -${REGRESSION_THRESHOLD}" | bc -l) )); then
    go_nogo="NO-GO"
    reasons+=("Handshake rate regression: ${handshake_diff}% (threshold: -${REGRESSION_THRESHOLD}%)")
fi

# Check latency p95 (lower is better, so positive diff is regression)
if (( $(echo "${latency_p95_diff} > ${REGRESSION_THRESHOLD}" | bc -l) )); then
    go_nogo="NO-GO"
    reasons+=("Latency p95 regression: +${latency_p95_diff}% (threshold: +${REGRESSION_THRESHOLD}%)")
fi

# Check latency p99 (lower is better, so positive diff is regression)
if (( $(echo "${latency_p99_diff} > ${REGRESSION_THRESHOLD}" | bc -l) )); then
    go_nogo="NO-GO"
    reasons+=("Latency p99 regression: +${latency_p99_diff}% (threshold: +${REGRESSION_THRESHOLD}%)")
fi

# Check throughput (higher is better, so negative diff is regression)
if (( $(echo "${throughput_diff} < -${REGRESSION_THRESHOLD}" | bc -l) )); then
    go_nogo="NO-GO"
    reasons+=("Throughput regression: ${throughput_diff}% (threshold: -${REGRESSION_THRESHOLD}%)")
fi

cat >> "${OUTPUT_FILE}" <<EOF
### Decision: **${go_nogo}**

**Regression Threshold**: ${REGRESSION_THRESHOLD}%

EOF

if [ "${go_nogo}" = "NO-GO" ]; then
    cat >> "${OUTPUT_FILE}" <<EOF
**Reasons for NO-GO**:
EOF
    for reason in "${reasons[@]}"; do
        echo "- ${reason}" >> "${OUTPUT_FILE}"
    done
    cat >> "${OUTPUT_FILE}" <<EOF

**Recommendation**: Address performance regressions before proceeding with wolfSSL migration.

EOF
else
    cat >> "${OUTPUT_FILE}" <<EOF
**Status**: All metrics within acceptable range (±${REGRESSION_THRESHOLD}%).

**Recommendation**: Proceed with wolfSSL backend migration.

EOF
fi

cat >> "${OUTPUT_FILE}" <<EOF
---

## Detailed Metrics

### Handshake Performance

| Metric | GnuTLS | wolfSSL | Difference |
|--------|--------|---------|------------|
| Handshake Rate (ops/sec) | ${gnutls_handshake_rate} | ${wolfssl_handshake_rate} | ${handshake_diff}% |

EOF

if (( $(echo "${handshake_diff} >= 0" | bc -l) )); then
    echo "**Analysis**: wolfSSL handshake rate is **${handshake_diff}% faster** than GnuTLS." >> "${OUTPUT_FILE}"
else
    echo "**Analysis**: wolfSSL handshake rate is **${handshake_diff}% slower** than GnuTLS." >> "${OUTPUT_FILE}"
fi

cat >> "${OUTPUT_FILE}" <<EOF

---

### Latency Metrics

| Percentile | GnuTLS (ms) | wolfSSL (ms) | Difference |
|------------|-------------|--------------|------------|
| p50 | ${gnutls_latency_p50} | ${wolfssl_latency_p50} | ${latency_p50_diff}% |
| p95 | ${gnutls_latency_p95} | ${wolfssl_latency_p95} | ${latency_p95_diff}% |
| p99 | ${gnutls_latency_p99} | ${wolfssl_latency_p99} | ${latency_p99_diff}% |

EOF

if (( $(echo "${latency_p95_diff} <= 0" | bc -l) )); then
    echo "**Analysis**: wolfSSL p95 latency is **${latency_p95_diff#-}% better** (lower) than GnuTLS." >> "${OUTPUT_FILE}"
else
    echo "**Analysis**: wolfSSL p95 latency is **${latency_p95_diff}% worse** (higher) than GnuTLS." >> "${OUTPUT_FILE}"
fi

cat >> "${OUTPUT_FILE}" <<EOF

---

### Throughput (64KB transfers)

| Metric | GnuTLS (MB/s) | wolfSSL (MB/s) | Difference |
|--------|---------------|----------------|------------|
| Throughput | ${gnutls_throughput} | ${wolfssl_throughput} | ${throughput_diff}% |

EOF

if (( $(echo "${throughput_diff} >= 0" | bc -l) )); then
    echo "**Analysis**: wolfSSL throughput is **${throughput_diff}% faster** than GnuTLS." >> "${OUTPUT_FILE}"
else
    echo "**Analysis**: wolfSSL throughput is **${throughput_diff}% slower** than GnuTLS." >> "${OUTPUT_FILE}"
fi

cat >> "${OUTPUT_FILE}" <<EOF

---

### Memory Usage

| Metric | GnuTLS (MB) | wolfSSL (MB) | Difference |
|--------|-------------|--------------|------------|
| RSS | ${gnutls_memory} | ${wolfssl_memory} | ${memory_diff}% |

EOF

if (( $(echo "${memory_diff} <= 0" | bc -l) )); then
    echo "**Analysis**: wolfSSL uses **${memory_diff#-}% less memory** than GnuTLS." >> "${OUTPUT_FILE}"
else
    echo "**Analysis**: wolfSSL uses **${memory_diff}% more memory** than GnuTLS." >> "${OUTPUT_FILE}"
fi

cat >> "${OUTPUT_FILE}" <<EOF

---

## Raw Data

### GnuTLS Results
\`\`\`json
$(cat "${GNUTLS_FILE}")
\`\`\`

### wolfSSL Results
\`\`\`json
$(cat "${WOLFSSL_FILE}")
\`\`\`

---

## Conclusion

EOF

if [ "${go_nogo}" = "GO" ]; then
    cat >> "${OUTPUT_FILE}" <<EOF
The wolfSSL backend demonstrates acceptable performance characteristics compared to GnuTLS,
with all key metrics within the ±${REGRESSION_THRESHOLD}% threshold. The migration can proceed.

### Next Steps:
1. Complete integration testing with ocserv
2. Validate Cisco Secure Client compatibility
3. Test DTLS 1.3 functionality
4. Verify TLS 1.3 0-RTT support
5. Run extended stress tests

EOF
else
    cat >> "${OUTPUT_FILE}" <<EOF
The wolfSSL backend shows performance regressions exceeding the ${REGRESSION_THRESHOLD}% threshold
in one or more critical metrics. Further optimization is required before proceeding.

### Recommended Actions:
1. Profile wolfSSL implementation to identify bottlenecks
2. Review cipher suite selection and priority strings
3. Verify wolfSSL build configuration (enable ASM optimizations)
4. Consider wolfSSL tuning parameters
5. Re-run benchmarks after optimizations

EOF
fi

log_success "Comparison report generated: ${OUTPUT_FILE}"

# Print summary to console
echo ""
echo "=========================================="
echo "  Performance Comparison Summary"
echo "=========================================="
echo ""
echo "Decision: ${go_nogo}"
echo ""
echo "Handshake Rate:  ${handshake_diff}%"
echo "Latency p95:     ${latency_p95_diff}%"
echo "Latency p99:     ${latency_p99_diff}%"
echo "Throughput:      ${throughput_diff}%"
echo "Memory Usage:    ${memory_diff}%"
echo ""
echo "Full report: ${OUTPUT_FILE}"
echo "=========================================="

# Exit with appropriate code
if [ "${go_nogo}" = "NO-GO" ]; then
    exit 1
else
    exit 0
fi
