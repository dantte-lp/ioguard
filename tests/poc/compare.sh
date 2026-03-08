#!/bin/bash
#
# TLS Performance Comparison Script
#
# Copyright (C) 2025 ringwall Contributors
#
# Purpose: Compare GnuTLS vs wolfSSL benchmark results

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Print usage
usage() {
    cat <<EOF
Usage: $0 RESULTS_DIR

Compare benchmark results from RESULTS_DIR.

Expected files:
  - results_gnutls_*.json
  - results_wolfssl_*.json

EOF
    exit 0
}

# Check arguments
if [[ $# -ne 1 ]]; then
    usage
fi

RESULTS_DIR=$1

if [[ ! -d "$RESULTS_DIR" ]]; then
    print_msg "$RED" "ERROR: Results directory not found: $RESULTS_DIR"
    exit 1
fi

# Find latest result files
GNUTLS_FILE=$(ls -t "$RESULTS_DIR"/results_gnutls_*.json 2>/dev/null | head -1)
WOLFSSL_FILE=$(ls -t "$RESULTS_DIR"/results_wolfssl_*.json 2>/dev/null | head -1)

if [[ -z "$GNUTLS_FILE" ]]; then
    print_msg "$RED" "ERROR: No GnuTLS results found in $RESULTS_DIR"
    exit 1
fi

if [[ -z "$WOLFSSL_FILE" ]]; then
    print_msg "$RED" "ERROR: No wolfSSL results found in $RESULTS_DIR"
    exit 1
fi

print_msg "$GREEN" "${BOLD}=== TLS Performance Comparison ===${NC}"
echo ""
print_msg "$BLUE" "GnuTLS results: $(basename "$GNUTLS_FILE")"
print_msg "$BLUE" "wolfSSL results: $(basename "$WOLFSSL_FILE")"
echo ""

# Parse JSON files using Python if available, otherwise use grep/sed
parse_json() {
    local file=$1

    if command -v python3 &>/dev/null; then
        python3 -c "
import json
import sys

with open('$file') as f:
    data = json.load(f)

print(f\"Backend: {data['backend']}\")
print(f\"Handshake time: {data['handshake_time_ms']:.3f} ms\")
print()
print(f\"{'Size':<15} {'Iterations':<12} {'Throughput':<15} {'Latency':<15}\")
print(f\"{'(bytes)':<15} {'':12} {'(MB/s)':<15} {'(ms)':<15}\")
print('-' * 60)

for test in data['tests']:
    size = test['size']
    iterations = test['iterations']
    throughput = test['throughput_mbps']
    latency = test['latency_ms']
    print(f\"{size:<15} {iterations:<12} {throughput:<15.2f} {latency:<15.3f}\")
"
    else
        # Fallback to basic parsing
        echo "Backend: $(grep -o '"backend": "[^"]*"' "$file" | cut -d'"' -f4)"
        echo "Handshake time: $(grep -o '"handshake_time_ms": [0-9.]*' "$file" | cut -d' ' -f2) ms"
        echo ""
        echo "Size            Iterations   Throughput      Latency"
        echo "(bytes)                      (MB/s)          (ms)"
        echo "------------------------------------------------------------"

        # Extract test results
        grep -o '"size": [0-9]*' "$file" | cut -d' ' -f2 | while read size; do
            echo "$size"
        done > /tmp/sizes.txt

        grep -o '"throughput_mbps": [0-9.]*' "$file" | cut -d' ' -f2 | while read tp; do
            echo "$tp"
        done > /tmp/throughput.txt

        grep -o '"latency_ms": [0-9.]*' "$file" | cut -d' ' -f2 | while read lat; do
            echo "$lat"
        done > /tmp/latency.txt

        grep -o '"iterations": [0-9]*' "$file" | cut -d' ' -f2 | while read iter; do
            echo "$iter"
        done > /tmp/iterations.txt

        paste /tmp/sizes.txt /tmp/iterations.txt /tmp/throughput.txt /tmp/latency.txt | \
            awk '{printf "%-15s %-12s %-15.2f %-15.3f\n", $1, $2, $3, $4}'

        rm -f /tmp/sizes.txt /tmp/throughput.txt /tmp/latency.txt /tmp/iterations.txt
    fi
}

# Print GnuTLS results
print_msg "$CYAN" "${BOLD}--- GnuTLS Results ---${NC}"
parse_json "$GNUTLS_FILE"
echo ""

# Print wolfSSL results
print_msg "$CYAN" "${BOLD}--- wolfSSL Results ---${NC}"
parse_json "$WOLFSSL_FILE"
echo ""

# Generate comparison if Python is available
if command -v python3 &>/dev/null; then
    print_msg "$CYAN" "${BOLD}--- Performance Comparison ---${NC}"

    python3 -c "
import json
import sys

# Load data
with open('$GNUTLS_FILE') as f:
    gnutls = json.load(f)

with open('$WOLFSSL_FILE') as f:
    wolfssl = json.load(f)

# Compare handshake time
gnutls_hs = gnutls['handshake_time_ms']
wolfssl_hs = wolfssl['handshake_time_ms']
hs_delta = ((wolfssl_hs - gnutls_hs) / gnutls_hs) * 100

print(f\"Handshake Time:\")
print(f\"  GnuTLS:  {gnutls_hs:8.3f} ms\")
print(f\"  wolfSSL: {wolfssl_hs:8.3f} ms\")
print(f\"  Delta:   {hs_delta:+8.2f}%\")
print()

# Compare throughput and latency
print(f\"{'Size':<15} {'Metric':<15} {'GnuTLS':<15} {'wolfSSL':<15} {'Delta':<15}\")
print('-' * 75)

for i, gnutls_test in enumerate(gnutls['tests']):
    if i >= len(wolfssl['tests']):
        break

    wolfssl_test = wolfssl['tests'][i]
    size = gnutls_test['size']

    # Throughput comparison
    gnutls_tp = gnutls_test['throughput_mbps']
    wolfssl_tp = wolfssl_test['throughput_mbps']
    tp_delta = ((wolfssl_tp - gnutls_tp) / gnutls_tp) * 100

    print(f\"{size:<15} {'Throughput':<15} {gnutls_tp:<15.2f} {wolfssl_tp:<15.2f} {tp_delta:+14.2f}%\")

    # Latency comparison
    gnutls_lat = gnutls_test['latency_ms']
    wolfssl_lat = wolfssl_test['latency_ms']
    lat_delta = ((wolfssl_lat - gnutls_lat) / gnutls_lat) * 100

    print(f\"{'':<15} {'Latency':<15} {gnutls_lat:<15.3f} {wolfssl_lat:<15.3f} {lat_delta:+14.2f}%\")
    print()

# Overall verdict
print('-' * 75)
print()

# Calculate average deltas
avg_tp_delta = sum([
    ((wolfssl['tests'][i]['throughput_mbps'] - gnutls['tests'][i]['throughput_mbps']) /
     gnutls['tests'][i]['throughput_mbps']) * 100
    for i in range(min(len(gnutls['tests']), len(wolfssl['tests'])))
]) / min(len(gnutls['tests']), len(wolfssl['tests']))

avg_lat_delta = sum([
    ((wolfssl['tests'][i]['latency_ms'] - gnutls['tests'][i]['latency_ms']) /
     gnutls['tests'][i]['latency_ms']) * 100
    for i in range(min(len(gnutls['tests']), len(wolfssl['tests'])))
]) / min(len(gnutls['tests']), len(wolfssl['tests']))

print(f\"Average Performance Delta:\")
print(f\"  Handshake:  {hs_delta:+8.2f}%\")
print(f\"  Throughput: {avg_tp_delta:+8.2f}%\")
print(f\"  Latency:    {avg_lat_delta:+8.2f}%\")
print()

# Verdict
print(f\"GO/NO-GO Decision Criteria: Performance within ±10%\")
print()

verdict = 'GO'
if abs(hs_delta) > 10:
    print(f\"  ⚠ Handshake delta {hs_delta:+.2f}% exceeds ±10% threshold\")
    verdict = 'NO-GO'
else:
    print(f\"  ✓ Handshake delta {hs_delta:+.2f}% within acceptable range\")

if abs(avg_tp_delta) > 10:
    print(f\"  ⚠ Throughput delta {avg_tp_delta:+.2f}% exceeds ±10% threshold\")
    verdict = 'NO-GO'
else:
    print(f\"  ✓ Throughput delta {avg_tp_delta:+.2f}% within acceptable range\")

if abs(avg_lat_delta) > 10:
    print(f\"  ⚠ Latency delta {avg_lat_delta:+.2f}% exceeds ±10% threshold\")
    verdict = 'NO-GO'
else:
    print(f\"  ✓ Latency delta {avg_lat_delta:+.2f}% within acceptable range\")

print()
if verdict == 'GO':
    print(f\"✓ VERDICT: GO - wolfSSL performance is acceptable\")
    sys.exit(0)
else:
    print(f\"✗ VERDICT: NO-GO - Performance regression detected\")
    sys.exit(1)
"

    verdict_result=$?
    echo ""

    if [[ $verdict_result -eq 0 ]]; then
        print_msg "$GREEN" "${BOLD}✓ Performance test PASSED${NC}"
    else
        print_msg "$RED" "${BOLD}✗ Performance test FAILED${NC}"
    fi
else
    print_msg "$YELLOW" "Python3 not available - install for detailed comparison"
fi

echo ""
print_msg "$BLUE" "Results available in: $RESULTS_DIR"
