#!/bin/bash
#
# TLS Backend Benchmark Script - ringwall
#
# Copyright (C) 2025 ringwall Contributors
#
# This script benchmarks the TLS abstraction layer with different backends
# and collects comprehensive performance metrics for comparison.
#
# Usage: ./benchmark.sh [--backend {gnutls|wolfssl}] [--output FILE]
#

set -euo pipefail

# Configuration
BACKEND="${1:-gnutls}"
OUTPUT_FILE="${2:-benchmark_${BACKEND}_$(date +%Y%m%d_%H%M%S).json}"
SERVER_PORT=4433
SERVER_HOST="127.0.0.1"
CERT_DIR="$(pwd)/tests/bench/certs"
ITERATIONS=1000
WARMUP_ITERATIONS=100

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if binaries exist
    if [ ! -f "poc-server-${BACKEND}" ]; then
        log_error "Server binary not found: poc-server-${BACKEND}"
        log_info "Run: make poc-both"
        exit 1
    fi

    if [ ! -f "poc-client-${BACKEND}" ]; then
        log_error "Client binary not found: poc-client-${BACKEND}"
        log_info "Run: make poc-both"
        exit 1
    fi

    # Check if certificates exist
    if [ ! -f "${CERT_DIR}/server-cert.pem" ] || [ ! -f "${CERT_DIR}/server-key.pem" ]; then
        log_error "Server certificates not found in ${CERT_DIR}"
        log_info "Run: tests/bench/generate_certs.sh"
        exit 1
    fi

    # Check if port is available
    if lsof -Pi :${SERVER_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_error "Port ${SERVER_PORT} is already in use"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Generate test certificates if needed
generate_certs() {
    if [ -f "${CERT_DIR}/server-cert.pem" ]; then
        log_info "Certificates already exist, skipping generation"
        return 0
    fi

    log_info "Generating test certificates..."
    mkdir -p "${CERT_DIR}"

    # Generate CA key and certificate
    openssl genrsa -out "${CERT_DIR}/ca-key.pem" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca-key.pem" \
        -out "${CERT_DIR}/ca-cert.pem" -subj "/CN=Test CA" 2>/dev/null

    # Generate server key and certificate
    openssl genrsa -out "${CERT_DIR}/server-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERT_DIR}/server-key.pem" \
        -out "${CERT_DIR}/server-csr.pem" -subj "/CN=localhost" 2>/dev/null

    # Create extension file for SAN
    cat > "${CERT_DIR}/san.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

    openssl x509 -req -days 365 -in "${CERT_DIR}/server-csr.pem" \
        -CA "${CERT_DIR}/ca-cert.pem" -CAkey "${CERT_DIR}/ca-key.pem" \
        -CAcreateserial -out "${CERT_DIR}/server-cert.pem" \
        -extensions v3_req -extfile "${CERT_DIR}/san.cnf" 2>/dev/null

    chmod 600 "${CERT_DIR}"/*.pem
    log_success "Certificates generated in ${CERT_DIR}"
}

# Start server
start_server() {
    log_info "Starting TLS server (backend: ${BACKEND})..."

    ./poc-server-${BACKEND} \
        --backend ${BACKEND} \
        --port ${SERVER_PORT} \
        --cert "${CERT_DIR}/server-cert.pem" \
        --key "${CERT_DIR}/server-key.pem" \
        > server.log 2>&1 &

    SERVER_PID=$!

    # Wait for server to start
    for i in {1..10}; do
        if lsof -Pi :${SERVER_PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
            log_success "Server started (PID: ${SERVER_PID})"
            return 0
        fi
        sleep 0.5
    done

    log_error "Server failed to start"
    cat server.log
    exit 1
}

# Stop server
stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        log_info "Stopping server (PID: ${SERVER_PID})..."
        kill ${SERVER_PID} 2>/dev/null || true
        wait ${SERVER_PID} 2>/dev/null || true
    fi
}

# Cleanup on exit
cleanup() {
    stop_server
    rm -f server.log
}

trap cleanup EXIT INT TERM

# Measure handshake rate
benchmark_handshake_rate() {
    log_info "Benchmarking handshake rate..."

    local start_time=$(date +%s.%N)
    local handshakes=0

    for i in $(seq 1 ${ITERATIONS}); do
        timeout 5 ./poc-client-${BACKEND} \
            --backend ${BACKEND} \
            --host ${SERVER_HOST} \
            --port ${SERVER_PORT} \
            --iterations 1 \
            --size 64 \
            >/dev/null 2>&1 && ((handshakes++)) || true

        if [ $((i % 100)) -eq 0 ]; then
            echo -ne "\r  Progress: ${i}/${ITERATIONS}"
        fi
    done
    echo ""

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "${end_time} - ${start_time}" | bc)
    local rate=$(echo "scale=2; ${handshakes} / ${elapsed}" | bc)

    log_success "Handshake rate: ${rate} handshakes/sec (${handshakes}/${ITERATIONS} successful)"

    echo "{\"handshake_rate\": ${rate}, \"total_handshakes\": ${handshakes}, \"elapsed_seconds\": ${elapsed}}"
}

# Measure throughput
benchmark_throughput() {
    log_info "Benchmarking throughput..."

    local result=$(./poc-client-${BACKEND} \
        --backend ${BACKEND} \
        --host ${SERVER_HOST} \
        --port ${SERVER_PORT} \
        --iterations ${ITERATIONS} \
        --json 2>/dev/null)

    echo "${result}"
}

# Measure CPU usage
benchmark_cpu_usage() {
    log_info "Benchmarking CPU usage..."

    # Get server PID CPU usage before test
    local cpu_before=$(ps -p ${SERVER_PID} -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")

    # Run test
    ./poc-client-${BACKEND} \
        --backend ${BACKEND} \
        --host ${SERVER_HOST} \
        --port ${SERVER_PORT} \
        --iterations 100 \
        --size 65536 \
        >/dev/null 2>&1 || true

    # Get server PID CPU usage after test
    local cpu_after=$(ps -p ${SERVER_PID} -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")

    log_success "CPU usage: before=${cpu_before}%, after=${cpu_after}%"

    echo "{\"cpu_before\": ${cpu_before}, \"cpu_after\": ${cpu_after}}"
}

# Measure memory usage
benchmark_memory_usage() {
    log_info "Benchmarking memory usage..."

    # Get server PID memory usage (RSS in KB)
    local mem_kb=$(ps -p ${SERVER_PID} -o rss= 2>/dev/null | tr -d ' ' || echo "0")
    local mem_mb=$(echo "scale=2; ${mem_kb} / 1024" | bc)

    log_success "Memory usage: ${mem_mb} MB"

    echo "{\"memory_rss_kb\": ${mem_kb}, \"memory_rss_mb\": ${mem_mb}}"
}

# Measure latency percentiles
benchmark_latency() {
    log_info "Benchmarking latency percentiles..."

    local latencies=()
    local tmp_file=$(mktemp)

    for i in $(seq 1 ${ITERATIONS}); do
        local start=$(date +%s.%N)

        timeout 5 ./poc-client-${BACKEND} \
            --backend ${BACKEND} \
            --host ${SERVER_HOST} \
            --port ${SERVER_PORT} \
            --iterations 1 \
            --size 1024 \
            >/dev/null 2>&1 || continue

        local end=$(date +%s.%N)
        local latency=$(echo "scale=3; (${end} - ${start}) * 1000" | bc)

        echo "${latency}" >> "${tmp_file}"

        if [ $((i % 100)) -eq 0 ]; then
            echo -ne "\r  Progress: ${i}/${ITERATIONS}"
        fi
    done
    echo ""

    # Calculate percentiles
    local p50=$(sort -n "${tmp_file}" | awk '{a[NR]=$1} END {print a[int(NR*0.50)]}')
    local p95=$(sort -n "${tmp_file}" | awk '{a[NR]=$1} END {print a[int(NR*0.95)]}')
    local p99=$(sort -n "${tmp_file}" | awk '{a[NR]=$1} END {print a[int(NR*0.99)]}')
    local avg=$(awk '{sum+=$1} END {print sum/NR}' "${tmp_file}")

    rm -f "${tmp_file}"

    log_success "Latency: p50=${p50}ms, p95=${p95}ms, p99=${p99}ms, avg=${avg}ms"

    echo "{\"p50_ms\": ${p50}, \"p95_ms\": ${p95}, \"p99_ms\": ${p99}, \"avg_ms\": ${avg}}"
}

# Main benchmark function
main() {
    echo ""
    echo "=========================================="
    echo "  TLS Backend Benchmark"
    echo "=========================================="
    echo "Backend: ${BACKEND}"
    echo "Output:  ${OUTPUT_FILE}"
    echo "=========================================="
    echo ""

    check_prerequisites
    generate_certs
    start_server

    # Warm up
    log_info "Warming up..."
    for i in $(seq 1 ${WARMUP_ITERATIONS}); do
        ./poc-client-${BACKEND} \
            --backend ${BACKEND} \
            --host ${SERVER_HOST} \
            --port ${SERVER_PORT} \
            --iterations 1 \
            --size 1024 \
            >/dev/null 2>&1 || true
    done
    log_success "Warmup complete"

    # Run benchmarks
    log_info "Running benchmarks..."
    echo ""

    local handshake_data=$(benchmark_handshake_rate)
    echo ""

    local throughput_data=$(benchmark_throughput)
    echo ""

    local cpu_data=$(benchmark_cpu_usage)
    echo ""

    local memory_data=$(benchmark_memory_usage)
    echo ""

    local latency_data=$(benchmark_latency)
    echo ""

    # Combine results into JSON
    cat > "${OUTPUT_FILE}" <<EOF
{
  "backend": "${BACKEND}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "config": {
    "iterations": ${ITERATIONS},
    "warmup_iterations": ${WARMUP_ITERATIONS},
    "server_port": ${SERVER_PORT}
  },
  "handshake": ${handshake_data},
  "throughput": ${throughput_data},
  "cpu": ${cpu_data},
  "memory": ${memory_data},
  "latency": ${latency_data}
}
EOF

    log_success "Benchmark complete!"
    log_info "Results saved to: ${OUTPUT_FILE}"
    echo ""

    # Print summary
    cat "${OUTPUT_FILE}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend)
            BACKEND="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--backend {gnutls|wolfssl}] [--output FILE]"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate backend
if [[ "${BACKEND}" != "gnutls" && "${BACKEND}" != "wolfssl" ]]; then
    log_error "Invalid backend: ${BACKEND}"
    echo "Usage: $0 [--backend {gnutls|wolfssl}] [--output FILE]"
    exit 1
fi

# Run main function
main
