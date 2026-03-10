#!/bin/bash
#
# TLS Performance Benchmarking Script
#
# Copyright (C) 2025 ioguard Contributors
#
# Purpose: Automated benchmarking of GnuTLS vs wolfSSL performance

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SERVER_GNUTLS="${WORKSPACE_DIR}/poc-server-gnutls"
CLIENT_GNUTLS="${WORKSPACE_DIR}/poc-client-gnutls"
SERVER_WOLFSSL="${WORKSPACE_DIR}/poc-server-wolfssl"
CLIENT_WOLFSSL="${WORKSPACE_DIR}/poc-client-wolfssl"
CERT_DIR="${WORKSPACE_DIR}/tests/certs"
CERT_FILE="${CERT_DIR}/server-cert.pem"
KEY_FILE="${CERT_DIR}/server-key.pem"
CA_FILE="${CERT_DIR}/ca-cert.pem"

# Default parameters
PORT=4433
ITERATIONS=1000
WARMUP_ITERATIONS=10
BACKENDS=("gnutls" "wolfssl")
OUTPUT_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Print usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -b, --backend BACKEND    Test specific backend (gnutls or wolfssl)
    -n, --iterations N       Number of iterations (default: $ITERATIONS)
    -p, --port PORT          Server port (default: $PORT)
    -o, --output DIR         Output directory (default: $OUTPUT_DIR)
    -h, --help               Show this help

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--backend)
            BACKENDS=("$2")
            shift 2
            ;;
        -n|--iterations)
            ITERATIONS=$2
            shift 2
            ;;
        -p|--port)
            PORT=$2
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if binaries exist
check_binaries() {
    if [[ ! -f "$SERVER_GNUTLS" || ! -f "$CLIENT_GNUTLS" ]]; then
        print_msg "$RED" "ERROR: GnuTLS binaries not found"
        print_msg "$YELLOW" "Please run: make poc-both"
        return 1
    fi

    if [[ ! -f "$SERVER_WOLFSSL" || ! -f "$CLIENT_WOLFSSL" ]]; then
        print_msg "$RED" "ERROR: wolfSSL binaries not found"
        print_msg "$YELLOW" "Please run: make poc-both"
        return 1
    fi

    return 0
}

# Generate test certificates if they don't exist
generate_test_certs() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        print_msg "$GREEN" "Test certificates already exist"
        return 0
    fi

    print_msg "$BLUE" "Generating test certificates..."

    # Generate CA key and certificate
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CA_FILE" \
        -out "$CA_FILE" \
        -days 365 \
        -subj "/CN=Test CA" 2>/dev/null

    # Generate server key and certificate
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" \
        -out "${SCRIPT_DIR}/test_cert.csr" \
        -subj "/CN=localhost" 2>/dev/null

    openssl x509 -req \
        -in "${SCRIPT_DIR}/test_cert.csr" \
        -CA "$CA_FILE" \
        -CAkey "$CA_FILE" \
        -CAcreateserial \
        -out "$CERT_FILE" \
        -days 365 2>/dev/null

    rm -f "${SCRIPT_DIR}/test_cert.csr"

    print_msg "$GREEN" "Test certificates generated successfully"
}

# Start server
start_server() {
    local backend=$1
    local log_file="${OUTPUT_DIR}/server_${backend}_${TIMESTAMP}.log"
    local server_bin

    if [[ "$backend" == "gnutls" ]]; then
        server_bin="$SERVER_GNUTLS"
    else
        server_bin="$SERVER_WOLFSSL"
    fi

    print_msg "$BLUE" "Starting $backend server on port $PORT..."

    # Start server with proper library path
    LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" \
        "$server_bin" \
        --backend "$backend" \
        --port "$PORT" \
        --cert "$CERT_FILE" \
        --key "$KEY_FILE" \
        > "$log_file" 2>&1 &

    local server_pid=$!
    echo "$server_pid" > "${OUTPUT_DIR}/server_${backend}.pid"

    # Wait for server to start
    sleep 2

    # Check if server is running
    if ! kill -0 "$server_pid" 2>/dev/null; then
        print_msg "$RED" "ERROR: Server failed to start"
        cat "$log_file"
        return 1
    fi

    print_msg "$GREEN" "Server started (PID: $server_pid)"
    return 0
}

# Stop server
stop_server() {
    local backend=$1
    local pid_file="${OUTPUT_DIR}/server_${backend}.pid"

    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            print_msg "$BLUE" "Stopping $backend server (PID: $pid)..."
            kill -TERM "$pid"
            sleep 1
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid"
            fi
        fi
        rm -f "$pid_file"
    fi
}

# Run client benchmark
run_benchmark() {
    local backend=$1
    local output_file="${OUTPUT_DIR}/results_${backend}_${TIMESTAMP}.json"
    local client_bin

    if [[ "$backend" == "gnutls" ]]; then
        client_bin="$CLIENT_GNUTLS"
    else
        client_bin="$CLIENT_WOLFSSL"
    fi

    print_msg "$BLUE" "Running $backend benchmark (iterations: $ITERATIONS)..."

    # Warmup
    print_msg "$YELLOW" "  Warmup ($WARMUP_ITERATIONS iterations)..."
    LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" \
        "$client_bin" \
        --backend "$backend" \
        --port "$PORT" \
        --iterations "$WARMUP_ITERATIONS" \
        > /dev/null 2>&1 || true

    # Actual benchmark
    print_msg "$GREEN" "  Benchmarking..."
    if LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" \
        "$client_bin" \
        --backend "$backend" \
        --port "$PORT" \
        --iterations "$ITERATIONS" \
        --json \
        > "$output_file" 2>&1; then
        print_msg "$GREEN" "  Results saved to: $output_file"
        return 0
    else
        print_msg "$RED" "  Benchmark failed!"
        return 1
    fi
}

# Measure system resources
measure_resources() {
    local backend=$1
    local pid_file="${OUTPUT_DIR}/server_${backend}.pid"
    local resource_file="${OUTPUT_DIR}/resources_${backend}_${TIMESTAMP}.txt"

    if [[ ! -f "$pid_file" ]]; then
        return 1
    fi

    local pid=$(cat "$pid_file")

    print_msg "$BLUE" "Measuring system resources for $backend..."

    {
        echo "=== System Resources - $backend ==="
        echo "Timestamp: $(date)"
        echo ""
        echo "Process Info:"
        ps -p "$pid" -o pid,ppid,cmd,%mem,%cpu,rss,vsz 2>/dev/null || true
        echo ""
        echo "Memory Map:"
        pmap "$pid" 2>/dev/null | tail -1 || true
        echo ""
    } > "$resource_file"

    print_msg "$GREEN" "  Resource data saved to: $resource_file"
}

# Main benchmark loop
main() {
    print_msg "$GREEN" "=== TLS Performance Benchmark ==="
    print_msg "$BLUE" "Timestamp: $TIMESTAMP"
    print_msg "$BLUE" "Iterations: $ITERATIONS"
    print_msg "$BLUE" "Port: $PORT"
    print_msg "$BLUE" "Backends: ${BACKENDS[*]}"
    echo ""

    # Check if binaries exist
    if ! check_binaries; then
        exit 1
    fi

    # Generate certificates
    generate_test_certs

    # System information
    print_msg "$BLUE" "=== System Information ==="
    uname -a
    cat /proc/cpuinfo | grep "model name" | head -1
    free -h | head -2
    echo ""

    # Disable CPU frequency scaling if possible
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        print_msg "$YELLOW" "CPU frequency scaling detected. Consider running:"
        print_msg "$YELLOW" "  sudo cpupower frequency-set --governor performance"
        echo ""
    fi

    # Benchmark each backend
    for backend in "${BACKENDS[@]}"; do
        print_msg "$GREEN" "=== Testing Backend: $backend ==="

        # Stop any existing server
        stop_server "$backend"

        # Start server
        if ! start_server "$backend"; then
            print_msg "$RED" "Failed to start $backend server, skipping..."
            continue
        fi

        # Run benchmark
        if run_benchmark "$backend"; then
            # Measure resources
            measure_resources "$backend"
        else
            print_msg "$RED" "Benchmark failed for $backend"
        fi

        # Stop server
        stop_server "$backend"

        echo ""
    done

    print_msg "$GREEN" "=== Benchmark Complete ==="
    print_msg "$BLUE" "Results saved to: $OUTPUT_DIR"
    echo ""
    print_msg "$YELLOW" "To compare results, run:"
    print_msg "$YELLOW" "  $SCRIPT_DIR/compare.sh $OUTPUT_DIR"
}

# Cleanup on exit
cleanup() {
    for backend in "${BACKENDS[@]}"; do
        stop_server "$backend"
    done
}

trap cleanup EXIT INT TERM

# Run main
main
