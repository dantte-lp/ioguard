#!/bin/bash
#
# PoC Server/Client Test Script
# Tests all combinations of GnuTLS and wolfSSL backends
#

set -e

# Ensure wolfSSL library is in path
export LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
# Detect if running in container (mounted at /workspace) or on host
if [ -d "/workspace" ] && [ -f "/workspace/Makefile" ]; then
    PROJECT_ROOT="/workspace"
else
    PROJECT_ROOT="/opt/projects/repositories/ioguard"
fi

TEST_PORT=4433
TEST_HOST="127.0.0.1"
CERT_FILE="${PROJECT_ROOT}/tests/certs/server-cert.pem"
KEY_FILE="${PROJECT_ROOT}/tests/certs/server-key.pem"
LOG_DIR="${PROJECT_ROOT}/tests/poc/logs"
ITERATIONS=10  # Reduced for faster testing

# Create log directory
mkdir -p "${LOG_DIR}"

# Test results
declare -A TEST_RESULTS
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to build binaries if needed
build_binaries() {
    print_info "Checking if binaries need to be built..."

    local need_build=false
    for binary in poc-server-gnutls poc-client-gnutls poc-server-wolfssl poc-client-wolfssl; do
        if [ ! -f "${PROJECT_ROOT}/${binary}" ]; then
            need_build=true
            break
        fi
    done

    if [ "$need_build" = false ]; then
        print_success "All binaries already exist"
        return 0
    fi

    print_info "Building binaries..."
    cd "${PROJECT_ROOT}"

    # Build GnuTLS (save to /tmp first to avoid make clean deleting them)
    print_info "Building GnuTLS version..."
    make clean >/dev/null 2>&1
    if ! make poc BACKEND=gnutls >/dev/null 2>&1; then
        print_error "Failed to build GnuTLS version"
        return 1
    fi
    mv poc-server /tmp/poc-server-gnutls
    mv poc-client /tmp/poc-client-gnutls

    # Build wolfSSL
    print_info "Building wolfSSL version..."
    make clean >/dev/null 2>&1
    if ! make poc BACKEND=wolfssl >/dev/null 2>&1; then
        print_error "Failed to build wolfSSL version"
        return 1
    fi
    mv poc-server /tmp/poc-server-wolfssl
    mv poc-client /tmp/poc-client-wolfssl

    # Move from /tmp to project root
    mv /tmp/poc-*-gnutls "${PROJECT_ROOT}/"
    mv /tmp/poc-*-wolfssl "${PROJECT_ROOT}/"

    print_success "Binaries built successfully"
    return 0
}

# Function to check if port is in use
check_port() {
    # Try multiple methods to check if port is listening
    # Method 1: ss (if available)
    if command -v ss >/dev/null 2>&1; then
        if ss -tln 2>/dev/null | grep -q ":${TEST_PORT} "; then
            return 0
        fi
    fi

    # Method 2: netstat (if available)
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tln 2>/dev/null | grep -q ":${TEST_PORT} "; then
            return 0
        fi
    fi

    # Method 3: Try to connect with timeout
    if timeout 1 bash -c "echo > /dev/tcp/${TEST_HOST}/${TEST_PORT}" 2>/dev/null; then
        return 0
    fi

    return 1
}

# Function to wait for server to start
wait_for_server() {
    local timeout=10
    local count=0

    while [ $count -lt $timeout ]; do
        if check_port; then
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done
    return 1
}

# Function to kill server
kill_server() {
    local server_pid=$1
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        print_info "Stopping server (PID: $server_pid)..."
        kill "$server_pid" 2>/dev/null || true
        sleep 0.5
        kill -9 "$server_pid" 2>/dev/null || true
    fi
}

# Function to run a test
run_test() {
    local test_name=$1
    local server_binary=$2
    local client_binary=$3
    local server_backend=$4
    local client_backend=$5

    TEST_COUNT=$((TEST_COUNT + 1))

    print_info "=========================================="
    print_info "Test #${TEST_COUNT}: ${test_name}"
    print_info "  Server: ${server_backend}"
    print_info "  Client: ${client_backend}"
    print_info "=========================================="

    local server_log="${LOG_DIR}/server_${server_backend}_${client_backend}.log"
    local client_log="${LOG_DIR}/client_${server_backend}_${client_backend}.log"
    local client_json="${LOG_DIR}/client_${server_backend}_${client_backend}.json"

    # Start server in background
    print_info "Starting ${server_backend} server..."
    "${PROJECT_ROOT}/${server_binary}" \
        -b "${server_backend}" \
        -p "${TEST_PORT}" \
        -c "${CERT_FILE}" \
        -k "${KEY_FILE}" \
        -v > "${server_log}" 2>&1 &

    local server_pid=$!
    print_info "Server started (PID: ${server_pid})"

    # Wait for server to start
    if ! wait_for_server; then
        print_error "Server failed to start within timeout"
        kill_server "$server_pid"
        TEST_RESULTS["${test_name}"]="FAIL: Server startup timeout"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi

    sleep 1  # Give server a moment to fully initialize

    # Run client
    print_info "Running ${client_backend} client..."
    if "${PROJECT_ROOT}/${client_binary}" \
        -b "${client_backend}" \
        -H "${TEST_HOST}" \
        -p "${TEST_PORT}" \
        -n "${ITERATIONS}" \
        -v > "${client_log}" 2>&1; then

        # Also get JSON output
        "${PROJECT_ROOT}/${client_binary}" \
            -b "${client_backend}" \
            -H "${TEST_HOST}" \
            -p "${TEST_PORT}" \
            -n "${ITERATIONS}" \
            -j > "${client_json}" 2>&1 || true

        print_success "Test passed: ${test_name}"
        TEST_RESULTS["${test_name}"]="PASS"
        PASS_COUNT=$((PASS_COUNT + 1))

        # Extract some stats
        if [ -f "${client_json}" ]; then
            local handshake_time=$(grep -m1 '"handshake_time_ms"' "${client_json}" | sed 's/.*: \([0-9.]*\).*/\1/')
            print_info "  Handshake time: ${handshake_time} ms"
        fi
    else
        print_error "Test failed: ${test_name}"
        print_error "  Server log: ${server_log}"
        print_error "  Client log: ${client_log}"
        TEST_RESULTS["${test_name}"]="FAIL: Client error"
        FAIL_COUNT=$((FAIL_COUNT + 1))

        # Show last few lines of logs
        print_warning "Last 10 lines of server log:"
        tail -10 "${server_log}" | sed 's/^/    /'
        print_warning "Last 10 lines of client log:"
        tail -10 "${client_log}" | sed 's/^/    /'
    fi

    # Stop server
    kill_server "$server_pid"

    # Wait for port to be released
    sleep 1

    echo ""
}

# Main test execution
main() {
    print_info "PoC Server/Client Communication Tests"
    print_info "======================================"
    print_info "Project root: ${PROJECT_ROOT}"
    print_info "Test port: ${TEST_PORT}"
    print_info "Iterations per test: ${ITERATIONS}"
    print_info "Log directory: ${LOG_DIR}"
    echo ""

    # Build binaries if needed
    if ! build_binaries; then
        print_error "Failed to build binaries"
        exit 1
    fi
    echo ""

    # Verify binaries exist
    for binary in poc-server-gnutls poc-client-gnutls poc-server-wolfssl poc-client-wolfssl; do
        if [ ! -f "${PROJECT_ROOT}/${binary}" ]; then
            print_error "Binary not found: ${binary}"
            exit 1
        fi
    done
    print_success "All binaries found"

    # Verify certificates exist
    if [ ! -f "${CERT_FILE}" ] || [ ! -f "${KEY_FILE}" ]; then
        print_error "Certificates not found"
        exit 1
    fi
    print_success "Certificates found"
    echo ""

    # Test 1: GnuTLS server + GnuTLS client
    run_test "GnuTLS-to-GnuTLS" "poc-server-gnutls" "poc-client-gnutls" "gnutls" "gnutls"

    # Test 2: wolfSSL server + wolfSSL client
    run_test "wolfSSL-to-wolfSSL" "poc-server-wolfssl" "poc-client-wolfssl" "wolfssl" "wolfssl"

    # Test 3: GnuTLS server + wolfSSL client (cross-backend)
    run_test "GnuTLS-server-wolfSSL-client" "poc-server-gnutls" "poc-client-wolfssl" "gnutls" "wolfssl"

    # Test 4: wolfSSL server + GnuTLS client (cross-backend)
    run_test "wolfSSL-server-GnuTLS-client" "poc-server-wolfssl" "poc-client-gnutls" "wolfssl" "gnutls"

    # Print summary
    echo ""
    print_info "=========================================="
    print_info "TEST SUMMARY"
    print_info "=========================================="
    print_info "Total tests: ${TEST_COUNT}"
    print_success "Passed: ${PASS_COUNT}"
    if [ ${FAIL_COUNT} -gt 0 ]; then
        print_error "Failed: ${FAIL_COUNT}"
    else
        print_info "Failed: ${FAIL_COUNT}"
    fi
    echo ""

    # Print individual results
    for test_name in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$test_name]}"
        if [[ "$result" == "PASS" ]]; then
            print_success "${test_name}: ${result}"
        else
            print_error "${test_name}: ${result}"
        fi
    done

    echo ""
    print_info "Logs saved to: ${LOG_DIR}"

    # Exit with failure if any tests failed
    if [ ${FAIL_COUNT} -gt 0 ]; then
        exit 1
    fi

    exit 0
}

# Run main
main
