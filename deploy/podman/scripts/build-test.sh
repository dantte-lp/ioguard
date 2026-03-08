#!/bin/bash
set -euo pipefail

# build-test.sh - Test Container Build Script
# Creates a runtime testing environment with test frameworks and coverage tools
# for ringwall

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
IMAGE_NAME="${IMAGE_NAME:-localhost/ringwall-test}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DEV_IMAGE="${DEV_IMAGE:-localhost/ringwall-dev:latest}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

cleanup_on_error() {
    local container_id=$1
    if [ -n "$container_id" ]; then
        log_warn "Cleaning up container: $container_id"
        buildah rm "$container_id" 2>/dev/null || true
    fi
}

trap 'cleanup_on_error "${container:-}"' ERR

log_info "Starting test container build"
log_info "Base image: $DEV_IMAGE"
log_info "Target: $IMAGE_NAME:$IMAGE_TAG"

# Check if dev image exists
if ! podman image exists "$DEV_IMAGE"; then
    log_error "Development image not found: $DEV_IMAGE"
    log_error "Please build the development image first: ./scripts/build-dev.sh"
    exit 1
fi

# Create container from dev image
log_info "Creating container from development image..."
container=$(buildah from "$DEV_IMAGE")

# Configure container metadata
buildah config \
    --label "io.ringwall.version=2.0.0-alpha.1" \
    --label "io.ringwall.environment=test" \
    --label "io.buildah.version=1.0" \
    --label "org.opencontainers.image.created=$BUILD_DATE" \
    --label "org.opencontainers.image.title=ringwall-test" \
    --label "org.opencontainers.image.description=Test environment for ringwall" \
    --label "org.opencontainers.image.version=2.0.0-alpha.1" \
    --label "org.opencontainers.image.licenses=GPLv2" \
    "$container"

# Install additional test frameworks and tools
log_info "Installing test frameworks and coverage tools..."
buildah run "$container" -- bash -c "dnf install -y \
    check-devel \
    cmocka-devel \
    python3-pytest \
    python3-coverage \
    python3-requests \
    python3-pexpect \
    lcov \
    gcovr \
    clang-tools-extra \
    && dnf clean all"

# Install network testing tools
log_info "Installing network testing tools..."
buildah run "$container" -- bash -c "dnf install -y \
    iproute \
    iputils \
    bind-utils \
    tcpdump \
    wireshark-cli \
    netcat \
    socat \
    iperf3 \
    nmap-ncat \
    && dnf clean all"

# Install debugging and profiling tools
log_info "Installing debugging and profiling tools..."
buildah run "$container" -- bash -c "dnf install -y \
    gdb \
    valgrind \
    strace \
    ltrace \
    perf \
    sysstat \
    htop \
    && dnf clean all"

# Create test directories
log_info "Creating test directories..."
buildah run "$container" -- bash -c "
    mkdir -p /workspace/test-results
    mkdir -p /workspace/coverage-reports
    mkdir -p /workspace/test-logs
    chown -R developer:developer /workspace
"

# Install test runner script
log_info "Installing test runner script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/run-tests << 'EOF'
#!/bin/bash
set -euo pipefail

# Test runner for ringwall
WORKSPACE=\${WORKSPACE:-/workspace}
TEST_RESULTS=\${TEST_RESULTS:-\$WORKSPACE/test-results}
COVERAGE_REPORTS=\${COVERAGE_REPORTS:-\$WORKSPACE/coverage-reports}

echo '================================================'
echo 'ringwall Test Runner'
echo '================================================'

# Run meson tests
echo 'Running meson tests...'
cd \$WORKSPACE
if [ -d build ]; then
    meson test -C build --verbose --timeout-multiplier=2 --print-errorlogs

    # Generate coverage reports if configured
    if [ -f build/meson-logs/coverage.info ]; then
        echo 'Generating coverage reports...'
        ninja -C build coverage-html
        cp -r build/meson-logs/coveragereport \$COVERAGE_REPORTS/
        echo \"Coverage report available at: \$COVERAGE_REPORTS/coveragereport/index.html\"
    fi
else
    echo 'ERROR: Build directory not found. Please build the project first.'
    exit 1
fi

# Run integration tests if available
if [ -d tests/integration ]; then
    echo 'Running integration tests...'
    cd tests/integration
    ./run_integration_tests.sh || true
fi

echo '================================================'
echo 'Test run completed'
echo 'Results: '\$TEST_RESULTS
echo '================================================'
EOF
    chmod +x /usr/local/bin/run-tests
"

# Install benchmark runner script
log_info "Installing benchmark runner script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/run-benchmarks << 'EOF'
#!/bin/bash
set -euo pipefail

# Benchmark runner for ringwall
WORKSPACE=\${WORKSPACE:-/workspace}

echo '================================================'
echo 'ringwall Benchmark Runner'
echo '================================================'

if [ -d \$WORKSPACE/tests/bench ]; then
    cd \$WORKSPACE/tests/bench
    ./run_benchmarks.sh
else
    echo 'ERROR: Benchmark directory not found.'
    exit 1
fi

echo '================================================'
echo 'Benchmark run completed'
echo '================================================'
EOF
    chmod +x /usr/local/bin/run-benchmarks
"

# Update developer bashrc for test environment
log_info "Updating test environment configuration..."
buildah run "$container" -- bash -c "
    cat >> /home/developer/.bashrc << 'EOF'

# Test environment specific configuration
export TEST_RESULTS=/workspace/test-results
export COVERAGE_REPORTS=/workspace/coverage-reports
export TEST_LOGS=/workspace/test-logs

# Test aliases
alias run-tests='run-tests'
alias run-benchmarks='run-benchmarks'
alias test-coverage='meson configure -Db_coverage=true build && ninja -C build test && ninja -C build coverage-html'
alias test-valgrind='meson test -C build --wrap=\"valgrind --leak-check=full\"'
alias test-verbose='meson test -C build --verbose --print-errorlogs'

echo ''
echo 'Test commands:'
echo '  run-tests       - Run all tests'
echo '  run-benchmarks  - Run benchmarks'
echo '  test-coverage   - Run tests with coverage'
echo '  test-valgrind   - Run tests with valgrind'
echo '  test-verbose    - Run tests with verbose output'
EOF
"

# Set default command to run tests
buildah config \
    --cmd /usr/local/bin/run-tests \
    "$container"

# Commit the container to an image
log_info "Committing container to image: $IMAGE_NAME:$IMAGE_TAG"
buildah commit --rm --squash "$container" "$IMAGE_NAME:$IMAGE_TAG"

log_info "Test container build completed successfully!"
log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_info "To run tests:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ringwall:/workspace:Z $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_info "To run interactively:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ringwall:/workspace:Z $IMAGE_NAME:$IMAGE_TAG /bin/bash"
