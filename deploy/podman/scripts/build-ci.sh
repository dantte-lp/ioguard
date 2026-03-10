#!/bin/bash
set -euo pipefail

# build-ci.sh - CI Container Build Script
# Creates a lightweight container optimized for CI/CD pipelines
# Fast startup, minimal dependencies, focused on testing and validation

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
IMAGE_NAME="${IMAGE_NAME:-localhost/ringwall-ci}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUILD_IMAGE="${BUILD_IMAGE:-localhost/ringwall-build:latest}"

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

log_info "Starting CI container build"
log_info "Base image: $BUILD_IMAGE"
log_info "Target: $IMAGE_NAME:$IMAGE_TAG"

# Check if build image exists
if ! podman image exists "$BUILD_IMAGE"; then
    log_error "Build image not found: $BUILD_IMAGE"
    log_error "Please build the build image first: ./scripts/build-build.sh"
    exit 1
fi

# Create container from build image
log_info "Creating container from build image..."
container=$(buildah from "$BUILD_IMAGE")

# Configure container metadata
buildah config \
    --label "io.ringwall.version=2.0.0-alpha.1" \
    --label "io.ringwall.environment=ci" \
    --label "io.buildah.version=1.0" \
    --label "org.opencontainers.image.created=$BUILD_DATE" \
    --label "org.opencontainers.image.title=ringwall-ci" \
    --label "org.opencontainers.image.description=CI/CD environment for ioguard" \
    --label "org.opencontainers.image.version=2.0.0-alpha.1" \
    --label "org.opencontainers.image.licenses=GPLv2" \
    "$container"

# Install minimal CI tools
log_info "Installing minimal CI tools..."
buildah run "$container" -- bash -c "microdnf install -y \
    git \
    curl \
    jq \
    && microdnf clean all"

# Install CI runner script
log_info "Installing CI runner script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/ci-runner << 'EOF'
#!/bin/bash
set -euo pipefail

# CI/CD runner for ioguard
WORKSPACE=\${WORKSPACE:-/workspace}
CI_REPORTS=\${CI_REPORTS:-/workspace/ci-reports}

echo '================================================'
echo 'ioguard CI/CD Runner'
echo '================================================'

mkdir -p \$CI_REPORTS

cd \$WORKSPACE

# Step 1: Configure build
echo '[1/5] Configuring build...'
meson setup build \
    --buildtype=release \
    --werror \
    -Db_coverage=true \
    -Db_lto=true

# Step 2: Build
echo '[2/5] Building...'
meson compile -C build

# Step 3: Run unit tests
echo '[3/5] Running unit tests...'
meson test -C build --verbose --timeout-multiplier=2 --print-errorlogs || {
    echo 'ERROR: Unit tests failed'
    exit 1
}

# Step 4: Generate coverage report
echo '[4/5] Generating coverage report...'
ninja -C build coverage-html || true
if [ -d build/meson-logs/coveragereport ]; then
    cp -r build/meson-logs/coveragereport \$CI_REPORTS/
fi

# Step 5: Run static analysis
echo '[5/5] Running static analysis...'
if command -v cppcheck >/dev/null 2>&1; then
    cppcheck --enable=all --inconclusive --xml --xml-version=2 \
        src/ 2> \$CI_REPORTS/cppcheck.xml || true
fi

echo '================================================'
echo 'CI/CD run completed successfully!'
echo 'Reports: '\$CI_REPORTS
echo '================================================'
EOF
    chmod +x /usr/local/bin/ci-runner
"

# Install quick validation script
log_info "Installing quick validation script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/quick-validate << 'EOF'
#!/bin/bash
set -euo pipefail

# Quick validation for fast feedback in CI
WORKSPACE=\${WORKSPACE:-/workspace}

echo '================================================'
echo 'Quick Validation (Fast CI Check)'
echo '================================================'

cd \$WORKSPACE

# Check if project builds
echo 'Quick build check...'
meson setup build-quick --buildtype=debug
meson compile -C build-quick

# Run smoke tests only
echo 'Smoke tests...'
meson test -C build-quick --suite=smoke --timeout-multiplier=1 || {
    echo 'ERROR: Smoke tests failed'
    exit 1
}

echo '================================================'
echo 'Quick validation passed!'
echo '================================================'
EOF
    chmod +x /usr/local/bin/quick-validate
"

# Install lint checker script
log_info "Installing lint checker script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/run-lint << 'EOF'
#!/bin/bash
set -euo pipefail

# Linting and code quality checks
WORKSPACE=\${WORKSPACE:-/workspace}

echo '================================================'
echo 'Code Quality Checks'
echo '================================================'

cd \$WORKSPACE

# Check code formatting (if clang-format is available)
if command -v clang-format >/dev/null 2>&1; then
    echo 'Checking code formatting...'
    find src tests -name '*.c' -o -name '*.h' | while read file; do
        if ! clang-format --dry-run --Werror \"\$file\" 2>/dev/null; then
            echo \"WARNING: \$file needs formatting\"
        fi
    done
fi

# Run cppcheck if available
if command -v cppcheck >/dev/null 2>&1; then
    echo 'Running cppcheck...'
    cppcheck --enable=warning,style,performance,portability \
        --error-exitcode=1 \
        --inline-suppr \
        src/ tests/
fi

echo '================================================'
echo 'Code quality checks completed'
echo '================================================'
EOF
    chmod +x /usr/local/bin/run-lint
"

# Clean up to reduce image size
log_info "Cleaning up to reduce image size..."
buildah run "$container" -- bash -c "
    # Remove unnecessary files
    rm -rf /tmp/*
    rm -rf /var/cache/*

    # Remove documentation
    rm -rf /usr/share/doc/*
    rm -rf /usr/share/man/*
    rm -rf /usr/share/info/*
"

# Set default command to run CI
buildah config \
    --cmd /usr/local/bin/ci-runner \
    "$container"

# Commit the container to an image with maximum compression
log_info "Committing container to image: $IMAGE_NAME:$IMAGE_TAG"
buildah commit --rm --squash "$container" "$IMAGE_NAME:$IMAGE_TAG"

log_info "CI container build completed successfully!"
log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_info "Available commands:"
log_info "  ci-runner       - Full CI pipeline (build, test, coverage, analysis)"
log_info "  quick-validate  - Fast validation for quick feedback"
log_info "  run-lint        - Code quality and linting checks"
log_info ""
log_info "To run CI pipeline:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ioguard:/workspace:Z $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_info "To run quick validation:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ioguard:/workspace:Z $IMAGE_NAME:$IMAGE_TAG quick-validate"
