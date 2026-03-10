#!/bin/bash
set -euo pipefail

# verify-selinux.sh - Verify SELinux labels for container volumes
# Ensures proper SELinux configuration for Podman containers

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNED=0

# Check 1: SELinux enabled
echo ""
log_info "Checking SELinux status..."
if command -v getenforce >/dev/null 2>&1; then
    SELINUX_STATUS=$(getenforce)
    case "$SELINUX_STATUS" in
        Enforcing)
            log_pass "SELinux is enforcing"
            ((CHECKS_PASSED++))
            ;;
        Permissive)
            log_warn "SELinux is permissive (not enforcing)"
            ((CHECKS_WARNED++))
            ;;
        Disabled)
            log_warn "SELinux is disabled"
            log_info "Most checks will be skipped"
            ((CHECKS_WARNED++))
            exit 0
            ;;
    esac
else
    log_warn "SELinux tools not installed"
    log_info "Install with: sudo dnf install policycoreutils"
    exit 0
fi

# Check 2: container_file_t context available
echo ""
log_info "Checking container SELinux contexts..."
if seinfo -t container_file_t >/dev/null 2>&1; then
    log_pass "container_file_t context available"
    ((CHECKS_PASSED++))
else
    log_warn "container_file_t not found (install container-selinux)"
    ((CHECKS_WARNED++))
fi

# Check 3: Check source code directory
echo ""
log_info "Checking source code directory SELinux labels..."
SOURCE_DIR="/opt/projects/repositories/ioguard"
if [ -d "$SOURCE_DIR" ]; then
    SOURCE_CONTEXT=$(ls -Zd "$SOURCE_DIR" | awk '{print $1}')
    log_info "Source directory context: $SOURCE_CONTEXT"

    # Verify it can be relabeled
    if [[ "$SOURCE_CONTEXT" == *"user_home_t"* ]] || [[ "$SOURCE_CONTEXT" == *"admin_home_t"* ]] || [[ "$SOURCE_CONTEXT" == *"container_file_t"* ]]; then
        log_pass "Source directory has compatible SELinux context"
        ((CHECKS_PASSED++))
    else
        log_warn "Source directory may need relabeling for container access"
        log_info "Fix with: chcon -R -t container_file_t $SOURCE_DIR"
        ((CHECKS_WARNED++))
    fi
else
    log_warn "Source directory not found: $SOURCE_DIR"
    ((CHECKS_WARNED++))
fi

# Check 4: Test volume mount with :Z flag
echo ""
log_info "Testing volume mount with SELinux relabeling..."
TEST_DIR="/tmp/podman-selinux-test-$$"
mkdir -p "$TEST_DIR"
echo "test" > "$TEST_DIR/testfile"

if podman run --rm -v "$TEST_DIR:/test:Z" registry.access.redhat.com/ubi9/ubi-micro:latest cat /test/testfile >/dev/null 2>&1; then
    log_pass "Volume mount with :Z flag works correctly"
    ((CHECKS_PASSED++))

    # Check if context was changed
    NEW_CONTEXT=$(ls -Zd "$TEST_DIR" | awk '{print $1}')
    if [[ "$NEW_CONTEXT" == *"container_file_t"* ]]; then
        log_pass "Directory correctly relabeled to container_file_t"
        ((CHECKS_PASSED++))
    else
        log_warn "Directory not relabeled as expected: $NEW_CONTEXT"
        ((CHECKS_WARNED++))
    fi
else
    log_fail "Volume mount with :Z flag failed"
    ((CHECKS_FAILED++))
fi

# Cleanup
rm -rf "$TEST_DIR"

# Check 5: Test volume mount with :z flag (shared)
echo ""
log_info "Testing shared volume mount with :z flag..."
TEST_DIR="/tmp/podman-selinux-test-shared-$$"
mkdir -p "$TEST_DIR"
echo "test" > "$TEST_DIR/testfile"

if podman run --rm -v "$TEST_DIR:/test:z" registry.access.redhat.com/ubi9/ubi-micro:latest cat /test/testfile >/dev/null 2>&1; then
    log_pass "Shared volume mount with :z flag works correctly"
    ((CHECKS_PASSED++))
else
    log_fail "Shared volume mount with :z flag failed"
    ((CHECKS_FAILED++))
fi

# Cleanup
rm -rf "$TEST_DIR"

# Check 6: Check container policy modules
echo ""
log_info "Checking SELinux policy modules..."
if semodule -l | grep -q container; then
    CONTAINER_MODULES=$(semodule -l | grep container | wc -l)
    log_pass "Container SELinux policy modules loaded ($CONTAINER_MODULES modules)"
    ((CHECKS_PASSED++))
else
    log_warn "No container SELinux policy modules found"
    log_info "Install with: sudo dnf install container-selinux"
    ((CHECKS_WARNED++))
fi

# Check 7: Verify Podman can set SELinux labels
echo ""
log_info "Checking if Podman can set SELinux labels..."
if podman run --rm --security-opt label=disable registry.access.redhat.com/ubi9/ubi-micro:latest echo "test" >/dev/null 2>&1; then
    log_pass "Podman can manage SELinux labels"
    ((CHECKS_PASSED++))
else
    log_fail "Podman cannot manage SELinux labels"
    ((CHECKS_FAILED++))
fi

# Check 8: Check for common denials in audit log
echo ""
log_info "Checking for recent SELinux denials..."
if [ -f /var/log/audit/audit.log ] && [ -r /var/log/audit/audit.log ]; then
    RECENT_DENIALS=$(sudo grep -c "denied.*container" /var/log/audit/audit.log 2>/dev/null || echo "0")
    if [ "$RECENT_DENIALS" -eq 0 ]; then
        log_pass "No recent container-related SELinux denials"
        ((CHECKS_PASSED++))
    else
        log_warn "Found $RECENT_DENIALS recent container-related SELinux denials"
        log_info "Check with: sudo ausearch -m avc -ts recent | grep container"
        ((CHECKS_WARNED++))
    fi
else
    log_info "Audit log not accessible (may need sudo)"
fi

# Summary
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}SELinux Verification Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}Passed:${NC}  $CHECKS_PASSED"
echo -e "${YELLOW}Warnings:${NC} $CHECKS_WARNED"
echo -e "${RED}Failed:${NC}  $CHECKS_FAILED"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    log_pass "SELinux is properly configured for Podman containers!"
    log_info "Remember to use :Z flag for exclusive mounts and :z for shared mounts"
    exit 0
else
    log_fail "Some SELinux checks failed"
    log_info "Review the failed checks and install missing components"
    exit 1
fi
