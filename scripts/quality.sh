#!/usr/bin/env bash
# shellcheck shell=bash
# Repository quality pipeline for ioguard.
# Run inside the dev container: cd /workspace && ./scripts/quality.sh
# Or from host: podman run --rm --security-opt seccomp=unconfined \
#   -v /opt/projects/repositories/ioguard:/workspace:Z \
#   localhost/ioguard-dev:latest bash -c "cd /workspace && ./scripts/quality.sh"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# shellcheck disable=SC1091
if [[ -f /usr/local/lib/ioplane/common.sh ]]; then
    source /usr/local/lib/ioplane/common.sh
else
    source "${SCRIPT_DIR}/lib/common.sh"
fi

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
readonly ROOT_DIR
readonly BUILD_DIR="${BUILD_DIR:-build/clang-debug}"
readonly PRESET="${PRESET:-clang-debug}"
readonly TOTAL_STEPS=9

cd "${ROOT_DIR}"

# ═══════════════════════════════════════════════════════
# Step 1: Repository baseline
# ═══════════════════════════════════════════════════════

ioj_step 1 "${TOTAL_STEPS}" "Repository baseline"
ioj_check_repo_baseline

# ═══════════════════════════════════════════════════════
# Step 2: Documentation lint
# ═══════════════════════════════════════════════════════

ioj_step 2 "${TOTAL_STEPS}" "Documentation lint"
ioj_check_docs_lint

# ═══════════════════════════════════════════════════════
# Step 3: Configure and build
# ═══════════════════════════════════════════════════════

ioj_step 3 "${TOTAL_STEPS}" "Configure and build"
ioj_check_build_and_test "${PRESET}" "${BUILD_DIR}"

# ═══════════════════════════════════════════════════════
# Step 4: Format check
# ═══════════════════════════════════════════════════════

ioj_step 4 "${TOTAL_STEPS}" "Format check"
ioj_check_format "${PRESET}"

# ═══════════════════════════════════════════════════════
# Step 5: cppcheck
# ═══════════════════════════════════════════════════════

ioj_step 5 "${TOTAL_STEPS}" "cppcheck"
ioj_check_cppcheck "${BUILD_DIR}"

# ═══════════════════════════════════════════════════════
# Step 6: PVS-Studio
# ═══════════════════════════════════════════════════════

ioj_step 6 "${TOTAL_STEPS}" "PVS-Studio"
ioj_check_pvs_studio "${BUILD_DIR}"

# ═══════════════════════════════════════════════════════
# Step 7: CodeChecker
# ═══════════════════════════════════════════════════════

ioj_step 7 "${TOTAL_STEPS}" "CodeChecker"
ioj_check_codechecker "${BUILD_DIR}"

# ═══════════════════════════════════════════════════════
# Step 8: GCC analyzer
# ═══════════════════════════════════════════════════════

ioj_step 8 "${TOTAL_STEPS}" "GCC analyzer"
ioj_check_gcc_analyzer

# ═══════════════════════════════════════════════════════
# Step 9: shellcheck
# ═══════════════════════════════════════════════════════

ioj_step 9 "${TOTAL_STEPS}" "Shellcheck"
ioj_check_shellcheck

# ═══════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════

ioj_print_summary
