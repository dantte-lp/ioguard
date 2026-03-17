#!/usr/bin/env bash
# shellcheck shell=bash
# ioplane shared shell library — sourced by all io* project scripts.
# Installed to /usr/local/lib/ioplane/common.sh via the ioplane-base image.
#
# Usage:
#   source /usr/local/lib/ioplane/common.sh
#   — or, for host-side use when the image is not available: —
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "${SCRIPT_DIR}/lib/common.sh"

set -euo pipefail

# ═══════════════════════════════════════════════════════
# Colors (disabled when stdout is not a terminal)
# ═══════════════════════════════════════════════════════

if [[ -t 1 ]]; then
    readonly IOJ_RED=$'\033[0;31m'
    readonly IOJ_GREEN=$'\033[0;32m'
    readonly IOJ_YELLOW=$'\033[0;33m'
    readonly IOJ_CYAN=$'\033[0;36m'
    readonly IOJ_NC=$'\033[0m'
else
    readonly IOJ_RED=''
    readonly IOJ_GREEN=''
    readonly IOJ_YELLOW=''
    readonly IOJ_CYAN=''
    readonly IOJ_NC=''
fi

# ═══════════════════════════════════════════════════════
# Logging helpers
# ═══════════════════════════════════════════════════════

ioj_pass() { printf '%sPASS%s: %s\n' "${IOJ_GREEN}" "${IOJ_NC}" "$1"; }
ioj_fail() { printf '%sFAIL%s: %s\n' "${IOJ_RED}" "${IOJ_NC}" "$1" >&2; }
ioj_skip() { printf '%sSKIP%s: %s\n' "${IOJ_YELLOW}" "${IOJ_NC}" "$1"; }
ioj_info() { printf '%sINFO%s: %s\n' "${IOJ_CYAN}" "${IOJ_NC}" "$1"; }
ioj_step() {
    local step_num="$1"
    local step_total="$2"
    local step_name="$3"
    printf '\n%s=== [%d/%d] %s ===%s\n' "${IOJ_CYAN}" "${step_num}" "${step_total}" "${step_name}" "${IOJ_NC}"
}

# ═══════════════════════════════════════════════════════
# Quality gate counters
# ═══════════════════════════════════════════════════════

IOJ_PASS_COUNT=0
IOJ_FAIL_COUNT=0
IOJ_SKIP_COUNT=0

ioj_record_pass() { ioj_pass "$1"; IOJ_PASS_COUNT=$((IOJ_PASS_COUNT + 1)); }
ioj_record_fail() { ioj_fail "$1"; IOJ_FAIL_COUNT=$((IOJ_FAIL_COUNT + 1)); }
ioj_record_skip() { ioj_skip "$1"; IOJ_SKIP_COUNT=$((IOJ_SKIP_COUNT + 1)); }

ioj_print_summary() {
    printf '\n%s=== Summary ===%s\n' "${IOJ_CYAN}" "${IOJ_NC}"
    printf '%sPASS: %d%s  %sFAIL: %d%s  %sSKIP: %d%s\n' \
        "${IOJ_GREEN}" "${IOJ_PASS_COUNT}" "${IOJ_NC}" \
        "${IOJ_RED}" "${IOJ_FAIL_COUNT}" "${IOJ_NC}" \
        "${IOJ_YELLOW}" "${IOJ_SKIP_COUNT}" "${IOJ_NC}"

    if [[ "${IOJ_FAIL_COUNT}" -gt 0 ]]; then
        printf '%sQuality pipeline FAILED%s\n' "${IOJ_RED}" "${IOJ_NC}"
        return 1
    fi
    printf '%sQuality pipeline PASSED%s\n' "${IOJ_GREEN}" "${IOJ_NC}"
    return 0
}

# ═══════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════

ioj_need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        ioj_fail "missing required command: $1"
        return 1
    fi
}

ioj_has_cmake_surface() {
    [[ -f "${1:-.}/CMakeLists.txt" && -f "${1:-.}/CMakePresets.json" ]]
}

ioj_resolve_root() {
    local script_path="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    cd "$(dirname "${script_path}")/.." && pwd -P
}

ioj_git_head_short() {
    local root_dir="${1:-.}"
    if git -C "${root_dir}" rev-parse --short HEAD 2>/dev/null; then
        return 0
    fi
    printf 'nogit\n'
}

ioj_git_safe_directory() {
    local root_dir="${1:-.}"
    git config --global --add safe.directory "${root_dir}" 2>/dev/null || true
}

ioj_nproc() {
    nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || printf '4\n'
}

# ═══════════════════════════════════════════════════════
# Temp file management with cleanup trap
# ═══════════════════════════════════════════════════════

declare -a IOJ_TEMP_FILES=()

ioj_mktemp() {
    local tmp
    tmp=$(mktemp "$@")
    IOJ_TEMP_FILES+=("${tmp}")
    printf '%s\n' "${tmp}"
}

ioj_cleanup() {
    local f
    for f in "${IOJ_TEMP_FILES[@]+"${IOJ_TEMP_FILES[@]}"}"; do
        rm -rf "${f}" 2>/dev/null || true
    done
}

trap ioj_cleanup EXIT

# ═══════════════════════════════════════════════════════
# Quality gate steps (shared across all io* projects)
# ═══════════════════════════════════════════════════════

ioj_check_repo_baseline() {
    if [[ -d .github && -f AGENTS.md && -f CLAUDE.md && -f CODEX.md ]]; then
        ioj_record_pass "Repository baseline files present"
    else
        ioj_record_fail "Missing baseline files (.github or root instructions)"
    fi
}

ioj_check_docs_lint() {
    if [[ -f scripts/lint-docs.py ]]; then
        if python3 scripts/lint-docs.py; then
            ioj_record_pass "Documentation lint clean"
        else
            ioj_record_fail "Documentation lint failed"
        fi
    else
        ioj_record_skip "Documentation linter not present"
    fi
}

ioj_check_build_and_test() {
    local preset="${1:-clang-debug}"
    local build_dir="${2:-build/clang-debug}"

    if ! ioj_has_cmake_surface; then
        ioj_record_skip "CMake surface not initialized yet"
        return 0
    fi

    if cmake --preset "${preset}" --fresh && cmake --build --preset "${preset}"; then
        ioj_record_pass "Build succeeded"
    else
        ioj_record_fail "Build failed"
        return 0
    fi

    if ctest --preset "${preset}" --output-on-failure 2>&1; then
        ioj_record_pass "All tests passed"
    else
        ioj_record_fail "Some tests failed"
    fi
}

ioj_check_format() {
    local preset="${1:-clang-debug}"

    if ! ioj_has_cmake_surface; then
        ioj_record_skip "Format target unavailable before CMake bootstrap"
        return 0
    fi

    if cmake --build --preset "${preset}" --target format-check 2>&1; then
        ioj_record_pass "Formatting clean"
    else
        ioj_record_fail "Formatting issues found"
    fi
}

ioj_check_cppcheck() {
    local build_dir="${1:-build/clang-debug}"

    if ! ioj_has_cmake_surface; then
        ioj_record_skip "Compile database unavailable before CMake bootstrap"
        return 0
    fi

    if [[ ! -f "${build_dir}/compile_commands.json" ]]; then
        ioj_record_fail "cppcheck: compile database missing"
        return 0
    fi

    if ! command -v cppcheck >/dev/null 2>&1; then
        ioj_record_skip "cppcheck not installed"
        return 0
    fi

    if cppcheck --enable=warning,performance,portability \
        --error-exitcode=1 --inline-suppr \
        --project="${build_dir}/compile_commands.json" \
        --suppress='*:/usr/local/src/unity/*' \
        -q 2>&1; then
        ioj_record_pass "cppcheck clean"
    else
        ioj_record_fail "cppcheck found issues"
    fi
}

ioj_check_pvs_studio() {
    local build_dir="${1:-build/clang-debug}"
    local nproc_val
    nproc_val="$(ioj_nproc)"

    if ! ioj_has_cmake_surface; then
        ioj_record_skip "Compile database unavailable before CMake bootstrap"
        return 0
    fi

    if [[ ! -f "${build_dir}/compile_commands.json" ]]; then
        ioj_record_fail "PVS-Studio: compile database missing"
        return 0
    fi

    if ! command -v pvs-studio-analyzer >/dev/null 2>&1; then
        ioj_record_skip "PVS-Studio not installed"
        return 0
    fi

    if [[ -z "${PVS_NAME:-}" || -z "${PVS_KEY:-}" ]]; then
        ioj_record_skip "PVS-Studio: missing PVS_NAME/PVS_KEY in environment"
        return 0
    fi

    pvs-studio-analyzer credentials "${PVS_NAME}" "${PVS_KEY}" >/dev/null 2>&1

    local pvs_log="${build_dir}/pvs-studio.log"

    if pvs-studio-analyzer analyze \
        -f "${build_dir}/compile_commands.json" \
        -o "${pvs_log}" \
        -e /usr/local/src/unity/ \
        -j"${nproc_val}" 2>&1 | grep -v '^\['; then

        local pvs_out
        pvs_out=$(plog-converter -t errorfile -a 'GA:1,2' "${pvs_log}" 2>/dev/null \
            | grep -v '^pvs-studio.com' | grep -v '^Analyzer log' \
            | grep -v '^PVS-Studio is' | grep -v '^$' \
            | grep -v 'Total messages' | grep -v 'Filtered messages' \
            | grep -v '^Copyright' \
            | grep -v 'V1042' || true)

        local pvs_count
        pvs_count=$(printf '%s\n' "${pvs_out}" | grep -cE '(error|warning):' || true)

        if [[ "${pvs_count}" -eq 0 ]]; then
            ioj_record_pass "PVS-Studio clean (GA:1,2)"
        else
            printf '%s\n' "${pvs_out}"
            ioj_record_fail "PVS-Studio: ${pvs_count} errors/warnings"
        fi
    else
        ioj_record_fail "PVS-Studio analysis failed"
    fi
}

ioj_check_gcc_analyzer() {
    if ! ioj_has_cmake_surface; then
        ioj_record_skip "Compile database unavailable before CMake bootstrap"
        return 0
    fi

    if [[ ! -f scripts/run-gcc-analyzer.sh ]]; then
        ioj_record_fail "GCC analyzer script missing"
        return 0
    fi

    local gcc_log
    gcc_log="$(ioj_mktemp)"

    if bash scripts/run-gcc-analyzer.sh >"${gcc_log}" 2>&1; then
        ioj_record_pass "GCC analyzer lane clean"
    else
        cat "${gcc_log}"
        ioj_record_fail "GCC analyzer lane failed"
    fi
}

ioj_check_codechecker() {
    local build_dir="${1:-build/clang-debug}"
    local third_party_dir="${2:-tests/third_party}"
    local nproc_val
    nproc_val="$(ioj_nproc)"

    if ! ioj_has_cmake_surface; then
        ioj_record_skip "Compile database unavailable before CMake bootstrap"
        return 0
    fi

    if [[ ! -f "${build_dir}/compile_commands.json" ]]; then
        ioj_record_fail "CodeChecker: compile database missing"
        return 0
    fi

    if ! command -v CodeChecker >/dev/null 2>&1; then
        ioj_record_skip "CodeChecker not installed"
        return 0
    fi

    local cc_dir
    cc_dir="$(ioj_mktemp -d)"
    local cc_skip
    cc_skip="$(ioj_mktemp)"

    cat > "${cc_skip}" <<SKIP
-/usr/local/src/unity/*
-${third_party_dir}/*
SKIP

    if CodeChecker analyze "${build_dir}/compile_commands.json" \
        -o "${cc_dir}" \
        --analyzers clangsa clang-tidy \
        --skip "${cc_skip}" \
        -j"${nproc_val}"; then

        local cc_parse
        cc_parse=$(CodeChecker parse "${cc_dir}" \
            --trim-path-prefix "$(pwd)/" 2>&1 || true)
        cc_parse=$(printf '%s\n' "${cc_parse}" \
            | grep -v '^\[INFO\]' \
            | grep -v '^$' \
            | grep -v '/usr/local/src/unity/' \
            | grep -v "${third_party_dir}/" || true)

        local cc_high cc_med
        cc_high=$(printf '%s\n' "${cc_parse}" | grep -c '\[HIGH\]' || true)
        cc_med=$(printf '%s\n' "${cc_parse}" | grep -c '\[MEDIUM\]' || true)

        if [[ "${cc_high}" -gt 0 || "${cc_med}" -gt 0 ]]; then
            printf '%s\n' "${cc_parse}" | grep -E '\[(HIGH|MEDIUM)\]' || true
            ioj_record_fail "CodeChecker: ${cc_high} HIGH, ${cc_med} MEDIUM"
        else
            ioj_record_pass "CodeChecker clean (no HIGH/MEDIUM)"
        fi
    else
        ioj_record_fail "CodeChecker analysis failed"
    fi
}

ioj_check_shellcheck() {
    if ! command -v shellcheck >/dev/null 2>&1; then
        ioj_record_skip "shellcheck not installed"
        return 0
    fi

    local scripts_found=0
    local -a script_files=()

    while IFS= read -r -d '' f; do
        script_files+=("${f}")
        scripts_found=1
    done < <(find scripts/ -name '*.sh' -print0 2>/dev/null)

    if [[ -d scripts/lib ]]; then
        while IFS= read -r -d '' f; do
            script_files+=("${f}")
        done < <(find scripts/lib/ -name '*.sh' -print0 2>/dev/null)
    fi

    if [[ "${scripts_found}" -eq 0 ]]; then
        ioj_record_skip "No shell scripts found"
        return 0
    fi

    if shellcheck --shell=bash --severity=style "${script_files[@]}"; then
        ioj_record_pass "shellcheck clean"
    else
        ioj_record_fail "shellcheck found issues"
    fi
}
