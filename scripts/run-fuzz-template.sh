# Shared fuzz runner template
# Source this, then call run_fuzz_target <target_name>
set -euo pipefail

RUNS="${RUNS:-256}"
PRESET="${PRESET:-clang-fuzz}"
BUILD_DIR="build/${PRESET}"

run_fuzz_target() {
    local TARGET="$1"
    local CORPUS_DIR="tests/fuzz/corpus/${TARGET}"
    local TMP_CORPUS
    TMP_CORPUS=$(mktemp -d)
    trap "rm -rf ${TMP_CORPUS}" EXIT

    echo "=== Building fuzz target: ${TARGET} ==="
    cmake --preset "${PRESET}"
    cmake --build --preset "${PRESET}" --target "fuzz_${TARGET}" -j"$(nproc)"

    if [ -d "${CORPUS_DIR}" ]; then
        cp "${CORPUS_DIR}"/* "${TMP_CORPUS}/" 2>/dev/null || true
    fi

    echo "=== Running ${TARGET} fuzzer (${RUNS} runs) ==="
    "./${BUILD_DIR}/fuzz_${TARGET}" "${TMP_CORPUS}" -runs="${RUNS}" -max_len=65536

    echo "=== PASSED: ${TARGET} (${RUNS} runs, no crashes) ==="
}
