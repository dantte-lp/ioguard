#!/usr/bin/env bash
# LLVM-based code coverage pipeline for ioguard
# Run inside container: cd /workspace && ./scripts/run-coverage.sh
set -euo pipefail

PRESET="${PRESET:-clang-coverage}"
BUILD_DIR="build/${PRESET}"
PROFRAW_DIR="${BUILD_DIR}/profraw"
MERGED_PROF="${BUILD_DIR}/coverage.profdata"
REPORT_DIR="${BUILD_DIR}/coverage-report"

echo "=== Configure + Build ==="
cmake --preset "${PRESET}"
cmake --build --preset "${PRESET}" -j"$(nproc)"

echo "=== Run Tests (collecting profiles) ==="
rm -rf "${PROFRAW_DIR}"
mkdir -p "${PROFRAW_DIR}"

export LLVM_PROFILE_FILE="${PROFRAW_DIR}/%p-%m.profraw"
ctest --preset "${PRESET}" --output-on-failure || true

echo "=== Merge Profiles ==="
llvm-profdata merge -sparse "${PROFRAW_DIR}"/*.profraw -o "${MERGED_PROF}"

echo "=== Generate Reports ==="
# Collect all test executables
TEST_BINS=$(find "${BUILD_DIR}" -maxdepth 1 -name 'test_*' -executable | sort)
OBJECT_ARGS=""
for bin in ${TEST_BINS}; do
    OBJECT_ARGS="${OBJECT_ARGS} -object=${bin}"
done

# Text summary
llvm-cov report ${OBJECT_ARGS} -instr-profile="${MERGED_PROF}" \
    -ignore-filename-regex='tests/|unity' 2>/dev/null | tee "${BUILD_DIR}/coverage-summary.txt"

# HTML report
mkdir -p "${REPORT_DIR}"
llvm-cov show ${OBJECT_ARGS} -instr-profile="${MERGED_PROF}" \
    -format=html -output-dir="${REPORT_DIR}" \
    -ignore-filename-regex='tests/|unity' 2>/dev/null

# LCOV export (for CI integration)
llvm-cov export ${OBJECT_ARGS} -instr-profile="${MERGED_PROF}" \
    -format=lcov -ignore-filename-regex='tests/|unity' \
    > "${BUILD_DIR}/coverage.lcov" 2>/dev/null

echo ""
echo "=== Coverage Summary ==="
cat "${BUILD_DIR}/coverage-summary.txt"
echo ""
echo "HTML report: ${REPORT_DIR}/index.html"
echo "LCOV data:   ${BUILD_DIR}/coverage.lcov"
