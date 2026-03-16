#!/usr/bin/env bash
# PMI/PSI (Performance Micro-Indicators / Performance Stability Indicators)
# Automated benchmark orchestration with multi-run median and artifact management.
#
# Run inside container:
#   cd /workspace && ./scripts/run-pmi-psi.sh
#
# Environment variables:
#   RUNS      — number of benchmark repetitions for median (default: 5)
#   PRESET    — CMake preset for release build (default: clang-debug)
#   OUT_DIR   — output directory for artifacts (default: tests/artifacts/pmi-psi)
set -euo pipefail

RUNS="${RUNS:-5}"
PRESET="${PRESET:-clang-debug}"
BUILD_DIR="build/${PRESET}"
OUT_DIR="${OUT_DIR:-tests/artifacts/pmi-psi}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="${OUT_DIR}/${TIMESTAMP}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { printf "\n${CYAN}=== [%d/6] %s ===${NC}\n" "$1" "$2"; }

# ── Step 1: Record host info ─────────────────────────────────
step 1 "Record host/toolchain info"
mkdir -p "${RUN_DIR}"

{
    echo "timestamp: ${TIMESTAMP}"
    echo "kernel: $(uname -r)"
    echo "arch: $(uname -m)"
    echo "cpu_model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "cpu_count: $(nproc)"
    echo "cpu_flags: $(grep -m1 'flags' /proc/cpuinfo | cut -d: -f2 | tr ' ' '\n' | grep -E 'avx|sse|neon|sve' | tr '\n' ' ')"
    echo "mem_total_kb: $(grep MemTotal /proc/meminfo | awk '{print $2}')"
    echo "---"
    echo "clang: $(clang --version 2>/dev/null | head -1 || echo 'N/A')"
    echo "gcc: $(gcc-15 --version 2>/dev/null | head -1 || echo 'N/A')"
    echo "cmake: $(cmake --version 2>/dev/null | head -1 || echo 'N/A')"
    echo "gdb: $(gdb --version 2>/dev/null | head -1 || echo 'N/A')"
    echo "valgrind: $(valgrind --version 2>/dev/null || echo 'N/A')"
    echo "uftrace: $(uftrace --version 2>/dev/null | head -1 || echo 'N/A')"
} > "${RUN_DIR}/environment.txt"

cat "${RUN_DIR}/environment.txt"

# ── Step 2: Build ────────────────────────────────────────────
step 2 "Build (${PRESET})"
cmake --preset "${PRESET}" 2>&1 | tail -3
cmake --build --preset "${PRESET}" -j"$(nproc)" 2>&1 | tail -3

# ── Step 3: Run tests (gate) ─────────────────────────────────
step 3 "Run tests (correctness gate)"
if ! ctest --preset "${PRESET}" --output-on-failure 2>&1 | tail -5; then
    printf "${RED}Tests failed — aborting benchmarks${NC}\n"
    exit 1
fi

# ── Step 4: Run benchmarks (multi-run median) ────────────────
step 4 "Run benchmarks (${RUNS} runs each)"

BENCH_BINS=$(find "${BUILD_DIR}" -maxdepth 1 -name 'bench_*' -executable 2>/dev/null | sort)
if [ -z "${BENCH_BINS}" ]; then
    echo "No bench_* executables found — skipping"
else
    for bench in ${BENCH_BINS}; do
        name=$(basename "${bench}")
        echo "--- ${name} (${RUNS} runs) ---"
        results_file="${RUN_DIR}/${name}.tsv"

        for run in $(seq 1 "${RUNS}"); do
            echo "  run ${run}/${RUNS}..."
            "./${bench}" 2>/dev/null | tee -a "${RUN_DIR}/${name}_run${run}.txt"
        done

        # Extract ops/s from each run and calculate median via Python
        grep -h 'ops/s' "${RUN_DIR}/${name}"_run*.txt 2>/dev/null | \
            awk '{print $NF}' | sed 's/[^0-9.]//g' | \
            python3 -c "
import sys, statistics
vals = [float(x) for x in sys.stdin if x.strip()]
if vals:
    print(f'median: {statistics.median(vals):.0f} ops/s')
    print(f'min:    {min(vals):.0f} ops/s')
    print(f'max:    {max(vals):.0f} ops/s')
    print(f'stdev:  {statistics.stdev(vals):.0f} ops/s' if len(vals) > 1 else 'stdev: N/A')
" 2>/dev/null | tee "${RUN_DIR}/${name}_summary.txt"
    done
fi

# ── Step 5: Generate manifest ─────────────────────────────────
step 5 "Generate manifest"

{
    echo "{"
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"preset\": \"${PRESET}\","
    echo "  \"runs\": ${RUNS},"
    echo "  \"tests\": \"pass\","
    echo "  \"benchmarks\": ["
    first=true
    for summary in "${RUN_DIR}"/*_summary.txt; do
        [ -f "$summary" ] || continue
        name=$(basename "$summary" _summary.txt)
        median=$(grep 'median' "$summary" 2>/dev/null | awk '{print $2}' || echo "0")
        if [ "$first" = true ]; then first=false; else echo ","; fi
        printf "    {\"name\": \"%s\", \"median_ops_s\": %s}" "$name" "$median"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "${RUN_DIR}/manifest.json"

cat "${RUN_DIR}/manifest.json"

# ── Step 6: Update index ─────────────────────────────────────
step 6 "Update index"

INDEX="${OUT_DIR}/index.tsv"
if [ ! -f "${INDEX}" ]; then
    echo -e "timestamp\tpreset\truns\tstatus" > "${INDEX}"
fi
echo -e "${TIMESTAMP}\t${PRESET}\t${RUNS}\tpass" >> "${INDEX}"
echo "${TIMESTAMP}" > "${OUT_DIR}/latest.txt"

printf "\n${GREEN}PMI/PSI run complete: ${RUN_DIR}${NC}\n"
printf "Manifest: ${RUN_DIR}/manifest.json\n"
printf "Index:    ${INDEX}\n"
