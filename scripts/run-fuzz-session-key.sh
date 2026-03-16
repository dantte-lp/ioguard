#!/usr/bin/env bash
# Fuzz MDBX session key lookup
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/run-fuzz-template.sh"
run_fuzz_target "session_key"
