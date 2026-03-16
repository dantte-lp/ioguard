#!/usr/bin/env bash
# Fuzz HTTP request parser
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/run-fuzz-template.sh"
run_fuzz_target "http"
