#!/usr/bin/env bash
# Fuzz TOML config parser
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/run-fuzz-template.sh"
run_fuzz_target "toml"
