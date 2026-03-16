#!/usr/bin/env bash
# Fuzz IPC protobuf-c message unpacking
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/run-fuzz-template.sh"
run_fuzz_target "ipc"
