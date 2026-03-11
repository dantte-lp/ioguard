#!/usr/bin/env bash
set -euo pipefail
cd /opt/projects/repositories/ioguard
rg -n "IOGUARD_IPC_FDPASS_H|IOGUARD_CORE_PROCESS_H|IOGUARD_CORE_MAIN_H|\bRW_FDPASS_MAX_FDS\b|\brw_fdpass_(send|recv)\b|\brw_process_(spawn|wait|signal|cleanup)\b|\brw_process_t\b|\brw_main_(parse_args|create_ipc_pair|create_accept_pair|create_signalfd)\b|\brw_fdpass\b|\brw_core\b" \
  src/ipc/fdpass.h src/ipc/fdpass.c src/core/process.h src/core/process.c src/core/main.h src/core/main.c \
  tests/unit/test_fdpass.c tests/unit/test_process.c tests/unit/test_main_bootstrap.c tests/unit/test_worker_loop.c src/core/worker_loop.c CMakeLists.txt
