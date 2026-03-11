#!/usr/bin/env bash
set -euo pipefail
cd /opt/projects/repositories/ioguard
rg -n "\bRW_IPC_MAX_MSG_SIZE\b|\brw_dpd_|\brw_compress_|\brw_lzs_|\brw_fw_|\brw_dtls_parse_accept_encoding\b|\brw_security_build_fw_session\b|\bRW_FW_CHAIN_NAME_MAX\b|\bRW_LZS_" \
  .claude/skills/c23-standards/SKILL.md \
  docs/plans/2026-03-07-sprint-1-foundation.md \
  docs/plans/2026-03-08-ringwall-rebranding-plan.md \
  docs/plans/2026-03-08-sprint-4-dtls-compression.md \
  docs/plans/2026-03-08-sprint-5-storage-security.md \
  docs/plans/2026-03-08-sprint-6-vertical-integration.md \
  src/core/conn_data.c src/core/conn_data.h src/core/conn_timer.c src/core/conn_timer.h \
  src/core/secmod.c src/core/security_hooks.c src/core/security_hooks.h src/core/worker.c src/core/worker.h \
  src/ipc/transport.h src/network/channel.h src/network/compress.c src/network/compress.h \
  src/network/compress_lzs.c src/network/compress_lzs.h src/network/dpd.c src/network/dpd.h \
  src/network/dtls_headers.c src/network/dtls_headers.h src/security/firewall.c src/security/firewall.h \
  tests/integration/test_auth_flow.c tests/integration/test_auth_mfa.c tests/integration/test_data_path.c \
  tests/integration/test_dtls_channel.c tests/integration/test_ipc_roundtrip.c tests/integration/test_vpn_flow.c \
  tests/unit/test_compress.c tests/unit/test_compress_cstp.c tests/unit/test_compress_lzs.c \
  tests/unit/test_conn_data.c tests/unit/test_conn_timer.c tests/unit/test_dpd.c tests/unit/test_dtls_headers.c \
  tests/unit/test_firewall.c tests/unit/test_ipc_messages.c tests/unit/test_secmod.c tests/unit/test_security_hooks.c
