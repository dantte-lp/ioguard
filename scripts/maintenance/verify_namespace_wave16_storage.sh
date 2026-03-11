#!/usr/bin/env bash
set -euo pipefail
cd /opt/projects/repositories/ioguard
rg -n "\brw_mdbx_|\brw_migrate\b|\brw_vault\b|\brw_totp\b|\bRW_MDBX_|RINGWALL_STORAGE_MDBX_H|RINGWALL_STORAGE_MIGRATE_H|RINGWALL_AUTH_TOTP_H|struct rw_vault|typedef struct rw_vault|TARGET rw_mdbx|TARGET rw_totp|TARGET rw_vault" \
  .claude/skills/storage-patterns/SKILL.md \
  docs/plans/2026-03-08-sprint-5-storage-security.md \
  docs/plans/2026-03-08-sprint-6-vertical-integration.md \
  src/core/secmod.c src/core/secmod.h src/storage/mdbx.c src/storage/mdbx.h src/storage/migrate.c src/storage/migrate.h src/storage/vault.c src/storage/vault.h src/auth/totp.h tests/fuzz/fuzz_session_key.c tests/integration/test_storage.c tests/unit/test_storage_mdbx.c tests/unit/test_storage_migrate.c CMakeLists.txt
