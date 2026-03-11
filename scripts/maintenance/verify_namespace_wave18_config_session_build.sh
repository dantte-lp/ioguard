#!/usr/bin/env bash
set -euo pipefail
cd /opt/projects/repositories/ioguard
rg -n "RINGWALL_CONFIG_CONFIG_H|RINGWALL_CORE_SESSION_H|RINGWALL_SESSION_CACHE_H|\brw_(memory|config|main_helpers|session)\b" \
  .claude/skills/c23-standards/SKILL.md \
  .claude/skills/coding-standards/SKILL.md \
  .claude/skills/security-coding/SKILL.md \
  .claude/skills/storage-patterns/SKILL.md \
  CMakeLists.txt \
  docs/plans/2026-03-07-sprint-1-foundation.md \
  docs/plans/2026-03-07-sprint-2-tls-auth.md \
  docs/plans/2026-03-08-ringwall-rebranding-plan.md \
  docs/plans/2026-03-08-sprint-5-storage-security.md \
  docs/plans/2026-03-08-sprint-6-vertical-integration.md \
  docs/plans/2026-03-10-sprint-7-auth-observability.md \
  src/config/config.h src/core/session.h src/crypto/session_cache.h
