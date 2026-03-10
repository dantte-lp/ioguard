#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/projects/repositories/ioguard"
cd "$ROOT"

rg -n \
  -e "rwctl" \
  -e "ringwall-dev" \
  -e "ringwall-test" \
  -e "ringwall-build" \
  -e "ringwall-ci" \
  -e "ringwall\\.toml" \
  -e "/etc/ringwall" \
  -e "/var/lib/ringwall" \
  -e "io\\.ringwall\\." \
  -e "ringwall-connect" \
  -e "ringwall-docs" \
  --glob '!docs/tmp/**' \
  --glob '!docs/plans/2026-03-11-ioguard-legacy-name-inventory.md' \
  --glob '!docs/plans/2026-03-11-ioguard-naming-options.md' \
  --glob '!scripts/maintenance/**' \
  . || true
