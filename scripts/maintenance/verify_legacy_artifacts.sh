#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/projects/repositories/ioguard"
cd "$ROOT"

rg -n \
  -e "rwctl" \
  -e "ioguard-dev" \
  -e "ioguard-test" \
  -e "ioguard-build" \
  -e "ioguard-ci" \
  -e "ioguard\\.toml" \
  -e "/etc/ioguard" \
  -e "/var/lib/ioguard" \
  -e "io\\.ioguard\\." \
  -e "ioguard-connect" \
  -e "ioguard-docs" \
  --glob '!docs/tmp/**' \
  --glob '!docs/plans/2026-03-11-ioguard-legacy-name-inventory.md' \
  --glob '!docs/plans/2026-03-11-ioguard-naming-options.md' \
  --glob '!scripts/maintenance/**' \
  . || true
