# Ioguard Legacy Name Inventory

## Purpose

The repository and human-facing project name have been moved from `ioguard` to `ioguard`.

This document tracks the remaining old-name patterns that were intentionally **not**
renamed in the first pass because they affect code prefixes, build targets, images,
config paths, or other operational identifiers that need a separate decision.

## Current State

- Remote repository: `https://github.com/dantte-lp/ioguard`
- Local repository path: `/opt/projects/repositories/ioguard`
- Standalone human-facing `ioguard` mentions have been swept
- Remaining old-name usage is concentrated in identifiers and operational artifacts

## Remaining Prefix Families

| Pattern | Rough count | Notes |
|---|---:|---|
| `iog_` | 5486 | Main C symbol prefix for functions, types, files, and CMake targets |
| `IOG_` | 1349 | Macros, enums, constants, labels |
| `IOGUARD_` | 280 | Include guards and some compile-time identifiers |
| `ioguard-dev` | 52 | Container image and utility naming |
| `ioguard.toml` | 11 | Config artifact naming |
| `/etc/ioguard` | 21 | Runtime path naming |

## Prefix And Identifier Categories

### Code/API prefixes

- `iog_` in source, tests, and build targets
  - [CMakeLists.txt](/opt/projects/repositories/ioguard/CMakeLists.txt)
- `IOG_` macros and enums
  - [src/core/main.c](/opt/projects/repositories/ioguard/src/core/main.c)
  - [src/security/firewall.h](/opt/projects/repositories/ioguard/src/security/firewall.h)
- `IOGUARD_` include guards
  - [src/auth/totp.h](/opt/projects/repositories/ioguard/src/auth/totp.h)
  - [docs/plans/2026-03-07-sprint-1-foundation.md](/opt/projects/repositories/ioguard/docs/plans/2026-03-07-sprint-1-foundation.md)

### Build and package identifiers

- CMake project name and summary strings still use `ioguard`
  - [CMakeLists.txt](/opt/projects/repositories/ioguard/CMakeLists.txt)
- Ceedling project name still uses `ioguard`
  - [project.yml](/opt/projects/repositories/ioguard/project.yml)
- Doxygen project name still uses `ioguard`
  - [Doxyfile](/opt/projects/repositories/ioguard/Doxyfile)
- Install include path still uses `include/ioguard`
  - [Makefile](/opt/projects/repositories/ioguard/Makefile)

### Runtime and operational names

- Default config filename and path
  - `ioguard.toml`
  - `/etc/ioguard/ioguard.toml`
  - [src/core/main.c](/opt/projects/repositories/ioguard/src/core/main.c)
- Container image names
  - `localhost/ioguard-dev`
  - `localhost/ioguard-test`
  - `localhost/ioguard-build`
  - `localhost/ioguard-ci`
  - [deploy/podman/compose.yaml](/opt/projects/repositories/ioguard/deploy/podman/compose.yaml)
- OCI labels
  - `io.ioguard.version`
  - `io.ioguard.environment`
  - [deploy/podman/scripts/build-dev.sh](/opt/projects/repositories/ioguard/deploy/podman/scripts/build-dev.sh)
- Logger target and other operational strings
  - [src/log/iog_log.c](/opt/projects/repositories/ioguard/src/log/iog_log.c)
- Firewall/nft table naming
  - [src/security/firewall.h](/opt/projects/repositories/ioguard/src/security/firewall.h)
- PAM / RADIUS / TOTP defaults
  - [src/auth/pam.c](/opt/projects/repositories/ioguard/src/auth/pam.c)
  - [src/auth/radius.c](/opt/projects/repositories/ioguard/src/auth/radius.c)
  - [src/config/config.c](/opt/projects/repositories/ioguard/src/config/config.c)

### Artifact and utility names

- Generated or packaged artifact names still use `ioguard`
  - tarballs in [deploy/podman/scripts/build-build.sh](/opt/projects/repositories/ioguard/deploy/podman/scripts/build-build.sh)
- Helper scripts still refer to old image names
  - [deploy/podman/scripts/push-image.sh](/opt/projects/repositories/ioguard/deploy/podman/scripts/push-image.sh)
  - [deploy/podman/scripts/inspect-images.sh](/opt/projects/repositories/ioguard/deploy/podman/scripts/inspect-images.sh)
- Test fixtures still use `ioguard.toml`
  - [tests/fixtures/ioguard.toml](/opt/projects/repositories/ioguard/tests/fixtures/ioguard.toml)

### External and adjacent names

- `ioguard-docs` references remain in skill docs and plan docs
  - [.claude/skills/ocprotocol/SKILL.md](/opt/projects/repositories/ioguard/.claude/skills/ocprotocol/SKILL.md)
  - [.claude/skills/wolfsentry-idps/SKILL.md](/opt/projects/repositories/ioguard/.claude/skills/wolfsentry-idps/SKILL.md)
  - [.claude/skills/wolfssl-api/SKILL.md](/opt/projects/repositories/ioguard/.claude/skills/wolfssl-api/SKILL.md)
- `ioguard-connect` remains as a client/product name in architecture docs
  - [docs/architecture/MODERN_ARCHITECTURE.md](/opt/projects/repositories/ioguard/docs/architecture/MODERN_ARCHITECTURE.md)

## Deferred Rename Queue

These need explicit naming decisions before editing:

1. C prefix family:
   - `iog_`
   - `IOG_`
   - `IOGUARD_`
2. Build/package identity:
   - `project(ioguard)`
   - install include directory `ioguard/`
3. Runtime artifacts:
   - binary name `ioguard`
   - config file `ioguard.toml`
   - `/etc/ioguard/` and `/var/lib/ioguard/`
4. Container images and labels:
   - `ioguard-dev`
   - `ioguard-test`
   - `ioguard-build`
   - `ioguard-ci`
   - `io.ioguard.*`
5. Product-adjacent names:
   - `ioguard-connect`
   - `ioguard-docs`

## Recommendation

Do the next rename wave in explicit layers:

1. Build and artifact naming
2. Runtime paths and default filenames
3. Container images and OCI labels
4. C/API prefixes and include guards
5. Adjacent repository and client naming

Trying to change all of these in one pass would create too much ABI, packaging, and tooling churn at once.
