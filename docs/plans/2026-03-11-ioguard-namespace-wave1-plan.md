# Sprint Plan: Namespace Wave 1

Date: 2026-03-11
Branch: `feature/ioguard-namespace-wave1`

## Goal

Start the code namespace migration from legacy `rw_` / `RW_` / `RINGWALL_` to:

- `iog_` for functions, libraries, internal identifiers
- `IOG_` for macro and enum prefixes
- `IOGUARD_` for product-level constants and include guards

This wave intentionally avoids broad uncontrolled rewrites across the whole codebase.

## Constraints

- Keep the tree buildable in small batches.
- Prefer low-risk surfaces first: docs, contributor instructions, naming rules, isolated constants.
- Do not rename every `rw_*` symbol in one pass.
- Keep automated rename scripts scoped and reviewable.

## Wave 1 scope

1. Update project instructions and coding guidance to the new naming scheme.
2. Rename low-risk product constants from `RW_*` / `RINGWALL_*` to `IOG_*` / `IOGUARD_*` where isolated.
3. Keep build target names and most function/type prefixes unchanged in this wave.
4. Capture remaining prefix inventory after the batch.

## Deferred to later waves

- CMake target names like `rw_io`, `rw_crypto`, `rw_http`
- function/type prefixes across the full source tree
- protobuf artifact names like `rw_ipc.proto`
- test target names and broad fixture symbol renames

## Exit criteria

- project guidance consistently points to `iog_` / `IOG_` / `IOGUARD_`
- no regressions in touched bootstrap/config tests
- remaining rename surface is re-inventoried for Wave 2
