# Rebranding: ioguard -> ioguard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Rename the entire project from ioguard to ioguard in a single atomic commit, then update GitHub repository metadata via gh api graphql.

**Architecture:** Global find-and-replace with ordered pattern matching (longest patterns first to avoid partial replacements), followed by file renames, build verification, and GitHub API calls.

**Tech Stack:** sed, git mv, gh api graphql, cmake, ctest (inside ringwall-dev container).

**Build/test:**
```bash
cmake --preset clang-debug
cmake --build --preset clang-debug
ctest --preset clang-debug
```

---

## Task 1: Rename source code patterns in src/

**Files:**
- Modify: All 55 `.c` and `.h` files under `src/`

**Step 1: Run ordered sed replacements on all source files**

Apply replacements in this order (longest first to prevent double-replacement):

```bash
# In src/ — all .c and .h files
find src/ -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i \
    -e 's/RINGWALL_/RINGWALL_/g' \
    -e 's/ringwall_/ringwall_/g' \
    -e 's/ringwall/ringwall/g' \
    -e 's/RW_COMPRESS/RW_COMPRESS/g' \
    -e 's/RW_CSTP/RW_CSTP/g' \
    -e 's/RW_DPD/RW_DPD/g' \
    -e 's/RW_CHANNEL/RW_CHANNEL/g' \
    -e 's/RW_DTLS/RW_DTLS/g' \
    -e 's/RW_TUN/RW_TUN/g' \
    -e 's/RW_IO/RW_IO/g' \
    -e 's/RW_IPC/RW_IPC/g' \
    -e 's/RW_MDBX/RW_MDBX/g' \
    -e 's/RW_WORKER/RW_WORKER/g' \
    -e 's/RW_SESSION/RW_SESSION/g' \
    -e 's/RW_CONFIG/RW_CONFIG/g' \
    -e 's/RW_HTTP/RW_HTTP/g' \
    -e 's/RW_XML/RW_XML/g' \
    -e 's/RW_PAM/RW_PAM/g' \
    -e 's/RW_SECMOD/RW_SECMOD/g' \
    -e 's/RW_MEMORY/RW_MEMORY/g' \
    -e 's/RW_LOG/RW_LOG/g' \
    -e 's/rw_compress/rw_compress/g' \
    -e 's/rw_cstp/rw_cstp/g' \
    -e 's/rw_dpd/rw_dpd/g' \
    -e 's/rw_channel/rw_channel/g' \
    -e 's/rw_dtls/rw_dtls/g' \
    -e 's/rw_tun/rw_tun/g' \
    -e 's/rw_io/rw_io/g' \
    -e 's/rw_ipc/rw_ipc/g' \
    -e 's/rw_mdbx/rw_mdbx/g' \
    -e 's/rw_worker/rw_worker/g' \
    -e 's/rw_session/rw_session/g' \
    -e 's/rw_config/rw_config/g' \
    -e 's/rw_http/rw_http/g' \
    -e 's/rw_xml/rw_xml/g' \
    -e 's/rw_pam/rw_pam/g' \
    -e 's/rw_secmod/rw_secmod/g' \
    -e 's/rw_memory/rw_memory/g' \
    -e 's/rw_log/rw_log/g' \
    -e 's/rw_lzs/rw_lzs/g' \
    -e 's/rw_lz4/rw_lz4/g' \
    -e 's/rw_add_test/rw_add_test/g' \
    -e 's/rw_metrics/rw_metrics/g' \
    -e 's/rw_core/rw_core/g' \
    -e 's/rw_crypto/rw_crypto/g' \
    {} +
```

**CRITICAL**: Do NOT replace bare `rw_` with `rw_` globally — use the module-specific patterns above to avoid corrupting unrelated tokens.

**Step 2: Handle the protobuf file**

```bash
sed -i 's/rw_ipc/rw_ipc/g' src/ipc/proto/rw_ipc.proto
```

**Step 3: Rename the proto file**

```bash
git mv src/ipc/proto/rw_ipc.proto src/ipc/proto/rw_ipc.proto
```

**Step 4: Verify no ringwall/rw_ remnants in src/**

```bash
grep -rn "ioguard\|IOGUARD\|rw_" src/ --include="*.c" --include="*.h" --include="*.proto"
# Expected: 0 matches (or only false positives like "rw_" inside string literals if any)
```

---

## Task 2: Rename test code patterns

**Files:**
- Modify: All 32 `.c` files under `tests/`

**Step 1: Run same sed replacements on test files**

```bash
find tests/ -type f -name "*.c" -exec sed -i \
    -e 's/RINGWALL_/RINGWALL_/g' \
    -e 's/ringwall_/ringwall_/g' \
    -e 's/ringwall/ringwall/g' \
    -e 's/RW_COMPRESS/RW_COMPRESS/g' \
    -e 's/RW_CSTP/RW_CSTP/g' \
    -e 's/RW_DPD/RW_DPD/g' \
    -e 's/RW_CHANNEL/RW_CHANNEL/g' \
    -e 's/RW_DTLS/RW_DTLS/g' \
    -e 's/RW_TUN/RW_TUN/g' \
    -e 's/RW_IO/RW_IO/g' \
    -e 's/RW_IPC/RW_IPC/g' \
    -e 's/RW_WORKER/RW_WORKER/g' \
    -e 's/RW_SESSION/RW_SESSION/g' \
    -e 's/RW_CONFIG/RW_CONFIG/g' \
    -e 's/RW_HTTP/RW_HTTP/g' \
    -e 's/RW_XML/RW_XML/g' \
    -e 's/RW_PAM/RW_PAM/g' \
    -e 's/RW_SECMOD/RW_SECMOD/g' \
    -e 's/RW_MEMORY/RW_MEMORY/g' \
    -e 's/RW_LOG/RW_LOG/g' \
    -e 's/rw_compress/rw_compress/g' \
    -e 's/rw_cstp/rw_cstp/g' \
    -e 's/rw_dpd/rw_dpd/g' \
    -e 's/rw_channel/rw_channel/g' \
    -e 's/rw_dtls/rw_dtls/g' \
    -e 's/rw_tun/rw_tun/g' \
    -e 's/rw_io/rw_io/g' \
    -e 's/rw_ipc/rw_ipc/g' \
    -e 's/rw_worker/rw_worker/g' \
    -e 's/rw_session/rw_session/g' \
    -e 's/rw_config/rw_config/g' \
    -e 's/rw_http/rw_http/g' \
    -e 's/rw_xml/rw_xml/g' \
    -e 's/rw_pam/rw_pam/g' \
    -e 's/rw_secmod/rw_secmod/g' \
    -e 's/rw_memory/rw_memory/g' \
    -e 's/rw_log/rw_log/g' \
    -e 's/rw_lzs/rw_lzs/g' \
    -e 's/rw_lz4/rw_lz4/g' \
    -e 's/rw_add_test/rw_add_test/g' \
    -e 's/rw_metrics/rw_metrics/g' \
    -e 's/rw_core/rw_core/g' \
    -e 's/rw_crypto/rw_crypto/g' \
    {} +
```

**Step 2: Verify no remnants in tests/**

```bash
grep -rn "ioguard\|IOGUARD\|rw_" tests/ --include="*.c"
# Expected: 0 matches
```

---

## Task 3: Rename CMakeLists.txt and CMakePresets.json

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `CMakePresets.json`

**Step 1: Update CMakeLists.txt**

Apply replacements:

```bash
sed -i \
    -e 's/ringwall/ringwall/g' \
    -e 's/rw_add_test/rw_add_test/g' \
    -e 's/rw_io/rw_io/g' \
    -e 's/rw_memory/rw_memory/g' \
    -e 's/rw_config/rw_config/g' \
    -e 's/rw_ipc/rw_ipc/g' \
    -e 's/rw_xml_auth/rw_xml_auth/g' \
    -e 's/rw_http/rw_http/g' \
    -e 's/rw_core/rw_core/g' \
    -e 's/rw_session/rw_session/g' \
    -e 's/rw_crypto/rw_crypto/g' \
    -e 's/rw_pam/rw_pam/g' \
    -e 's/rw_secmod/rw_secmod/g' \
    -e 's/rw_cstp/rw_cstp/g' \
    -e 's/rw_tun/rw_tun/g' \
    -e 's/rw_dpd/rw_dpd/g' \
    -e 's/rw_worker/rw_worker/g' \
    -e 's/rw_compress/rw_compress/g' \
    -e 's/rw_compress_lzs/rw_compress_lzs/g' \
    -e 's/rw_compress_lz4/rw_compress_lz4/g' \
    -e 's/rw_dtls/rw_dtls/g' \
    -e 's/rw_dtls_keying/rw_dtls_keying/g' \
    -e 's/rw_channel/rw_channel/g' \
    -e 's/rw_dtls_headers/rw_dtls_headers/g' \
    CMakeLists.txt
```

Also update the proto file reference:
```bash
sed -i 's/rw_ipc\.proto/rw_ipc.proto/g; s/rw_ipc\.pb-c/rw_ipc.pb-c/g' CMakeLists.txt
```

**Step 2: Verify CMakeLists.txt has no rw_ remnants**

```bash
grep -n "rw_\|ioguard" CMakeLists.txt
# Expected: 0 matches
```

**Step 3: CMakePresets.json needs no changes** (no ringwall/rw_ references)

---

## Task 4: Rename deploy/ files

**Files:**
- Modify: All files under `deploy/podman/` (21 files with 136 occurrences)

**Step 1: Run sed on deploy files**

```bash
find deploy/ -type f \( -name "*.sh" -o -name "*.yml" -o -name "*.yaml" -o -name "Makefile" \
    -o -name "Dockerfile*" -o -name "Containerfile" -o -name "*.md" -o -name "*.conf" -o -name "*.py" \) \
    -exec sed -i \
    -e 's/ringwall-dev/ringwall-dev/g' \
    -e 's/ringwall-build/ringwall-build/g' \
    -e 's/ringwall-test/ringwall-test/g' \
    -e 's/ringwall-ci/ringwall-ci/g' \
    -e 's/ringwall/ringwall/g' \
    -e 's/RINGWALL/RINGWALL/g' \
    {} +
```

**Step 2: Verify**

```bash
grep -rn "ioguard\|IOGUARD" deploy/
# Expected: 0 matches
```

---

## Task 5: Rename documentation and CLAUDE.md

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `REBRAND.md`
- Modify: `docs/README.md`, `docs/en/README.md`, `docs/ru/README.md`
- Modify: All files under `docs/` (excluding `docs/tmp/`)
- Modify: `.claude/skills/*.md`

**Step 1: Run sed on all non-tmp docs**

```bash
# Top-level md files
sed -i 's/ringwall/ringwall/g; s/RINGWALL/RINGWALL/g; s/rw_/rw_/g; s/RW_/RW_/g; s/rwctl/rwctl/g' \
    README.md CLAUDE.md REBRAND.md

# docs/ (excluding tmp/)
find docs/ -path "docs/tmp" -prune -o -name "*.md" -print -exec sed -i \
    -e 's/ringwall/ringwall/g' \
    -e 's/RINGWALL/RINGWALL/g' \
    -e 's/rw_/rw_/g' \
    -e 's/RW_/RW_/g' \
    -e 's/rwctl/rwctl/g' \
    {} +

# .claude/skills/
find .claude/skills/ -name "*.md" -exec sed -i \
    -e 's/ringwall/ringwall/g' \
    -e 's/RINGWALL/RINGWALL/g' \
    -e 's/rw_/rw_/g' \
    -e 's/RW_/RW_/g' \
    -e 's/rwctl/rwctl/g' \
    {} +
```

**Step 2: Update .github/ files**

```bash
find .github/ -type f -name "*.md" -o -name "*.yml" | xargs sed -i \
    -e 's/ringwall/ringwall/g' \
    -e 's/RINGWALL/RINGWALL/g'
```

**Step 3: Verify**

```bash
grep -rn "ioguard\|IOGUARD" README.md CLAUDE.md docs/ .claude/ .github/ --include="*.md" --include="*.yml" | grep -v "docs/tmp/"
# Expected: 0 matches (tmp/ is excluded from git anyway)
```

---

## Task 6: Update auto-memory and design docs

**Files:**
- Modify: `/root/.claude/projects/-opt/memory/MEMORY.md`
- Modify: `docs/plans/2026-03-08-ringwall-rebranding-and-s5-design.md` (update ioguard refs in design doc itself)

**Step 1: Update MEMORY.md**

Replace `ioguard` with `ioguard`, `rw_` with `rw_`, `RW_` with `RW_` throughout the memory file. Update the project name and all function prefix references.

**Step 2: Update the design doc's path references**

The design doc already uses `ioguard` but has some `ioguard` references in the storage architecture diagram and guide quotes — update those.

---

## Task 7: Build verification inside container

**Step 1: Clean build directory**

```bash
rm -rf build/
```

**Step 2: Configure, build, and test**

```bash
podman exec -it ringwall-dev bash -c "cd /opt/projects/repositories/ioguard && \
    cmake --preset clang-debug && \
    cmake --build --preset clang-debug && \
    ctest --preset clang-debug --output-on-failure"
```

**Step 3: If build fails, fix remaining rename issues**

Common issues:
- Generated protobuf files reference old names (clean build should regenerate)
- Include paths in headers may reference old filenames
- String literals containing `rw_` patterns that shouldn't have been renamed

**Step 4: Final remnant check**

```bash
grep -rn "ioguard\|IOGUARD" src/ tests/ CMakeLists.txt --include="*.c" --include="*.h" --include="*.proto" --include="*.txt"
grep -rn '"rw_' src/ tests/ --include="*.c" --include="*.h"
# Expected: 0 matches for both
```

---

## Task 8: Commit and GitHub operations

**Step 1: Stage all changes**

```bash
git add -A
```

**Step 2: Commit**

```bash
git commit -m "$(cat <<'EOF'
rebrand: ioguard -> ioguard

Rename project to eliminate conflict with wolfSSL Inc.'s commercial
wolfGuard product (FIPS 140-3 WireGuard VPN).

Naming convention:
- Server: ioguard (ring = io_uring, wall = security)
- CLI: rwctl
- DB tool: rwdb
- Function prefix: rw_ (replaces rw_)
- Include guards: RINGWALL_* (replaces RINGWALL_*)
- Config: ringwall.toml, /etc/ringwall/

See https://github.com/dantte-lp/ioguard/issues/11

All source code, tests, build system, containers, and documentation
updated. 772 occurrences in src/, 861 in tests/, 143 in CMakeLists.txt,
136 in deploy/, plus all documentation.
EOF
)"
```

**Step 3: Rename GitHub repository**

```bash
gh api graphql -f query='
mutation {
  updateRepository(input: {
    repositoryId: "<REPO_NODE_ID>",
    name: "ioguard",
    description: "Modern io_uring-powered OpenConnect VPN server (C23, wolfSSL, Linux)",
    homepageUrl: "https://ringwall.dev"
  }) {
    repository {
      name
      url
    }
  }
}'
```

First get the repo node ID:
```bash
gh api graphql -f query='{ repository(owner: "dantte-lp", name: "ioguard") { id } }'
```

**Step 4: Update repository topics**

```bash
gh api graphql -f query='
mutation {
  updateTopics(input: {
    repositoryId: "<REPO_NODE_ID>",
    topicNames: ["vpn", "openconnect", "wolfssl", "io-uring", "tls", "linux", "c23", "vpn-server"]
  }) {
    repository { repositoryTopics(first: 10) { nodes { topic { name } } } }
  }
}'
```

**Step 5: Close issue #11**

```bash
gh issue close 11 --repo dantte-lp/ioguard --comment "Completed. Project renamed to ringwall. See commit $(git rev-parse HEAD)."
```

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | Rename src/ patterns + proto file | 55 source files + 1 proto |
| 2 | Rename tests/ patterns | 32 test files |
| 3 | Rename CMakeLists.txt | 1 file |
| 4 | Rename deploy/ files | 21 files |
| 5 | Rename docs, CLAUDE.md, skills | ~40 files |
| 6 | Update auto-memory + design docs | 2 files |
| 7 | Build verification (container) | 0 files (verification) |
| 8 | Commit + GitHub API operations | 0 files (git + gh) |

**All tasks form one atomic commit** — tasks 1-6 are staged together, task 7 verifies, task 8 commits.

## Verification

After all tasks:
1. `grep -rn "ioguard\|IOGUARD" src/ tests/ CMakeLists.txt` — 0 matches
2. `grep -rn '"rw_' src/ tests/` — 0 matches
3. `cmake --build --preset clang-debug` — builds clean
4. `ctest --preset clang-debug` — all tests pass
5. `gh repo view dantte-lp/ioguard` — repo renamed
