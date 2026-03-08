# Quick Start: CI/CD for ringwall

This guide helps you quickly understand and use the CI/CD pipelines for ringwall.

## TL;DR

```bash
# Push to develop branch → triggers dev-ci.yml (< 15 min)
git push origin develop

# Push to main branch → triggers containers.yml (30-45 min) + publishes images
git push origin main

# Manual workflow dispatch
gh workflow run dev-ci.yml
gh workflow run containers.yml
```

## Runners Overview

The project uses **self-hosted runners** with pre-built dependencies:

| Component | Version | Built-in |
|-----------|---------|----------|
| GCC | 14.2+ | C23 support |
| wolfSSL | 5.8.2 | TLS 1.3, DTLS 1.3 |
| libuv | 1.51.0 | Async I/O |
| cJSON | 1.7.18 | JSON parsing |
| mimalloc | 2.2.4 | Performance allocator |

**No manual dependency installation required!**

## Workflow Selection

### Use `dev-ci.yml` when:
- Developing features on `develop` or `feature/*` branches
- Need fast feedback (< 15 minutes)
- Running unit tests and sanitizers
- Checking code quality

### Use `containers.yml` when:
- Merging to `main` or `master` branch
- Building production containers
- Running full integration tests
- Publishing container images

## Development Workflow (dev-ci.yml)

### What It Does

1. **Quick Checks** (< 5 min)
   - Code formatting (clang-format)
   - Static analysis (cppcheck)
   - Syntax validation

2. **Build Matrix** (5-10 min)
   - GnuTLS backend (Debug + Release)
   - wolfSSL backend (Debug + Release)

3. **Unit Tests** (5-10 min)
   - Per-backend test execution
   - Test result reporting

4. **Memory Safety** (10-15 min)
   - AddressSanitizer tests
   - Valgrind memory leak detection

5. **Coverage** (optional)
   - Code coverage reports (Debug builds only)

### Example: Feature Development

```bash
# Create feature branch
git checkout -b feature/dtls13-support

# Make changes
vim src/tls/dtls.c

# Commit and push
git add src/tls/dtls.c
git commit -m "feat: add DTLS 1.3 support"
git push origin feature/dtls13-support

# Workflow runs automatically
# Check status: gh run watch
```

### View Results

```bash
# List recent workflow runs
gh run list --workflow=dev-ci.yml

# View specific run
gh run view <run-id> --log

# Download artifacts
gh run download <run-id> --name test-results-wolfssl
```

## Container Workflow (containers.yml)

### What It Does

1. **Verify Setup** (< 1 min)
   - Check Podman, Buildah, GCC versions

2. **Build Containers** (25-30 min)
   - Development image (full toolchain)
   - Test image (test suite)
   - Build image (optimized build)
   - CI image (minimal CI tools)

3. **Test Backends** (5 min)
   - Compile and test GnuTLS backend
   - Compile and test wolfSSL backend

4. **Security Scan** (2-3 min)
   - Trivy vulnerability scan
   - SARIF report to GitHub Security

5. **Publish Images** (only on main/master push)
   - Push to ghcr.io
   - Tag with `latest` and commit SHA

### Example: Release Preparation

```bash
# Merge feature to develop
git checkout develop
git merge feature/dtls13-support
git push origin develop

# Workflow runs but does NOT publish images

# After testing on develop, merge to main
git checkout main
git merge develop
git push origin main

# Workflow runs AND publishes images to ghcr.io
```

### Pull Published Images

```bash
# After successful main branch push
docker pull ghcr.io/dantte-lp/ringwall-dev:latest
docker pull ghcr.io/dantte-lp/ringwall-dev:<commit-sha>

# Run development container
docker run -it --rm \
  -v /opt/projects/repositories/ringwall:/workspace:Z \
  ghcr.io/dantte-lp/ringwall-dev:latest
```

## Build System Cheat Sheet

### Meson (Primary)

```bash
# Configure Debug build with wolfSSL
meson setup build-wolfssl-debug \
  --buildtype=debug \
  -Dtls_backend=wolfssl \
  -Db_coverage=true

# Compile
meson compile -C build-wolfssl-debug -v

# Run tests
meson test -C build-wolfssl-debug --verbose

# Generate coverage
ninja -C build-wolfssl-debug coverage-html
```

### Make (Fallback)

```bash
# Build with specific backend
make BACKEND=wolfssl all

# Run unit tests
make BACKEND=wolfssl test-unit

# Clean build
make BACKEND=wolfssl clean
```

## Troubleshooting

### Problem: Workflow Stuck in "Queued"
**Solution**: Check runner status
```bash
gh runner list
# Restart runner if offline
```

### Problem: "Library not found" errors
**Solution**: Verify library paths in workflow
```yaml
- name: Debug libraries
  run: |
    pkg-config --modversion wolfssl libuv cjson
    echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
```

### Problem: Tests failing locally but passing in CI
**Solution**: Use the dev container
```bash
# Pull the CI container
docker pull ghcr.io/dantte-lp/ringwall-dev:latest

# Run tests in container
docker run --rm \
  -v $PWD:/workspace:Z \
  -w /workspace \
  ghcr.io/dantte-lp/ringwall-dev:latest \
  meson test -C build --verbose
```

### Problem: Workflow takes too long
**Solution**: Use caching or split jobs
```yaml
- name: Cache build
  uses: actions/cache@v4
  with:
    path: build/
    key: ${{ runner.os }}-${{ hashFiles('meson.build') }}
```

## Artifact Downloads

```bash
# List artifacts for a run
gh run view <run-id>

# Download test results
gh run download <run-id> --name test-results-wolfssl

# Download coverage report
gh run download <run-id> --name coverage-report

# Download container image (local development)
# Already built by workflow, just load it
podman load -i /tmp/images-<run-id>/dev-image.tar
```

## Workflow Triggers

### Automatic Triggers

| Event | Branches | Workflows |
|-------|----------|-----------|
| Push | develop, feature/*, bugfix/* | dev-ci.yml |
| Push | main, master | containers.yml + dev-ci.yml |
| Pull Request | any → develop/main | dev-ci.yml |
| Pull Request (containers) | any → main | containers.yml |

### Manual Triggers

```bash
# Trigger workflow manually
gh workflow run dev-ci.yml

# Trigger with branch selection
gh workflow run containers.yml --ref feature/my-branch

# Trigger and wait for completion
gh workflow run dev-ci.yml && gh run watch
```

## Environment Variables (Override)

```yaml
# In workflow file or step
env:
  CC: clang              # Use Clang instead of GCC
  CFLAGS: "-std=c2x -O3" # Override compiler flags
  BUILD_TYPE: Release    # Release build
  ENABLE_COVERAGE: false # Disable coverage
```

## Best Practices

1. **Branch Naming**:
   - `feature/dtls13-support` → triggers dev-ci.yml
   - `bugfix/memory-leak` → triggers dev-ci.yml
   - `develop` → runs dev-ci.yml only
   - `main` → runs both workflows + publishes images

2. **Commit Messages**:
   ```
   feat: add DTLS 1.3 support
   fix: memory leak in session handling
   test: add unit tests for priority string parser
   docs: update README with new build instructions
   ```

3. **Pull Requests**:
   - Always create PR from feature branch to `develop` first
   - Let CI pass before merging
   - Review test results and coverage reports

4. **Releases**:
   - Tag releases on `main` branch: `git tag v2.0.0-alpha.2`
   - Push tags: `git push origin v2.0.0-alpha.2`
   - GitHub Actions will build and publish containers

## Next Steps

- **Full Documentation**: Read [WORKFLOWS.md](WORKFLOWS.md)
- **Runner Setup**: Check [self-hosted-runners/RUNNER_SETUP_OCSERV.md](../../../self-hosted-runners/RUNNER_SETUP_OCSERV.md)
- **Build System**: Review meson.build and Makefile
- **Testing**: Write unit tests in `tests/unit/`

## Getting Help

```bash
# View workflow file
cat .github/workflows/dev-ci.yml

# Check runner status
gh runner list

# View recent runs
gh run list

# View logs for failed run
gh run view <run-id> --log --log-failed
```

Last Updated: 2025-10-29
