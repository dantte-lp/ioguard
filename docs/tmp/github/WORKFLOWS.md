# GitHub Actions Workflows for ringwall

This document describes the CI/CD workflows configured for the ringwall project.

## Overview

The project uses **self-hosted runners** optimized for C23 development with pre-built dependencies (wolfSSL, libuv, cJSON, mimalloc). Two workflows are available:

1. **containers.yml** - Container build and integration testing (production-focused)
2. **dev-ci.yml** - Fast development feedback loop (< 15 minutes target)

## Self-Hosted Runner Labels

All workflows use self-hosted runners with specific labels:

| Runner Type | Labels | Base OS | Use Case |
|-------------|--------|---------|----------|
| Oracle Linux | `[self-hosted, linux, x64, oracle-linux]` | Oracle Linux 10 | RPM builds, production containers |
| Debian | `[self-hosted, linux, x64, debian]` | Debian Trixie | Universal development, DEB packages |

**Important**: Always use array syntax for runner labels:
```yaml
runs-on: [self-hosted, linux, x64, oracle-linux]  # Correct
runs-on: self-hosted  # Wrong - will use any available runner
```

## Workflow 1: containers.yml (Container Build & Test)

**Trigger**: Push to main/master/develop, PRs, manual dispatch
**Target Time**: 30-45 minutes
**Purpose**: Build production containers, run integration tests

### Jobs Overview

```
verify-setup → build-dev ──┬──> build-test → run-tests
                           │
                           ├──> test-backends (matrix: gnutls, wolfssl)
                           │
                           └──> security-scan

verify-setup → build-build → build-ci → quick-validate

[all jobs] → cleanup
[on push to main] → push-images
```

### Key Jobs

#### 1. `verify-setup`
- **Purpose**: Verify Podman, Buildah, Skopeo availability
- **Checks**: GCC version, system info, rootless support
- **Time**: < 1 minute

#### 2. `build-dev`
- **Purpose**: Build development container with all dependencies
- **Image**: `localhost/ringwall-dev:latest`
- **Contents**: Full toolchain, wolfSSL, libuv, cJSON, mimalloc
- **Time**: ~25-30 minutes (cached after first build)
- **Artifact**: Saved as `dev-image.tar` for downstream jobs

#### 3. `build-test`, `build-build`, `build-ci`
- **Purpose**: Build specialized containers for testing and CI
- **Dependencies**: Inherit from dev or build images
- **Time**: 5-10 minutes each

#### 4. `test-backends`
- **Purpose**: Test both TLS backends (GnuTLS and wolfSSL)
- **Strategy**: Matrix build (2 parallel jobs)
- **Commands**:
  ```bash
  make clean && make BACKEND=gnutls all
  make BACKEND=gnutls test-unit

  make clean && make BACKEND=wolfssl all
  make BACKEND=wolfssl test-unit
  ```
- **Time**: 3-5 minutes per backend

#### 5. `security-scan`
- **Purpose**: Scan container images for vulnerabilities
- **Tool**: Trivy
- **Output**: SARIF report uploaded to GitHub Security tab
- **Time**: 2-3 minutes

#### 6. `push-images`
- **Trigger**: Only on push to main/master branch
- **Purpose**: Push images to GitHub Container Registry (ghcr.io)
- **Tags**: `latest` and `${{ github.sha }}`
- **Permissions**: Requires `packages: write`

### Usage Examples

**Trigger manually**:
```bash
gh workflow run containers.yml
```

**View logs**:
```bash
gh run view --log
```

**Download artifacts**:
```bash
gh run download <run-id> --name dev-image
```

## Workflow 2: dev-ci.yml (Development CI)

**Trigger**: Push to develop/feature/bugfix branches, PRs, manual dispatch
**Target Time**: < 15 minutes
**Purpose**: Fast feedback for developers

### Pipeline Stages

```
Stage 1: Quick Checks (< 5 min)
  ├─ Code formatting (clang-format)
  ├─ Static analysis (cppcheck)
  └─ Syntax check (gcc -fsyntax-only)

Stage 2: Build Matrix (5-10 min)
  ├─ Build (gnutls, Debug)
  ├─ Build (gnutls, Release)
  ├─ Build (wolfssl, Debug)
  └─ Build (wolfssl, Release)

Stage 3: Unit Tests (5-10 min)
  ├─ Unit Tests (gnutls)
  └─ Unit Tests (wolfssl)

Stage 4: Memory & Sanitizers (10-15 min)
  ├─ AddressSanitizer tests
  └─ Valgrind memory leak detection

Stage 5: Coverage (10 min)
  └─ Generate coverage report (Debug builds only)

Stage 6: Integration Tests (15-30 min, optional)
  └─ TLS handshake, connection tests
```

### Key Features

#### 1. Fast Feedback Loop
- Quick checks run in < 5 minutes
- Fail-fast strategy: stop on critical failures
- Parallel matrix builds for speed

#### 2. Comprehensive Testing
- **Unit tests**: Per-backend validation
- **AddressSanitizer**: Memory error detection
- **Valgrind**: Memory leak detection
- **Code coverage**: Track test coverage (Debug builds)

#### 3. Build Matrix
```yaml
strategy:
  matrix:
    backend: [gnutls, wolfssl]
    build_type: [Debug, Release]
```
Results in 4 parallel build jobs:
- gnutls + Debug
- gnutls + Release
- wolfssl + Debug
- wolfssl + Release

#### 4. Sanitizer Support
```yaml
# AddressSanitizer build
meson setup . .. \
  --buildtype=debug \
  -Db_sanitize=address \
  -Db_lundef=false

# Run with ASan options
ASAN_OPTIONS=detect_leaks=1:halt_on_error=0 meson test
```

#### 5. Code Coverage
```yaml
# Enable coverage in Debug builds
meson setup . .. \
  --buildtype=debug \
  -Db_coverage=true

# Generate HTML report
ninja coverage-html
```

### Usage Examples

**Run on feature branch**:
```bash
git checkout feature/my-feature
git push origin feature/my-feature
# Workflow runs automatically
```

**View test results**:
```bash
gh run view --log | grep "Test Summary"
```

**Download coverage report**:
```bash
gh run download <run-id> --name coverage-report
```

## Environment Variables

Both workflows use consistent environment configuration:

```yaml
env:
  # Compiler settings
  CC: gcc
  CFLAGS: "-std=c23 -Wall -Wextra -Wpedantic -Werror -O2"

  # Build configuration
  BUILD_TYPE: Debug
  ENABLE_COVERAGE: true

  # Library paths
  PKG_CONFIG_PATH: /usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig
  LD_LIBRARY_PATH: /usr/local/lib:/usr/local/lib64
```

**Override in workflow**:
```yaml
- name: Build with Clang
  run: make all
  env:
    CC: clang
    CFLAGS: "-std=c2x -O3"
```

## Artifacts

Workflows generate various artifacts:

| Artifact | Description | Retention | Size (approx) |
|----------|-------------|-----------|---------------|
| `dev-image` | Development container image | 1 day | 2-3 GB |
| `build-*` | Compiled binaries and libraries | 1 day | 50-100 MB |
| `test-results-*` | Test logs and JUnit XML | 7 days | 1-5 MB |
| `coverage-report` | HTML coverage report | 7 days | 5-10 MB |
| `trivy-results` | Security scan (SARIF) | 7 days | < 1 MB |

**Download artifacts**:
```bash
# List artifacts for a run
gh run view <run-id> --log

# Download specific artifact
gh run download <run-id> --name coverage-report

# Download all artifacts
gh run download <run-id>
```

## Build System Integration

### Meson Build (Primary)

Expected directory structure:
```
ringwall/
├── meson.build           # Main build file
├── src/
│   └── meson.build
├── tests/
│   └── meson.build
└── build-*/              # Build directories (gitignored)
```

**Configure**:
```bash
meson setup build \
  --buildtype=debug \
  -Dtls_backend=wolfssl \
  -Db_coverage=true
```

**Build**:
```bash
meson compile -C build -v
```

**Test**:
```bash
meson test -C build --verbose --print-errorlogs
```

**Coverage**:
```bash
ninja -C build coverage-html
xdg-open build/meson-logs/coveragereport/index.html
```

### Make (Fallback)

If meson.build is not ready:
```bash
make BACKEND=wolfssl all
make BACKEND=wolfssl test-unit
make BACKEND=wolfssl clean
```

## Troubleshooting

### Common Issues

#### 1. "No runner available"
**Problem**: Workflow stuck in "Queued" state
**Solution**:
- Check runner status: `gh runner list`
- Verify runner labels match workflow requirements
- Restart runner if offline

#### 2. "Library not found"
**Problem**: Compile errors for wolfSSL, libuv, etc.
**Solution**:
```yaml
- name: Debug library paths
  run: |
    pkg-config --list-all | grep -E 'wolfssl|libuv|cjson'
    ldconfig -p | grep wolfssl
    echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
```

#### 3. "meson.build not found"
**Problem**: Build system not ready
**Solution**: Workflow gracefully handles this with `continue-on-error: true`
```yaml
- name: Configure build
  run: |
    if [ -f meson.build ]; then
      meson setup build
    else
      echo "Build system not ready yet"
      exit 1
    fi
  continue-on-error: true
```

#### 4. "Tests timeout"
**Problem**: Tests hang or exceed timeout
**Solution**: Adjust timeout in workflow:
```yaml
- name: Run tests
  run: meson test -C build
  timeout-minutes: 10  # Adjust as needed
```

### Debugging Workflows

**Enable debug logging**:
1. Go to Settings → Secrets and variables → Actions
2. Add repository variable: `ACTIONS_RUNNER_DEBUG` = `true`
3. Add repository variable: `ACTIONS_STEP_DEBUG` = `true`

**Check runner logs**:
```bash
# On runner host
sudo journalctl -u actions.runner.* -f
```

**Test locally with act**:
```bash
# Install act (GitHub Actions local runner)
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow locally
act -j quick-checks -P self-hosted=catthehacker/ubuntu:full-latest
```

## Best Practices

### 1. Use Specific Runner Labels
```yaml
# Good: Specific platform
runs-on: [self-hosted, linux, x64, oracle-linux]

# Bad: Too generic
runs-on: self-hosted
```

### 2. Set Reasonable Timeouts
```yaml
jobs:
  build:
    timeout-minutes: 30  # Prevent stuck jobs
    steps:
      - name: Compile
        timeout-minutes: 10  # Per-step timeout
```

### 3. Use Caching for Dependencies
```yaml
- name: Cache build directory
  uses: actions/cache@v4
  with:
    path: build/
    key: ${{ runner.os }}-build-${{ hashFiles('meson.build') }}
```

### 4. Fail Fast for Critical Checks
```yaml
strategy:
  fail-fast: true  # Stop all jobs on first failure
  matrix:
    backend: [gnutls, wolfssl]
```

### 5. Continue on Non-Critical Errors
```yaml
- name: Optional static analysis
  run: cppcheck src/
  continue-on-error: true
```

## Performance Optimization

### Current Timings

| Workflow | Target | Actual (first run) | Actual (cached) |
|----------|--------|-------------------|-----------------|
| containers.yml | 30-45 min | 45-60 min | 15-20 min |
| dev-ci.yml | < 15 min | 20-25 min | 10-15 min |

### Optimization Strategies

1. **Parallel Jobs**: Use matrix strategy for independent builds
2. **Artifact Reuse**: Share built containers between jobs
3. **Conditional Execution**: Skip non-essential jobs on PRs
4. **Runner Warm-up**: Keep runners alive to avoid cold starts

## Security Considerations

1. **Secrets Management**: Never expose secrets in logs
2. **Runner Isolation**: Runners should be in isolated network
3. **Container Scanning**: Always scan images before publishing
4. **SARIF Upload**: Security results uploaded to GitHub Security tab

## Migration from Generic Runners

If migrating from GitHub-hosted runners:

**Before** (GitHub-hosted):
```yaml
runs-on: ubuntu-latest
steps:
  - name: Install dependencies
    run: |
      sudo apt-get update
      sudo apt-get install -y gcc make cmake
      # Build wolfSSL from source (~5-10 minutes)
```

**After** (Self-hosted):
```yaml
runs-on: [self-hosted, linux, x64, oracle-linux]
steps:
  - name: Build project
    run: make all
    # Dependencies pre-installed, wolfSSL ready to use
```

**Benefits**:
- 5-10 minutes saved on dependency installation
- Consistent build environment
- Better control over library versions

## Contributing

When adding new workflows:

1. Test locally with `act` if possible
2. Use `continue-on-error: true` for experimental features
3. Document expected artifacts and timings
4. Add timeout limits to prevent runaway jobs
5. Use descriptive job names and step names

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Self-Hosted Runners Setup](../../../self-hosted-runners/RUNNER_SETUP_OCSERV.md)
- [Meson Build System](https://mesonbuild.com/Manual.html)
- [wolfSSL Documentation](https://www.wolfssl.com/documentation/)

Last Updated: 2025-10-29
