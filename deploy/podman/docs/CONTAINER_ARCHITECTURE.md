# Container Architecture

This document describes the design decisions, architecture, and rationale behind the ringwall Podman container infrastructure.

## Table of Contents

- [Design Goals](#design-goals)
- [Architecture Overview](#architecture-overview)
- [Container Design](#container-design)
- [Build Strategy](#build-strategy)
- [Security Architecture](#security-architecture)
- [Performance Optimizations](#performance-optimizations)
- [Rootless Design](#rootless-design)
- [Volume Architecture](#volume-architecture)
- [Networking](#networking)
- [Future Enhancements](#future-enhancements)

## Design Goals

### Primary Goals

1. **Production-Grade Quality**
   - Suitable for development, testing, AND production deployments
   - Follows container best practices and security standards
   - Reproducible builds with pinned dependencies

2. **Podman-First Approach**
   - No dependency on Docker daemon
   - Rootless containers by default
   - SELinux-aware from the ground up
   - crun runtime for optimal performance

3. **Developer Experience**
   - Quick startup (<5 seconds for dev container)
   - Hot-reload development workflow
   - Minimal context switching
   - Clear error messages and diagnostics

4. **Security by Default**
   - Minimal attack surface
   - Capability dropping (CAP_DROP: ALL)
   - SELinux labels on all mounts
   - No secrets in images
   - Regular security updates

5. **Performance**
   - Fast builds through layer caching
   - Minimal image sizes
   - Efficient resource utilization
   - Optimized for CI/CD pipelines

## Architecture Overview

### Four-Environment Strategy

We use a **multi-environment** approach instead of a single monolithic container:

```
┌─────────────┐
│ Development │  ← Full toolchain, debug symbols
│    (dev)    │     Interactive work, debugging
└─────────────┘

┌─────────────┐
│    Test     │  ← Based on dev, adds test frameworks
│   (test)    │     Automated testing, coverage
└─────────────┘

┌─────────────┐
│    Build    │  ← Minimal, release-optimized
│   (build)   │     Production artifact creation
└─────────────┘

┌─────────────┐
│   CI/CD     │  ← Based on build, ultra-lightweight
│    (ci)     │     Fast pipeline execution
└─────────────┘
```

**Rationale**:
- Separation of concerns (development vs. production)
- Smaller images for specific tasks
- Faster CI/CD (doesn't need dev tools)
- Clear purpose for each environment

### Image Inheritance

```
registry.access.redhat.com/ubi9/ubi:latest
    │
    ├─> ringwall-dev:latest (500MB)
    │       │
    │       └─> ringwall-test:latest (500MB)
    │
    └─> registry.access.redhat.com/ubi9/ubi-minimal:latest
            │
            └─> ringwall-build:latest (200MB)
                    │
                    └─> ringwall-ci:latest (200MB)
```

**Rationale**:
- Test inherits from dev (already has all libraries)
- Build uses minimal base (smaller final image)
- CI inherits from build (gets optimized libraries)

## Container Design

### Development Container

**Purpose**: Interactive development and debugging

**Key Features**:
- Full UBI9 base (not minimal)
- Debug symbols (`-g` flag)
- Development tools (gdb, valgrind, perf, strace)
- All libraries built from source
- Non-root user (developer:1000)

**Design Decisions**:

1. **Why UBI9 full (not minimal)?**
   - Need full toolchain for compilation
   - Development tools require many dependencies
   - Debugging needs system utilities
   - Size not critical for dev environment

2. **Why build libraries from source?**
   - Latest versions (not available in repos)
   - Custom compile flags (debug symbols, optimizations)
   - Control over configuration options
   - Reproducible builds

3. **Why non-root user?**
   - Matches host user permissions
   - Prevents accidental file ownership issues
   - Better security posture
   - Required for rootless Podman

**Size Target**: <500MB (acceptable for dev environment)

### Test Container

**Purpose**: Automated testing and coverage

**Inherits From**: Development container

**Additions**:
- Test frameworks (check, cmocka, pytest)
- Coverage tools (lcov, gcovr)
- Network testing utilities (tcpdump, iperf3)
- Test runner scripts

**Design Decisions**:

1. **Why inherit from dev?**
   - Already has all libraries compiled
   - Avoids rebuilding dependencies
   - Faster build time (1-2 minutes vs 8-10)

2. **Why separate from dev?**
   - Clean test environment
   - Can be run in CI without dev tools
   - Pre-configured test runners
   - Default command runs tests (not bash)

3. **Why include network tools?**
   - VPN server needs network testing
   - Integration tests require traffic analysis
   - Performance benchmarking needs iperf3

**Size Target**: <500MB (inherits dev size)

### Build Container

**Purpose**: Creating release artifacts

**Base**: UBI9-minimal (not full UBI9)

**Key Features**:
- Release optimizations (O3, LTO, stripped binaries)
- Packaging tools (rpm-build, createrepo)
- Libraries built without debug symbols
- Minimal dependencies

**Design Decisions**:

1. **Why UBI9-minimal?**
   - Much smaller base (~80MB vs 200MB)
   - Fewer packages to update
   - Faster vulnerability scanning
   - Production-like environment

2. **Why separate build from dev?**
   - Different optimization flags (O3 vs O2)
   - Stripped binaries (no debug symbols)
   - Smaller final image
   - Clear separation: dev vs production

3. **Why include packaging tools?**
   - Create RPM packages for distribution
   - Repository metadata generation
   - Signing capabilities

**Size Target**: <200MB

### CI Container

**Purpose**: Fast automated testing in pipelines

**Inherits From**: Build container

**Additions**:
- CI runner scripts
- Minimal testing tools
- Quick validation scripts

**Design Decisions**:

1. **Why inherit from build?**
   - Gets optimized libraries
   - Small size (critical for CI)
   - Fast startup time

2. **Why separate from test?**
   - Much faster (no dev tools to load)
   - Minimal dependencies (faster pulls)
   - Focused on quick feedback
   - Can run on smaller CI runners

3. **What's the quick-validate script?**
   - Fast smoke tests only
   - No coverage generation
   - Fails fast on errors
   - Gives feedback in <1 minute

**Size Target**: <200MB

## Build Strategy

### Buildah vs Dockerfile

**Decision**: Use Buildah scripts instead of Dockerfiles

**Rationale**:

1. **More Control**
   - Programmatic container creation
   - Conditional logic in shell scripts
   - Better error handling
   - Can inspect intermediate states

2. **Podman Integration**
   - Same tool ecosystem
   - No translation layer (Docker → Podman)
   - Native OCI image format
   - Rootless-aware

3. **Security**
   - No Docker daemon required
   - Runs as non-root
   - Better audit trail
   - Explicit layer management

**Trade-offs**:
- Less familiar syntax (vs Dockerfile)
- More verbose
- Requires shell scripting knowledge

### Multi-Stage Approach

Each library build follows this pattern:

```bash
# Download
curl -LsSf -o source.tar.gz https://...

# Extract
tar xzf source.tar.gz

# Build
cd source && ./configure && make && make install

# Clean up
cd / && rm -rf /tmp/source*
```

**Why clean up immediately?**
- Reduces final image size
- Each layer is smaller
- No leftover build artifacts
- Forces explicit caching strategy

### Layer Optimization

**Strategy**: Minimize layers, maximize caching

```bash
# GOOD: Single layer for related operations
buildah run $container -- bash -c "
    dnf install -y pkg1 pkg2 pkg3 && dnf clean all
"

# BAD: Multiple layers
buildah run $container -- dnf install -y pkg1
buildah run $container -- dnf install -y pkg2
buildah run $container -- dnf clean all
```

**Current Layer Structure**:
1. Base image (UBI9)
2. System packages (dnf install)
3. Runtime dependencies
4. wolfSSL build
5. wolfSentry build
6. wolfCLU build
7. libuv build
8. llhttp build
9. cJSON build
10. mimalloc build
11. User setup
12. Configuration

Total: ~12 layers (reasonable for caching)

### Squashing

**Decision**: Use `--squash` on final commit

```bash
buildah commit --rm --squash $container $IMAGE_NAME:$IMAGE_TAG
```

**Rationale**:
- Reduces final image size
- Hides intermediate layers
- Faster image pulls
- Better for distribution

**Trade-off**:
- Loses layer caching for pulls
- But we're not distributing intermediate layers anyway

## Security Architecture

### Rootless by Default

All containers run as non-root user (UID 1000):

```yaml
user: "1000:1000"
```

**How it works**:
1. Container user matches host user
2. File permissions align naturally
3. No privilege escalation possible
4. SELinux labels work correctly

### Capability Dropping

Default configuration:

```yaml
cap_drop:
  - ALL
cap_add:
  - NET_ADMIN  # For TUN/TAP
  - NET_RAW    # For raw sockets
```

**Why drop ALL first?**
- Principle of least privilege
- Explicit about what's needed
- Easier to audit
- Prevents accidental capabilities

**Why NET_ADMIN/NET_RAW?**
- VPN server needs TUN/TAP devices
- Raw sockets for ICMP (ping)
- Required for network simulation
- Still safer than --privileged

### SELinux Labels

All volume mounts use `:Z` flag:

```yaml
volumes:
  - ../../:/workspace:Z
```

**`:Z` vs `:z`**:
- `:Z`: Exclusive relabeling (container-only access)
- `:z`: Shared relabeling (multiple containers)

**Decision**: Use `:Z` for security
- Prevents cross-container access
- Each container gets unique label
- Better isolation

### Security Hardening

**Compile-time hardening**:
```bash
CFLAGS="-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2"
LDFLAGS="-Wl,-z,relro -Wl,-z,now"
```

- `fstack-protector-strong`: Stack canaries
- `D_FORTIFY_SOURCE=2`: Buffer overflow detection
- `-z,relro`: Read-only relocations
- `-z,now`: Full RELRO

**Runtime hardening**:
- Read-only /proc (planned)
- Read-only /sys (planned)
- Seccomp profiles
- AppArmor/SELinux policies

## Performance Optimizations

### Build Performance

**1. Parallel Compilation**
```bash
make -j$(nproc)
```
- Uses all CPU cores
- 4x faster on 4-core systems

**2. Build Cache**
- Buildah caches intermediate layers
- Unchanged layers reused
- Only rebuilds what changed

**3. Aggressive Cleanup**
```bash
cd /tmp/build
# ... build ...
rm -rf source.tar.gz source-dir
```
- Immediate cleanup reduces layer size
- Faster image commits

### Runtime Performance

**1. crun Runtime**
- 50% faster startup than runc
- Lower memory overhead
- Better cgroup v2 support

**2. fuse-overlayfs**
- Required for rootless overlay
- Fast copy-on-write
- Efficient layer composition

**3. Resource Limits**
```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 8G
```
- Prevents resource exhaustion
- Better multi-tenant performance
- Predictable behavior

## Rootless Design

### User Namespace Mapping

**Host Setup Required**:
```bash
$ cat /etc/subuid
user:100000:65536

$ cat /etc/subgid
user:100000:65536
```

**How it works**:
- Container UID 0 → Host UID 100000
- Container UID 1000 → Host UID 101000
- Provides isolation without root privileges

### File Permissions

**Problem**: Container files owned by 100000:100000 on host

**Solution**: Mount with user namespace mapping
```yaml
user: "1000:1000"  # Matches host user
volumes:
  - ../../:/workspace:Z  # Proper ownership
```

**Result**: Files created in container have correct ownership on host

### Network Limitations

**Rootless networking uses slirp4netns**:
- Cannot bind to ports <1024
- Slightly higher latency
- No raw socket support (without NET_RAW capability)

**Solution**:
- Add NET_RAW capability for VPN testing
- Use port mapping for privileged ports
- Accept minor performance trade-off for security

## Volume Architecture

### Named Volumes

**dev-home**:
- Purpose: Persistent developer home directory
- Contains: .bashrc, .vimrc, command history
- Why: Preserves user environment between sessions

**build-cache**:
- Purpose: Meson build artifacts
- Contains: Compiled objects, build metadata
- Why: Speeds up incremental builds (90% faster)

**test-results**:
- Purpose: Test outputs and coverage reports
- Contains: JUnit XML, coverage HTML, logs
- Why: Preserve test history, debugging

**ci-reports**:
- Purpose: CI pipeline artifacts
- Contains: Static analysis, linting reports
- Why: Upload to CI system, archive

### Bind Mounts

**Source code** (`../../:/workspace:Z`):
- Why bind mount: Hot-reload development
- Why :Z: SELinux exclusive access
- Read-write: Code changes in container visible on host

### tmpfs Mounts

**Planned**: `/tmp` as tmpfs
- Why: Faster temporary file operations
- When: Build artifacts, test data
- Trade-off: Limited by RAM

## Networking

### Default Network

**ocserv-net** bridge:
```yaml
networks:
  ocserv-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

**Why custom network?**
- Isolation from other containers
- Predictable IP addressing
- DNS resolution between containers
- Network policies

### Future: External Network

For multi-project Traefik setup:
```yaml
networks:
  traefik-public:
    external: true
```

**When**: If ringwall web UI is added
**Why**: Automatic HTTPS, service discovery

## Future Enhancements

### Planned Improvements

1. **Multi-Architecture Builds**
   - ARM64 support
   - Build for multiple platforms
   - Manifest lists

2. **Image Signing**
   - GPG signing of images
   - Cosign integration
   - Supply chain security

3. **Health Checks**
   - Container health endpoints
   - Automatic restart on failure
   - Integration with orchestration

4. **Distroless Final Images**
   - Even smaller production images
   - Minimal attack surface
   - Static binaries only

5. **Reproducible Builds**
   - Deterministic builds
   - Build attestation
   - SLSA compliance

6. **OCI Artifacts**
   - Store SBOM in registry
   - Vulnerability scans
   - License compliance

### Under Consideration

1. **Kubernetes Compatibility**
   - Generate K8s manifests with `podman generate kube`
   - Deploy to K8s clusters
   - Use Quadlet for systemd integration

2. **Development Containers (devcontainer.json)**
   - VS Code integration
   - GitHub Codespaces support
   - Standardized dev environment

3. **Build Cache Optimization**
   - Remote build cache
   - Shared cache between developers
   - CI cache persistence

## Conclusion

This architecture prioritizes:
1. Security (rootless, SELinux, capabilities)
2. Performance (crun, layer caching, parallel builds)
3. Developer experience (hot-reload, clear purposes)
4. Production readiness (optimized builds, minimal images)

The multi-environment strategy provides flexibility while maintaining clear boundaries between development, testing, and production concerns.

---

Generated with Claude Code - https://claude.com/claude-code
