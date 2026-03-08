# ringwall Podman Container Infrastructure

Production-grade containerized development environment for ringwall using **Podman**, **Buildah**, **Skopeo**, and **crun**.

## Quick Start

```bash
# 1. Build all containers
make build-all

# 2. Start development environment
make dev

# 3. Run tests
make test

# 4. Build release artifacts
make build
```

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Container Environments](#container-environments)
- [Usage](#usage)
- [Makefile Commands](#makefile-commands)
- [Volume Management](#volume-management)
- [Image Registry Operations](#image-registry-operations)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)

## Overview

Four specialized container environments:

| Environment | Purpose | Base | Size Target | Use Case |
|-------------|---------|------|-------------|----------|
| **dev** | Development | UBI9 | <500MB | Interactive development, debugging |
| **test** | Testing | dev | <500MB | Running tests, generating coverage |
| **build** | Build | UBI9-minimal | <200MB | Creating release artifacts |
| **ci** | CI/CD | build | <200MB | Automated testing in pipelines |

### Key Features

- **Rootless by default**: Enhanced security
- **SELinux-compatible**: Proper volume labeling
- **Latest libraries**: wolfSSL 5.8.2 (GPLv3), libuv 1.51.0, llhttp 9.3.0, cJSON 1.7.19, mimalloc 3.1.5
- **Modern build system**: CMake 4.1.2 with C23 support
- **Comprehensive testing**: Unity 2.6.1, CMock 2.6.0, Ceedling 1.0.1
- **Code quality tools**: clang-format, clang-tidy, cppcheck
- **Documentation**: Doxygen 1.15.0 with Graphviz
- **Package management**: vcpkg for C/C++ dependencies
- **crun runtime**: Faster startup
- **Production-ready**: Security hardening, resource limits

## Prerequisites

### Required Software

```bash
# Oracle Linux 10 / RHEL 10
sudo dnf install podman buildah skopeo crun

# Podman Compose
pip3 install podman-compose
```

### Rootless Setup

```bash
# Enable user namespaces
sudo sysctl -w user.max_user_namespaces=28633

# Configure subuid/subgid
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Install dependencies
sudo dnf install fuse-overlayfs slirp4netns container-selinux

# Verify
./scripts/verify-rootless.sh
./scripts/verify-selinux.sh
```

## Installation

```bash
cd /opt/projects/repositories/ringwall/deploy/podman

# Build all containers (8-12 minutes)
make build-all

# Verify
make info
```

## Container Environments

### Development (dev)

**Features**: Full toolchain, debug symbols, modern build and testing tools

**Build System:**
- CMake 4.1.2 (C23 support)
- Make (traditional builds)
- Meson + Ninja (alternative build system)

**Testing Frameworks:**
- Unity 2.6.1 (C unit testing)
- CMock 2.6.0 (mocking framework)
- Ceedling 1.0.1 (test automation)

**Code Quality:**
- clang-format (code formatting)
- clang-tidy (static analysis)
- cppcheck (additional checks)
- valgrind (memory leak detection)
- gdb (debugging)

**Documentation:**
- Doxygen 1.15.0 (API docs)
- Graphviz (diagrams)

**Package Management:**
- vcpkg (C/C++ packages)

```bash
# Start interactive session
make dev

# Inside container - CMake build
cmake -B build -DUSE_WOLFSSL=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build

# Inside container - Traditional Make
make BACKEND=wolfssl
make test-unit BACKEND=wolfssl

# Inside container - Ceedling
ceedling test:all
ceedling gcov:all

# Code quality checks
make -C build format    # Format code
make -C build lint      # Static analysis
make -C build cppcheck  # Additional checks
make -C build doc       # Generate docs
```

### Test (test)

**Features**: Test frameworks, coverage tools, network utilities

```bash
# Run all tests
make test

# Generate coverage
podman-compose run --rm test bash -c "ninja -C build coverage-html"
```

### Build (build)

**Features**: Release-optimized (O3, LTO), packaging tools

```bash
# Build release
make release

# Output: artifacts/ringwall-YYYYMMDD.tar.gz
```

### CI (ci)

**Features**: Lightweight, automated testing, quick validation

```bash
# Full CI pipeline
make ci

# Quick validation
make quick
```

## Usage

### Development Workflow

```bash
# Start dev container
make dev

# Edit code on host (changes visible immediately)
vim ../../src/main.c

# Rebuild in container
ninja -C build
```

### Testing Workflow

```bash
# Run tests with coverage
make full-test

# Run benchmarks
make benchmark

# Valgrind
podman-compose run --rm test bash -c "meson test -C build --wrap='valgrind --leak-check=full'"
```

### Release Workflow

```bash
make release
ls -lh artifacts/
```

## Makefile Commands

### Build

```bash
make build-all       # Build all images
make build-dev       # Development image
make build-test      # Test image
make build-build     # Build image
make build-ci        # CI image
```

### Run

```bash
make dev             # Start development
make test            # Run tests
make build           # Build release
make ci              # Run CI
```

### Shell Access

```bash
make shell-dev       # Interactive dev shell
make shell-test      # Interactive test shell
make shell-build     # Interactive build shell
make shell-ci        # Interactive CI shell
```

### Validation

```bash
make lint            # Code quality checks
make validate        # Quick validation
make verify-rootless # Verify rootless setup
make verify-selinux  # Verify SELinux
```

### Cleanup

```bash
make clean           # Remove containers + build cache
make clean-images    # Remove built images
make clean-all       # Full cleanup (WARNING!)
make prune           # Safe cleanup
```

### Advanced

```bash
make info            # System information
make rebuild-all     # Rebuild from scratch
make quick           # Quick build + test
make full-test       # Full test suite
make benchmark       # Performance tests
```

## Volume Management

### Volumes

- **dev-home**: Developer home (persistent)
- **build-cache**: Meson cache (persistent)
- **test-results**: Test outputs
- **ci-reports**: CI reports

### Backup/Restore

```bash
# Backup
make volumes-backup

# Restore from latest
make volumes-restore

# Restore from specific backup
./scripts/restore-volumes.sh volumes/backups/20251029_143000/
```

## Image Registry Operations

### Push to Registry

```bash
# Login
podman login ghcr.io

# Push all
make push-all

# Push specific image
./scripts/push-image.sh localhost/ringwall-dev:latest ghcr.io/dantte-lp/ringwall-dev:latest
```

### Inspect Images

```bash
# Inspect all
make inspect-all

# Inspect specific
skopeo inspect containers-storage:localhost/ringwall-dev:latest
```

## Troubleshooting

### Permission Denied

```bash
./scripts/verify-rootless.sh
grep "^$USER:" /etc/subuid /etc/subgid
```

### SELinux Denials

```bash
./scripts/verify-selinux.sh
sudo ausearch -m avc -ts recent | grep container
chcon -R -t container_file_t /opt/projects/repositories/ringwall
```

### Build Failures

```bash
make clean
make build-all
df -h
podman system prune -af
```

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for detailed guide.

## Development Tools Reference

### Build Systems

#### CMake 4.1.2
Modern cross-platform build system with full C23 support.

```bash
# Configure with wolfSSL backend
cmake -B build -DUSE_WOLFSSL=ON -DCMAKE_BUILD_TYPE=Debug

# Configure with GnuTLS backend
cmake -B build -DUSE_WOLFSSL=OFF -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build -j$(nproc)

# Run tests
ctest --test-dir build --output-on-failure

# Install
cmake --install build --prefix /usr/local

# Build options
cmake -B build \
  -DUSE_WOLFSSL=ON \
  -DBUILD_TESTING=ON \
  -DBUILD_POC=ON \
  -DENABLE_SANITIZERS=OFF \
  -DENABLE_COVERAGE=OFF \
  -DBUILD_DOCUMENTATION=ON
```

#### Traditional Make
Simple Makefile-based build for quick iterations.

```bash
# Build with GnuTLS (default)
make

# Build with wolfSSL
make BACKEND=wolfssl

# Run unit tests
make test-unit

# Build PoC server/client
make poc

# Debug build
make DEBUG=1

# With sanitizers
make SANITIZE=1
```

### Testing Frameworks

#### Unity 2.6.1
Lightweight C unit testing framework.

```c
// Example test
#include <unity/unity.h>

void setUp(void) { /* setup */ }
void tearDown(void) { /* cleanup */ }

void test_example(void) {
    TEST_ASSERT_EQUAL(42, my_function());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_example);
    return UNITY_END();
}
```

#### CMock 2.6.0
Automatic mock generation for Unity tests.

```bash
# Generate mocks from header file
ruby /usr/local/lib/cmock/cmock.rb my_module.h
```

#### Ceedling 1.0.1
Build automation for Unity/CMock projects.

```bash
# Initialize new test
ceedling module:create[my_module]

# Run all tests
ceedling test:all

# Run specific test
ceedling test:test_tls_gnutls

# Generate coverage report
ceedling gcov:all

# Clean
ceedling clean

# See coverage in build/ceedling/artifacts/gcov/
```

### Code Quality Tools

#### clang-format
Automatic code formatting (configured in `.clang-format`).

```bash
# Format single file
clang-format -i src/crypto/tls_abstract.c

# Format entire project (via CMake)
cmake --build build --target format

# Check format without modifying
clang-format --dry-run --Werror src/crypto/*.c
```

#### clang-tidy
Static analysis and linting (configured in `.clang-tidy`).

```bash
# Analyze single file
clang-tidy src/crypto/tls_abstract.c -- -Isrc/crypto

# Analyze entire project (via CMake)
cmake --build build --target lint

# Fix issues automatically
clang-tidy -fix src/crypto/tls_abstract.c -- -Isrc/crypto
```

#### cppcheck
Additional static analysis.

```bash
# Run cppcheck (via CMake)
cmake --build build --target cppcheck

# Manual run
cppcheck --enable=all --inconclusive --std=c11 \
  -Isrc/crypto src/
```

### Documentation Tools

#### Doxygen 1.15.0
API documentation generator (configured in `Doxyfile`).

```bash
# Generate documentation (via CMake)
cmake --build build --target doc

# Manual generation
doxygen Doxyfile

# Output: docs/api/html/index.html
```

Documentation comments format:
```c
/**
 * @brief Brief description of function
 *
 * Detailed description of what the function does.
 *
 * @param ctx TLS context pointer
 * @param buffer Data buffer
 * @param size Buffer size in bytes
 * @return Number of bytes processed, or -1 on error
 *
 * @note This function is thread-safe
 * @warning Buffer must be at least size bytes
 */
int tls_process_data(tls_ctx_t *ctx, void *buffer, size_t size);
```

#### Graphviz
Generates diagrams for Doxygen documentation.

```bash
# Installed automatically with Doxygen
# Enables call graphs, include graphs, class diagrams
```

### Package Management

#### vcpkg
Cross-platform C/C++ package manager.

```bash
# Search for packages
vcpkg search json

# Install package
vcpkg install cjson

# List installed packages
vcpkg list

# Integrate with CMake
vcpkg integrate install

# Use in CMakeLists.txt
set(CMAKE_TOOLCHAIN_FILE /opt/vcpkg/scripts/buildsystems/vcpkg.cmake)
```

### Debugging and Profiling

#### valgrind
Memory leak detection and profiling.

```bash
# Memory leak check
valgrind --leak-check=full --show-leak-kinds=all \
  ./poc-server

# With test suite
ctest --test-dir build --verbose \
  --overwrite MemoryCheckCommandOptions="--leak-check=full"

# Cache profiling
valgrind --tool=cachegrind ./poc-server
```

#### gdb
GNU debugger.

```bash
# Start debugging
gdb ./poc-server

# Common commands
(gdb) break tls_init
(gdb) run
(gdb) backtrace
(gdb) print variable
(gdb) step
(gdb) continue
```

#### strace
System call tracer.

```bash
# Trace system calls
strace -o trace.log ./poc-server

# Trace specific calls
strace -e trace=network ./poc-server

# Attach to running process
strace -p <pid>
```

### Development Workflow Examples

#### Full Development Cycle

```bash
# 1. Start development container
make -C deploy/podman dev

# 2. Configure build with CMake
cmake -B build -DUSE_WOLFSSL=ON -DBUILD_TESTING=ON

# 3. Write code and tests
vim src/crypto/new_feature.c
vim tests/unit/test_new_feature.c

# 4. Format code
cmake --build build --target format

# 5. Build
cmake --build build -j$(nproc)

# 6. Run static analysis
cmake --build build --target lint

# 7. Run tests
ctest --test-dir build --output-on-failure

# 8. Check memory leaks
valgrind --leak-check=full build/test_new_feature

# 9. Generate documentation
cmake --build build --target doc

# 10. Generate coverage report
ceedling gcov:all
```

#### Quick Iteration

```bash
# Format, build, test in one command
cmake --build build --target format && \
cmake --build build -j$(nproc) && \
ctest --test-dir build --output-on-failure
```

#### Code Review Preparation

```bash
# 1. Format all code
cmake --build build --target format

# 2. Run all static analysis
cmake --build build --target lint
cmake --build build --target cppcheck

# 3. Run full test suite
ctest --test-dir build --output-on-failure

# 4. Generate coverage report
ceedling gcov:all

# 5. Generate documentation
cmake --build build --target doc

# 6. Check for memory leaks
make test-unit BACKEND=wolfssl | tee test-output.log
```

### Tool Version Verification

```bash
# Verify all tools are installed correctly
podman run --rm localhost/ringwall-dev:latest bash -c "
  echo '=== Build Tools ===' &&
  cmake --version | head -1 &&
  gcc --version | head -1 &&
  make --version | head -1 &&
  echo '' &&
  echo '=== Testing Tools ===' &&
  ruby -e 'require \"ceedling\"; puts \"Ceedling: #{Ceedling::Version::CEEDLING}\"' &&
  echo 'Unity: 2.6.1 (header-only)' &&
  echo 'CMock: 2.6.0 (header-only)' &&
  echo '' &&
  echo '=== Code Quality ===' &&
  clang-format --version &&
  clang-tidy --version | head -1 &&
  cppcheck --version &&
  echo '' &&
  echo '=== Documentation ===' &&
  doxygen --version &&
  dot -V &&
  echo '' &&
  echo '=== Debugging ===' &&
  valgrind --version | head -1 &&
  gdb --version | head -1 &&
  strace --version | head -1 &&
  echo '' &&
  echo '=== Package Management ===' &&
  vcpkg --version
"
```

## Documentation

- [CONTAINER_ARCHITECTURE.md](docs/CONTAINER_ARCHITECTURE.md) - Design and architecture
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common issues
- [Configuration Files](config/) - Runtime configuration
- [CMakeLists.txt](../../CMakeLists.txt) - CMake build configuration
- [project.yml](../../project.yml) - Ceedling test configuration
- [Doxyfile](../../Doxyfile) - Doxygen documentation config
- [.clang-format](../../.clang-format) - Code formatting rules
- [.clang-tidy](../../.clang-tidy) - Static analysis rules

## License Notice

**IMPORTANT**: wolfSSL v5.8.2 uses GPLv3 license (changed from GPLv2).
Verify compatibility before distribution.

---

Generated with Claude Code - https://claude.com/claude-code
