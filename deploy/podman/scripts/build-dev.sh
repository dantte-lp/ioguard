#!/bin/bash
set -euo pipefail

# build-dev.sh - Development Container Build Script
# Creates a full development environment with debug symbols and development tools
# for ringwall with wolfSSL and modern C libraries

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
IMAGE_NAME="${IMAGE_NAME:-localhost/ringwall-dev}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Library versions (verified and updated 2025-10-29)
CMAKE_VERSION="${CMAKE_VERSION:-4.1.2}"
DOXYGEN_VERSION="${DOXYGEN_VERSION:-1.15.0}"
UNITY_VERSION="${UNITY_VERSION:-2.6.1}"
CMOCK_VERSION="${CMOCK_VERSION:-2.6.0}"
CEEDLING_VERSION="${CEEDLING_VERSION:-1.0.1}"
WOLFSSL_VERSION="${WOLFSSL_VERSION:-v5.8.2-stable}"
WOLFSENTRY_VERSION="${WOLFSENTRY_VERSION:-v1.6.3}"
WOLFCLU_VERSION="${WOLFCLU_VERSION:-v0.1.8}"
LIBUV_VERSION="${LIBUV_VERSION:-v1.51.0}"  # Updated: 1.48.0 → 1.51.0
LLHTTP_VERSION="${LLHTTP_VERSION:-v9.3.0}"
CJSON_VERSION="${CJSON_VERSION:-v1.7.19}"  # Updated: v1.7.18 → v1.7.19
MIMALLOC_VERSION="${MIMALLOC_VERSION:-v3.1.5}"  # Updated: v2.2.4 → v3.1.5 (breaking changes!)

# Base image
BASE_IMAGE="${BASE_IMAGE:-oraclelinux:10}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

cleanup_on_error() {
    local container_id=$1
    if [ -n "$container_id" ]; then
        log_warn "Cleaning up container: $container_id"
        buildah rm "$container_id" 2>/dev/null || true
    fi
}

# Trap errors
trap 'cleanup_on_error "${container:-}"' ERR

log_info "Starting development container build"
log_info "Base image: $BASE_IMAGE"
log_info "Target: $IMAGE_NAME:$IMAGE_TAG"
log_warn "IMPORTANT: wolfSSL ${WOLFSSL_VERSION} uses GPLv3 license (changed from GPLv2)"

# Create container from base image
log_info "Creating container from base image..."
container=$(buildah from "$BASE_IMAGE")

# Configure container metadata
buildah config \
    --label "io.ringwall.version=2.0.0-alpha.1" \
    --label "io.ringwall.environment=development" \
    --label "io.buildah.version=1.0" \
    --label "org.opencontainers.image.created=$BUILD_DATE" \
    --label "org.opencontainers.image.title=ringwall-dev" \
    --label "org.opencontainers.image.description=Development environment for ringwall" \
    --label "org.opencontainers.image.version=2.0.0-alpha.1" \
    --label "org.opencontainers.image.licenses=GPLv2" \
    "$container"

# Enable Oracle Linux 10 repositories
log_info "Enabling Oracle Linux 10 repositories..."
buildah run "$container" -- bash -c "
    dnf config-manager --set-enabled ol10_addons
    dnf config-manager --set-enabled ol10_appstream
    dnf config-manager --set-enabled ol10_codeready_builder
    dnf config-manager --set-enabled ol10_distro_builder
"

# Install EPEL repository for additional packages
log_info "Installing EPEL repository..."
buildah run "$container" -- bash -c "
    dnf install -y oracle-epel-release-el10
    dnf update -y --allowerasing
    dnf clean all
"

# Install base development tools
log_info "Installing base development tools..."
buildah run "$container" -- bash -c "dnf install -y --allowerasing \
    gcc \
    gcc-c++ \
    make \
    cmake \
    meson \
    ninja-build \
    autoconf \
    automake \
    libtool \
    pkgconf \
    git \
    vim \
    nano \
    gdb \
    valgrind \
    strace \
    wget \
    curl \
    tar \
    xz \
    bzip2 \
    patch \
    diffutils \
    && dnf clean all"

# Install runtime dependencies
log_info "Installing runtime dependencies..."
buildah run "$container" -- bash -c "dnf install -y \
    pam-devel \
    libseccomp-devel \
    readline-devel \
    lz4-devel \
    libnl3-devel \
    krb5-devel \
    libev-devel \
    protobuf-c-devel \
    json-c-devel \
    check-devel \
    pcre2-devel \
    libcap-ng-devel \
    systemd-devel \
    libtalloc-devel \
    radcli-devel \
    liboath-devel \
    gperf \
    && dnf clean all"

# Install documentation and code quality tools
log_info "Installing documentation and quality tools..."
buildah run "$container" -- bash -c "dnf install -y \
    doxygen \
    graphviz \
    cppcheck \
    clang-tools-extra \
    gcovr \
    && dnf clean all"

# Create build directory
buildah run "$container" -- mkdir -p /tmp/build

# Build and install wolfSSL v5.8.2 (GPLv3!)
log_info "Building wolfSSL ${WOLFSSL_VERSION} from source..."
log_warn "Note: wolfSSL ${WOLFSSL_VERSION} is licensed under GPLv3 (changed from GPLv2)"
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o wolfssl.tar.gz https://github.com/wolfSSL/wolfssl/archive/refs/tags/${WOLFSSL_VERSION}.tar.gz
    tar xzf wolfssl.tar.gz
    cd wolfssl-${WOLFSSL_VERSION#v}
    ./autogen.sh
    ./configure \
        --enable-tls13 \
        --enable-dtls \
        --enable-dtls13 \
        --enable-session-ticket \
        --enable-alpn \
        --enable-sni \
        --enable-secure-renegotiation \
        --enable-extended-master \
        --enable-ocsp \
        --enable-crl \
        --enable-aesni \
        --enable-intelasm \
        --disable-oldtls \
        --enable-harden \
        --enable-sp \
        --disable-sp-asm \
        --enable-opensslextra \
        --enable-opensslall \
        --enable-curve25519 \
        --enable-ed25519 \
        --enable-sha3 \
        --enable-shake256 \
        --enable-postauth \
        --enable-hrrcookie \
        --enable-quic \
        --enable-debug \
        --prefix=/usr/local \
        CFLAGS='-std=c23 -g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
        LDFLAGS='-Wl,-z,relro -Wl,-z,now'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf wolfssl-${WOLFSSL_VERSION#v} wolfssl.tar.gz
"
#
## Build and install wolfSentry v1.6.3
#log_info "Building wolfSentry ${WOLFSENTRY_VERSION} from source..."
#buildah run "$container" -- bash -c "
#    set -euo pipefail
#    cd /tmp/build
#    curl -LsSf -o wolfsentry.tar.gz https://github.com/wolfSSL/wolfsentry/archive/refs/tags/${WOLFSENTRY_VERSION}.tar.gz
#    tar xzf wolfsentry.tar.gz
#    cd wolfsentry-${WOLFSENTRY_VERSION#v}
#    make -j\$(nproc) \
#        EXTRA_CFLAGS='-std=c23 -g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
#        EXTRA_LDFLAGS='-Wl,-z,relro -Wl,-z,now'
#    make install
#    ldconfig
#    cd /tmp/build
#    rm -rf wolfsentry-${WOLFSENTRY_VERSION#v} wolfsentry.tar.gz
#"
#
## Build and install wolfCLU v0.1.8
#log_info "Building wolfCLU ${WOLFCLU_VERSION} from source..."
#buildah run "$container" -- bash -c "
#    set -euo pipefail
#    cd /tmp/build
#    curl -LsSf -o wolfclu.tar.gz https://github.com/wolfSSL/wolfCLU/archive/refs/tags/${WOLFCLU_VERSION}.tar.gz
#    tar xzf wolfclu.tar.gz
#    cd wolfCLU-${WOLFCLU_VERSION#v}
#    ./autogen.sh
#    ./configure --prefix=/usr/local
#    make -j\$(nproc)
#    make install
#    ldconfig
#    cd /tmp/build
#    rm -rf wolfCLU-${WOLFCLU_VERSION#v} wolfclu.tar.gz
#"

# Build and install Unity v2.6.1
log_info "Installing Unity testing framework ${UNITY_VERSION}..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o unity.tar.gz https://github.com/ThrowTheSwitch/Unity/archive/refs/tags/v${UNITY_VERSION}.tar.gz
    tar xzf unity.tar.gz
    cd Unity-${UNITY_VERSION}
    mkdir -p /usr/local/include/unity
    mkdir -p /usr/local/src/unity
    cp src/unity.h src/unity_internals.h /usr/local/include/unity/
    cp src/unity.c /usr/local/src/unity/
    cp -r extras /usr/local/src/unity/
    cd /tmp/build
    rm -rf Unity-${UNITY_VERSION} unity.tar.gz
"

# Build and install CMock v2.6.0
log_info "Installing CMock ${CMOCK_VERSION}..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o cmock.tar.gz https://github.com/ThrowTheSwitch/CMock/archive/refs/tags/v${CMOCK_VERSION}.tar.gz
    tar xzf cmock.tar.gz
    cd CMock-${CMOCK_VERSION}
    mkdir -p /usr/local/lib/cmock /usr/local/src/cmock
    cp -r lib/* /usr/local/lib/cmock/
    cp -r src/* /usr/local/src/cmock/
    cd /tmp/build
    rm -rf CMock-${CMOCK_VERSION} cmock.tar.gz
"

# Build and install libuv v1.51.0
log_info "Building libuv ${LIBUV_VERSION} from source..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o libuv.tar.gz https://github.com/libuv/libuv/archive/refs/tags/${LIBUV_VERSION}.tar.gz
    tar xzf libuv.tar.gz
    cd libuv-${LIBUV_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_TESTING=ON \
        -DCMAKE_C_FLAGS='-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf libuv-${LIBUV_VERSION#v} libuv.tar.gz
"

## Build and install llhttp v9.3.0
#log_info "Building llhttp ${LLHTTP_VERSION} from source..."
#buildah run "$container" -- bash -c "
#    set -euo pipefail
#    cd /tmp/build
#    curl -LsSf -o llhttp.tar.gz https://github.com/nodejs/llhttp/archive/refs/tags/release/${LLHTTP_VERSION}.tar.gz
#    tar xzf llhttp.tar.gz
#    cd llhttp-release-${LLHTTP_VERSION}
#    mkdir build && cd build
#    cmake .. \
#        -DCMAKE_BUILD_TYPE=Debug \
#        -DCMAKE_INSTALL_PREFIX=/usr/local \
#        -DBUILD_SHARED_LIBS=ON \
#        -DBUILD_STATIC_LIBS=ON \
#        -DCMAKE_C_FLAGS='-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
#        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now'
#    make -j\$(nproc)
#    make install
#    ldconfig
#    cd /tmp/build
#    rm -rf llhttp-release-${LLHTTP_VERSION} llhttp.tar.gz
#"

# Build and install cJSON v1.7.18 (not v1.7.19 due to potential issues)
log_info "Building cJSON ${CJSON_VERSION} from source..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o cjson.tar.gz https://github.com/DaveGamble/cJSON/archive/refs/tags/${CJSON_VERSION}.tar.gz
    tar xzf cjson.tar.gz
    cd cJSON-${CJSON_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_CJSON_TEST=ON \
        -DENABLE_CJSON_UTILS=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_SHARED_AND_STATIC_LIBS=ON \
        -DCMAKE_C_FLAGS='-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf cJSON-${CJSON_VERSION#v} cjson.tar.gz
"

# Build and install mimalloc v2.2.4 (stable release)
log_info "Building mimalloc ${MIMALLOC_VERSION} from source..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o mimalloc.tar.gz https://github.com/microsoft/mimalloc/archive/refs/tags/${MIMALLOC_VERSION}.tar.gz
    tar xzf mimalloc.tar.gz
    cd mimalloc-${MIMALLOC_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DMI_BUILD_TESTS=ON \
        -DMI_BUILD_SHARED=ON \
        -DMI_BUILD_STATIC=ON \
        -DCMAKE_C_FLAGS='-g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf mimalloc-${MIMALLOC_VERSION#v} mimalloc.tar.gz
"

# Install linenoise (header-only library)
log_info "Installing linenoise..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    git clone --depth 1 https://github.com/antirez/linenoise.git
    mkdir -p /usr/local/include/linenoise
    cp linenoise/linenoise.h /usr/local/include/linenoise/
    cp linenoise/linenoise.c /usr/local/include/linenoise/
    rm -rf linenoise
"

# Clean up build directory
log_info "Cleaning up build directory..."
buildah run "$container" -- rm -rf /tmp/build

# Create non-root developer user
log_info "Creating developer user..."
buildah run "$container" -- bash -c "
    useradd -m -s /bin/bash -u 1000 -U developer
    mkdir -p /etc/sudoers.d
    echo 'developer ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/developer
    chmod 0440 /etc/sudoers.d/developer
"

# Create workspace directory with proper permissions
log_info "Creating workspace directory..."
buildah run "$container" -- bash -c "
    mkdir -p /workspace
    chown developer:developer /workspace
"

# Install developer environment configuration
log_info "Installing developer environment configuration..."
buildah run "$container" -- bash -c "
    cat > /home/developer/.bashrc << 'EOF'
# Developer environment for ringwall

# Environment variables
export PS1='\\[\\033[01;32m\\]\\u@ocserv-dev\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '
export EDITOR=vim
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:\$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64:\$LD_LIBRARY_PATH
export CFLAGS='-std=c23 -g -O2 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2'
export LDFLAGS='-Wl,-z,relro -Wl,-z,now'

# Aliases
alias ll='ls -lah --color=auto'
alias grep='grep --color=auto'
alias meson-dev='meson setup build --buildtype=debug --werror'
alias meson-release='meson setup build --buildtype=release --werror'
alias meson-test='meson test -C build --verbose'
alias meson-coverage='ninja -C build coverage-html'

# Welcome message
echo '================================================'
echo 'ringwall Development Environment'
echo '================================================'
echo 'Library versions:'
echo '  wolfSSL:     ${WOLFSSL_VERSION} (GPLv3 - LICENSE CHANGE!)'
echo '  wolfSentry:  ${WOLFSENTRY_VERSION}'
echo '  wolfCLU:     ${WOLFCLU_VERSION}'
echo '  libuv:       ${LIBUV_VERSION}'
echo '  llhttp:      ${LLHTTP_VERSION}'
echo '  cJSON:       ${CJSON_VERSION}'
echo '  mimalloc:    ${MIMALLOC_VERSION}'
echo ''
echo 'Quick commands:'
echo '  meson-dev      - Configure debug build'
echo '  meson-release  - Configure release build'
echo '  meson-test     - Run tests'
echo '  meson-coverage - Generate coverage report'
echo ''
echo 'Workspace: /workspace'
echo '================================================'
EOF
    chown developer:developer /home/developer/.bashrc
"

# Set environment variables
buildah config \
    --env PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig \
    --env LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64 \
    --env WOLFSSL_VERSION="${WOLFSSL_VERSION}" \
    --env WOLFSENTRY_VERSION="${WOLFSENTRY_VERSION}" \
    --env WOLFCLU_VERSION="${WOLFCLU_VERSION}" \
    --env LIBUV_VERSION="${LIBUV_VERSION}" \
    --env LLHTTP_VERSION="${LLHTTP_VERSION}" \
    --env CJSON_VERSION="${CJSON_VERSION}" \
    --env MIMALLOC_VERSION="${MIMALLOC_VERSION}" \
    "$container"

# Set default user, working directory, and command
buildah config \
    --user developer \
    --workingdir /workspace \
    --cmd /bin/bash \
    "$container"

# Commit the container to an image
log_info "Committing container to image: $IMAGE_NAME:$IMAGE_TAG"
buildah commit --rm --squash "$container" "$IMAGE_NAME:$IMAGE_TAG"

log_info "Development container build completed successfully!"
log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_warn "IMPORTANT LICENSE NOTICE:"
log_warn "  wolfSSL ${WOLFSSL_VERSION} changed license from GPLv2 to GPLv3"
log_warn "  Verify compatibility with ringwall GPLv2 license before distribution"
log_info ""
log_info "To run the container:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ringwall:/workspace:Z $IMAGE_NAME:$IMAGE_TAG"
