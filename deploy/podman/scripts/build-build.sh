#!/bin/bash
set -euo pipefail

# build-build.sh - Build Container Build Script
# Creates a release-optimized build environment for producing production artifacts
# for ringwall

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
IMAGE_NAME="${IMAGE_NAME:-localhost/ringwall-build}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Library versions (verified 2025-10-29)
WOLFSSL_VERSION="${WOLFSSL_VERSION:-v5.8.2}"
WOLFSENTRY_VERSION="${WOLFSENTRY_VERSION:-v1.6.3}"
WOLFCLU_VERSION="${WOLFCLU_VERSION:-v0.1.8}"
LIBUV_VERSION="${LIBUV_VERSION:-v1.51.0}"
LLHTTP_VERSION="${LLHTTP_VERSION:-v9.3.0}"
CJSON_VERSION="${CJSON_VERSION:-v1.7.18}"
MIMALLOC_VERSION="${MIMALLOC_VERSION:-v2.2.4}"

# Base image - use minimal base
BASE_IMAGE="${BASE_IMAGE:-registry.access.redhat.com/ubi9/ubi-minimal:latest}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

trap 'cleanup_on_error "${container:-}"' ERR

log_info "Starting build container build"
log_info "Base image: $BASE_IMAGE"
log_info "Target: $IMAGE_NAME:$IMAGE_TAG"

# Create container from base image
log_info "Creating container from base image..."
container=$(buildah from "$BASE_IMAGE")

# Configure container metadata
buildah config \
    --label "io.ringwall.version=2.0.0-alpha.1" \
    --label "io.ringwall.environment=build" \
    --label "io.buildah.version=1.0" \
    --label "org.opencontainers.image.created=$BUILD_DATE" \
    --label "org.opencontainers.image.title=ringwall-build" \
    --label "org.opencontainers.image.description=Build environment for ringwall release artifacts" \
    --label "org.opencontainers.image.version=2.0.0-alpha.1" \
    --label "org.opencontainers.image.licenses=GPLv2" \
    "$container"

# Install minimal build tools using microdnf
log_info "Installing minimal build tools..."
buildah run "$container" -- bash -c "microdnf install -y \
    gcc \
    gcc-c++ \
    make \
    cmake \
    meson \
    ninja-build \
    autoconf \
    automake \
    libtool \
    pkgconfig \
    git \
    wget \
    curl \
    tar \
    xz \
    bzip2 \
    && microdnf clean all"

# Install runtime dependencies
log_info "Installing runtime dependencies..."
buildah run "$container" -- bash -c "microdnf install -y \
    pam-devel \
    libseccomp-devel \
    readline-devel \
    lz4-devel \
    libnl3-devel \
    krb5-devel \
    libev-devel \
    protobuf-c-devel \
    json-c-devel \
    pcre2-devel \
    libcap-ng-devel \
    tcp_wrappers-devel \
    systemd-devel \
    http-parser-devel \
    libtalloc-devel \
    libradcli-devel \
    oath-toolkit-devel \
    gperf \
    && microdnf clean all"

# Install packaging tools
log_info "Installing packaging tools..."
buildah run "$container" -- bash -c "microdnf install -y \
    rpm-build \
    rpmdevtools \
    rpmlint \
    createrepo_c \
    && microdnf clean all"

# Create build directory
buildah run "$container" -- mkdir -p /tmp/build

# Build and install wolfSSL v5.8.2 (RELEASE optimized)
log_info "Building wolfSSL ${WOLFSSL_VERSION} (release-optimized)..."
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
        --disable-debug \
        --prefix=/usr/local \
        CFLAGS='-std=c23 -O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        LDFLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf wolfssl-${WOLFSSL_VERSION#v} wolfssl.tar.gz
"

# Build and install wolfSentry v1.6.3 (RELEASE)
log_info "Building wolfSentry ${WOLFSENTRY_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o wolfsentry.tar.gz https://github.com/wolfSSL/wolfsentry/archive/refs/tags/${WOLFSENTRY_VERSION}.tar.gz
    tar xzf wolfsentry.tar.gz
    cd wolfsentry-${WOLFSENTRY_VERSION#v}
    make -j\$(nproc) \
        EXTRA_CFLAGS='-std=c23 -O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        EXTRA_LDFLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make install
    ldconfig
    cd /tmp/build
    rm -rf wolfsentry-${WOLFSENTRY_VERSION#v} wolfsentry.tar.gz
"

# Build and install wolfCLU v0.1.8 (RELEASE)
log_info "Building wolfCLU ${WOLFCLU_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o wolfclu.tar.gz https://github.com/wolfSSL/wolfCLU/archive/refs/tags/${WOLFCLU_VERSION}.tar.gz
    tar xzf wolfclu.tar.gz
    cd wolfCLU-${WOLFCLU_VERSION#v}
    ./autogen.sh
    ./configure --prefix=/usr/local CFLAGS='-std=c23 -O3 -flto' LDFLAGS='-flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf wolfCLU-${WOLFCLU_VERSION#v} wolfclu.tar.gz
"

# Build and install libuv v1.51.0 (RELEASE)
log_info "Building libuv ${LIBUV_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o libuv.tar.gz https://github.com/libuv/libuv/archive/refs/tags/${LIBUV_VERSION}.tar.gz
    tar xzf libuv.tar.gz
    cd libuv-${LIBUV_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_TESTING=OFF \
        -DCMAKE_C_FLAGS='-O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf libuv-${LIBUV_VERSION#v} libuv.tar.gz
"

# Build and install llhttp v9.3.0 (RELEASE)
log_info "Building llhttp ${LLHTTP_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o llhttp.tar.gz https://github.com/nodejs/llhttp/archive/refs/tags/release/${LLHTTP_VERSION}.tar.gz
    tar xzf llhttp.tar.gz
    cd llhttp-release-${LLHTTP_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=ON \
        -DCMAKE_C_FLAGS='-O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf llhttp-release-${LLHTTP_VERSION#v} llhttp.tar.gz
"

# Build and install cJSON v1.7.18 (RELEASE)
log_info "Building cJSON ${CJSON_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o cjson.tar.gz https://github.com/DaveGamble/cJSON/archive/refs/tags/${CJSON_VERSION}.tar.gz
    tar xzf cjson.tar.gz
    cd cJSON-${CJSON_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_CJSON_TEST=OFF \
        -DENABLE_CJSON_UTILS=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_SHARED_AND_STATIC_LIBS=ON \
        -DCMAKE_C_FLAGS='-O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf cJSON-${CJSON_VERSION#v} cjson.tar.gz
"

# Build and install mimalloc v2.2.4 (RELEASE)
log_info "Building mimalloc ${MIMALLOC_VERSION} (release-optimized)..."
buildah run "$container" -- bash -c "
    set -euo pipefail
    cd /tmp/build
    curl -LsSf -o mimalloc.tar.gz https://github.com/microsoft/mimalloc/archive/refs/tags/${MIMALLOC_VERSION}.tar.gz
    tar xzf mimalloc.tar.gz
    cd mimalloc-${MIMALLOC_VERSION#v}
    mkdir build && cd build
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DMI_BUILD_TESTS=OFF \
        -DMI_BUILD_SHARED=ON \
        -DMI_BUILD_STATIC=ON \
        -DCMAKE_C_FLAGS='-O3 -march=x86-64 -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -flto' \
        -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro -Wl,-z,now -flto'
    make -j\$(nproc)
    make install
    ldconfig
    cd /tmp/build
    rm -rf mimalloc-${MIMALLOC_VERSION#v} mimalloc.tar.gz
"

# Install linenoise
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

# Create builder user
log_info "Creating builder user..."
buildah run "$container" -- bash -c "
    useradd -m -s /bin/bash -u 1000 -U builder
    mkdir -p /workspace /artifacts
    chown builder:builder /workspace /artifacts
"

# Install build script
log_info "Installing build script..."
buildah run "$container" -- bash -c "
    cat > /usr/local/bin/build-release << 'EOF'
#!/bin/bash
set -euo pipefail

# Release build script for ringwall
WORKSPACE=\${WORKSPACE:-/workspace}
ARTIFACTS=\${ARTIFACTS:-/artifacts}

echo '================================================'
echo 'ringwall Release Build'
echo '================================================'

cd \$WORKSPACE

# Configure release build
echo 'Configuring release build...'
meson setup build \
    --buildtype=release \
    --strip \
    --werror \
    -Db_lto=true \
    -Db_pie=true \
    -Db_ndebug=true

# Build
echo 'Building...'
meson compile -C build

# Create artifacts
echo 'Creating artifacts...'
mkdir -p \$ARTIFACTS/bin
mkdir -p \$ARTIFACTS/lib
mkdir -p \$ARTIFACTS/share

# Copy binaries
if [ -d build/src ]; then
    find build/src -type f -executable -exec cp {} \$ARTIFACTS/bin/ \\;
fi

# Copy libraries
if [ -d build/src ]; then
    find build/src -name '*.so*' -exec cp {} \$ARTIFACTS/lib/ \\;
fi

# Create tarball
echo 'Creating tarball...'
cd \$ARTIFACTS
tar czf ringwall-\$(date +%Y%m%d).tar.gz bin/ lib/ share/

echo '================================================'
echo 'Build completed successfully!'
echo 'Artifacts: '\$ARTIFACTS
echo '================================================'
ls -lh \$ARTIFACTS/*.tar.gz
EOF
    chmod +x /usr/local/bin/build-release
"

# Set environment variables
buildah config \
    --env PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig \
    --env LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64 \
    "$container"

# Set default user, working directory, and command
buildah config \
    --user builder \
    --workingdir /workspace \
    --cmd /usr/local/bin/build-release \
    "$container"

# Commit the container to an image
log_info "Committing container to image: $IMAGE_NAME:$IMAGE_TAG"
buildah commit --rm --squash "$container" "$IMAGE_NAME:$IMAGE_TAG"

log_info "Build container build completed successfully!"
log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
log_info ""
log_info "To build release artifacts:"
log_info "  podman run -it --rm -v /opt/projects/repositories/ringwall:/workspace:Z -v ./artifacts:/artifacts:Z $IMAGE_NAME:$IMAGE_TAG"
