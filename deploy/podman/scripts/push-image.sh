#!/bin/bash
set -euo pipefail

# push-image.sh - Push container image to registry using Skopeo
# Skopeo provides direct image-to-image copy without requiring Docker daemon
#
# Usage:
#   ./push-image.sh <source-image> <dest-image> [--sign]
#
# Examples:
#   ./push-image.sh localhost/ringwall-dev:latest ghcr.io/dantte-lp/ringwall-dev:latest
#   ./push-image.sh localhost/ringwall-dev:latest ghcr.io/dantte-lp/ringwall-dev:v2.0.0
#   ./push-image.sh localhost/ringwall-dev:latest ghcr.io/dantte-lp/ringwall-dev:latest --sign

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check arguments
if [ $# -lt 2 ]; then
    log_error "Usage: $0 <source-image> <dest-image> [--sign]"
    log_error "Example: $0 localhost/ringwall-dev:latest ghcr.io/dantte-lp/ringwall-dev:latest"
    exit 1
fi

SOURCE_IMAGE="$1"
DEST_IMAGE="$2"
SIGN_IMAGE=false

if [ $# -eq 3 ] && [ "$3" = "--sign" ]; then
    SIGN_IMAGE=true
fi

# Check if source image exists
log_info "Checking if source image exists: $SOURCE_IMAGE"
if ! skopeo inspect "containers-storage:$SOURCE_IMAGE" >/dev/null 2>&1; then
    log_error "Source image not found: $SOURCE_IMAGE"
    log_error "Available images:"
    podman images | grep ioguard || echo "  No ioguard images found"
    exit 1
fi

# Get image information
log_info "Inspecting source image..."
IMAGE_INFO=$(skopeo inspect "containers-storage:$SOURCE_IMAGE")
IMAGE_DIGEST=$(echo "$IMAGE_INFO" | jq -r '.Digest // "unknown"')
IMAGE_SIZE=$(echo "$IMAGE_INFO" | jq -r '.Size // 0')
IMAGE_SIZE_MB=$((IMAGE_SIZE / 1024 / 1024))

log_info "Image details:"
log_info "  Digest: $IMAGE_DIGEST"
log_info "  Size: ${IMAGE_SIZE_MB} MB"

# Extract registry and credentials check
DEST_REGISTRY=$(echo "$DEST_IMAGE" | cut -d'/' -f1)
log_info "Target registry: $DEST_REGISTRY"

# Check if logged in to registry
log_info "Checking authentication to registry..."
if ! skopeo login --get-login "$DEST_REGISTRY" >/dev/null 2>&1; then
    log_warn "Not logged in to $DEST_REGISTRY"
    log_warn "You may need to authenticate. Run:"
    log_warn "  podman login $DEST_REGISTRY"
    log_warn "  or"
    log_warn "  skopeo login $DEST_REGISTRY"

    # Ask if user wants to continue
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Aborted by user"
        exit 1
    fi
fi

# Push image using Skopeo
log_info "Pushing image to registry..."
log_info "  Source: containers-storage:$SOURCE_IMAGE"
log_info "  Destination: docker://$DEST_IMAGE"

SKOPEO_OPTS=(
    --format v2s2                    # Use Docker manifest v2 schema 2
    --override-os linux              # Target OS
    --override-arch amd64            # Target architecture
    --remove-signatures              # Remove old signatures
    --digestfile /tmp/image-digest   # Save digest for verification
)

# Add signing options if requested
if [ "$SIGN_IMAGE" = true ]; then
    log_info "Image signing requested"
    if [ -z "${GPG_KEY_ID:-}" ]; then
        log_warn "GPG_KEY_ID environment variable not set"
        log_warn "Skipping image signing"
    else
        log_info "Signing with GPG key: $GPG_KEY_ID"
        SKOPEO_OPTS+=(--sign-by "$GPG_KEY_ID")
    fi
fi

# Perform the copy/push
if skopeo copy "${SKOPEO_OPTS[@]}" \
    "containers-storage:$SOURCE_IMAGE" \
    "docker://$DEST_IMAGE"; then

    log_info "Image pushed successfully!"

    # Display digest
    if [ -f /tmp/image-digest ]; then
        PUSHED_DIGEST=$(cat /tmp/image-digest)
        log_info "Pushed digest: $PUSHED_DIGEST"
        rm -f /tmp/image-digest
    fi

    # Verify the pushed image
    log_info "Verifying pushed image..."
    REMOTE_INFO=$(skopeo inspect "docker://$DEST_IMAGE")
    REMOTE_DIGEST=$(echo "$REMOTE_INFO" | jq -r '.Digest')
    REMOTE_SIZE=$(echo "$REMOTE_INFO" | jq -r '.Size')
    REMOTE_SIZE_MB=$((REMOTE_SIZE / 1024 / 1024))

    log_info "Remote image details:"
    log_info "  Digest: $REMOTE_DIGEST"
    log_info "  Size: ${REMOTE_SIZE_MB} MB"

    # Verify digest matches
    if [ "$IMAGE_DIGEST" != "unknown" ] && [ "$REMOTE_DIGEST" = "$IMAGE_DIGEST" ]; then
        log_info "${GREEN}✓${NC} Digest verification passed"
    else
        log_warn "Digest verification skipped or failed"
        log_warn "  Local:  $IMAGE_DIGEST"
        log_warn "  Remote: $REMOTE_DIGEST"
    fi

    # Display pull command
    echo ""
    log_info "Image pushed: ${BLUE}$DEST_IMAGE${NC}"
    log_info "Pull command:"
    echo "  podman pull $DEST_IMAGE"
    echo ""

    exit 0
else
    log_error "Failed to push image"
    exit 1
fi
