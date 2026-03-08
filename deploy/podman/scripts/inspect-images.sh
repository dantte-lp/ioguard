#!/bin/bash
set -euo pipefail

# inspect-images.sh - Inspect all ringwall images using Skopeo
# Provides detailed information about built images

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}$*${NC}"
    echo -e "${BLUE}======================================${NC}"
}

# Images to inspect
IMAGES=(
    "localhost/ringwall-dev:latest"
    "localhost/ringwall-test:latest"
    "localhost/ringwall-build:latest"
    "localhost/ringwall-ci:latest"
)

log_section "Inspecting ringwall Container Images"

for IMAGE in "${IMAGES[@]}"; do
    log_section "Image: $IMAGE"

    if ! skopeo inspect "containers-storage:$IMAGE" >/dev/null 2>&1; then
        echo -e "${YELLOW}[SKIP]${NC} Image not found: $IMAGE"
        continue
    fi

    # Get full image information
    IMAGE_INFO=$(skopeo inspect "containers-storage:$IMAGE")

    # Extract and display key information
    echo "Basic Information:"
    echo "  Name:         $(echo "$IMAGE_INFO" | jq -r '.Name // "unknown"')"
    echo "  Digest:       $(echo "$IMAGE_INFO" | jq -r '.Digest // "unknown"')"
    echo "  Created:      $(echo "$IMAGE_INFO" | jq -r '.Created // "unknown"')"

    # Size information
    SIZE=$(echo "$IMAGE_INFO" | jq -r '.Size // 0')
    SIZE_MB=$((SIZE / 1024 / 1024))
    echo "  Size:         ${SIZE_MB} MB"

    # Architecture
    echo ""
    echo "Platform:"
    echo "  OS:           $(echo "$IMAGE_INFO" | jq -r '.Os // "unknown"')"
    echo "  Architecture: $(echo "$IMAGE_INFO" | jq -r '.Architecture // "unknown"')"

    # Labels
    echo ""
    echo "Labels:"
    echo "$IMAGE_INFO" | jq -r '.Labels // {} | to_entries[] | "  \(.key): \(.value)"' | head -10

    # Layers
    LAYER_COUNT=$(echo "$IMAGE_INFO" | jq -r '.Layers // [] | length')
    echo ""
    echo "Layers: $LAYER_COUNT"

    # Environment variables
    echo ""
    echo "Environment Variables:"
    echo "$IMAGE_INFO" | jq -r '.Env // [] | .[]' | head -5
    if [ "$(echo "$IMAGE_INFO" | jq -r '.Env // [] | length')" -gt 5 ]; then
        echo "  ... (truncated)"
    fi

    # Entrypoint and Command
    echo ""
    echo "Execution:"
    echo "  Entrypoint:   $(echo "$IMAGE_INFO" | jq -r '.Config.Entrypoint // [] | join(" ") // "none"')"
    echo "  Cmd:          $(echo "$IMAGE_INFO" | jq -r '.Config.Cmd // [] | join(" ") // "none"')"
    echo "  WorkingDir:   $(echo "$IMAGE_INFO" | jq -r '.Config.WorkingDir // "/"')"
    echo "  User:         $(echo "$IMAGE_INFO" | jq -r '.Config.User // "root"')"

done

log_section "Summary"

# Total size of all images
TOTAL_SIZE=0
for IMAGE in "${IMAGES[@]}"; do
    if skopeo inspect "containers-storage:$IMAGE" >/dev/null 2>&1; then
        SIZE=$(skopeo inspect "containers-storage:$IMAGE" | jq -r '.Size // 0')
        TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
    fi
done

TOTAL_SIZE_MB=$((TOTAL_SIZE / 1024 / 1024))
echo "Total size of all images: ${TOTAL_SIZE_MB} MB"

log_info "Inspection complete"
