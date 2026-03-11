#!/bin/bash
set -euo pipefail

# backup-volumes.sh - Backup all named volumes for ioguard
# Creates compressed archives of volume data for disaster recovery
#
# Usage:
#   ./backup-volumes.sh [backup-directory]
#
# Default backup directory: ./volumes/backups

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

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${1:-${SCRIPT_DIR}/../volumes/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_SUBDIR="${BACKUP_DIR}/${TIMESTAMP}"

# Volumes to backup
VOLUMES=(
    "ioguard_dev-home"
    "ioguard_build-cache"
    "ioguard_test-results"
    "ioguard_ci-reports"
)

log_info "Starting volume backup"
log_info "Backup directory: $BACKUP_SUBDIR"
log_info "Timestamp: $TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_SUBDIR"

# Function to backup a single volume
backup_volume() {
    local volume_name=$1
    local backup_file="${BACKUP_SUBDIR}/${volume_name}.tar.gz"

    log_info "Backing up volume: $volume_name"

    # Check if volume exists
    if ! podman volume exists "$volume_name" 2>/dev/null; then
        log_warn "Volume not found: $volume_name (skipping)"
        return 0
    fi

    # Get volume mountpoint
    VOLUME_PATH=$(podman volume inspect "$volume_name" --format '{{.Mountpoint}}')

    if [ -z "$VOLUME_PATH" ]; then
        log_error "Failed to get mountpoint for volume: $volume_name"
        return 1
    fi

    log_info "  Volume path: $VOLUME_PATH"

    # Create backup using tar
    # Run as root if needed for permission issues
    if [ -r "$VOLUME_PATH" ]; then
        # Can read directory directly
        tar czf "$backup_file" -C "$VOLUME_PATH" . 2>/dev/null || {
            log_error "Failed to backup volume: $volume_name"
            return 1
        }
    else
        # Need to use podman run with volume mount
        log_info "  Using container to backup (permission workaround)"
        podman run --rm \
            -v "$volume_name":/volume:Z \
            -v "$BACKUP_SUBDIR":/backup:Z \
            registry.access.redhat.com/ubi9/ubi-minimal:latest \
            tar czf "/backup/${volume_name}.tar.gz" -C /volume . 2>/dev/null || {
            log_error "Failed to backup volume: $volume_name"
            return 1
        }
    fi

    # Get backup file size
    BACKUP_SIZE=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
    BACKUP_SIZE_MB=$((BACKUP_SIZE / 1024 / 1024))

    log_info "  Backup created: ${backup_file}"
    log_info "  Size: ${BACKUP_SIZE_MB} MB"

    return 0
}

# Backup all volumes
BACKUP_COUNT=0
FAILED_COUNT=0

for volume in "${VOLUMES[@]}"; do
    if backup_volume "$volume"; then
        ((BACKUP_COUNT++))
    else
        ((FAILED_COUNT++))
    fi
done

# Create manifest file
MANIFEST_FILE="${BACKUP_SUBDIR}/manifest.txt"
log_info "Creating backup manifest..."

cat > "$MANIFEST_FILE" << EOF
Backup Manifest
===============

Timestamp: $TIMESTAMP
Date: $(date)
Host: $(hostname)

Volumes Backed Up: $BACKUP_COUNT
Failed Backups: $FAILED_COUNT

Files:
$(ls -lh "$BACKUP_SUBDIR"/*.tar.gz 2>/dev/null || echo "  No backup files created")

Checksums (SHA256):
$(cd "$BACKUP_SUBDIR" && sha256sum *.tar.gz 2>/dev/null || echo "  No checksums available")
EOF

log_info "Manifest created: $MANIFEST_FILE"

# Create latest symlink
LATEST_LINK="${BACKUP_DIR}/latest"
rm -f "$LATEST_LINK"
ln -s "$BACKUP_SUBDIR" "$LATEST_LINK"

log_info "Created symlink: $LATEST_LINK -> $BACKUP_SUBDIR"

# Summary
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Backup Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo "Timestamp:        $TIMESTAMP"
echo "Backup directory: $BACKUP_SUBDIR"
echo "Volumes backed up: $BACKUP_COUNT"
echo "Failed backups:    $FAILED_COUNT"
echo ""

if [ $FAILED_COUNT -eq 0 ]; then
    log_info "${GREEN}All volumes backed up successfully!${NC}"
    exit 0
else
    log_warn "Some volumes failed to backup"
    exit 1
fi
