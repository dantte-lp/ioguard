# Quick Start Guide - ringwall Containers

## 30-Second Quick Start

```bash
cd /opt/projects/repositories/ringwall/deploy/podman

# Build all containers (10-12 minutes)
make build-all

# Start development
make dev
```

## 5-Minute Setup

### 1. Install Prerequisites

```bash
# Oracle Linux 10 / RHEL 10
sudo dnf install -y podman buildah skopeo crun fuse-overlayfs slirp4netns container-selinux

# Podman Compose
pip3 install podman-compose
```

### 2. Configure Rootless Mode

```bash
# Enable user namespaces
sudo sysctl -w user.max_user_namespaces=28633
echo "user.max_user_namespaces=28633" | sudo tee /etc/sysctl.d/userns.conf

# Configure subuid/subgid
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Verify
./scripts/verify-rootless.sh
./scripts/verify-selinux.sh
```

### 3. Build Containers

```bash
# Build all images
make build-all

# Or build individually
make build-dev      # Development (10 min)
make build-test     # Test (2 min, requires dev)
make build-build    # Build (8 min)
make build-ci       # CI (1 min, requires build)
```

### 4. Verify Installation

```bash
# Check images
podman images | grep ringwall

# System info
make info

# Verify setup
make verify-rootless
make verify-selinux
```

## Common Commands

### Development

```bash
# Start dev environment
make dev

# Inside container
meson setup build --buildtype=debug
ninja -C build
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make full-test

# Run benchmarks
make benchmark
```

### Building

```bash
# Build release
make release

# Check artifacts
ls -lh artifacts/
```

### Cleanup

```bash
# Clean containers + cache
make clean

# Remove images
make clean-images

# Full cleanup (WARNING!)
make clean-all
```

## Troubleshooting

### Permission Denied

```bash
./scripts/verify-rootless.sh
grep "^$USER:" /etc/subuid /etc/subgid
```

### SELinux Issues

```bash
./scripts/verify-selinux.sh
chcon -R -t container_file_t /opt/projects/repositories/ringwall
```

### Build Failures

```bash
make clean
podman system prune -af
make build-all
```

## Next Steps

- Read [README.md](README.md) for full documentation
- Check [CONTAINER_ARCHITECTURE.md](docs/CONTAINER_ARCHITECTURE.md) for design details
- See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues
- Review [Makefile](Makefile) for all available commands

## Important Notes

1. **wolfSSL License**: v5.8.2 uses GPLv3 (changed from GPLv2)
2. **Rootless Mode**: All containers run as non-root by default
3. **SELinux**: Use `:Z` flag on volume mounts
4. **Hot Reload**: Edit code on host, rebuild in container

## Support

- Issues: https://github.com/dantte-lp/ringwall/issues
- Documentation: [README.md](README.md)

---

Happy coding!
