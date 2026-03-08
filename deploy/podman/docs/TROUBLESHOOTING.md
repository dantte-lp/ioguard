# Troubleshooting Guide

Common issues and solutions for the ringwall Podman container infrastructure.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Permission Issues](#permission-issues)
- [SELinux Issues](#selinux-issues)
- [Network Issues](#network-issues)
- [Volume Issues](#volume-issues)
- [Performance Issues](#performance-issues)
- [Advanced Debugging](#advanced-debugging)

## Quick Diagnostics

Start here if something isn't working:

```bash
# System information
make info

# Verify rootless setup
./scripts/verify-rootless.sh

# Verify SELinux
./scripts/verify-selinux.sh

# Check running containers
podman ps -a

# Check images
podman images | grep ringwall

# Check logs
podman logs <container-name>
```

## Build Issues

### Error: "Failed to pull base image"

**Symptom**:
```
Error: initializing source docker://registry.access.redhat.com/ubi9/ubi:latest:
error pinging docker registry...
```

**Solutions**:

1. Check internet connectivity:
```bash
curl -I https://registry.access.redhat.com
```

2. Check registry configuration:
```bash
cat ~/.config/containers/registries.conf
```

3. Try pulling manually:
```bash
podman pull registry.access.redhat.com/ubi9/ubi:latest
```

4. Use alternative registry:
```bash
export BASE_IMAGE="docker.io/library/oraclelinux:10"
./scripts/build-dev.sh
```

### Error: "Disk space full"

**Symptom**:
```
Error: error creating build container: write /var/tmp/...: no space left on device
```

**Solutions**:

1. Check disk space:
```bash
df -h
```

2. Clean up Podman resources:
```bash
podman system prune -af --volumes
```

3. Remove old images:
```bash
podman rmi $(podman images -q) -f
```

4. Check storage driver:
```bash
podman info | grep -A5 storage
```

### Error: "Library build failed"

**Symptom**:
```
make[1]: *** [Makefile:123: install] Error 1
```

**Solutions**:

1. Check build logs:
```bash
# Rebuild with verbose output
DEBUG=1 ./scripts/build-dev.sh
```

2. Verify library versions:
```bash
# Check if version tags exist
curl -I https://github.com/wolfSSL/wolfssl/releases/tag/v5.8.2
```

3. Try without optimizations:
```bash
# Edit build-dev.sh, remove -O3 flags
CFLAGS="-g -O0"
```

4. Build libraries separately:
```bash
# Test wolfSSL build
buildah run $container -- bash -c "
    cd /tmp && curl -LO https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.2.tar.gz
    tar xzf v5.8.2.tar.gz
    cd wolfssl-5.8.2
    ./autogen.sh
    ./configure --prefix=/usr/local
    make -j4
    make install
"
```

## Runtime Issues

### Error: "Permission denied" when starting container

**Symptom**:
```
Error: OCI permission denied
```

**Solutions**:

1. Verify rootless configuration:
```bash
./scripts/verify-rootless.sh
```

2. Check subuid/subgid:
```bash
grep "^$USER:" /etc/subuid /etc/subgid
```

3. If missing, configure:
```bash
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
podman system migrate
```

4. Restart user services:
```bash
systemctl --user restart podman.socket
```

### Error: "Container exits immediately"

**Symptom**:
```
$ podman ps
CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES
(empty)
```

**Solutions**:

1. Check exit code:
```bash
podman ps -a | grep ocserv
podman logs <container-id>
```

2. Run interactively:
```bash
podman run -it --rm localhost/ringwall-dev:latest /bin/bash
```

3. Check command:
```bash
podman inspect localhost/ringwall-dev:latest | jq '.[0].Config.Cmd'
```

4. Override command:
```bash
podman-compose run --rm dev sleep infinity
```

### Error: "Library not found"

**Symptom**:
```
error while loading shared libraries: libwolfssl.so.42: cannot open shared object file
```

**Solutions**:

1. Run ldconfig:
```bash
podman exec <container-name> ldconfig
```

2. Check library path:
```bash
podman exec <container-name> ldconfig -p | grep wolfssl
```

3. Verify LD_LIBRARY_PATH:
```bash
podman exec <container-name> echo $LD_LIBRARY_PATH
```

4. Rebuild image:
```bash
make clean-images
make build-dev
```

## Permission Issues

### Error: "Cannot write to /workspace"

**Symptom**:
```
touch: cannot touch '/workspace/test': Permission denied
```

**Solutions**:

1. Check volume mount:
```bash
podman inspect <container-name> | jq '.[0].Mounts'
```

2. Verify SELinux context:
```bash
ls -Zd /opt/projects/repositories/ringwall
```

3. Fix ownership:
```bash
# On host
sudo chown -R $USER:$USER /opt/projects/repositories/ringwall
```

4. Relabel for SELinux:
```bash
chcon -R -t container_file_t /opt/projects/repositories/ringwall
```

5. Check container user:
```bash
podman exec <container-name> whoami
podman exec <container-name> id
```

### Error: "Operation not permitted" in container

**Symptom**:
```
mkdir: cannot create directory '/workspace/build': Operation not permitted
```

**Solutions**:

1. Check if read-only mount:
```bash
podman inspect <container-name> | jq '.[0].Mounts[] | select(.Destination=="/workspace")'
```

2. Verify user namespace:
```bash
podman unshare cat /proc/self/uid_map
```

3. Check capabilities:
```bash
podman inspect <container-name> | jq '.[0].EffectiveCaps'
```

4. Restart with correct user:
```bash
podman-compose down
podman-compose up dev
```

## SELinux Issues

### Error: "SELinux is preventing access"

**Symptom**:
```
audit: type=1400 audit(1234567890.123:456): avc:  denied  { read } for  pid=12345 comm="podman"...
```

**Solutions**:

1. Run verification:
```bash
./scripts/verify-selinux.sh
```

2. Check audit log:
```bash
sudo ausearch -m avc -ts recent | grep container
```

3. Use :Z flag on mounts:
```yaml
volumes:
  - ../../:/workspace:Z  # Correct
  - ../../:/workspace    # Wrong - missing :Z
```

4. Relabel directory:
```bash
chcon -R -t container_file_t /opt/projects/repositories/ringwall
```

5. Generate policy (last resort):
```bash
sudo ausearch -m avc -ts recent | audit2allow -M mycontainer
sudo semodule -i mycontainer.pp
```

### Error: "Context not valid"

**Symptom**:
```
Error: error creating container storage: context not valid for file /path/to/file
```

**Solutions**:

1. Check SELinux status:
```bash
getenforce
```

2. If permissive, check for errors:
```bash
sudo setenforce 0
# Try again
sudo setenforce 1
```

3. Reinstall container-selinux:
```bash
sudo dnf reinstall container-selinux
```

4. Reset file contexts:
```bash
sudo restorecon -R /opt/projects/repositories/ringwall
```

## Network Issues

### Error: "Cannot connect to container"

**Symptom**:
```
curl: (7) Failed to connect to localhost port 8080: Connection refused
```

**Solutions**:

1. Check container is running:
```bash
podman ps | grep ocserv
```

2. Verify port mapping:
```bash
podman port <container-name>
```

3. Check if service is listening:
```bash
podman exec <container-name> netstat -tuln
```

4. Test from inside container:
```bash
podman exec <container-name> curl localhost:8080
```

5. Check firewall:
```bash
sudo firewall-cmd --list-ports
```

### Error: "Network ocserv-net not found"

**Symptom**:
```
Error: unable to find network with name or ID ocserv-net
```

**Solutions**:

1. Create network:
```bash
podman network create ocserv-net
```

2. Or use podman-compose:
```bash
podman-compose up -d
```

3. List networks:
```bash
podman network ls
```

4. Inspect network:
```bash
podman network inspect ocserv-net
```

## Volume Issues

### Error: "Volume not found"

**Symptom**:
```
Error: volume ringwall_dev-home not found
```

**Solutions**:

1. Create volumes:
```bash
podman volume create ringwall_dev-home
podman volume create ringwall_build-cache
```

2. Or use compose:
```bash
podman-compose up -d
```

3. List volumes:
```bash
podman volume ls
```

### Error: "Cannot backup volume"

**Symptom**:
```
tar: /volume: Cannot open: Permission denied
```

**Solutions**:

1. Use container method:
```bash
# Edit backup-volumes.sh to always use container method
# Line ~65: Force container backup
```

2. Run with sudo (not recommended):
```bash
sudo ./scripts/backup-volumes.sh
```

3. Fix volume ownership:
```bash
podman volume inspect ringwall_dev-home
# Check Mountpoint, then:
sudo chown -R $USER:$USER <mountpoint>
```

## Performance Issues

### Issue: Slow builds

**Symptoms**:
- Build takes >20 minutes
- High CPU usage
- Disk thrashing

**Solutions**:

1. Use parallel builds:
```bash
# Already default in scripts
make -j$(nproc)
```

2. Check disk I/O:
```bash
iostat -x 1
```

3. Use tmpfs for builds:
```yaml
tmpfs:
  - /tmp
  - /var/tmp
```

4. Increase build cache:
```bash
export BUILDAH_LAYERS=true
```

5. Use SSD for storage:
```bash
# Edit storage.conf
graphroot = "/path/to/fast/ssd"
```

### Issue: Slow container startup

**Symptoms**:
- Container takes >10 seconds to start
- High memory usage

**Solutions**:

1. Verify crun runtime:
```bash
podman info | grep ociRuntime
```

2. Enable crun:
```bash
# Edit containers.conf
runtime = "crun"
```

3. Reduce image size:
```bash
# Rebuild with squash
buildah commit --rm --squash $container
```

4. Pre-pull images:
```bash
podman pull localhost/ringwall-dev:latest
```

## Advanced Debugging

### Enable debug logging

```bash
# Podman debug mode
podman --log-level=debug run ...

# Buildah debug mode
buildah --log-level=debug from ...

# Compose debug mode
podman-compose --log-level=debug up
```

### Inspect container internals

```bash
# Full container inspection
podman inspect <container-name> | jq .

# Check mounts
podman inspect <container-name> | jq '.[0].Mounts'

# Check environment
podman inspect <container-name> | jq '.[0].Config.Env'

# Check user namespace
podman inspect <container-name> | jq '.[0].HostConfig.UsernsMode'
```

### Debug failed build

```bash
# Keep intermediate container
container=$(buildah from ubi9/ubi:latest)
buildah run $container -- bash
# ... debug manually ...
buildah rm $container
```

### Examine layer history

```bash
# Show image layers
podman history localhost/ringwall-dev:latest

# Export image filesystem
podman export <container-name> > filesystem.tar
tar -tf filesystem.tar | less
```

### Network debugging

```bash
# Attach to container network namespace
podman exec -it <container-name> bash
ip addr
ip route
netstat -tuln

# Capture traffic
sudo tcpdump -i cni-podman0
```

### Performance profiling

```bash
# Resource usage
podman stats

# Detailed stats
podman inspect <container-name> | jq '.[0].State.Stats'

# System call trace
podman exec <container-name> strace -c <command>
```

## Getting Help

If you're still stuck:

1. **Check logs**:
```bash
podman logs <container-name>
journalctl --user -u podman.service
```

2. **System information**:
```bash
podman info > podman-info.txt
podman version >> podman-info.txt
```

3. **File an issue**:
   - Include `podman info` output
   - Include error messages
   - Describe steps to reproduce
   - Include logs

4. **Podman documentation**:
   - https://docs.podman.io
   - man podman
   - man containers.conf

---

Generated with Claude Code - https://claude.com/claude-code
