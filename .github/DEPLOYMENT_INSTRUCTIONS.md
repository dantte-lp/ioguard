# Deployment Instructions for CI/CD Infrastructure

This guide provides step-by-step instructions to deploy the updated CI/CD infrastructure for ringwall.

## Prerequisites

- Podman or Docker installed on runner host
- Root or sudo access to runner host
- GitHub repository admin access
- At least 50GB free disk space for runner images

## Step 1: Rebuild Runner Images

### Rebuild Debian Runner

```bash
# Navigate to Debian runner directory
cd /opt/projects/repositories/self-hosted-runners/pods/github-runner-debian

# Rebuild the image (this will take 15-20 minutes)
podman build -t github-runner-debian:latest -f Containerfile .

# Verify the image was built
podman images | grep github-runner-debian

# Test the image
podman run --rm github-runner-debian:latest bash -c "gcc --version && pkg-config --modversion wolfssl libuv cjson"
```

**Expected Output**:
```
gcc (Debian 14.2.0-19) 14.2.0
5.8.2
1.51.0
1.7.18
```

### Rebuild Oracle Linux Runner

```bash
# Navigate to Oracle Linux runner directory
cd /opt/projects/repositories/self-hosted-runners/pods/github-runner-oracle

# Rebuild the image (this will take 15-20 minutes)
podman build -t github-runner-oracle:latest -f Containerfile .

# Verify the image was built
podman images | grep github-runner-oracle

# Test the image
podman run --rm github-runner-oracle:latest bash -c "gcc --version && pkg-config --modversion wolfssl libuv cjson"
```

**Expected Output**:
```
gcc (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7)
5.8.2
1.51.0
1.7.18
```

## Step 2: Stop and Remove Old Runners

```bash
# Stop existing runners (if running)
podman stop github-runner-debian github-runner-oracle || true

# Remove old containers
podman rm github-runner-debian github-runner-oracle || true

# Optional: Remove old images to free space
podman image prune -f
```

## Step 3: Start New Runners

### Start Debian Runner

```bash
# Get GitHub runner registration token
# Go to: https://github.com/dantte-lp/ringwall/settings/actions/runners/new

# Start Debian runner with new image
podman run -d \
  --name github-runner-debian \
  --restart unless-stopped \
  -e RUNNER_NAME="debian-runner-1" \
  -e RUNNER_LABELS="self-hosted,linux,x64,debian" \
  -e GITHUB_TOKEN="<your-github-token>" \
  -e REPO_URL="https://github.com/dantte-lp/ringwall" \
  -v /var/run/docker.sock:/var/run/docker.sock:Z \
  github-runner-debian:latest
```

### Start Oracle Linux Runner

```bash
# Start Oracle Linux runner with new image
podman run -d \
  --name github-runner-oracle \
  --restart unless-stopped \
  -e RUNNER_NAME="oracle-runner-1" \
  -e RUNNER_LABELS="self-hosted,linux,x64,oracle-linux" \
  -e GITHUB_TOKEN="<your-github-token>" \
  -e REPO_URL="https://github.com/dantte-lp/ringwall" \
  -v /var/run/docker.sock:/var/run/docker.sock:Z \
  github-runner-oracle:latest
```

## Step 4: Verify Runner Registration

```bash
# Check runner status
gh runner list

# Should show:
# NAME              STATUS   LABELS
# debian-runner-1   online   self-hosted,linux,x64,debian
# oracle-runner-1   online   self-hosted,linux,x64,oracle-linux
```

## Step 5: Test Workflows

### Test dev-ci.yml (Development Workflow)

```bash
# Navigate to ringwall repository
cd /opt/projects/repositories/ringwall

# Create test branch
git checkout -b ci-test-branch

# Make a small change
echo "# CI Test" >> README.md

# Commit and push
git add README.md
git commit -m "test: CI infrastructure validation"
git push origin ci-test-branch

# Trigger workflow manually
gh workflow run dev-ci.yml --ref ci-test-branch

# Watch the workflow
gh run watch
```

**Expected Result**: Workflow completes in 10-20 minutes with all checks passing.

### Test containers.yml (Container Workflow)

```bash
# Trigger container workflow manually
gh workflow run containers.yml --ref ci-test-branch

# Watch the workflow
gh run watch
```

**Expected Result**: Workflow completes in 30-45 minutes, all container images built successfully.

## Step 6: Validate Dependencies

### Check wolfSSL Installation

```bash
# On runner host, exec into Oracle Linux runner
podman exec -it github-runner-oracle bash

# Check wolfSSL version and features
pkg-config --modversion wolfssl
pkg-config --cflags wolfssl
pkg-config --libs wolfssl

# Verify library exists
ls -la /usr/local/lib/libwolfssl.so*

# Check headers
ls -la /usr/local/include/wolfssl/

# Exit container
exit
```

### Check libuv Installation

```bash
# Exec into runner
podman exec -it github-runner-oracle bash

# Check libuv
pkg-config --modversion libuv
ls -la /usr/local/lib/libuv.so*

# Exit
exit
```

### Check cJSON Installation

```bash
# Exec into runner
podman exec -it github-runner-oracle bash

# Check cJSON
pkg-config --modversion cjson
ls -la /usr/local/lib/libcjson.so*

# Exit
exit
```

## Step 7: Monitor First Real Build

```bash
# Watch logs from a real build
cd /opt/projects/repositories/ringwall

# Create a feature branch
git checkout -b feature/real-test

# Make changes
vim src/tls/tls_backend.c

# Commit and push
git add src/tls/tls_backend.c
git commit -m "feat: test real CI/CD pipeline"
git push origin feature/real-test

# Monitor workflow
gh run watch

# Check logs for any errors
gh run view --log
```

## Troubleshooting

### Issue: Runner Not Registering

**Problem**: Runner doesn't appear in GitHub UI.

**Solution**:
```bash
# Check runner logs
podman logs github-runner-oracle

# Verify GitHub token
echo $GITHUB_TOKEN

# Re-register manually
podman exec -it github-runner-oracle bash
cd /home/runner
./config.sh --url https://github.com/dantte-lp/ringwall --token <token>
```

### Issue: Library Not Found During Build

**Problem**: Compiler cannot find wolfSSL or other libraries.

**Solution**:
```bash
# Check PKG_CONFIG_PATH in workflow
podman exec -it github-runner-oracle bash
echo $PKG_CONFIG_PATH
pkg-config --list-all | grep -E 'wolfssl|libuv|cjson'

# If not found, rebuild runner image
cd /opt/projects/repositories/self-hosted-runners/pods/github-runner-oracle
podman build -t github-runner-oracle:latest --no-cache -f Containerfile .
```

### Issue: Workflow Stuck in "Queued"

**Problem**: Workflow doesn't start.

**Solution**:
```bash
# Check runner status
gh runner list

# If offline, restart runner
podman restart github-runner-oracle

# Check runner logs
podman logs -f github-runner-oracle
```

### Issue: Container Build Fails

**Problem**: Podman/Buildah errors during container build.

**Solution**:
```bash
# Ensure Docker socket is accessible
ls -la /var/run/docker.sock

# Check SELinux context (if enabled)
ls -Z /var/run/docker.sock

# Restart Docker/Podman
sudo systemctl restart docker
sudo systemctl restart podman
```

## Rollback Procedure

If you need to rollback to the previous configuration:

### Rollback Workflow Files

```bash
cd /opt/projects/repositories/ringwall

# Restore original containers.yml
cp .github/workflows/containers-backup.yml.bak .github/workflows/containers.yml

# Remove dev-ci.yml (if needed)
# git rm .github/workflows/dev-ci.yml

# Commit rollback
git add .github/workflows/containers.yml
git commit -m "rollback: restore original CI/CD configuration"
git push origin main
```

### Rollback Runner Images

```bash
# Stop new runners
podman stop github-runner-debian github-runner-oracle

# Remove new containers
podman rm github-runner-debian github-runner-oracle

# Pull old images (if tagged)
podman pull github-runner-debian:old
podman pull github-runner-oracle:old

# Start old runners
# (use previous run commands with old image tags)
```

## Post-Deployment Checklist

- [ ] Both runners show "online" status in GitHub
- [ ] Runners have correct labels assigned
- [ ] dev-ci.yml triggered successfully on test branch
- [ ] containers.yml triggered successfully on test branch
- [ ] All workflow stages completed without errors
- [ ] Artifacts uploaded successfully
- [ ] wolfSSL, libuv, cJSON available in runners
- [ ] GCC 14.2+ verified in runner environment
- [ ] Documentation reviewed and understood by team
- [ ] Rollback procedure tested and documented

## Next Steps

1. **Monitor Performance**: Track workflow run times over the next week
2. **Optimize Caching**: Identify opportunities for faster builds
3. **Team Training**: Share QUICKSTART_CI.md with development team
4. **Security Review**: Schedule audit of runner security configuration
5. **Backup Strategy**: Implement runner image backups

## Support

For issues or questions:

- **Documentation**: See `.github/WORKFLOWS.md` and `QUICKSTART_CI.md`
- **Runner Setup**: See `self-hosted-runners/RUNNER_SETUP_OCSERV.md`
- **GitHub Actions**: https://docs.github.com/en/actions
- **Project Issues**: https://github.com/dantte-lp/ringwall/issues

Last Updated: 2025-10-29
