# wolfguard Release Policy

## Overview

wolfguard follows Semantic Versioning 2.0.0 for all releases. This document defines the release process, versioning strategy, support policy, and lifecycle management.

## Semantic Versioning

### Version Format: MAJOR.MINOR.PATCH

- **MAJOR** version: Incompatible API changes, breaking protocol changes, or major architectural rewrites
- **MINOR** version: New features added in a backward-compatible manner
- **PATCH** version: Backward-compatible bug fixes and security patches

### Pre-release Labels

- **Alpha** (`X.Y.Z-alpha.N`): Early development, unstable, breaking changes expected
- **Beta** (`X.Y.Z-beta.N`): Feature-complete, undergoing testing, minor breaking changes possible
- **Release Candidate** (`X.Y.Z-rc.N`): Production-ready candidate, no new features, bug fixes only

### Examples

- `1.0.0` - First stable release
- `1.1.0` - New DTLS 1.3 support added
- `1.1.1` - Security patch for DTLS handshake
- `2.0.0` - Breaking change: minimum TLS version now 1.2
- `1.2.0-alpha.1` - Early alpha with experimental QUIC support
- `1.2.0-beta.2` - Second beta with QUIC support
- `1.2.0-rc.1` - Release candidate for 1.2.0

## Version Bump Guidelines

### MAJOR Version Bump

Trigger conditions (any of):
- API breaking changes requiring client updates
- Minimum TLS/DTLS version increase
- Configuration file format changes (not backward-compatible)
- Protocol changes incompatible with previous versions
- Removal of deprecated features
- Major architecture changes (e.g., multi-process to multi-threaded)

Example: Migrating from GnuTLS to wolfSSL native API (1.x → 2.0.0)

### MINOR Version Bump

Trigger conditions (any of):
- New features added (backward-compatible)
- New cipher suite support
- New authentication method
- Performance improvements without breaking changes
- New configuration options (with defaults maintaining backward compatibility)
- Deprecation warnings (feature removed in next MAJOR)

Example: Adding DTLS 1.3 support (1.0.0 → 1.1.0)

### PATCH Version Bump

Trigger conditions (any of):
- Security vulnerability fixes (CVE)
- Bug fixes (crashes, memory leaks, incorrect behavior)
- Documentation updates
- Performance regressions
- Build system fixes
- Dependency version updates (security only)

Example: Fixing TLS handshake timeout (1.1.0 → 1.1.1)

## Release Cadence

### Time-Based Releases

- **MINOR releases**: Every 4-6 months
- **PATCH releases**: As needed, typically 2-4 weeks for security issues
- **MAJOR releases**: No fixed schedule, driven by architectural needs

### Feature-Based Releases

A MINOR release may be triggered early if:
- Critical new feature requested by enterprise users
- Protocol standard update (e.g., new RFC)
- Major dependency update enabling new capabilities

## Release Stages and Timeline

### Alpha Stage

**Duration**: 2-4 weeks per alpha
**Purpose**: Early development, experimentation, API exploration
**Characteristics**:
- Breaking changes expected and frequent
- Incomplete features
- Known bugs and crashes
- Not for production
- Testing by core developers only

**Exit Criteria**:
- Core feature implementation complete
- API surface defined
- Basic integration tests passing

### Beta Stage

**Duration**: 4-8 weeks total (1-2 betas)
**Purpose**: Feature-complete testing, stabilization
**Characteristics**:
- All planned features implemented
- Minor breaking changes possible (with justification)
- Focus on bug fixing and performance
- Documentation complete
- Testing by early adopters and contributors

**Exit Criteria**:
- No known critical bugs
- All planned features working
- Performance benchmarks meet targets (within 10% of goals)
- Security audit completed (for MAJOR releases)
- Documentation reviewed and complete

### Release Candidate Stage

**Duration**: 2-4 weeks per RC
**Purpose**: Production readiness validation
**Characteristics**:
- No new features
- Bug fixes only
- No breaking changes
- API frozen
- Extensive testing by community

**Exit Criteria**:
- Zero critical bugs
- Zero high-severity bugs (or approved exceptions)
- All tests passing (unit, integration, security)
- Client compatibility verified
- Performance regression testing passed
- Documentation final review complete

**RC Promotion**:
- If bugs found: Fix → new RC
- If no issues for 1 week: Promote to stable
- Maximum 3 RCs before reassessment

### Stable Release

**Characteristics**:
- Production-ready
- Fully tested and documented
- Security-audited (MAJOR releases)
- Long-term support commitment (LTS versions)
- Package availability (RPM, DEB, source)

## Support and Maintenance Policy

### Support Tiers

#### Tier 1: Active Development (Current Stable)

- **Duration**: Until next MINOR release (4-6 months)
- **Support**: Full support for all issues
- **Updates**: Feature updates, bug fixes, security patches
- **Response Time**: Critical security issues within 24-48 hours

#### Tier 2: Maintenance (Previous MINOR)

- **Duration**: 12 months from release
- **Support**: Security patches and critical bug fixes only
- **Updates**: No new features
- **Response Time**: Security issues within 1 week

#### Tier 3: Long-Term Support (LTS)

- **Eligibility**: Every MAJOR release (1.0, 2.0, 3.0)
- **Duration**: 24-36 months from release
- **Support**: Security patches only
- **Updates**: Minimal, security-critical only
- **Response Time**: Security issues within 2 weeks

#### End-of-Life (EOL)

- **Notice Period**: 6 months advance notice
- **Final Update**: Security patch release before EOL
- **Support**: Community-based only (no official support)

### Example Support Timeline

```
v2.0.0 (LTS)     ========================================= [36 months support]
v2.1.0           =============== [12 months]
v2.2.0           ----=============== [12 months]
v2.3.0 (current) --------========[Active Dev]
v3.0.0 (next)    ---------------? [Future LTS]
```

## Release Process

### 1. Planning Phase (Weeks -8 to -6)

- [ ] Define release goals and features
- [ ] Create milestone in GitHub
- [ ] Assign feature owners
- [ ] Update project roadmap
- [ ] Announce planned release to community

### 2. Development Phase (Weeks -6 to -4)

- [ ] Feature development and integration
- [ ] Continuous integration testing
- [ ] Code review and merge
- [ ] Update documentation as features merge

### 3. Alpha Phase (Weeks -4 to -3)

- [ ] Create alpha branch `release/vX.Y.Z-alpha`
- [ ] Tag alpha releases (`vX.Y.Z-alpha.1`, `vX.Y.Z-alpha.2`)
- [ ] Internal testing and feedback
- [ ] Fix critical issues
- [ ] Community testing invitation (optional)

### 4. Beta Phase (Weeks -3 to -1)

- [ ] Create beta branch `release/vX.Y.Z-beta`
- [ ] Tag beta releases (`vX.Y.Z-beta.1`, `vX.Y.Z-beta.2`)
- [ ] Public testing announcement
- [ ] Freeze API and configuration format
- [ ] Security testing and audit (MAJOR releases)
- [ ] Performance benchmarking
- [ ] Client compatibility testing

### 5. Release Candidate Phase (Weeks -1 to 0)

- [ ] Create RC branch `release/vX.Y.Z-rc`
- [ ] Tag RC releases (`vX.Y.Z-rc.1`, etc.)
- [ ] Code freeze (bug fixes only)
- [ ] Final documentation review
- [ ] Release notes preparation
- [ ] Package preparation (RPM, DEB, source tarball)
- [ ] Final security audit (MAJOR releases)

### 6. Stable Release (Week 0)

- [ ] Tag stable release `vX.Y.Z`
- [ ] Merge release branch to `main`
- [ ] Generate release packages
- [ ] Upload to GitHub releases
- [ ] Update documentation website
- [ ] Announce release (mailing list, social media, blog)
- [ ] Update distribution packages (Fedora, Debian, etc.)
- [ ] Create release blog post with migration guide

### 7. Post-Release (Weeks 1-4)

- [ ] Monitor issue tracker for regression reports
- [ ] Prepare PATCH release if critical issues found
- [ ] Collect feedback for next release
- [ ] Update roadmap based on feedback

## Hotfix Process

For critical security vulnerabilities or production-breaking bugs:

1. **Assessment** (0-4 hours): Severity determination
2. **Development** (4-48 hours): Fix implementation and testing
3. **Release** (immediate):
   - Tag hotfix version (increment PATCH)
   - Generate packages
   - Publish release with CVE details (if applicable)
   - Notify affected users directly
4. **Backport**: Apply to all supported versions (LTS, Maintenance)

## Deprecation Policy

### Deprecation Process

1. **Announcement**: Feature marked deprecated in release notes (MINOR release)
2. **Deprecation Period**: Minimum 12 months (one MAJOR release cycle)
3. **Warnings**: Compile-time and runtime warnings added
4. **Documentation**: Alternative solutions documented
5. **Removal**: Feature removed in next MAJOR release

### Example Deprecation Timeline

```
v1.2.0: Feature X announced deprecated, warnings added
v1.3.0: Feature X still available with warnings
v1.4.0: Feature X still available with warnings
v2.0.0: Feature X removed, migration guide provided
```

## Version Support Matrix

| Version | Release Date | Support Tier | EOL Date | Notes |
|---------|-------------|--------------|----------|-------|
| 2.3.0 | TBD | Active | TBD | Current development |
| 2.2.0 | TBD | Maintenance | TBD + 12mo | |
| 2.1.0 | TBD | Maintenance | TBD + 12mo | |
| 2.0.0 | TBD | LTS | TBD + 36mo | First wolfSSL release |
| 1.x.x | Historical | EOL | N/A | Legacy GnuTLS version |

## Communication Channels

### Release Announcements

- GitHub Releases page
- Project mailing list (ocserv-dev@lists.infradead.org)
- Project website news section
- Twitter/Mastodon (@wolfguard)
- Reddit (r/VPN, r/opensource)

### Security Advisories

- GitHub Security Advisories
- CVE publication (MITRE)
- Direct notification to registered enterprise users
- Security mailing list (security@wolfguard.org)

## Quality Gates

### All Releases

- [ ] All CI/CD tests passing (unit, integration, functional)
- [ ] Code coverage ≥ 80%
- [ ] No compiler warnings (-Wall -Wextra -Werror)
- [ ] Static analysis clean (Coverity, clang-tidy)
- [ ] Memory leak testing (Valgrind) clean
- [ ] Documentation complete and reviewed

### MINOR and MAJOR Releases

- [ ] Performance benchmarks meet targets
- [ ] Client compatibility matrix complete
- [ ] Security testing (fuzzing, penetration testing)
- [ ] Upgrade/downgrade testing passed
- [ ] Multi-platform testing (Linux, FreeBSD, OpenBSD)

### MAJOR Releases

- [ ] External security audit completed
- [ ] Long-term support commitment approved
- [ ] Migration guide and tools provided
- [ ] Breaking changes justified and documented

## Rollback and Recovery

### Rollback Scenarios

If critical issues discovered post-release:

1. **Immediate**: Publish advisory recommending previous version
2. **Fast Track**: Hotfix release within 24-48 hours
3. **Long Term**: Root cause analysis and comprehensive fix

### Package Rollback

- All previous versions remain available on GitHub Releases
- Package repositories maintain last 3 MINOR versions
- Docker images tagged and archived

## Metrics and KPIs

### Release Quality Metrics

- Time to fix critical bugs post-release
- Number of hotfixes required per release
- User-reported regressions
- Security vulnerabilities per release
- Client compatibility success rate

### Release Velocity Metrics

- Days from feature-complete to stable release
- Number of alpha/beta/RC cycles
- Average time in each release stage

### Target KPIs (v2.x)

- Critical bugs post-release: 0
- High-severity bugs post-release: < 2
- Release cycle duration: 4-6 months
- Security audit findings: 0 critical, < 3 high
- Client compatibility: 100% Cisco Secure Client 5.x+

## References

- Semantic Versioning: https://semver.org/
- CVE Program: https://cve.mitre.org/
- GitHub Release Process: https://docs.github.com/en/repositories/releasing-projects-on-github

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Next Review**: 2026-04-29 (6 months)
