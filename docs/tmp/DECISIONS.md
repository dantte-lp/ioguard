# Architecture and Technical Decisions Log

**Project**: wolfguard
**Purpose**: Document significant technical and architectural decisions

---

## Decision Log Format

Each decision follows this structure:

- **ID**: Unique identifier
- **Date**: When the decision was made
- **Status**: Proposed, Accepted, Rejected, Superseded
- **Context**: What is the issue we're trying to address
- **Decision**: What we decided to do
- **Rationale**: Why we made this decision
- **Consequences**: What are the implications (positive and negative)
- **Alternatives Considered**: What other options were evaluated
- **References**: Links to discussions, documents, RFCs

---

## ADR-001: Use wolfSSL Native API (Not Compatibility Layer)

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, based on critical analysis

### Context

ocserv currently uses GnuTLS for TLS/DTLS. We need to decide on the cryptographic library and API approach for the refactored version.

### Decision

Use **wolfSSL native API**, not the OpenSSL compatibility layer.

### Rationale

1. **Performance**: Native API provides direct function calls without translation overhead
2. **Size**: Smaller footprint (20-100 KB vs 100-200+ KB with compatibility layer)
3. **Features**: Direct access to wolfSSL-specific features (DTLS 1.3, QUIC)
4. **Maintenance**: Cleaner integration, fewer abstraction layers
5. **FIPS**: Better FIPS 140-3 integration with native API

### Consequences

**Positive**:
- Better performance (target 5-15% improvement)
- Smaller binary size
- Direct access to latest features
- Cleaner code architecture

**Negative**:
- More migration work (complete API rewrite)
- GnuTLS → wolfSSL mapping complexity
- Learning curve for wolfSSL API
- Cannot easily switch back to OpenSSL/GnuTLS

### Alternatives Considered

1. **OpenSSL Compatibility Layer**: Less work, but loses performance benefits
2. **GnuTLS Continuation**: Zero migration work, but no DTLS 1.3 or FIPS 140-3
3. **mbedTLS**: Smaller footprint, but slower for server workloads
4. **BoringSSL**: Best performance, but API instability nightmare

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md)
- [ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md](../../ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md)

---

## ADR-002: DO NOT Migrate IPC Layer (Keep protobuf-c)

**Date**: 2025-10-29
**Status**: ✅ Accepted (FINAL - Not open for reconsideration)
**Deciders**: Project team, based on critical analysis

### Context

Original plan proposed migrating from protobuf-c to Cap'n Proto or nanopb for IPC between ocserv processes.

### Decision

**DO NOT change the IPC layer**. Keep protobuf-c for inter-process communication.

### Rationale

1. **Not a Bottleneck**: IPC is not a performance bottleneck in VPN servers (crypto is)
2. **No Clear Benefit**: Cap'n Proto RPC features are overkill for simple command/response patterns
3. **High Risk**: Multi-process IPC changes are risky and hard to test
4. **Scope Creep**: Adds 2-4 weeks with no proven benefit
5. **Backward Compatibility**: Risk breaking occtl tool integration
6. **Testing Burden**: Requires extensive multi-process integration testing

From critical analysis: "Focus on TLS migration, not IPC changes."

### Consequences

**Positive**:
- Reduces project scope by 2-4 weeks
- Eliminates significant risk
- Maintains stability of IPC layer
- Allows focus on core TLS migration

**Negative**:
- No IPC performance improvement (but wasn't needed)
- Continue using protobuf-c (which is fine)

### Alternatives Considered

1. **Cap'n Proto**: Zero-copy serialization, but overkill for our use case
2. **nanopb**: Lightweight, but no functional advantage over protobuf-c
3. **Custom binary protocol**: Too much work for no benefit

### References

- Critical Analysis section: "DO NOT change IPC"
- [ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md](../../ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md)

---

## ADR-003: Realistic Timeline of 50-70 Weeks (Not 34)

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, based on critical analysis

### Context

Original refactoring plan estimated 34 weeks. Critical analysis shows this is unrealistic.

### Decision

Use **50-70 person-weeks** as the realistic project timeline.

### Rationale

1. **Historical Data**: Software projects average 30% overruns
2. **Complex Migrations**: 45% cost overruns, 33% schedule delays (McKinsey study)
3. **Critical Gaps**: Original plan lacked:
   - Security audit (3-4 weeks)
   - Comprehensive testing (8 weeks)
   - Bug fixing contingency (6 weeks)
   - Documentation (5 weeks)
   - Beta/RC releases (3 weeks)
4. **Realistic Breakdown**:
   - Phase 0: 3 weeks (was 2)
   - Phase 1: 3 weeks (was 2)
   - Phase 2: 12-14 weeks (was 12)
   - Phase 3: 8 weeks (was 0)
   - Phase 4: 6 weeks (was 0)
   - Phase 5: 5 weeks (was 0)
   - Phase 6: 3 weeks (was 0)
   - **Total**: 40-50 weeks + 30% contingency = 50-70 weeks

### Consequences

**Positive**:
- Realistic expectations for stakeholders
- Adequate time for quality assurance
- Buffer for unexpected issues
- Proper security and testing

**Negative**:
- Longer project duration
- Higher cost (budget $200k-250k)
- Delayed time-to-market

### Alternatives Considered

1. **34 Weeks (Original)**: Unrealistic, would lead to quality issues
2. **40 Weeks (Optimistic)**: Still underestimates testing and contingency
3. **100+ Weeks (Overly Conservative)**: Would lose stakeholder support

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md) - Section "Timeline Reality Check"

---

## ADR-004: Mandatory External Security Audit

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, security requirements

### Context

Migrating TLS/DTLS implementation in a VPN server is security-critical. Original plan had no security audit.

### Decision

**Mandatory external security audit** by qualified security firm (budget: $50k-100k).

### Rationale

1. **Security-Critical**: VPN servers are high-value targets
2. **TLS Complexity**: TLS implementations are notoriously difficult to get right
3. **Migration Risk**: API changes can introduce subtle vulnerabilities
4. **Industry Standard**: Security-critical projects require independent review
5. **Compliance**: FIPS 140-3, enterprise requirements
6. **Trust**: Users need assurance the migration is secure

### Consequences

**Positive**:
- Independent validation of security
- Discover vulnerabilities before release
- Build user trust
- Meet enterprise compliance requirements

**Negative**:
- Significant cost ($50k-100k)
- Timeline impact (3-4 weeks)
- Potential rework if issues found

### Alternatives Considered

1. **No External Audit**: Unacceptable risk for security-critical VPN
2. **Internal-Only Review**: Lacks independence and expertise
3. **Community Review**: Helpful but not sufficient for production
4. **Delayed Audit (Post-Release)**: Too late if critical issues exist

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md) - "Security Concerns"

---

## ADR-005: Realistic Performance Targets (5-15%, Not 2x)

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, based on critical analysis

### Context

Original plan claimed "2x TLS performance" and "30-50% CPU reduction". Critical analysis shows these are unrealistic.

### Decision

Set **realistic performance targets**:
- TLS Handshakes: ≥5% improvement
- DTLS Handshakes: ≥5% improvement
- Throughput: ≥5% improvement OR ≥10% CPU reduction
- Memory: ≤10% increase acceptable

### Rationale

1. **No GnuTLS Benchmarks**: wolfSSL benchmarks are vs OpenSSL, not GnuTLS
2. **GnuTLS Already Optimized**: Mature library with assembly optimizations
3. **VPN Bottlenecks**: Often kernel, network I/O, routing (not TLS)
4. **Hardware Acceleration**: AES-NI minimizes crypto differences
5. **wolfSSL vs OpenSSL**: 10-40% improvement (not 2x)
6. **Realistic Expectations**: 5-15% is good for library swap

From critical analysis: "Realistic expectation: 5-15% improvement handshake, 0-10% throughput"

### Consequences

**Positive**:
- Honest communication with stakeholders
- Achievable targets
- Avoids disappointment
- Focus on quality over unrealistic performance

**Negative**:
- Less impressive marketing
- Harder to justify investment
- May not meet some expectations

### Alternatives Considered

1. **Keep 2x Claim**: Dishonest, would lead to failed expectations
2. **Conservative 0-5%**: Too pessimistic, undersells benefits
3. **Variable Target**: Too vague, hard to measure success

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md) - "Performance Reality Check"
- [ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md](../../ocserv-ref/docs/ocserv-refactoring-plan-wolfssl-native_v2.md)

---

## ADR-006: Proof of Concept GO/NO-GO Gate

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, risk management

### Context

Given the high cost and risk, we need validation before full commitment.

### Decision

Implement **mandatory Proof of Concept (PoC) in Sprint 1** with GO/NO-GO decision gate.

**PoC Requirements**:
- Minimal TLS connection with wolfSSL
- Benchmark against GnuTLS baseline
- Demonstrate ≥10% handshake improvement OR ≥5% throughput improvement
- Security review finds no fundamental flaws

**If PoC fails**: Project stops, pursue alternative optimizations.

### Rationale

1. **Validation**: Prove performance claims before full investment
2. **Risk Management**: Early exit if approach doesn't work
3. **Cost Control**: Avoid wasting $200k+ if PoC fails
4. **Informed Decision**: Stakeholders decide based on data, not assumptions

### Consequences

**Positive**:
- Data-driven decision making
- Early detection of infeasibility
- Stakeholder confidence
- Risk mitigation

**Negative**:
- 2-week delay before full migration starts
- Possible project cancellation
- PoC effort wasted if project stops

### Alternatives Considered

1. **No PoC**: Too risky, $200k+ investment on unvalidated assumptions
2. **Theoretical Analysis Only**: Not sufficient, need empirical data
3. **Partial Migration First**: More work than PoC, same risk

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md) - "GO/NO-GO Decision Gate"

---

## ADR-007: Dual-Build Capability (GnuTLS + wolfSSL)

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, rollback strategy

### Context

Need ability to rollback to GnuTLS if wolfSSL migration fails.

### Decision

Implement **TLS abstraction layer** enabling dual-build with both GnuTLS and wolfSSL backends.

### Rationale

1. **Risk Mitigation**: Ability to rollback if issues found
2. **Gradual Migration**: Can ship both, let users choose
3. **Testing**: Validate abstraction layer correctness
4. **Confidence**: Safety net for production deployments

### Consequences

**Positive**:
- Rollback capability if migration fails
- Safer transition path
- Can support both backends long-term (if needed)
- Better testing (run same tests on both)

**Negative**:
- Extra implementation work (abstraction layer)
- More complex build system
- Maintenance burden (two code paths)
- Performance overhead of abstraction (target <5%)

### Alternatives Considered

1. **No Abstraction**: All-or-nothing migration, high risk
2. **OpenSSL Compatibility Layer**: Adds more overhead
3. **Conditional Compilation Only**: No runtime selection

### References

- [docs/REFACTORING_PLAN.md](REFACTORING_PLAN.md) - "Phase 1: Infrastructure"

---

## ADR-008: Meson Build System (Not CMake/Autotools)

**Date**: 2025-10-29
**Status**: ✅ Accepted
**Deciders**: Project team, modern tooling

### Context

Original ocserv uses Autotools. Need to choose build system for modern refactoring.

### Decision

Use **Meson** as the primary build system.

### Rationale

1. **Modern**: Fast, clean syntax, designed for C/C++
2. **Cross-Platform**: Excellent Windows/macOS support (future)
3. **Dependency Management**: Built-in dependency discovery
4. **Fast Builds**: Ninja backend, much faster than Make
5. **Testing**: Integrated test framework
6. **IDE Support**: VSCode, CLion, etc.

### Consequences

**Positive**:
- Faster builds
- Cleaner build files
- Better cross-platform support
- Modern tooling

**Negative**:
- Learning curve (if team unfamiliar)
- Less common than CMake in C projects
- Some distributions may not package Meson

### Alternatives Considered

1. **CMake**: Most popular, but verbose, complex
2. **Autotools**: Legacy, slow, complex
3. **Plain Make**: Too manual, poor cross-platform

### References

- Original plan mentioned Meson as option

---

## Future Decisions (To Be Documented)

### ADR-009: QUIC Integration Strategy
**Status**: 🟡 Proposed
**Target**: v2.1.0 (future)

### ADR-010: Multi-Threading vs Multi-Process Architecture
**Status**: 🟡 Proposed
**Target**: TBD (out of scope for v2.0)

### ADR-011: HTTP/3 Support
**Status**: 🟡 Proposed
**Target**: v2.2.0 (future)

---

## Decision Review Process

### When to Create an ADR

Create an ADR for decisions that:
- Have significant architectural impact
- Affect multiple components
- Are hard to reverse
- Require stakeholder approval
- Set precedent for future decisions

### Review Schedule

- **Major Decisions**: Reviewed at sprint planning
- **ADR Document**: Reviewed quarterly
- **Superseded ADRs**: Never deleted, marked as superseded

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Next Review**: 2026-01-29 (quarterly)
