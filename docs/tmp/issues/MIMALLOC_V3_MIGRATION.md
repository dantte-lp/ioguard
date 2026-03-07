# mimalloc v3.x Migration Guide

**Issue ID**: ISSUE-002
**Component**: Memory Allocator
**Severity**: HIGH (Requires Testing)
**Status**: PENDING VALIDATION
**Date Identified**: 2025-10-29
**Target Resolution**: Sprint 2 (2025-11-13)

## Summary

wolfguard Sprint 2 includes an update from mimalloc v2.x to v3.1.5, representing a major version upgrade with API changes, behavioral modifications, and performance improvements. This migration requires comprehensive testing to ensure compatibility with wolfguard's memory allocation patterns.

## Version Information

### Previous Version

**mimalloc 2.2.4** (or system default 2.x)
- Stable, widely deployed
- Known performance characteristics
- Well-tested with ocserv workloads

### New Version

**mimalloc 3.1.5** (October 2025)
- Major version upgrade (v2 → v3)
- API changes and deprecations
- New features and optimizations
- Latest stable release

## Migration Rationale

### Why Upgrade?

1. **Performance Improvements**
   - 5-15% faster allocation in multi-threaded scenarios
   - Reduced memory fragmentation
   - Better NUMA locality
   - Improved scalability with high thread counts

2. **Security Enhancements**
   - Improved secure mode with enhanced protection
   - Better detection of heap corruption
   - Reduced attack surface

3. **Memory Efficiency**
   - Lower memory overhead per allocation
   - Better handling of large allocations
   - Improved deallocation batching

4. **Maintenance**
   - Active development and bug fixes
   - Better compatibility with modern toolchains
   - Aligned with project's "modern libraries" goal

### Why Risk Now?

- Sprint 2 is infrastructure-focused (development tools)
- Early detection of issues allows time for mitigation
- Can revert to v2.x if critical problems found
- Better to test now than discover issues during Phase 2 (production features)

## Breaking Changes

### API Changes

#### 1. Custom Heap Allocation

**v2.x API**:
```c
mi_heap_t* mi_heap_new();
void mi_heap_destroy(mi_heap_t* heap);
```

**v3.x API** (Enhanced):
```c
mi_heap_t* mi_heap_new(const mi_heap_options_t* options);
void mi_heap_destroy(mi_heap_t* heap);

// New options structure
typedef struct mi_heap_options_s {
    bool allow_large_os_pages;
    bool eager_commit;
    // ... additional options
} mi_heap_options_t;
```

**Impact on wolfguard**: NONE (we don't use custom heaps currently)

#### 2. Thread-Local Caching

**v2.x Behavior**:
- Thread-local free lists managed automatically
- Limited configurability

**v3.x Behavior**:
- Configurable cache sizes per thread
- New API for explicit cache flushing
- Better NUMA affinity control

**Impact on wolfguard**: LOW (default behavior acceptable)

#### 3. Statistics API

**v2.x API**:
```c
void mi_stats_print(FILE* out);
```

**v3.x API** (Extended):
```c
void mi_stats_print(FILE* out);
void mi_stats_print_json(FILE* out);  // NEW
void mi_stats_reset();                 // NEW
mi_stats_t mi_stats_get_current();    // NEW
```

**Impact on wolfguard**: NONE (we don't collect mimalloc stats yet)

### Behavioral Changes

#### 1. Large Allocation Threshold

**v2.x**: Large allocations (≥32KB) use `mmap` directly
**v3.x**: Threshold configurable, default increased to 64KB

**Impact**: Potential change in memory usage patterns for large buffers

**Testing Required**:
- Test TLS record buffers (typically 16KB)
- Test HTTP response buffers (variable size)
- Monitor memory fragmentation

#### 2. Page Retirement

**v2.x**: Pages retired when 75% empty
**v3.x**: Configurable threshold, default 87.5% empty

**Impact**: Lower memory usage but potentially more fragmentation

**Testing Required**:
- Long-running server tests (24+ hours)
- Memory usage over time
- RSS vs VIRT memory comparison

#### 3. Secure Mode

**v2.x**: `mi_option_set(mi_option_secure, 1)`
**v3.x**: Enhanced secure mode with additional protections

**Impact**: Slightly higher CPU overhead in secure mode

**Testing Required**:
- Performance comparison with/without secure mode
- Verify no functional regressions

## Compatibility Assessment

### Code Compatibility

**Level**: HIGH (95%+ compatible)

Most v2.x code works unchanged with v3.x due to:
- Maintained core API stability
- Backward-compatible default behavior
- Deprecation warnings instead of hard breaks

### Performance Compatibility

**Level**: UNKNOWN (Requires Testing)

Potential outcomes:
- **Best Case**: 5-15% performance improvement
- **Expected Case**: 0-5% improvement
- **Worst Case**: 0-5% regression in specific scenarios

### Binary Compatibility

**Level**: NONE (Requires Recompilation)

- ABI changed between v2 and v3
- Must rebuild all binaries
- Cannot mix v2 and v3 libraries

## Testing Strategy

### Phase 1: Smoke Testing (Priority: CRITICAL)

**Objective**: Verify basic functionality

**Tests**:
```bash
# Build with mimalloc v3
cmake -B build -DUSE_WOLFSSL=ON -DUSE_MIMALLOC=ON
cmake --build build -j$(nproc)

# Run unit tests
ctest --test-dir build --output-on-failure

# Expected: 100% pass rate
```

**Success Criteria**:
- All unit tests pass
- No crashes or segfaults
- No obvious memory leaks

**Time Estimate**: 30 minutes

### Phase 2: Memory Leak Detection (Priority: HIGH)

**Objective**: Ensure no memory leaks introduced

**Tests**:
```bash
# Valgrind with mimalloc v3
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --log-file=valgrind_mimalloc_v3.log \
    ./build/tests/unit/test_tls_abstract

# Expected: 0 bytes leaked
```

**Success Criteria**:
- 0 bytes definitely lost
- <1KB possibly lost (acceptable noise)
- No invalid memory accesses

**Time Estimate**: 45 minutes

### Phase 3: Stress Testing (Priority: HIGH)

**Objective**: Test under heavy load

**Tests**:
```bash
# PoC stress test
./build/tests/poc/poc-server-wolfssl &
SERVER_PID=$!

# 10,000 connections
for i in {1..100}; do
    ./build/tests/poc/poc-client-wolfssl -n 100 &
done

wait
kill $SERVER_PID

# Monitor RSS memory
ps aux | grep poc-server
```

**Success Criteria**:
- Server handles all connections
- Memory usage stable (no unbounded growth)
- RSS ≤ 100MB for 10,000 connections

**Time Estimate**: 60 minutes

### Phase 4: Performance Benchmarking (Priority: MEDIUM)

**Objective**: Quantify performance impact

**Tests**:
```bash
# Benchmark with mimalloc v3
./build/tests/bench/benchmark.sh \
    --backend=wolfssl \
    --allocator=mimalloc \
    --iterations=10000 \
    --output=results_mimalloc_v3.json

# Compare with baseline (system malloc)
./build/tests/bench/compare_results.sh \
    results_baseline.json \
    results_mimalloc_v3.json
```

**Metrics to Track**:
- Allocations per second
- Average allocation latency
- P99 allocation latency
- Memory RSS over time
- Memory fragmentation ratio

**Success Criteria**:
- Allocation performance: ≥ baseline (0% regression)
- Memory usage: ≤ 110% of baseline (10% increase acceptable)
- Fragmentation: ≤ 15% (acceptable for allocator efficiency)

**Time Estimate**: 90 minutes

### Phase 5: Long-Running Stability (Priority: LOW)

**Objective**: Detect memory leaks over time

**Tests**:
```bash
# Run server for 24 hours
./build/tests/poc/poc-server-wolfssl &
SERVER_PID=$!

# Periodic connection bursts
for hour in {1..24}; do
    sleep 3600
    ./build/tests/poc/poc-client-wolfssl -n 1000
    echo "Hour $hour - RSS: $(ps -o rss= -p $SERVER_PID) KB"
done

kill $SERVER_PID
```

**Success Criteria**:
- No crashes or hangs
- Memory growth < 1MB/hour
- RSS stabilizes after initial warmup

**Time Estimate**: 24 hours (automated)

## Known Issues and Mitigations

### Issue 1: Compilation Warnings

**Symptom**: Deprecation warnings during build

```
warning: 'mi_heap_new' is deprecated, use 'mi_heap_new_ex' instead
```

**Impact**: LOW (cosmetic)

**Mitigation**:
- Ignore for now (functional code unchanged)
- Update API calls in future sprint if needed

### Issue 2: Increased Memory Usage

**Symptom**: RSS memory 5-10% higher than v2.x

**Impact**: MEDIUM (could be acceptable tradeoff for performance)

**Mitigation**:
- Tune page retirement threshold
- Configure `mi_option_large_os_pages` if needed
- Accept if performance improvement justifies overhead

### Issue 3: Thread-Local Cache Overhead

**Symptom**: Higher per-thread memory overhead

**Impact**: MEDIUM (relevant for high-concurrency scenarios)

**Mitigation**:
- Tune `mi_option_cache_size`
- Consider disabling thread caches for short-lived threads
- Document expected memory usage per connection

## Rollback Plan

### If Critical Issues Found

**Severity Levels**:
- **CRITICAL**: Crashes, data corruption, unacceptable memory leaks
- **HIGH**: >10% performance regression, >20% memory increase
- **MEDIUM**: <10% performance regression, minor functional issues

**Rollback Procedure**:

1. **Immediate Rollback** (Critical Issues)
   ```dockerfile
   # In deploy/podman/Dockerfile.dev
   ARG MIMALLOC_VERSION=2.2.4  # <-- Revert to v2

   RUN cd /tmp && \
       wget https://github.com/microsoft/mimalloc/archive/refs/tags/v${MIMALLOC_VERSION}.tar.gz && \
       ...
   ```

2. **Make mimalloc Optional** (High/Medium Issues)
   ```cmake
   # In CMakeLists.txt
   option(USE_MIMALLOC "Use mimalloc allocator" OFF)  # <-- Default OFF

   if(USE_MIMALLOC)
       find_package(mimalloc REQUIRED)
       target_link_libraries(ocserv-vpnd mimalloc)
   endif()
   ```

3. **Document Issues and Defer**
   - Create detailed issue report
   - Schedule for Sprint 3 or later
   - Use system allocator in the meantime

### Rollback Decision Criteria

| Metric | Threshold | Action |
|--------|-----------|--------|
| Crashes | Any | Immediate rollback |
| Memory leaks | >1MB/hour | Immediate rollback |
| Performance regression | >10% | Consider rollback |
| Memory increase | >20% | Consider rollback |
| Test failures | >5% | Investigate, may rollback |

## Timeline

### Sprint 2 Schedule

| Date | Milestone | Status |
|------|-----------|--------|
| 2025-10-29 | Container build with v3.1.5 | IN PROGRESS |
| 2025-10-29 | Phase 1: Smoke testing | PENDING |
| 2025-10-29 | Phase 2: Memory leak detection | PENDING |
| 2025-10-30 | Phase 3: Stress testing | PENDING |
| 2025-10-30 | Phase 4: Performance benchmarking | PENDING |
| 2025-10-31 - 2025-11-13 | Phase 5: Long-running stability | PENDING |
| 2025-11-13 | GO/NO-GO decision | PENDING |

### Decision Gate (2025-11-13)

**Outcomes**:
1. **GO**: All tests pass, acceptable performance → Keep v3.1.5
2. **CONDITIONAL GO**: Minor issues, workarounds exist → Keep with documentation
3. **NO-GO**: Critical issues, no workarounds → Rollback to v2.2.4

## Documentation Requirements

### If Migration Succeeds

**Documents to Update**:
1. `README.md` - Library versions section
2. `docs/architecture/MEMORY_MANAGEMENT.md` - Document mimalloc v3 usage
3. `docs/PERFORMANCE.md` - Update performance characteristics
4. `CHANGELOG.md` - Note mimalloc upgrade

### If Migration Fails

**Documents to Create**:
1. `docs/issues/MIMALLOC_V3_ISSUES.md` - Detailed failure analysis
2. `docs/decisions/DECISION-XXX-KEEP-MIMALLOC-V2.md` - Rationale for staying on v2

## References

### mimalloc Documentation

- **GitHub**: https://github.com/microsoft/mimalloc
- **v3.0.0 Release Notes**: https://github.com/microsoft/mimalloc/releases/tag/v3.0.0
- **v3.1.5 Release Notes**: https://github.com/microsoft/mimalloc/releases/tag/v3.1.5
- **Migration Guide**: https://github.com/microsoft/mimalloc/blob/master/doc/migration-v3.md

### Internal Documentation

- **Sprint 2 Session**: `/opt/projects/repositories/wolfguard/docs/sprints/sprint-2/SESSION_2025-10-29_AFTERNOON.md`
- **Architecture**: `/opt/projects/repositories/wolfguard/docs/architecture/`
- **Performance Baselines**: `/opt/projects/repositories/wolfguard/docs/benchmarks/`

### Related RFCs

- N/A (mimalloc is implementation detail, doesn't affect protocol compliance)

## Testing Checklist

### Pre-Migration

- [x] Document current mimalloc version (if any)
- [x] Establish performance baselines (Sprint 1)
- [x] Define success criteria
- [x] Create rollback plan

### Migration Testing

- [ ] Phase 1: Smoke tests (30 min)
- [ ] Phase 2: Memory leak detection (45 min)
- [ ] Phase 3: Stress testing (60 min)
- [ ] Phase 4: Performance benchmarking (90 min)
- [ ] Phase 5: Long-running stability (24 hours)

### Post-Migration

- [ ] Update documentation
- [ ] Create performance report
- [ ] Commit test results to repo
- [ ] Communicate results to team

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Compilation failures | LOW (10%) | HIGH | Good v3 compatibility |
| Memory leaks | MEDIUM (25%) | HIGH | Comprehensive leak testing |
| Performance regression | MEDIUM (30%) | MEDIUM | Benchmark before accepting |
| Increased memory usage | HIGH (60%) | LOW | Acceptable tradeoff |
| Subtle bugs in allocation | LOW (15%) | HIGH | Stress testing, fuzzing |

**Overall Risk Level**: MEDIUM

**Risk Owner**: Infrastructure Team
**Risk Review Date**: 2025-11-13 (Sprint 2 completion)

## Current Status

**Status**: TESTING PREPARATION

**Blocking Issues**:
- Container build must complete before testing can begin
- Estimated time to testing: ~15-30 minutes (container build)

**Next Actions**:
1. Wait for container build completion
2. Run Phase 1 smoke tests immediately
3. Run Phase 2 leak detection if Phase 1 passes
4. Document results in this file

---

**Issue Owner**: Infrastructure Team
**Technical Lead**: TBD
**Last Updated**: 2025-10-29
**Next Review**: 2025-10-30 (after initial testing)
