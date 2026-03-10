# Benchmarking Infrastructure - ioguard

## Overview

This document describes the benchmarking infrastructure for measuring and comparing TLS performance between GnuTLS and wolfSSL backends in the ioguard project.

## Purpose

The benchmarking infrastructure serves several critical purposes:

1. **Performance Baseline**: Establish GnuTLS performance baseline for comparison
2. **wolfSSL Validation**: Measure wolfSSL performance to validate migration viability
3. **Regression Detection**: Detect performance regressions during development
4. **GO/NO-GO Decision**: Provide objective data for migration decision (±10% threshold)
5. **Continuous Monitoring**: Track performance over time through CI/CD integration

## Components

### 1. benchmark.sh

**Location**: `/opt/projects/repositories/ioguard/tests/poc/benchmark.sh`

**Purpose**: Automated benchmark execution script

**Features**:
- Automatic certificate generation
- Backend-specific binary selection (GnuTLS/wolfSSL)
- Configurable test parameters (iterations, duration, output directory)
- System information capture (CPU, memory, kernel)
- Resource usage measurement (CPU%, memory MB)
- Automated server lifecycle management (start/stop)
- Error handling and cleanup

**Usage**:
```bash
# Test both backends (recommended)
./benchmark.sh

# Test specific backend
./benchmark.sh --backend gnutls
./benchmark.sh --backend wolfssl

# Custom iterations
./benchmark.sh --iterations 5000

# Custom output directory
./benchmark.sh --output ./my_results
```

**Parameters**:
- `--backend BACKEND`: Specify backend (gnutls or wolfssl), default: both
- `--iterations N`: Number of test iterations, default: 1000
- `--port PORT`: Server port, default: 4433
- `--output DIR`: Output directory, default: tests/poc/results
- `--help`: Show usage information

**Output Files**:
- `results_BACKEND_TIMESTAMP.json`: Benchmark results in JSON format
- `server_BACKEND_TIMESTAMP.log`: Server logs
- `resources_BACKEND_TIMESTAMP.txt`: System resource usage
- `server_BACKEND.pid`: Server process ID (temporary)

### 2. compare.sh

**Location**: `/opt/projects/repositories/ioguard/tests/poc/compare.sh`

**Purpose**: Compare benchmark results between backends

**Features**:
- JSON result parsing
- Performance delta calculation (percentage)
- GO/NO-GO decision logic (±10% threshold)
- Human-readable comparison report
- Exit code indication (0=GO, 1=NO-GO)

**Usage**:
```bash
# Compare latest results in directory
./compare.sh ./results

# Results will show:
# - GnuTLS baseline metrics
# - wolfSSL test metrics
# - Delta percentages for all metrics
# - GO/NO-GO verdict with rationale
```

**Output Format**:
```
=== TLS Performance Comparison ===

--- GnuTLS Results ---
Backend: gnutls
Handshake time: 2.376 ms

Size            Iterations   Throughput      Latency
(bytes)                      (MB/s)          (ms)
------------------------------------------------------------
1               50           0.00            0.851
64              50           3.57            0.034
256             50           14.04           0.035
...

--- wolfSSL Results ---
Backend: wolfssl
Handshake time: 2.123 ms
...

--- Performance Comparison ---
Handshake Time:
  GnuTLS:     2.376 ms
  wolfSSL:    2.123 ms
  Delta:      -10.6%

Average Performance Delta:
  Handshake:  -10.6%
  Throughput: +5.2%
  Latency:    -4.1%

GO/NO-GO Decision Criteria: Performance within ±10%
  ⚠ Handshake delta -10.6% exceeds ±10% threshold (marginal)
  ✓ Throughput delta +5.2% within acceptable range
  ✓ Latency delta -4.1% within acceptable range

✓ VERDICT: GO - wolfSSL performance is acceptable
```

### 3. PoC Server

**Location**: `/opt/projects/repositories/ioguard/poc-server-{gnutls,wolfssl}`

**Purpose**: TLS echo server for benchmarking

**Features**:
- Backend-agnostic implementation using abstraction layer
- TLS 1.3 support
- Configurable port and certificates
- Connection statistics tracking
- Graceful shutdown

**Built Automatically**: Run `make poc-both` to create both versions

### 4. PoC Client

**Location**: `/opt/projects/repositories/ioguard/poc-client-{gnutls,wolfssl}`

**Purpose**: TLS client for benchmarking

**Features**:
- Multiple payload size testing (1B, 64B, 256B, 1KB, 4KB, 16KB, 64KB)
- Configurable iterations
- JSON output format
- Latency and throughput measurement
- Handshake time measurement

**Built Automatically**: Run `make poc-both` to create both versions

## Metrics Collected

### 1. Handshake Performance
- **handshake_time_ms**: Time to complete TLS handshake (milliseconds)
- **Calculation**: Time from connection start to handshake completion
- **Significance**: Initial connection overhead

### 2. Throughput
- **throughput_mbps**: Data transfer rate (megabytes per second)
- **Measured for**: Multiple payload sizes (1B to 64KB)
- **Calculation**: (bytes_transferred * 2) / elapsed_seconds / 1024 / 1024
- **Significance**: Bulk data transfer performance

### 3. Latency
- **latency_ms**: Round-trip time per operation (milliseconds)
- **Measured for**: Each payload size
- **Calculation**: (elapsed_seconds * 1000) / iterations
- **Significance**: Request/response overhead

### 4. Resource Usage
- **CPU usage**: Process CPU utilization percentage
- **Memory usage**: RSS and VSZ in megabytes
- **Collection Method**: `ps` command sampling during benchmark execution

## JSON Output Format

The benchmark script outputs results in machine-readable JSON format:

```json
{
  "backend": "gnutls",
  "handshake_time_ms": 2.376,
  "tests": [
    {
      "size": 1,
      "iterations": 50,
      "elapsed_seconds": 0.042557,
      "throughput_mbps": 0.00,
      "latency_ms": 0.851
    },
    {
      "size": 64,
      "iterations": 50,
      "elapsed_seconds": 0.001708,
      "throughput_mbps": 3.57,
      "latency_ms": 0.034
    },
    ...
  ]
}
```

**Fields**:
- `backend`: TLS backend name ("gnutls" or "wolfssl")
- `handshake_time_ms`: TLS handshake duration
- `tests[]`: Array of test results for different payload sizes
  - `size`: Payload size in bytes
  - `iterations`: Number of iterations performed
  - `elapsed_seconds`: Total time for all iterations
  - `throughput_mbps`: Calculated throughput in MB/s
  - `latency_ms`: Calculated latency in milliseconds

## GO/NO-GO Decision Criteria

The benchmarking infrastructure implements automated GO/NO-GO decision logic:

### GO Criteria (ALL must be met):
- ✅ TLS connection establishes successfully
- ✅ Data echoes correctly (integrity verified)
- ✅ Handshake time within ±10% of GnuTLS baseline
- ✅ Throughput within ±10% of GnuTLS baseline
- ✅ Latency within ±10% of GnuTLS baseline
- ✅ No critical errors or crashes
- ✅ Memory usage acceptable (no leaks)

### NO-GO Criteria (ANY triggers NO-GO):
- ❌ Connection establishment fails
- ❌ Data corruption detected
- ❌ Performance regression >10%
- ❌ Critical errors or crashes
- ❌ Memory leaks detected
- ❌ Incompatibility issues

### Rationale for ±10% Threshold:
- **Measurement variance**: Network timing variability in benchmarks
- **Acceptable trade-off**: Minor performance differences acceptable for migration benefits
- **Statistical significance**: 10% is measurable and meaningful
- **Industry standard**: Common acceptance criteria for performance migrations

## Running Benchmarks

### Prerequisites

1. **Build PoC binaries**:
```bash
make poc-both
```

This creates:
- `poc-server-gnutls` + `poc-client-gnutls`
- `poc-server-wolfssl` + `poc-client-wolfssl`

2. **Ensure certificates exist**:
The benchmark script automatically generates self-signed certificates if they don't exist. Located in `/opt/projects/repositories/ioguard/tests/certs/`.

### Quick Start

**Test both backends (recommended)**:
```bash
cd tests/poc
./benchmark.sh
```

**Test specific backend**:
```bash
./benchmark.sh --backend gnutls
./benchmark.sh --backend wolfssl
```

**Compare results**:
```bash
./compare.sh ./results
```

### Advanced Usage

**Custom iterations for longer test**:
```bash
./benchmark.sh --iterations 10000
```

**Custom output directory**:
```bash
./benchmark.sh --output /tmp/my_benchmarks
./compare.sh /tmp/my_benchmarks
```

**Benchmark in container**:
```bash
podman run --rm \
  -v /opt/projects/repositories/ioguard:/workspace:Z \
  -w /workspace \
  localhost/ioguard-dev:latest \
  bash -c "cd tests/poc && ./benchmark.sh"
```

## Interpreting Results

### Good Performance Indicators
- **Low latency**: <5ms for small payloads
- **High throughput**: >100 MB/s for large payloads (16KB+)
- **Fast handshake**: <5ms for TLS 1.3
- **Low memory**: <100MB for server process
- **Consistent results**: Low standard deviation across runs

### Performance Comparison Guidelines
- **Handshake time**: wolfSSL often faster due to optimized implementation
- **Throughput**: Varies by payload size, both backends competitive
- **Latency**: Should be similar for both backends
- **Memory**: wolfSSL typically uses less memory
- **CPU**: Depends on cipher suite and hardware acceleration

### Example Comparison
```
Handshake Time:
  GnuTLS:  2.376 ms
  wolfSSL: 2.123 ms
  Delta:   -10.6% (wolfSSL faster)

Throughput (16KB):
  GnuTLS:  480.96 MB/s
  wolfSSL: 505.80 MB/s
  Delta:   +5.2% (wolfSSL faster)

Latency (1KB):
  GnuTLS:  0.037 ms
  wolfSSL: 0.035 ms
  Delta:   -5.4% (wolfSSL faster)
```

**Verdict**: GO - wolfSSL shows slightly better performance across all metrics while staying within ±10% threshold.

## Known Issues

### 1. wolfSSL Server + GnuTLS Client Shutdown
**Issue**: Connection terminates prematurely during benchmarking when wolfSSL server is used with GnuTLS client.

**Symptoms**:
- First handshake succeeds
- First data exchange works correctly
- Subsequent iterations fail with "Connection terminated prematurely"

**Root Cause**: TLS close_notify handling differences between wolfSSL server and GnuTLS client implementations.

**Status**: Documented, not blocking (3/4 test scenarios pass)

**Workaround**:
- Use GnuTLS server + wolfSSL client for cross-backend testing
- Use same-backend combinations (GnuTLS↔GnuTLS, wolfSSL↔wolfSSL)
- Both approaches provide valid performance data

**Impact**: Medium - Affects one specific test combination, but alternative configurations work correctly

**Planned Resolution**: Sprint 2 - Investigate wolfSSL shutdown sequence compatibility

### 2. wolfSSL Shared Library Path
**Issue**: wolfSSL shared library (libwolfssl.so.44) not in default LD_LIBRARY_PATH.

**Symptoms**:
- Error: "error while loading shared libraries: libwolfssl.so.44: cannot open shared object file"

**Root Cause**: wolfSSL installed in `/usr/local/lib` which isn't in default library search path.

**Status**: Fixed in benchmark.sh

**Solution**: benchmark.sh now sets `LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"` before executing binaries.

**Impact**: Low - Resolved

## Best Practices

### 1. System Preparation
- **Disable CPU frequency scaling**: `sudo cpupower frequency-set --governor performance`
- **Disable turbo boost**: Ensures consistent CPU performance
- **Close unnecessary applications**: Reduce system load variance
- **Use isolated CPU cores**: `taskset -c 0-3 ./benchmark.sh` (optional)

### 2. Benchmark Execution
- **Run multiple times**: Minimum 3 runs, take average
- **Use sufficient iterations**: At least 1000 for statistical significance
- **Warm up properly**: Let system stabilize before measurement
- **Document system state**: Record CPU/memory/kernel versions

### 3. Result Analysis
- **Check variance**: Standard deviation should be <5%
- **Compare like-to-like**: Same hardware, same system state
- **Consider payload sizes**: Both backends may have sweet spots
- **Review logs**: Check for errors or warnings

### 4. CI/CD Integration
- **Automate on PRs**: Run benchmarks for significant changes
- **Track trends**: Store historical results
- **Set thresholds**: Fail build on >10% regression
- **Generate reports**: Automatic comparison reports

## Troubleshooting

### Problem: Benchmark script fails to start server
**Solution**: Check if binaries exist (`ls poc-server-*`). Run `make poc-both` if missing.

### Problem: "Connection refused" errors
**Solution**: Server may not have started. Check server log in `results/server_BACKEND_TIMESTAMP.log`.

### Problem: Inconsistent results
**Solution**:
- Increase iterations (`--iterations 5000`)
- Disable CPU frequency scaling
- Run on bare metal instead of VM
- Close background applications

### Problem: Very low throughput
**Solution**:
- Check if hardware acceleration is enabled (AES-NI)
- Verify no CPU throttling
- Ensure sufficient network buffer sizes
- Test on localhost to eliminate network latency

### Problem: "Short send" warnings
**Solution**: This is informational, not an error. Indicates partial buffer writes on very large payloads (64KB). Results are still valid.

## Integration with Sprint Planning

### Sprint 1 Usage (Current)
- **Task 5**: Create benchmarking infrastructure (5 points) ✅
- **Task 6**: Run GnuTLS baseline (2 points)
- **Task 7**: Run wolfSSL validation and GO/NO-GO decision (3 points)

### Sprint 2+ Usage (Future)
- **Regression testing**: After each significant change
- **Performance optimization validation**: Measure improvements
- **CI/CD integration**: Automatic benchmark runs
- **Release validation**: Pre-release performance verification

## References

- **User Stories**: [US-008, US-009, US-010](/opt/projects/repositories/ioguard/docs/agile/USER_STORIES.md)
- **PoC README**: [tests/poc/README.md](/opt/projects/repositories/ioguard/tests/poc/README.md)
- **Sprint 1 Plan**: [docs/sprints/sprint-1/SPRINT_PLAN.md](/opt/projects/repositories/ioguard/docs/sprints/sprint-1/SPRINT_PLAN.md)
- **TLS Abstraction**: [docs/architecture/TLS_ABSTRACTION.md](/opt/projects/repositories/ioguard/docs/architecture/TLS_ABSTRACTION.md)

## License

Copyright (C) 2025 ioguard Contributors

This file is part of ioguard.

ioguard is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.
