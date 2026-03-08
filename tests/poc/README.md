# TLS Proof of Concept - ringwall

This directory contains the Proof of Concept (PoC) implementation for validating the TLS abstraction layer and comparing GnuTLS vs wolfSSL performance.

## Purpose

The PoC serves to:
1. Validate TLS abstraction layer design
2. Implement reference backends (GnuTLS and wolfSSL)
3. Establish performance baselines
4. Make GO/NO-GO decision for full migration

## Files

### Source Code

- **tls_poc_server.c** - TLS echo server implementation
  - Accepts TLS connections
  - Echoes received data back to client
  - Collects performance statistics
  - Supports both GnuTLS and wolfSSL backends

- **tls_poc_client.c** - TLS client for testing
  - Connects to TLS server
  - Tests multiple payload sizes
  - Measures handshake time, throughput, latency
  - Outputs results in JSON format

### Scripts

- **benchmark.sh** - Automated benchmarking script
  - Generates test certificates
  - Starts/stops server automatically
  - Runs comprehensive benchmarks
  - Collects system resource metrics

- **compare.sh** - Results comparison script
  - Parses JSON benchmark results
  - Calculates performance deltas
  - Applies GO/NO-GO decision criteria (±10%)
  - Generates comparison reports

## Build Instructions

### Prerequisites

```bash
# Install dependencies (example for Debian/Ubuntu)
sudo apt-get install -y \
    build-essential \
    gcc-14 \
    libgnutls28-dev \
    libwolfssl-dev \
    pkg-config \
    openssl

# For C23 support, ensure GCC 14+ or Clang 18+
gcc --version  # Should be 14.0 or higher
```

### Compilation

**Option 1: Manual compilation (GnuTLS backend)**

```bash
gcc-14 -std=c23 -Wall -Wextra -O2 \
    -I../../src \
    -o tls_poc_server \
    tls_poc_server.c \
    ../../src/crypto/tls_gnutls.c \
    $(pkg-config --cflags --libs gnutls)

gcc-14 -std=c23 -Wall -Wextra -O2 \
    -I../../src \
    -o tls_poc_client \
    tls_poc_client.c \
    ../../src/crypto/tls_gnutls.c \
    $(pkg-config --cflags --libs gnutls)
```

**Option 2: Manual compilation (wolfSSL backend)**

```bash
gcc-14 -std=c23 -Wall -Wextra -O2 \
    -I../../src \
    -o tls_poc_server \
    tls_poc_server.c \
    ../../src/crypto/tls_wolfssl.c \
    $(pkg-config --cflags --libs wolfssl)

gcc-14 -std=c23 -Wall -Wextra -O2 \
    -I../../src \
    -o tls_poc_client \
    tls_poc_client.c \
    ../../src/crypto/tls_wolfssl.c \
    $(pkg-config --cflags --libs wolfssl)
```

**Option 3: Using Makefile (to be created)**

```bash
# Build with GnuTLS backend
make BACKEND=gnutls

# Build with wolfSSL backend
make BACKEND=wolfssl

# Build both
make all
```

## Usage

### Manual Testing

**Step 1: Generate test certificates**

```bash
# Generate CA
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout test_ca.pem \
    -out test_ca.pem \
    -days 365 \
    -subj "/CN=Test CA"

# Generate server certificate
openssl req -newkey rsa:2048 -nodes \
    -keyout test_key.pem \
    -out test_cert.csr \
    -subj "/CN=localhost"

openssl x509 -req \
    -in test_cert.csr \
    -CA test_ca.pem \
    -CAkey test_ca.pem \
    -CAcreateserial \
    -out test_cert.pem \
    -days 365

rm test_cert.csr
```

**Step 2: Start server**

```bash
# GnuTLS backend
./tls_poc_server \
    --backend gnutls \
    --port 4433 \
    --cert test_cert.pem \
    --key test_key.pem \
    --verbose

# wolfSSL backend
./tls_poc_server \
    --backend wolfssl \
    --port 4433 \
    --cert test_cert.pem \
    --key test_key.pem \
    --verbose
```

**Step 3: Run client (in another terminal)**

```bash
# GnuTLS backend
./tls_poc_client \
    --backend gnutls \
    --host 127.0.0.1 \
    --port 4433 \
    --iterations 100 \
    --verbose

# wolfSSL backend
./tls_poc_client \
    --backend wolfssl \
    --host 127.0.0.1 \
    --port 4433 \
    --iterations 100 \
    --verbose

# JSON output for automated analysis
./tls_poc_client \
    --backend gnutls \
    --port 4433 \
    --iterations 1000 \
    --json > results_gnutls.json
```

### Automated Benchmarking

**Run full benchmark suite**

```bash
# Benchmark both backends (recommended)
./benchmark.sh

# Benchmark specific backend
./benchmark.sh --backend gnutls
./benchmark.sh --backend wolfssl

# Custom iterations
./benchmark.sh --iterations 5000

# Custom output directory
./benchmark.sh --output ./my_results
```

**Compare results**

```bash
# Compare latest results
./compare.sh results/

# Output example:
# === TLS Performance Comparison ===
#
# --- GnuTLS Results ---
# Backend: gnutls
# Handshake time: 2.345 ms
#
# Size            Iterations   Throughput      Latency
# (bytes)                      (MB/s)          (ms)
# ------------------------------------------------------------
# 1               1000         0.05            0.020
# 64              1000         2.50            0.025
# 1024            1000        35.20            0.029
# ...
#
# --- wolfSSL Results ---
# Backend: wolfssl
# Handshake time: 2.123 ms
#
# --- Performance Comparison ---
# Handshake Time:
#   GnuTLS:     2.345 ms
#   wolfSSL:    2.123 ms
#   Delta:      -9.47%
#
# Average Performance Delta:
#   Handshake:   -9.47%
#   Throughput:  +5.23%
#   Latency:     -4.12%
#
# GO/NO-GO Decision Criteria: Performance within ±10%
#   ✓ Handshake delta -9.47% within acceptable range
#   ✓ Throughput delta +5.23% within acceptable range
#   ✓ Latency delta -4.12% within acceptable range
#
# ✓ VERDICT: GO - wolfSSL performance is acceptable
```

## Performance Metrics

The PoC measures the following metrics:

### Handshake Performance
- **Handshake time** (ms) - Time to complete TLS handshake
- **Connections/sec** - Handshake rate

### Data Transfer Performance
- **Throughput** (MB/s) - Data transfer rate
  - Measured for multiple payload sizes (1B to 64KB)
  - Includes both send and receive
- **Latency** (ms) - Round-trip time per operation
  - Per-payload-size measurement
  - Average over multiple iterations

### Resource Usage
- **CPU usage** (%) - Server process CPU utilization
- **Memory usage** (MB) - RSS and VSZ
- **System calls** - Via strace (optional)

## GO/NO-GO Criteria

The PoC determines GO/NO-GO decision based on:

**GO Criteria** (all must be met):
- ✅ TLS connection establishes successfully
- ✅ Data echoes correctly (integrity verified)
- ✅ Handshake time within ±10% of GnuTLS
- ✅ Throughput within ±10% of GnuTLS
- ✅ Latency within ±10% of GnuTLS
- ✅ No critical errors or crashes
- ✅ Memory usage acceptable

**NO-GO Criteria** (any triggers NO-GO):
- ❌ Connection establishment fails
- ❌ Data corruption detected
- ❌ Performance regression >10%
- ❌ Critical errors or crashes
- ❌ Memory leaks detected
- ❌ Incompatibility issues

## Test Payload Sizes

The client tests the following payload sizes:

| Size | Description | Purpose |
|------|-------------|---------|
| 1 B | Minimum | Edge case testing |
| 64 B | Small | Typical control messages |
| 256 B | Medium | Short HTTP responses |
| 1 KB | Standard | Common packet size |
| 4 KB | Page | Typical memory page |
| 16 KB | Large | TLS record max |
| 64 KB | Maximum | Stress testing |

## Expected Results

### Baseline (GnuTLS)

Typical performance on modern hardware (example):

- **Handshake time**: 2-5 ms
- **Throughput (1KB)**: 30-50 MB/s
- **Throughput (16KB)**: 80-120 MB/s
- **Latency (1KB)**: 0.02-0.05 ms
- **Connections/sec**: 200-500

### wolfSSL Target

wolfSSL should achieve:

- **Handshake time**: ±10% of GnuTLS
- **Throughput**: ±10% of GnuTLS (or better)
- **Latency**: ±10% of GnuTLS (or better)

Note: wolfSSL is often faster due to optimized assembly implementations (AES-NI, etc.)

## Troubleshooting

### Build Issues

**Error: C23 features not supported**
```
Solution: Use GCC 14+ or Clang 18+
gcc-14 -std=c23 ...
```

**Error: gnutls.h not found**
```
Solution: Install GnuTLS development headers
sudo apt-get install libgnutls28-dev
```

**Error: wolfssl/ssl.h not found**
```
Solution: Install wolfSSL development headers
sudo apt-get install libwolfssl-dev
# or build from source: https://github.com/wolfSSL/wolfssl
```

### Runtime Issues

**Error: Failed to load certificate**
```
Solution: Generate test certificates (see above)
./benchmark.sh  # Generates automatically
```

**Error: Connection refused**
```
Solution: Ensure server is running
ps aux | grep tls_poc_server
```

**Error: Handshake failed**
```
Solution: Check certificate/key match
openssl x509 -noout -modulus -in test_cert.pem | openssl md5
openssl rsa -noout -modulus -in test_key.pem | openssl md5
# Should produce same hash
```

### Performance Issues

**Low throughput**
```
Possible causes:
1. CPU frequency scaling enabled
   Solution: sudo cpupower frequency-set --governor performance

2. Network loopback buffering
   Solution: Increase socket buffer sizes

3. Virtualization overhead
   Solution: Test on bare metal
```

**High latency variance**
```
Possible causes:
1. Background processes
   Solution: Use isolated CPU cores (taskset)

2. Interrupt handling
   Solution: Disable IRQ balancing

3. Not enough iterations
   Solution: Increase --iterations parameter
```

## Next Steps

After successful PoC validation:

1. **US-011**: Implement priority string parser
2. **US-012**: Implement session caching
3. **US-013**: Add DTLS support
4. **US-014**: Certificate verification
5. **US-017**: Test with Cisco Secure Client

See `/opt/projects/repositories/ringwall/docs/agile/USER_STORIES.md` for full roadmap.

## References

- **TLS Abstraction API**: ../../src/crypto/tls_abstract.h
- **GnuTLS Manual**: https://gnutls.org/manual/
- **wolfSSL Manual**: https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
- **wolfSSL Examples**: https://github.com/wolfSSL/wolfssl-examples
- **User Stories**: ../../docs/agile/USER_STORIES.md
- **API Audit**: ../../docs/architecture/GNUTLS_API_AUDIT.md
- **Sprint Progress**: ../../docs/SPRINT0_PROGRESS.md

## Contributing

When modifying PoC code:

1. Maintain C23 compliance
2. Update benchmarks if metrics change
3. Document performance impacts
4. Follow existing code style
5. Add error handling for new features
6. Update this README

## License

Copyright (C) 2025 ringwall Contributors

This file is part of ringwall.

ringwall is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.
