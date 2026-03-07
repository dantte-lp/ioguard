# Технический план реализации wolfguard

## Executive Summary для GitHub README

После комплексного исследования современных VPN архитектур (ExpressVPN Lightway, CloudFlare WARP, WireGuard, Tailscale), рекомендуется **модернизация на C23 с современными библиотеками**, а не полное переписывание на Rust/Go.

### Почему не Rust?
- **Временные затраты**: 12+ месяцев на полное переписывание
- **Совместимость**: Потеря обратной совместимости с OpenConnect экосистемой
- **Интеграция**: Сложность FFI с существующими C библиотеками
- **Команда**: Необходимость найма Rust разработчиков

### Почему не минимальный рефакторинг?
- **Архитектурный потолок**: Модель "процесс на пользователя" не масштабируется
- **Производительность**: Отставание от современных решений на 40-60%
- **Конкуренция**: WireGuard и Lightway уже захватывают рынок

### Оптимальный путь: Modern C + Event-driven архитектура
- **Баланс рисков**: Постепенная миграция с сохранением совместимости
- **Proven подход**: CloudFlare, NGINX, HAProxy используют похожую архитектуру
- **Производительность**: Достижимы 100K+ соединений и 10+ Gb/s
- **Команда**: Существующие C разработчики могут адаптироваться

## Детальная техническая архитектура

### 1. Core Event Loop Architecture

```c
// include/wolfguard.h
#ifndef WOLFGUARD_H
#define WOLFGUARD_H

#include <uv.h>
#include <wolfssl/ssl.h>
#include <wolfssl/dtls.h>
#include <stdatomic.h>
#include <stdbool.h>

// Configuration constants
#define OCSERV_MAX_WORKERS 64
#define OCSERV_CONN_POOL_SIZE 4096
#define OCSERV_BUFFER_SIZE 65536
#define OCSERV_BACKLOG 512

// Connection states
typedef enum {
    CONN_STATE_INIT,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_AUTH,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_REKEYING,
    CONN_STATE_CLOSING,
    CONN_STATE_CLOSED
} conn_state_t;

// Forward declarations
typedef struct ocserv_server ocserv_server_t;
typedef struct ocserv_worker ocserv_worker_t;
typedef struct ocserv_connection ocserv_connection_t;

// Connection structure with zero-copy buffers
struct ocserv_connection {
    // Identification
    uint64_t id;
    uint32_t client_ip;
    uint16_t client_port;
    
    // State machine
    conn_state_t state;
    atomic_int ref_count;
    
    // Network handles
    uv_tcp_t tcp_handle;
    uv_udp_t dtls_handle;
    uv_timer_t timeout_timer;
    
    // Crypto context
    WOLFSSL *ssl;
    WOLFSSL *dtls;
    
    // Ring buffers for zero-copy
    struct {
        uint8_t *data;
        size_t size;
        size_t read_idx;
        size_t write_idx;
    } rx_ring, tx_ring;
    
    // Statistics
    struct {
        uint64_t bytes_in;
        uint64_t bytes_out;
        uint64_t packets_in;
        uint64_t packets_out;
        uint64_t last_activity;
    } stats;
    
    // Back-references
    ocserv_worker_t *worker;
    struct ocserv_connection *next;
    struct ocserv_connection *prev;
};

// Worker thread context
struct ocserv_worker {
    uint32_t id;
    pthread_t thread;
    
    // Event loop
    uv_loop_t *loop;
    uv_async_t async;
    
    // Connection management
    ocserv_connection_t *conn_pool;
    ocserv_connection_t *active_conns;
    ocserv_connection_t *free_conns;
    atomic_int conn_count;
    
    // Statistics
    struct {
        atomic_uint64_t total_connections;
        atomic_uint64_t active_connections;
        atomic_uint64_t bytes_processed;
    } stats;
    
    // Back-reference
    ocserv_server_t *server;
};

// Main server structure
struct ocserv_server {
    // Configuration
    struct {
        char *bind_addr;
        uint16_t tcp_port;
        uint16_t dtls_port;
        uint32_t num_workers;
        uint32_t conn_timeout;
        char *cert_file;
        char *key_file;
    } config;
    
    // Workers
    ocserv_worker_t *workers;
    uint32_t num_workers;
    atomic_int next_worker;
    
    // Crypto contexts
    WOLFSSL_CTX *tls_ctx;
    WOLFSSL_CTX *dtls_ctx;
    
    // Main loop for control plane
    uv_loop_t *main_loop;
    uv_tcp_t tcp_server;
    uv_udp_t dtls_server;
    
    // Shared state
    atomic_bool running;
    pthread_rwlock_t config_lock;
};

#endif // WOLFGUARD_H
```

### 2. Event Loop Implementation

```c
// src/event_loop.c
#include "wolfguard.h"
#include <mimalloc.h>

// Per-worker event loop
static void* worker_thread(void *arg) {
    ocserv_worker_t *worker = (ocserv_worker_t*)arg;
    
    // Set CPU affinity for NUMA optimization
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    // Initialize worker's event loop
    worker->loop = mi_malloc(sizeof(uv_loop_t));
    uv_loop_init(worker->loop);
    
    // Pre-allocate connection pool
    worker->conn_pool = mi_calloc(OCSERV_CONN_POOL_SIZE, 
                                  sizeof(ocserv_connection_t));
    
    // Initialize free list
    for (int i = 0; i < OCSERV_CONN_POOL_SIZE - 1; i++) {
        worker->conn_pool[i].next = &worker->conn_pool[i + 1];
    }
    worker->free_conns = &worker->conn_pool[0];
    
    // Run event loop
    while (atomic_load(&worker->server->running)) {
        uv_run(worker->loop, UV_RUN_DEFAULT);
    }
    
    // Cleanup
    uv_loop_close(worker->loop);
    mi_free(worker->loop);
    
    return NULL;
}

// Connection allocation from pool
static ocserv_connection_t* conn_alloc(ocserv_worker_t *worker) {
    ocserv_connection_t *conn = worker->free_conns;
    if (conn) {
        worker->free_conns = conn->next;
        memset(conn, 0, sizeof(*conn));
        conn->worker = worker;
        conn->id = atomic_fetch_add(&worker->stats.total_connections, 1);
        atomic_fetch_add(&worker->conn_count, 1);
    }
    return conn;
}

// Connection deallocation to pool
static void conn_free(ocserv_connection_t *conn) {
    ocserv_worker_t *worker = conn->worker;
    
    // Cleanup SSL contexts
    if (conn->ssl) {
        wolfSSL_free(conn->ssl);
    }
    if (conn->dtls) {
        wolfSSL_free(conn->dtls);
    }
    
    // Free ring buffers
    if (conn->rx_ring.data) {
        mi_free(conn->rx_ring.data);
    }
    if (conn->tx_ring.data) {
        mi_free(conn->tx_ring.data);
    }
    
    // Return to free list
    conn->next = worker->free_conns;
    worker->free_conns = conn;
    atomic_fetch_sub(&worker->conn_count, 1);
}
```

### 3. Network I/O with Zero-Copy

```c
// src/network_io.c
#include "wolfguard.h"
#include <sys/sendfile.h>
#include <sys/uio.h>

// TCP accept callback with SO_REUSEPORT load balancing
static void on_tcp_accept(uv_stream_t *server, int status) {
    if (status < 0) {
        return;
    }
    
    ocserv_server_t *srv = (ocserv_server_t*)server->data;
    
    // Round-robin worker assignment
    uint32_t worker_id = atomic_fetch_add(&srv->next_worker, 1) 
                         % srv->num_workers;
    ocserv_worker_t *worker = &srv->workers[worker_id];
    
    // Allocate connection from pool
    ocserv_connection_t *conn = conn_alloc(worker);
    if (!conn) {
        // Pool exhausted, reject connection
        uv_tcp_t *client = mi_malloc(sizeof(uv_tcp_t));
        uv_tcp_init(srv->main_loop, client);
        uv_accept(server, (uv_stream_t*)client);
        uv_close((uv_handle_t*)client, NULL);
        return;
    }
    
    // Initialize TCP handle in worker's loop
    uv_tcp_init(worker->loop, &conn->tcp_handle);
    conn->tcp_handle.data = conn;
    
    // Accept connection
    if (uv_accept(server, (uv_stream_t*)&conn->tcp_handle) == 0) {
        // Start TLS handshake
        conn->state = CONN_STATE_TLS_HANDSHAKE;
        start_tls_handshake(conn);
    } else {
        conn_free(conn);
    }
}

// Zero-copy send using sendmsg with MSG_ZEROCOPY
static int send_zerocopy(ocserv_connection_t *conn, 
                         const void *data, size_t len) {
    struct msghdr msg = {0};
    struct iovec iov[1];
    
    iov[0].iov_base = (void*)data;
    iov[0].iov_len = len;
    
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    
    int fd = conn->tcp_handle.io_watcher.fd;
    ssize_t sent = sendmsg(fd, &msg, MSG_ZEROCOPY | MSG_NOSIGNAL);
    
    if (sent > 0) {
        atomic_fetch_add(&conn->stats.bytes_out, sent);
    }
    
    return sent;
}

// DTLS with io_uring for batch processing
#ifdef HAVE_IO_URING
#include <liburing.h>

static void dtls_batch_send(ocserv_worker_t *worker) {
    struct io_uring ring;
    io_uring_queue_init(256, &ring, IORING_SETUP_SQPOLL);
    
    ocserv_connection_t *conn = worker->active_conns;
    while (conn) {
        if (conn->tx_ring.read_idx != conn->tx_ring.write_idx) {
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            
            size_t len = conn->tx_ring.write_idx - conn->tx_ring.read_idx;
            io_uring_prep_send(sqe, conn->dtls_handle.io_watcher.fd,
                             &conn->tx_ring.data[conn->tx_ring.read_idx],
                             len, MSG_DONTWAIT);
            sqe->user_data = (uint64_t)conn;
        }
        conn = conn->next;
    }
    
    io_uring_submit(&ring);
    
    // Process completions
    struct io_uring_cqe *cqe;
    unsigned head;
    io_uring_for_each_cqe(&ring, head, cqe) {
        conn = (ocserv_connection_t*)cqe->user_data;
        if (cqe->res > 0) {
            conn->tx_ring.read_idx += cqe->res;
        }
    }
    
    io_uring_queue_exit(&ring);
}
#endif
```

### 4. Modern Crypto with wolfSSL

```c
// src/crypto.c
#include "wolfguard.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

// Initialize wolfSSL with hardware acceleration
int crypto_init(ocserv_server_t *server) {
    wolfSSL_Init();
    
    // Enable debugging in dev mode
    #ifdef DEBUG
    wolfSSL_Debugging_ON();
    #endif
    
    // Create TLS 1.3 context
    server->tls_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!server->tls_ctx) {
        return -1;
    }
    
    // Create DTLS 1.3 context
    server->dtls_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!server->dtls_ctx) {
        return -1;
    }
    
    // Configure contexts
    for (WOLFSSL_CTX *ctx : {server->tls_ctx, server->dtls_ctx}) {
        // Load certificates
        wolfSSL_CTX_use_certificate_file(ctx, server->config.cert_file,
                                        SSL_FILETYPE_PEM);
        wolfSSL_CTX_use_PrivateKey_file(ctx, server->config.key_file,
                                       SSL_FILETYPE_PEM);
        
        // Enable hardware acceleration
        wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
        wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_X25519);
        
        // Set cipher suites (prioritize AEAD)
        wolfSSL_CTX_set_cipher_list(ctx,
            "TLS13-AES128-GCM-SHA256:"
            "TLS13-AES256-GCM-SHA384:"
            "TLS13-CHACHA20-POLY1305-SHA256");
        
        // Enable session resumption
        wolfSSL_CTX_UseSessionTicket(ctx);
        
        // Set ALPN for protocol negotiation
        unsigned char alpn_list[] = {
            8, 'o', 'c', 's', 'e', 'r', 'v', '/', '2'
        };
        wolfSSL_CTX_set_alpn_protos(ctx, alpn_list, sizeof(alpn_list));
    }
    
    return 0;
}

// Non-blocking TLS handshake
static void tls_handshake_cb(uv_stream_t *stream, 
                            ssize_t nread, const uv_buf_t *buf) {
    ocserv_connection_t *conn = (ocserv_connection_t*)stream->data;
    
    if (nread > 0) {
        // Feed data to wolfSSL
        wolfSSL_SetIOReadCtx(conn->ssl, buf->base);
        wolfSSL_SetIOReadSz(conn->ssl, nread);
        
        int ret = wolfSSL_accept(conn->ssl);
        if (ret == SSL_SUCCESS) {
            conn->state = CONN_STATE_AUTH;
            start_authentication(conn);
        } else if (ret != SSL_ERROR_WANT_READ) {
            // Handshake failed
            conn_close(conn);
        }
    }
}
```

### 5. High-Performance Data Path

```c
// src/datapath.c
#include "wolfguard.h"
#include <linux/if_tun.h>
#include <sys/ioctl.h>

// TUN device with multi-queue support
typedef struct {
    int fd[OCSERV_MAX_WORKERS];
    char name[IFNAMSIZ];
    uint32_t mtu;
} tun_device_t;

// Initialize multi-queue TUN for RSS
static int tun_init_multiqueue(tun_device_t *tun, uint32_t queues) {
    struct ifreq ifr = {0};
    
    for (uint32_t i = 0; i < queues; i++) {
        tun->fd[i] = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (tun->fd[i] < 0) {
            return -1;
        }
        
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
        if (i == 0) {
            // First queue creates the interface
            snprintf(ifr.ifr_name, IFNAMSIZ, "ocserv%d", getpid());
        } else {
            // Subsequent queues attach to existing interface
            strcpy(ifr.ifr_name, tun->name);
        }
        
        if (ioctl(tun->fd[i], TUNSETIFF, &ifr) < 0) {
            return -1;
        }
        
        if (i == 0) {
            strcpy(tun->name, ifr.ifr_name);
        }
    }
    
    return 0;
}

// eBPF XDP program for fast path
#ifdef HAVE_XDP
static const char *xdp_prog = R"(
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int ocserv_xdp_fast_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IP packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Only process UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    // Parse UDP header
    struct udphdr *udp = (void*)((char*)ip + ip->ihl * 4);
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;
    
    // Check for DTLS port
    if (udp->dest == htons(443)) {
        // Fast path: redirect to worker queue
        return bpf_redirect_map(&worker_map, 
                               ctx->rx_queue_index, 0);
    }
    
    return XDP_PASS;
}
)";

static int load_xdp_program(const char *ifname) {
    // Compile and load eBPF program
    // ... (implementation details)
    return 0;
}
#endif
```

### 6. Production Configuration

```toml
# config/wolfguard.toml

[server]
bind = "0.0.0.0"
tcp_port = 443
dtls_port = 443
workers = 0  # 0 = auto-detect CPU cores

[crypto]
cert_file = "/etc/ocserv/server.crt"
key_file = "/etc/ocserv/server.key"
dh_file = "/etc/ocserv/dh.pem"
cipher_priority = "SECURE256:+SECURE128:-VERS-TLS-ALL:+VERS-DTLS1.3"

[performance]
conn_pool_size = 4096
buffer_size = 65536
keepalive_interval = 30
session_timeout = 86400
enable_zero_copy = true
enable_xdp = true
enable_multiqueue = true

[auth]
method = "pam"  # pam, radius, ldap, oauth2
pam_service = "ocserv"
two_factor = true

[network]
ipv4_network = "192.168.100.0/24"
ipv6_network = "fd00::/64"
dns_servers = ["1.1.1.1", "1.0.0.1"]
mtu = 1400
enable_compression = true

[monitoring]
stats_port = 9090
enable_prometheus = true
log_level = "info"
log_file = "/var/log/ocserv/ocserv.log"
```

### 7. Build System (CMake)

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.28)
project(wolfguard 
        VERSION 2.0.0
        LANGUAGES C)

# C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler flags
add_compile_options(
    -Wall -Wextra -Wpedantic
    -O3 -march=native -mtune=native
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv>=1.48)
pkg_check_modules(WOLFSSL REQUIRED wolfssl>=5.7)
find_package(Threads REQUIRED)

# Optional features
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_XDP "Enable XDP fast path" ON)
option(ENABLE_IO_URING "Enable io_uring support" ON)

# Source files
set(SOURCES
    src/main.c
    src/event_loop.c
    src/network_io.c
    src/crypto.c
    src/datapath.c
    src/auth.c
    src/config.c
    src/logging.c
)

# Main executable
add_executable(wolfguard ${SOURCES})

# Link libraries
target_link_libraries(wolfguard
    PRIVATE
        ${LIBUV_LIBRARIES}
        ${WOLFSSL_LIBRARIES}
        Threads::Threads
        mimalloc
        llhttp
        cjson
)

# Include directories
target_include_directories(wolfguard
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${LIBUV_INCLUDE_DIRS}
        ${WOLFSSL_INCLUDE_DIRS}
)

# Sanitizers
if(ENABLE_ASAN)
    target_compile_options(wolfguard PRIVATE -fsanitize=address)
    target_link_options(wolfguard PRIVATE -fsanitize=address)
endif()

if(ENABLE_UBSAN)
    target_compile_options(wolfguard PRIVATE -fsanitize=undefined)
    target_link_options(wolfguard PRIVATE -fsanitize=undefined)
endif()

# Installation
install(TARGETS wolfguard DESTINATION bin)
install(FILES config/wolfguard.toml DESTINATION /etc/ocserv)
install(FILES systemd/wolfguard.service 
        DESTINATION /lib/systemd/system)

# Testing
enable_testing()
add_subdirectory(tests)

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    doxygen_add_docs(doc ${CMAKE_SOURCE_DIR}/include)
endif()
```

### 8. Performance Testing

```c
// tests/benchmark.c
#include <criterion/criterion.h>
#include <criterion/parameterized.h>
#include "wolfguard.h"

// Benchmark connection establishment
Test(performance, connection_rate) {
    ocserv_server_t server = {0};
    server_init(&server);
    
    const int num_connections = 10000;
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < num_connections; i++) {
        // Simulate connection
        ocserv_connection_t *conn = create_test_connection(&server);
        cr_assert_not_null(conn);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_nsec - start.tv_nsec) / 1e9;
    double rate = num_connections / elapsed;
    
    cr_log_info("Connection rate: %.0f conn/sec", rate);
    cr_assert_gt(rate, 5000.0, "Should handle >5000 conn/sec");
}

// Benchmark throughput
Test(performance, throughput) {
    const size_t data_size = 1024 * 1024 * 1024; // 1GB
    uint8_t *data = aligned_alloc(4096, data_size);
    memset(data, 'A', data_size);
    
    ocserv_connection_t conn = {0};
    setup_test_connection(&conn);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    size_t sent = send_data(&conn, data, data_size);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput = (sent * 8.0) / elapsed / 1e9; // Gbps
    
    cr_log_info("Throughput: %.2f Gbps", throughput);
    cr_assert_gt(throughput, 5.0, "Should achieve >5 Gbps");
    
    free(data);
}
```

### 9. GitHub Actions CI/CD

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-24.04
    
    strategy:
      matrix:
        compiler: [gcc-13, clang-17]
        build_type: [Debug, Release]
        
    steps:
    - uses: actions/checkout@v4
      with:
        submodules: recursive
    
    - name: Install Dependencies
      run: |
        sudo apt update
        sudo apt install -y \
          libuv1-dev \
          libwolfssl-dev \
          libllhttp-dev \
          libcjson-dev \
          libcriterion-dev \
          valgrind
    
    - name: Configure
      env:
        CC: ${{ matrix.compiler }}
      run: |
        cmake -B build \
          -DCMAKE_BUILD_TYPE=${{ matrix.build_type }} \
          -DENABLE_ASAN=${{ matrix.build_type == 'Debug' }} \
          -DENABLE_UBSAN=${{ matrix.build_type == 'Debug' }}
    
    - name: Build
      run: cmake --build build --parallel
    
    - name: Test
      run: |
        cd build
        ctest --output-on-failure
    
    - name: Valgrind
      if: matrix.build_type == 'Debug'
      run: |
        valgrind --leak-check=full \
                 --show-leak-kinds=all \
                 ./build/tests/test_ocserv
    
    - name: Benchmark
      if: matrix.build_type == 'Release'
      run: |
        ./build/tests/benchmark
    
    - name: Coverage
      if: matrix.compiler == 'gcc-13' && matrix.build_type == 'Debug'
      run: |
        lcov --capture --directory . --output-file coverage.info
        lcov --remove coverage.info '/usr/*' --output-file coverage.info
        bash <(curl -s https://codecov.io/bash)

  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Static Analysis
      uses: github/super-linter@v5
      env:
        DEFAULT_BRANCH: main
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Security Scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
    
    - name: Fuzzing
      run: |
        # Run AFL++ fuzzing for 5 minutes
        docker run -v $PWD:/src aflplusplus/aflplusplus \
          afl-fuzz -i /src/tests/fuzz/input \
                   -o /src/tests/fuzz/output \
                   -t 5000 \
                   -- /src/build/wolfguard-fuzz
```

### 10. Deployment и Monitoring

```yaml
# docker/docker-compose.yml
version: '3.8'

services:
  ocserv:
    build:
      context: .
      dockerfile: Dockerfile
    image: wolfguard:latest
    container_name: wolfguard
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    devices:
      - /dev/net/tun
    ports:
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./config:/etc/ocserv
      - ./certs:/etc/ocserv/certs
      - ocserv-data:/var/lib/ocserv
    environment:
      - OCSERV_WORKERS=auto
      - OCSERV_LOG_LEVEL=info
    restart: unless-stopped
    
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    
  grafana:
    image: grafana/grafana:latest
    volumes:
      - ./monitoring/dashboards:/etc/grafana/provisioning/dashboards
      - grafana-data:/var/lib/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

volumes:
  ocserv-data:
  prometheus-data:
  grafana-data:
```

## Timeline и Milestones

### Phase 1: Foundation (Weeks 1-4)
- [x] Research and analysis
- [ ] Setup development environment
- [ ] Create basic libuv event loop
- [ ] Integrate wolfSSL
- [ ] Basic connection handling

### Phase 2: Core Features (Weeks 5-12)
- [ ] Multi-worker architecture
- [ ] Connection pooling
- [ ] Zero-copy optimizations
- [ ] DTLS 1.3 support
- [ ] Authentication framework

### Phase 3: Performance (Weeks 13-16)
- [ ] io_uring integration
- [ ] XDP fast path
- [ ] Multi-queue TUN
- [ ] Benchmark suite
- [ ] Performance tuning

### Phase 4: Production (Weeks 17-20)
- [ ] Security audit
- [ ] Documentation
- [ ] Deployment tools
- [ ] Monitoring integration
- [ ] Beta release

## Команда и ресурсы

### Минимальная команда:
- **Lead Developer** (C expert, networking)
- **Systems Developer** (Linux kernel, eBPF)
- **Security Engineer** (crypto, audit)
- **DevOps Engineer** (CI/CD, deployment)

### Инструменты разработки:
- **IDE**: CLion / VSCode with C/C++ extension
- **Debugger**: GDB / LLDB
- **Profiler**: perf / VTune
- **Static Analysis**: clang-tidy / PVS-Studio
- **Fuzzing**: AFL++ / libFuzzer

## Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|------|------------|---------|-----------|
| Сложность libuv интеграции | Средняя | Высокое | PoC first, incremental migration |
| wolfSSL compatibility issues | Низкая | Среднее | Fallback to OpenSSL option |
| Performance regression | Средняя | Высокое | Continuous benchmarking |
| Security vulnerabilities | Средняя | Критическое | Security audit, fuzzing |
| Team expertise gap | Высокая | Среднее | Training, external consultants |

## Заключение

Проект wolfguard представляет собой амбициозную, но реалистичную модернизацию ocserv. Используя проверенные технологии (libuv, wolfSSL) и современные подходы (event-driven, zero-copy), можно достичь производительности на уровне лучших коммерческих решений, сохранив открытость и гибкость.

Ключевые факторы успеха:
1. **Постепенная миграция** - минимизация рисков
2. **Производительность с первого дня** - continuous benchmarking
3. **Безопасность by design** - modern C practices + audits
4. **Активное сообщество** - open development process

При правильной реализации, wolfguard может стать de facto стандартом для enterprise OpenConnect deployments.

---

*Документ подготовлен для https://github.com/dantte-lp/wolfguard*
*Версия: 1.0.0 | Дата: 2025-01-14*