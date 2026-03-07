# wolfguard: Современный VPN сервер на C23

## 📋 README.md

### Описание проекта

Высокопроизводительный VPN сервер нового поколения на языке C23, совместимый с протоколом Cisco AnyConnect/OpenConnect. Разработан с использованием современных технологий: wolfSSL, wolfSentry и eBPF для максимальной производительности и безопасности в Linux kernel 6+.

### 🎯 Цели проекта

- **Производительность**: Multi-queue TUN + eBPF fast path для обработки миллионов пакетов в секунду
- **Безопасность**: wolfSentry IDPS + eBPF kernel-level filtering + wolfSSL с FIPS 140-3
- **Совместимость**: Полная поддержка Cisco Secure Client v5+ на всех платформах
- **Современность**: C23, Linux 6+, современные криптографические алгоритмы

### 🏗️ Архитектура
```
┌─────────────────────────────────────────────────┐
│          Cisco Secure Client v5+                │
│   Windows 10/11 | Linux | macOS | Android | iOS │
└──────────────────┬──────────────────────────────┘
                   │ TLS 1.3 / DTLS 1.2/1.3
                   ↓
┌─────────────────────────────────────────────────┐
│  Physical NIC                                   │
│  ↓ [XDP eBPF] - DDoS protection                 │  ← Kernel Fast Path
│  ↓ [Linux Network Stack]                        │
│  ↓ [Netfilter/conntrack]                        │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  wolfguard (User Space)                     │
│  ├─ wolfSSL 5.8+    - TLS/DTLS crypto          │
│  ├─ wolfSentry 1.6+ - IDPS/Firewall            │  ← User Space Processing
│  ├─ Multi-queue TUN - Parallel packet handling │
│  └─ C23 features   - Modern C, safety          │
└──────────────────┬──────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────┐
│  Multi-queue TUN Interface (vpns0)              │
│  ├─ Queue 0 → CPU 0 [TC eBPF filter]            │  ← Kernel Virtual Interface
│  ├─ Queue 1 → CPU 1 [TC eBPF filter]            │
│  └─ Queue N → CPU N [TC eBPF filter]            │
└──────────────────┬──────────────────────────────┘
                   ↓
         Decrypted Client Traffic → Internet
```

### 🔧 Технологический стек

#### Основные компоненты

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| **C Standard** | C23 | Современный C с улучшенной безопасностью |
| **wolfSSL** | 5.8.2+ | TLS/DTLS криптография, FIPS 140-3 |
| **wolfSentry** | 1.6.3+ | Embedded IDPS/firewall |
| **eBPF** | Linux 6.1+ | Kernel-level packet filtering |
| **libbpf** | 1.0+ | BPF programs и maps |
| **Linux Kernel** | 6.1+ | Multi-queue TUN, modern eBPF |

#### Сетевые технологии

- **Multi-queue TUN**: Параллельная обработка по CPU cores
- **TC eBPF**: Traffic Control для ingress/egress filtering
- **XDP** (опционально): DDoS protection на входе
- **Zero-copy**: Минимизация копирования данных

#### Криптография (wolfSSL)

- **TLS**: 1.2, 1.3
- **DTLS**: 1.0 (legacy), 1.2, 1.3
- **Ciphers**: ChaCha20-Poly1305, AES-GCM, Curve25519
- **FIPS**: 140-2 и 140-3 сертификация

### 🚀 Ключевые особенности

#### 1. Производительность
```c
// Multi-queue TUN с привязкой к CPU cores
typedef struct {
    int num_queues;           // По числу CPU cores
    int fds[MAX_QUEUES];      // File descriptors для каждой очереди
    pthread_t workers[MAX_QUEUES];  // Worker thread на каждый core
} tun_mq_context_t;

// eBPF fast path - блокировка в kernel space
// До 10-20 Mpps на современном hardware
```

**Benchmarks** (предварительные цели):
- Throughput: 10+ Gbps на 8-core CPU
- Latency: <1ms для TLS, <0.5ms для DTLS
- Connections: 10,000+ одновременных клиентов

#### 2. Безопасность

##### Уровень 1: eBPF (Kernel Fast Path)
```c
// Ранняя фильтрация в kernel
- IP/Port blocklist (обновляется из wolfSentry)
- Rate limiting per IP
- DDoS protection (SYN flood, amplification)
- Protocol validation
```

##### Уровень 2: wolfSentry (User Space IDPS)
```c
// Интеллектуальный анализ
- Поведенческий анализ подключений
- Динамические правила firewall
- Обнаружение аномалий
- Автоматическая блокировка атак
```

##### Уровень 3: wolfSSL (Crypto)
```c
// Современная криптография
- TLS 1.3 с 0-RTT
- Perfect Forward Secrecy (ECDHE)
- FIPS 140-3 compliance
- Post-quantum ready (Kyber, Dilithium)
```

#### 3. Совместимость с Cisco Secure Client v5+

Полная поддержка протокола AnyConnect:
```ini
# Режимы совместимости
cisco-client-compat = true      # Legacy DTLS support
dtls-legacy = true              # Pre-draft DTLS 1.0
dtls-psk = true                 # Modern DTLS-PSK (openconnect 7.08+)
user-profile = profile.xml      # XML profile для клиентов
```

**Поддерживаемые клиенты:**
- ✅ Cisco Secure Client v5+ - Windows, macOS, Linux, iOS, Android
- ✅ OpenConnect CLI - Linux, macOS, Windows
- ✅ OpenConnect GUI - Windows, Linux
- ✅ Network Manager OpenConnect - Linux (GNOME)

**Протоколы:**
- ✅ TLS 1.2 / TLS 1.3 (контрольный канал)
- ✅ DTLS 1.0 (legacy для старых клиентов)
- ✅ DTLS 1.2 (стандарт)
- ✅ DTLS 1.3 (новейший)

### 📦 Структура проекта
```
wolfguard/
├── src/
│   ├── main.c                 # Точка входа
│   ├── tun/
│   │   ├── tun_multiqueue.c   # Multi-queue TUN interface
│   │   └── tun_multiqueue.h
│   ├── bpf/
│   │   ├── vpn_filter.bpf.c   # eBPF programs (TC/XDP)
│   │   ├── bpf_loader.c       # BPF загрузчик
│   │   └── bpf_maps.h         # BPF maps definitions
│   ├── crypto/
│   │   ├── wolfssl_wrapper.c  # wolfSSL интеграция
│   │   └── dtls_handler.c     # DTLS logic
│   ├── security/
│   │   ├── wolfsentry_integration.c  # wolfSentry + eBPF bridge
│   │   └── policy_manager.c   # Policy management
│   ├── workers/
│   │   ├── worker_pool.c      # Worker thread pool
│   │   └── packet_processor.c # Packet processing logic
│   └── config/
│       ├── config_parser.c    # Configuration
│       └── ocserv.conf        # Config file
├── bpf/                       # eBPF programs (отдельно для build)
├── docs/
│   ├── architecture/
│   │   ├── WOLFSSL_ECOSYSTEM.md
│   │   ├── PROTOCOL_REFERENCE.md
│   │   ├── PERFORMANCE.md
│   │   └── SECURITY.md
│   └── guides/
│       ├── BUILDING.md
│       └── TUNING.md
├── tests/
│   ├── unit/
│   ├── integration/
│   └── performance/
├── scripts/
│   ├── build-bpf.sh          # Compile eBPF programs
│   └── setup-system.sh        # System requirements setup
├── CMakeLists.txt
└── README.md
```

### 🔨 Сборка

#### Системные требования
```bash
# Минимальные требования
- Linux Kernel 6.1+
- GCC 13+ или Clang 16+ (с поддержкой C23)
- 2+ CPU cores
- 1 GB RAM

# Рекомендуемые требования
- Linux Kernel 6.6+ (LTS)
- 8+ CPU cores
- 8 GB RAM
- 10 Gbps NIC с XDP support
```

#### Зависимости
```bash
# Debian/Ubuntu
sudo apt install -y \
    build-essential \
    cmake \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    libelf-dev \
    pkg-config

# wolfSSL (собрать из исходников)
wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.2-stable.tar.gz
tar xf v5.8.2-stable.tar.gz
cd wolfssl-5.8.2-stable
./autogen.sh
./configure --enable-all --enable-jni --enable-wolfsentry
make -j$(nproc)
sudo make install

# wolfSentry
wget https://github.com/wolfSSL/wolfsentry/archive/refs/tags/v1.6.3.tar.gz
tar xf v1.6.3.tar.gz
cd wolfsentry-1.6.3
make -j$(nproc)
sudo make install
```

#### Компиляция
```bash
git clone https://github.com/dantte-lp/wolfguard.git
cd wolfguard

# Сборка eBPF programs
./scripts/build-bpf.sh

# Основная сборка
mkdir build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_WOLFSSL=ON \
    -DENABLE_WOLFSENTRY=ON \
    -DENABLE_EBPF=ON \
    -DC_STANDARD=23

make -j$(nproc)
sudo make install
```

### ⚙️ Конфигурация

#### Основной конфиг (ocserv.conf)
```ini
# Основные настройки
tcp-port = 443
udp-port = 443
run-as-user = ocserv
run-as-group = ocserv

# wolfSSL настройки
server-cert = /etc/ocserv/certs/server-cert.pem
server-key = /etc/ocserv/certs/server-key.pem
ca-cert = /etc/ocserv/certs/ca.pem

# TLS/DTLS приоритеты
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-TLS1.0:-VERS-TLS1.1:+VERS-TLS1.3"

# Cisco v5+ compatibility
cisco-client-compat = true
dtls-legacy = true
dtls-psk = true
user-profile = /etc/ocserv/profile.xml

# Multi-queue настройки
tun-device = vpns
tun-queues = auto  # Автоматически по числу CPU cores
worker-threads = auto

# wolfSentry IDPS
enable-wolfsentry = true
wolfsentry-config = /etc/ocserv/wolfsentry.conf

# eBPF настройки
enable-ebpf = true
ebpf-programs = /etc/ocserv/bpf/
ebpf-xdp-mode = native  # native, offload, или disabled

# IP pools
ipv4-network = 10.0.16.0/24
ipv4-netmask = 255.255.255.0
ipv6-network = fc00::1:8600/121

# DNS
dns = 8.8.8.8
dns = 8.8.4.4

# Routing
route = 10.0.0.0/255.0.0.0
no-route = 192.168.0.0/255.255.0.0

# Безопасность
max-clients = 1024
max-same-clients = 10
min-reauth-time = 300
cookie-timeout = 300
deny-roaming = false
isolate-workers = true

# Performance
tcp-keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
mtu = 1400
```

#### wolfSentry конфигурация (wolfsentry.conf)
```json
{
    "config-version": 2,
    "default-policies": {
        "default-policy-static": "accept",
        "default-policy-dynamic": "reject",
        "default-event": "default-event"
    },
    "static-routes": [
        {
            "family": "inet",
            "protocol": "tcp",
            "remote-address": "0.0.0.0/0",
            "remote-port": 443,
            "action": "accept"
        }
    ],
    "dynamic-rules": {
        "max-connection-rate": {
            "interval": 60,
            "threshold": 100,
            "penalty-time": 300,
            "action": "reject"
        },
        "failed-auth-protection": {
            "max-attempts": 5,
            "window": 300,
            "penalty-time": 900,
            "action": "reject"
        }
    }
}
```

### 🚀 Запуск
```bash
# Подготовка системы
sudo ./scripts/setup-system.sh

# Запуск сервера
sudo wolfguard -c /etc/ocserv/ocserv.conf -f

# Или как systemd service
sudo systemctl enable wolfguard
sudo systemctl start wolfguard
sudo systemctl status wolfguard

# Мониторинг
sudo occtl show status
sudo occtl show users
sudo occtl show stats

# eBPF statistics
sudo bpftool map dump name stats_map
sudo tc -s filter show dev vpns0 ingress
```

### 📊 Производительность

#### Оптимизация системы
```bash
# Kernel tuning
cat >> /etc/sysctl.conf << EOF
# Network performance
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# eBPF
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 0  # Отключить для production после тестирования

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
EOF

sudo sysctl -p

# IRQ balancing для multi-queue
sudo systemctl enable irqbalance
sudo systemctl start irqbalance

# CPU governor
sudo cpupower frequency-set -g performance
```

#### Тестирование производительности
```bash
# С клиента
# Throughput test
iperf3 -c VPN_SERVER_IP -t 60 -P 4

# Latency test
ping -c 100 VPN_SERVER_IP

# Connection test
for i in {1..1000}; do
    openconnect VPN_SERVER_IP &
done
```

#### Целевые показатели

| Метрика | Значение |
|---------|----------|
| Throughput (8-core) | 10+ Gbps |
| Latency (TLS) | <1ms |
| Latency (DTLS) | <0.5ms |
| Concurrent connections | 10,000+ |
| CPU usage (idle) | <5% |
| Memory per connection | ~256 KB |
| Packet loss | <0.01% |

### 🔒 Безопасность

#### Многоуровневая защита

1. **Layer 1 - Kernel (eBPF/XDP)**
   - Ранняя фильтрация пакетов
   - DDoS protection
   - Rate limiting

2. **Layer 2 - wolfSentry (IDPS)**
   - Поведенческий анализ
   - Автоматическая блокировка
   - Динамические правила

3. **Layer 3 - wolfSSL (Crypto)**
   - TLS 1.3
   - FIPS 140-3 compliance
   - Perfect Forward Secrecy

#### Hardening
```bash
# AppArmor/SELinux profile
# Seccomp filtering
# Capability dropping
# Namespace isolation
```

### 📚 Документация

- [Архитектура wolfSSL экосистемы](docs/architecture/WOLFSSL_ECOSYSTEM.md)
- [Протокол OpenConnect](docs/architecture/PROTOCOL_REFERENCE.md)
- [Руководство по производительности](docs/architecture/PERFORMANCE.md)
- [Руководство по безопасности](docs/architecture/SECURITY.md)
- [Сборка и установка](docs/guides/BUILDING.md)
- [Настройка производительности](docs/guides/TUNING.md)

### 🤝 Разработка

#### Стандарты кода

- C23 standard
- Clang-format (LLVM style)
- Static analysis (clang-tidy)
- Memory safety (AddressSanitizer, MemorySanitizer)

#### Тестирование
```bash
# Unit tests
cd build
make test

# Integration tests
./tests/run_integration_tests.sh

# Performance tests
./tests/run_performance_tests.sh

# Security fuzzing
./tests/fuzz/run_fuzzer.sh
```

### 📝 Лицензия

GPLv2 (совместимо с wolfSSL GPLv2 и Linux kernel GPL)

### 🙏 Благодарности

- [wolfSSL](https://www.wolfssl.com/) - TLS/DTLS библиотека
- [wolfSentry](https://www.wolfssl.com/products/wolfsentry/) - IDPS
- [OpenConnect](https://www.infradead.org/openconnect/) - Protocol reference
- [Linux kernel eBPF](https://ebpf.io/) - Packet filtering
- [ocserv](https://ocserv.gitlab.io/www/) - Original project

### 📧 Контакты

- GitHub: https://github.com/dantte-lp/wolfguard
- Issues: https://github.com/dantte-lp/wolfguard/issues

---

**Status**: 🚧 В активной разработке | **Version**: 0.1.0-alpha | **Last updated**: 2025-01-29

---

## 🔬 AI Research Prompt

### Промпт для глубокого исследования: Разработка высокопроизводительного VPN сервера

#### Контекст
Я разрабатываю современный VPN сервер на языке C23 для Linux Kernel 6+ с использованием:
- wolfSSL 5.8+ (TLS/DTLS криптография с FIPS 140-3)
- wolfSentry 1.6+ (embedded IDPS/firewall)
- eBPF/XDP (kernel-level packet filtering)
- Multi-queue TUN interface (параллельная обработка)

Проект должен быть полностью совместим с Cisco Secure Client v5+ (протокол AnyConnect) и поддерживать клиентов на Windows 10/11, Linux, macOS, Android, iOS.

#### Основные направления исследования

### 1. ПРОИЗВОДИТЕЛЬНОСТЬ

**Вопросы для исследования:**

#### 1.1. Multi-queue TUN оптимизация
- Оптимальное количество очередей vs количество CPU cores
- Алгоритмы распределения пакетов между очередями (RSS, flow director)
- Zero-copy техники между kernel space и user space
- Влияние размера MTU на производительность (1400 vs 1500 vs jumbo frames)
- CPU affinity стратегии для worker threads
- NUMA-aware memory allocation

#### 1.2. eBPF оптимизация
- TC vs XDP для TUN interfaces: что реально работает?
- Оптимальная структура BPF maps (HASH vs ARRAY vs LRU)
- Per-CPU maps vs global maps: trade-offs
- Map sizing и memory footprint
- JIT compilation оптимизации
- Co-RE (Compile Once – Run Everywhere) best practices

#### 1.3. wolfSSL производительность
- Hardware acceleration (AES-NI, AVX, NEON)
- Session resumption strategies (session tickets vs session cache)
- DTLS vs TLS performance comparison для VPN
- 0-RTT в TLS 1.3: безопасность vs производительность
- ChaCha20-Poly1305 vs AES-GCM на разных архитектурах
- Batch processing для crypto operations

#### 1.4. Системные оптимизации
- TCP BBR vs CUBIC для fallback connections
- Optimal kernel parameters для high-performance VPN
- Interrupt handling (NAPI, IRQ affinity)
- Hugepages для crypto buffers
- CPU governor settings (performance vs powersave)

**Задачи для анализа:**
- Проанализируй современные benchmark результаты VPN серверов
- Сравни производительность kernel-space vs user-space VPN implementations
- Изучи bottlenecks в wolfSSL для high-throughput scenarios
- Исследуй влияние eBPF на latency в data path

### 2. БЕЗОПАСНОСТЬ

**Вопросы для исследования:**

#### 2.1. eBPF security
- Безопасность BPF verifier: известные уязвимости и mitigations
- BPF program signing и verification
- Защита от malicious BPF programs
- Безопасная коммуникация между eBPF и user space
- Secrets management в BPF maps
- Audit logging для BPF events

#### 2.2. wolfSentry интеграция
- Архитектура взаимодействия wolfSentry + eBPF
- Real-time threat intelligence feed integration
- Behavioral analysis алгоритмы для VPN traffic
- False positive reduction strategies
- Performance impact of deep packet inspection
- Memory-safe parsing в C23

#### 2.3. TLS/DTLS безопасность
- FIPS 140-3 compliance requirements для VPN
- Post-quantum cryptography roadmap (Kyber, Dilithium)
- Certificate pinning для mobile clients
- DTLS replay protection optimization
- Side-channel attack mitigations в wolfSSL
- Secure random number generation

#### 2.4. Cisco AnyConnect protocol security (v5+)
- Известные уязвимости в протоколе
- Защита от downgrade attacks
- XML injection в profile.xml
- Authentication bypass vulnerabilities
- Session hijacking protection
- Улучшения безопасности в v5 по сравнению со старыми версиями

**Задачи для анализа:**
- Изучи CVE базу для OpenConnect/ocserv
- Проанализируй security audit reports для wolfSSL
- Исследуй eBPF security best practices от Google/Facebook
- Сравни DTLS 1.2 vs 1.3 с точки зрения безопасности

### 3. СОВМЕСТИМОСТЬ И ПРОТОКОЛ

**Вопросы для исследования:**

#### 3.1. Cisco AnyConnect protocol (v5+)
- Детали handshake process (TLS + DTLS establishment)
- X-CSTP headers: обязательные vs опциональные
- DTLS-PSK vs legacy DTLS negotiation
- Mobile и desktop client различия
- Улучшения в v5 по сравнению с предыдущими версиями
- profile.xml: required fields для каждой платформы (v5+)

#### 3.2. Platform-specific issues
- Windows: TAP-Windows driver vs Wintun
- macOS: SystemExtension requirements
- iOS: Network Extension framework limitations
- Android: VPNService API peculiarities
- Linux: NetworkManager integration

#### 3.3. Multi-platform testing
- Automated testing infrastructure
- Client compatibility matrix
- Regression testing strategies
- Performance benchmarking per platform

**Задачи для анализа:**
- Декомпилируй/reverse engineer Cisco AnyConnect v5+ protocol details
- Изучи OpenConnect source code для understanding протокола
- Проанализируй Wireshark captures AnyConnect v5+ sessions
- Исследуй compatibility issues в ocserv bug tracker

### 4. АРХИТЕКТУРНЫЕ РЕШЕНИЯ

**Вопросы для исследования:**

#### 4.1. Thread model
- Thread-per-core vs thread pool
- Lock-free data structures в C23
- Memory ordering и atomics
- Work stealing queues
- Event-driven vs threaded architecture

#### 4.2. Memory management
- Custom allocators для crypto buffers
- Memory pools per thread
- NUMA-aware allocation
- Memory leak detection в production
- SafeStack, AddressSanitizer в production builds

#### 4.3. Error handling и reliability
- C23 error handling patterns
- Graceful degradation strategies
- Connection migration при node failure
- State persistence при restart
- Zero-downtime reload

#### 4.4. Monitoring и observability
- eBPF-based monitoring (без overhead)
- Prometheus metrics export
- Distributed tracing (OpenTelemetry)
- Real-time dashboard
- Anomaly detection

**Задачи для анализа:**
- Изучи architecture WireGuard как reference
- Проанализируй production VPN deployments (Cloudflare, Tailscale)
- Исследуй C23 features полезные для systems programming
- Сравни memory management strategies в high-performance servers

---

### Формат ответа

Для каждого направления предоставь:

1. **Детальный анализ** с техническими деталями
2. **Code examples** на C23 где применимо
3. **Benchmark data** из реальных источников
4. **Best practices** от industry leaders
5. **Pitfalls и anti-patterns** которых следует избегать
6. **Ссылки на источники** (papers, GitHub repos, documentation)
7. **Рекомендации** специфичные для моего use case

### Дополнительный контекст

- Целевая аудитория: enterprise VPN deployment
- Ожидаемая нагрузка: 10,000+ concurrent connections
- Целевая производительность: 10+ Gbps, <1ms latency
- Бюджет: open-source, no licensing costs
- Timeline: MVP в 6 месяцев

### Приоритеты

1. Безопасность (критично)
2. Производительность (очень важно)
3. Совместимость с Cisco Secure Client v5+ (обязательно)
4. Maintainability (важно)
5. Feature parity with ocserv (желательно)

**Начни исследование с наиболее критичных аспектов безопасности и производительности.**

---

## Дополнительные технические детали

### Интеграция wolfSentry + eBPF

#### Архитектура взаимодействия
```c
// wolfsentry_bpf_bridge.h
typedef struct {
    struct WOLFSENTRY_CONTEXT *wolfsentry;
    
    // BPF map file descriptors
    int blocklist_map_fd;
    int session_map_fd;
    int stats_map_fd;
    
    // Background thread для синхронизации
    pthread_t sync_thread;
    volatile int running;
} wolfsentry_bpf_context_t;

// Callback от wolfSentry при блокировке IP
int wolfsentry_action_block_ip(
    struct WOLFSENTRY_CONTEXT *wolfsentry,
    const struct WOLFSENTRY_EVENT *event,
    struct WOLFSENTRY_ACTION *action,
    void *caller_arg
);

// Синхронизация wolfSentry decisions в eBPF maps
void *wolfsentry_bpf_sync_thread(void *arg);
```

### Multi-queue TUN Implementation
```c
// tun_multiqueue.h
typedef struct {
    char name[IFNAMSIZ];
    int num_queues;
    int fds[MAX_TUN_QUEUES];
    int ifindex;
    
    // eBPF program fds для TC hook
    int tc_ingress_prog_fd;
    int tc_egress_prog_fd;
    
    // BPF maps для communication
    int policy_map_fd;
    int stats_map_fd;
    int session_map_fd;
} tun_device_t;

// Создание multi-queue TUN
int tun_mq_create(tun_device_t *dev, const char *name, int num_queues);

// Attach eBPF programs
int tun_attach_bpf_programs(tun_device_t *dev);
```

### eBPF программа для TC filtering
```c
// bpf_vpn_filter.c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // Source IP
    __type(value, __u64);    // Timestamp + action
} session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);      // IP address
    __type(value, __u8);     // Block (1) or Allow (0)
} blocklist_map SEC(".maps");

// TC ingress hook
SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
    // Parse IP header
    // Check blocklist
    // Update statistics
    // Return TC_ACT_OK or TC_ACT_SHOT
}

// TC egress hook
SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb) {
    // Similar logic for outbound traffic
}
```

### Worker Pool для packet processing
```c
// worker_threads.c
typedef struct {
    int queue_id;
    int tun_fd;
    int cpu_id;
    
    wolfsentry_bpf_context_t *wolfsentry_ctx;
    WOLFSSL_CTX *ssl_ctx;
    
    pthread_t thread;
    volatile int running;
} worker_thread_t;

void *worker_thread_func(void *arg) {
    worker_thread_t *worker = (worker_thread_t *)arg;
    
    // Привязка к CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    // Main processing loop
    while (worker->running) {
        // Read from TUN
        // Process with wolfSentry/wolfSSL
        // Write back
    }
}
```

---

## Производительные характеристики TUN интерфейса

### Типы интерфейсов в Linux Kernel 6+

| Тип | Код | Link Layer | Применение |
|-----|-----|------------|------------|
| Ethernet | 1 | Yes (MAC) | Физические и виртуальные сети |
| TUN | 65534 (ARPHRD_NONE) | No | VPN (Layer 3, IP packets) |
| TAP | 1 (но link/ether) | Yes (MAC) | VPN (Layer 2, Ethernet frames) |
| WireGuard | 65534 | No | Modern VPN |
| VETH | 1 | Yes | Container networking |

### Проверка типа интерфейса
```bash
# Драйвер и bus-info
ethtool -i vpns0
# driver: tun
# bus-info: tun

# Тип интерфейса
cat /sys/class/net/vpns0/type
# 65534 = ARPHRD_NONE (TUN)

# Детальная информация
ip -d link show vpns0
# link/none - TUN device
```

### Multi-queue TUN преимущества
```
Single Queue:
[All packets] → [Single FD] → [One CPU] → Bottleneck at ~1-2 Gbps

Multi-Queue (8 queues):
[Packets] → [Hash] → [Queue 0] → [CPU 0] ──┐
                  → [Queue 1] → [CPU 1] ──┤
                  → [Queue 2] → [CPU 2] ──┤→ 10+ Gbps
                  → [Queue N] → [CPU N] ──┘
```

### eBPF integration points
```
Packet flow:
[NIC] → [XDP eBPF] → [Network Stack] → [TUN device]
                                           ↓
                                    [TC eBPF ingress]
                                           ↓
                                    [User space VPN]
                                           ↓
                                    [TC eBPF egress]
                                           ↓
                                    [Back to TUN]
```

---

**Итоговый документ готов для глубокого AI-анализа и разработки!**