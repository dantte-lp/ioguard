# Правильный набор C-библиотек для wolfguard

## ⚠️ Важное предупреждение о совместимости

### ❌ Проблемы с C++ библиотеками в C проекте:

1. **Несовместимость ABI** - C++ name mangling, классы, исключения
2. **Невозможность прямого вызова** - нужны extern "C" обертки  
3. **Зависимость от C++ runtime** - libstdc++, исключения, RTTI
4. **Усложнение сборки** - смешанная компиляция gcc/g++

**Вывод:** Для чистого C проекта используем только C библиотеки!

## ✅ Core библиотеки (уже правильно выбраны)

```yaml
libuv: 1.48+             # ✅ Event loop (чистый C)
wolfssl: 5.7+            # ✅ Криптография (чистый C)
llhttp: 9.2+             # ✅ HTTP парсер (чистый C)
cjson: 1.7+              # ✅ JSON парсер (чистый C)
mimalloc: 2.1+           # ✅ Memory allocator (чистый C)
```

## 📦 Дополнительные C-only библиотеки

### Логирование (чистый C)

```yaml
# Рекомендуемые
zlog: 1.2.18              # Мощный, категории, ротация, форматы
log4c: 1.2.5              # Порт log4j на C
syslog: встроенный        # Стандартный POSIX syslog
journald-devel            # systemd journal API (C)

# НЕ использовать
spdlog                    # ❌ C++ библиотека
log4cxx                   # ❌ C++ библиотека
glog                      # ❌ C++ библиотека
```

### Мониторинг и метрики (чистый C)

```yaml
# Рекомендуемые
libprom: 0.1.3            # Официальный Prometheus client для C
libpromhttp: 0.1.3        # HTTP endpoint для метрик
statsd-c-client: 2.0.0    # StatsD клиент на C

# НЕ использовать
prometheus-cpp            # ❌ C++ библиотека
```

### Конфигурация (чистый C)

```yaml
# TOML парсеры
tomlc99: 1.0              # MIT licensed TOML parser
toml-c: 0.5.0             # Альтернативный TOML parser

# Другие форматы
libconfig: 1.7.3          # Иерархическая конфигурация
iniparser: 4.2.4          # Простой INI parser
jansson: 2.14             # JSON для C
libyaml: 0.2.5            # YAML parser для C

# НЕ использовать
tomlplusplus              # ❌ C++ библиотека
yaml-cpp                  # ❌ C++ библиотека
```

### База данных и кэширование

```yaml
# SQL базы данных
libpq: 16+                # PostgreSQL C API ✅
libmysqlclient: 8.0+      # MySQL/MariaDB C API ✅
sqlite3: 3.45+            # SQLite embedded ✅

# NoSQL и кэши
hiredis: 1.2+             # Redis C client ✅
libmemcached: 1.1+        # Memcached client ✅
lmdb: 0.9+                # Lightning Memory-Mapped DB ✅
libmongoc: 1.27+          # MongoDB C driver ✅
```

### Аутентификация и безопасность

```yaml
# Аутентификация
libpam: 1.5+              # PAM интеграция ✅
libldap: 2.6+             # LDAP/AD ✅
libradius: 0.16           # RADIUS ✅
libsasl2: 2.1.28          # SASL механизмы ✅
liboath: 2.6+             # TOTP/HOTP для 2FA ✅
libfido2: 1.16+           # WebAuthn/FIDO2 ✅

# Криптография
libsodium: 1.0.20         # Modern crypto primitives ✅
nettle: 3.10+             # Low-level crypto ✅
libargon2: 20190702       # Password hashing ✅

# Безопасность системы
libseccomp: 2.5+          # Syscall filtering ✅
libcap: 2.70+             # Linux capabilities ✅
libaudit: 3.0+            # Audit logging ✅
libselinux: 3.6+          # SELinux integration ✅
```

### IPC и межпроцессное взаимодействие

```yaml
# Message passing
nanomsg: 1.2+             # ✅ Чистый C
nng: 1.8+                 # ✅ Successor to nanomsg (C)
libzmq: 4.3+              # ⚠️ C++ core, но с полным C API

# Shared memory
librt: POSIX              # POSIX shared memory ✅
libshmem: 1.5+            # OpenSHMEM ✅
```

### Сетевые библиотеки

```yaml
# Packet processing
libpcap: 1.10+            # Packet capture ✅
libnet: 1.3               # Packet construction ✅
libnetfilter_queue: 1.0+  # Netfilter userspace ✅
libnfnetlink: 1.0+        # Netlink library ✅

# High-performance
dpdk: 24.11               # Data Plane Development Kit ✅
libxdp: 1.4+              # XDP userspace library ✅
libbpf: 1.5+              # eBPF programs loader ✅
```

### Утилиты и вспомогательные библиотеки

```yaml
# String processing
pcre2: 10.44+             # Perl Compatible RegEx ✅
libiconv: 1.17+           # Character encoding ✅
icu4c: 75.1+              # Unicode support ✅

# Compression
zlib: 1.3+                # Standard compression ✅
liblz4: 1.10+             # Fast compression ✅
libzstd: 1.5+             # Zstandard compression ✅
libbz2: 1.0.8+            # Bzip2 compression ✅

# Event notification
inotify-tools: 4.23       # File system events ✅
libfswatch: 1.18+         # Cross-platform file watching ✅
```

## 💻 Примеры интеграции C библиотек

### 1. Логирование с zlog (чистый C)

```c
// src/logging.c
#include <zlog.h>

typedef struct {
    zlog_category_t *main_cat;
    zlog_category_t *auth_cat;
    zlog_category_t *audit_cat;
    zlog_category_t *perf_cat;
} logger_t;

int init_logging(ocserv_context_t *ctx) {
    // Инициализация zlog
    if (zlog_init("/etc/ocserv/zlog.conf") != 0) {
        return -1;
    }
    
    // Создаем категории логирования
    ctx->logger.main_cat = zlog_get_category("main");
    ctx->logger.auth_cat = zlog_get_category("auth");
    ctx->logger.audit_cat = zlog_get_category("audit");
    ctx->logger.perf_cat = zlog_get_category("performance");
    
    // Структурированное логирование
    zlog_info(ctx->logger.main_cat, 
              "Server started | version=%s | workers=%d | pid=%d",
              OCSERV_VERSION, ctx->num_workers, getpid());
    
    return 0;
}
```

### 2. Конфигурация zlog

```ini
# /etc/ocserv/zlog.conf
[global]
strict init = true
buffer min = 1024
buffer max = 2MB
rotate lock file = /var/run/zlog.lock
default format = "%d(%F %T.%l) %-6V (%c:%F:%L) - %m%n"

[formats]
json_format = '{"time":"%d(%s.%ms)","level":"%V","category":"%c","message":"%m"}'

[rules]
main.DEBUG      >stdout
main.INFO       "/var/log/ocserv/ocserv.log", 100MB * 10 ~ "ocserv-%d(%Y%m%d).#r.log"
auth.*          "/var/log/ocserv/auth.log", 50MB * 5
audit.*         | /usr/bin/audit-collector
*.ERROR         >syslog,LOG_LOCAL0
```

### 3. Prometheus метрики с libprom (чистый C)

```c
// src/metrics.c
#include <prom.h>
#include <promhttp.h>
#include <microhttpd.h>

typedef struct {
    prom_counter_t *connections_total;
    prom_gauge_t *connections_active;
    prom_histogram_t *request_duration;
    prom_registry_t *registry;
} metrics_t;

int init_metrics(ocserv_context_t *ctx) {
    // Создаем registry
    ctx->metrics.registry = prom_registry_new();
    
    // Счетчик соединений
    ctx->metrics.connections_total = prom_counter_new(
        "ocserv_connections_total",
        "Total number of connections",
        1, (const char*[]){"type"}
    );
    prom_registry_register_metric(ctx->metrics.registry,
                                  ctx->metrics.connections_total);
    
    // Активные соединения  
    ctx->metrics.connections_active = prom_gauge_new(
        "ocserv_connections_active",
        "Current active connections",
        0, NULL
    );
    prom_registry_register_metric(ctx->metrics.registry,
                                  ctx->metrics.connections_active);
    
    // Гистограмма latency
    ctx->metrics.request_duration = prom_histogram_new(
        "ocserv_request_duration_seconds",
        "Request latency in seconds",
        prom_histogram_buckets_exponential(0.001, 2, 10),
        1, (const char*[]){"method"}
    );
    
    return 0;
}

// Использование
void on_connection_accept(ocserv_context_t *ctx) {
    prom_counter_inc(ctx->metrics.connections_total,
                    (const char*[]){"tcp"});
    prom_gauge_inc(ctx->metrics.connections_active, NULL);
}
```

### 4. Конфигурация с tomlc99 (чистый C)

```c
// src/config.c
#include <toml.h>
#include <inotify.h>

int load_config(ocserv_context_t *ctx, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    char errbuf[256];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    
    if (!conf) {
        fprintf(stderr, "TOML parse error: %s\n", errbuf);
        return -1;
    }
    
    // Парсинг секции server
    toml_table_t *server = toml_table_in(conf, "server");
    if (server) {
        toml_datum_t bind = toml_string_in(server, "bind");
        if (bind.ok) {
            ctx->config.bind_addr = strdup(bind.u.s);
            free(bind.u.s);
        }
        
        toml_datum_t port = toml_int_in(server, "port");
        if (port.ok) {
            ctx->config.port = port.u.i;
        }
    }
    
    toml_free(conf);
    return 0;
}

// Hot reload с inotify
void setup_config_watch(ocserv_context_t *ctx) {
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(inotify_fd, "/etc/ocserv/", IN_MODIFY);
    
    // Добавляем в libuv event loop
    uv_poll_t *watcher = malloc(sizeof(uv_poll_t));
    uv_poll_init(ctx->loop, watcher, inotify_fd);
    watcher->data = ctx;
    
    uv_poll_start(watcher, UV_READABLE, config_changed_cb);
}
```

### 5. База данных с чистыми C API

```c
// src/database.c
#include <postgresql/libpq-fe.h>  // PostgreSQL C API
#include <hiredis/hiredis.h>       // Redis C API
#include <lmdb.h>                  // Embedded DB
#include <sqlite3.h>               // SQLite

typedef struct {
    PGconn *pg_conn;
    redisContext *redis;
    MDB_env *lmdb_env;
    MDB_dbi lmdb_dbi;
    sqlite3 *sqlite_db;
} storage_t;

int init_storage(ocserv_context_t *ctx) {
    // PostgreSQL для пользователей
    ctx->storage.pg_conn = PQconnectdb(
        "host=localhost dbname=ocserv user=ocserv"
    );
    if (PQstatus(ctx->storage.pg_conn) != CONNECTION_OK) {
        fprintf(stderr, "PostgreSQL: %s\n", 
                PQerrorMessage(ctx->storage.pg_conn));
        return -1;
    }
    
    // Redis для сессий
    ctx->storage.redis = redisConnect("127.0.0.1", 6379);
    if (ctx->storage.redis->err) {
        fprintf(stderr, "Redis: %s\n", ctx->storage.redis->errstr);
        return -1;
    }
    
    // LMDB для локального кэша
    mdb_env_create(&ctx->storage.lmdb_env);
    mdb_env_set_mapsize(ctx->storage.lmdb_env, 10485760);
    mdb_env_open(ctx->storage.lmdb_env, "/var/lib/ocserv/cache",
                 MDB_NOSUBDIR, 0664);
    
    // SQLite для конфигурации
    sqlite3_open("/etc/ocserv/config.db", &ctx->storage.sqlite_db);
    
    return 0;
}
```

### 6. 2FA с liboath (чистый C)

```c
// src/auth_2fa.c
#include <liboath/oath.h>

bool verify_totp(const char *secret, const char *code) {
    char generated[7];
    time_t now = time(NULL);
    
    // Инициализация библиотеки
    if (oath_init() != OATH_OK) {
        return false;
    }
    
    // Проверяем текущее окно и ±1 для clock skew
    for (int window = -1; window <= 1; window++) {
        int result = oath_totp_generate(
            secret, strlen(secret),
            now, 30, window, 6,
            generated
        );
        
        if (result == OATH_OK && strcmp(generated, code) == 0) {
            oath_done();
            return true;
        }
    }
    
    oath_done();
    return false;
}

// WebAuthn/FIDO2
#include <fido.h>

int verify_fido2(const uint8_t *challenge, size_t challenge_len,
                 const uint8_t *credential_id, size_t cred_len) {
    fido_assert_t *assert = fido_assert_new();
    fido_dev_t *dev = fido_dev_new();
    
    // ... FIDO2 verification logic ...
    
    fido_assert_free(&assert);
    fido_dev_free(&dev);
    return 0;
}
```

### 7. High-performance IPC с nanomsg

```c
// src/ipc.c
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include <nanomsg/pubsub.h>

typedef struct {
    int sock_push;
    int sock_pull;
    int sock_pub;
    int sock_sub;
} ipc_t;

int init_ipc(ocserv_context_t *ctx) {
    // Pipeline для work distribution
    ctx->ipc.sock_push = nn_socket(AF_SP, NN_PUSH);
    nn_bind(ctx->ipc.sock_push, "ipc:///tmp/ocserv-work.ipc");
    
    ctx->ipc.sock_pull = nn_socket(AF_SP, NN_PULL);
    nn_connect(ctx->ipc.sock_pull, "ipc:///tmp/ocserv-work.ipc");
    
    // Pub/Sub для событий
    ctx->ipc.sock_pub = nn_socket(AF_SP, NN_PUB);
    nn_bind(ctx->ipc.sock_pub, "ipc:///tmp/ocserv-events.ipc");
    
    ctx->ipc.sock_sub = nn_socket(AF_SP, NN_SUB);
    nn_setsockopt(ctx->ipc.sock_sub, NN_SUB, NN_SUB_SUBSCRIBE, "", 0);
    nn_connect(ctx->ipc.sock_sub, "ipc:///tmp/ocserv-events.ipc");
    
    return 0;
}

// Отправка задачи worker'у
void dispatch_work(ipc_t *ipc, const void *task, size_t size) {
    nn_send(ipc->sock_push, task, size, 0);
}

// Публикация события
void publish_event(ipc_t *ipc, const char *event) {
    nn_send(ipc->sock_pub, event, strlen(event), 0);
}
```

## 🔨 CMakeLists.txt для чистого C проекта

```cmake
cmake_minimum_required(VERSION 3.28)
project(wolfguard 
        VERSION 2.0.0
        LANGUAGES C)  # Только C!

# C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Компилятор и линковщик
set(CMAKE_C_COMPILER clang-17)
set(CMAKE_LINKER lld)

# Флаги компиляции
add_compile_options(
    -Wall -Wextra -Wpedantic
    -O3 -march=native -mtune=native
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)

# Флаги линковки
add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -pie
)

# Поиск зависимостей - только C библиотеки!
find_package(PkgConfig REQUIRED)

# Core dependencies
pkg_check_modules(CORE_DEPS REQUIRED
    libuv>=1.48
    wolfssl>=5.7
)

# Additional C libraries
pkg_check_modules(EXTRA_DEPS REQUIRED
    zlog                # Logging
    jansson             # JSON
    hiredis             # Redis
    libpq               # PostgreSQL
)

# Optional features
option(ENABLE_LMDB "Enable LMDB cache" ON)
option(ENABLE_OATH "Enable OATH 2FA" ON)
option(ENABLE_PAM "Enable PAM auth" ON)
option(ENABLE_PROMETHEUS "Enable Prometheus metrics" ON)

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
    src/database.c
    src/metrics.c
    src/ipc.c
)

# Main executable
add_executable(wolfguard ${SOURCES})

# Include directories
target_include_directories(wolfguard PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CORE_DEPS_INCLUDE_DIRS}
    ${EXTRA_DEPS_INCLUDE_DIRS}
)

# Link libraries - только C библиотеки!
target_link_libraries(wolfguard PRIVATE
    ${CORE_DEPS_LIBRARIES}
    ${EXTRA_DEPS_LIBRARIES}
    m                   # Math library
    pthread             # POSIX threads
    rt                  # Real-time extensions
)

# Optional libraries
if(ENABLE_LMDB)
    target_link_libraries(wolfguard PRIVATE lmdb)
    target_compile_definitions(wolfguard PRIVATE HAVE_LMDB)
endif()

if(ENABLE_OATH)
    target_link_libraries(wolfguard PRIVATE oath)
    target_compile_definitions(wolfguard PRIVATE HAVE_OATH)
endif()

if(ENABLE_PAM)
    target_link_libraries(wolfguard PRIVATE pam)
    target_compile_definitions(wolfguard PRIVATE HAVE_PAM)
endif()

if(ENABLE_PROMETHEUS)
    find_library(PROM_LIB prom)
    find_library(PROMHTTP_LIB promhttp)
    target_link_libraries(wolfguard PRIVATE ${PROM_LIB} ${PROMHTTP_LIB})
    target_compile_definitions(wolfguard PRIVATE HAVE_PROMETHEUS)
endif()

# Sanitizers для debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(wolfguard PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(wolfguard PRIVATE
        -fsanitize=address,undefined
    )
endif()

# Installation
install(TARGETS wolfguard DESTINATION bin)
install(FILES config/ocserv.toml DESTINATION /etc/ocserv)
install(FILES config/zlog.conf DESTINATION /etc/ocserv)

# Tests
enable_testing()
add_subdirectory(tests)
```

## 📦 Dockerfile для production

```dockerfile
FROM alpine:3.21 AS builder

# Установка только C библиотек и инструментов
RUN apk add --no-cache \
    # Build tools
    clang17 lld cmake ninja pkgconfig \
    # Core C libraries
    libuv-dev wolfssl-dev \
    # C libraries для функциональности
    zlog-dev jansson-dev tomlc99-dev \
    postgresql-dev hiredis-dev lmdb-dev \
    linux-pam-dev openldap-dev \
    oath-toolkit-dev libsodium-dev \
    libseccomp-dev libcap-dev \
    nanomsg-dev pcre2-dev \
    # НЕ устанавливаем C++ библиотеки!

WORKDIR /build
COPY . .

RUN cmake -B build \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-17 && \
    cmake --build build

FROM alpine:3.21

# Runtime - только C библиотеки
RUN apk add --no-cache \
    libuv wolfssl \
    zlog jansson tomlc99 \
    postgresql-libs hiredis lmdb \
    linux-pam openldap-client \
    oath-toolkit libsodium \
    libseccomp libcap \
    nanomsg pcre2

# Создаем пользователя
RUN adduser -D -s /sbin/nologin ocserv

# Копируем бинарник
COPY --from=builder /build/build/wolfguard /usr/local/bin/

# Конфигурация
COPY config/*.conf /etc/ocserv/
COPY config/*.toml /etc/ocserv/

# Права и capabilities
RUN chown -R ocserv:ocserv /etc/ocserv /var/lib/ocserv && \
    setcap cap_net_admin,cap_net_bind_service=+ep /usr/local/bin/wolfguard

USER ocserv
CMD ["/usr/local/bin/wolfguard"]
```

## ✅ Production Checklist для C проекта

### Обязательные компоненты:
- [x] **zlog** - структурированное логирование для C
- [x] **libprom** - Prometheus метрики для C
- [x] **tomlc99** - TOML конфигурация для C
- [x] **PostgreSQL/Redis C API** - persistent storage
- [x] **libpam/libldap** - enterprise authentication
- [x] **liboath** - 2FA support
- [x] **inotify** - hot reload
- [x] **libseccomp** - sandboxing

### Рекомендуемые:
- [ ] **lmdb** - embedded key-value storage
- [ ] **nanomsg/nng** - IPC messaging
- [ ] **libxdp/libbpf** - kernel bypass
- [ ] **libaudit** - audit logging

### Опциональные:
- [ ] **dpdk** - для экстремальной производительности
- [ ] **libraft** - для кластеризации
- [ ] **libetcd** - distributed configuration

## 🎯 Преимущества чистого C подхода

1. **Никаких зависимостей от C++ runtime** - меньший размер, проще deployment
2. **Предсказуемое поведение** - нет исключений, RTTI, виртуальных функций
3. **Лучшая переносимость** - C ABI стабилен между компиляторами
4. **Проще отладка** - нет name mangling, проще stack traces
5. **Меньше overhead** - прямые вызовы функций, нет vtables
6. **Совместимость с FFI** - легко использовать из других языков

## 📊 Сравнение размера зависимостей

| Подход | Runtime зависимости | Размер Docker образа |
|--------|---------------------|---------------------|
| C + C++ библиотеки | libc + libstdc++ + ... | ~150-200 MB |
| Чистый C | только libc | ~50-80 MB |
| Static linking | нет | ~20-30 MB |

---

*Документ подготовлен для проекта wolfguard*  
*Версия: 2.0.0 | Дата: 2025-01-14*  
*Фокус: Чистые C библиотеки без C++ зависимостей*