# wolfguard: Комплексное архитектурное исследование и план реализации

**Версия документа**: 2.0
**Дата**: 2026-03-07
**Статус**: Объединённое исследование + анализ репозитория
**Проект**: wolfguard (ocserv-modern) v2.0.0+

---

## Оглавление

1. [Введение и цели](#1-введение-и-цели)
2. [Стандарт C23: возможности для VPN-сервера](#2-стандарт-c23-возможности-для-vpn-сервера)
3. [WolfSSL: конфигурация и лучшие практики](#3-wolfssl-конфигурация-и-лучшие-практики)
4. [Стек рекомендуемых библиотек](#4-стек-рекомендуемых-библиотек)
5. [Максимальная сетевая производительность](#5-максимальная-сетевая-производительность)
6. [Архитектура VPN-сервера](#6-архитектура-vpn-сервера)
7. [Возможности ядра Linux 6+](#7-возможности-ядра-linux-6)
8. [Обфускация трафика и обход ТСПУ](#8-обфускация-трафика-и-обход-тспу)
9. [Совместимость с Cisco Secure Client](#9-совместимость-с-cisco-secure-client)
10. [Аутентификация: полный стек](#10-аутентификация-полный-стек)
11. [Per-User/Per-Group Firewall и Traffic Shaping](#11-per-userper-group-firewall-и-traffic-shaping)
12. [Split DNS и Split Tunneling](#12-split-dns-и-split-tunneling)
13. [Собственный клиент: мультиплатформенная стратегия](#13-собственный-клиент-мультиплатформенная-стратегия)
14. [Безопасность и изоляция](#14-безопасность-и-изоляция)
15. [Мониторинг и наблюдаемость](#15-мониторинг-и-наблюдаемость)
16. [Сравнение с существующей документацией](#16-сравнение-с-существующей-документацией)
17. [Интегрированная дорожная карта](#17-интегрированная-дорожная-карта)
18. [Выводы и рекомендации](#18-выводы-и-рекомендации)

---

## 1. Введение и цели

### 1.1. Назначение документа

Настоящий документ объединяет результаты независимого исследования современных технологий VPN-серверов с анализом существующей документации репозитория wolfguard. Цель — предоставить единый, непротиворечивый технический план, покрывающий все требования технического задания.

### 1.2. Полный набор требований ТЗ

Сервер wolfguard должен соответствовать следующим требованиям:

- Стандарт C23 (ISO/IEC 9899:2024)
- WolfSSL как основа криптографии, WolfSentry как IDPS
- Обратная совместимость с Cisco Secure Client (TLS 1.3, DTLS 1.2)
- Собственный клиент без режима совместимости (TLS 1.3, DTLS 1.3) для Windows, Mac, Linux, iPhone, Android
- Обфускация трафика для обхода ТСПУ и DPI
- Аутентификация: логин/пароль, TOTP, сертификаты, LDAP, RADIUS
- Split DNS, Split Tunneling, IPv4, IPv6
- Группы, per-user firewall, per-group firewall
- Per-user traffic shaping, per-group traffic shaping
- Linux, ядро 6+
- Сотни одновременных пользователей

### 1.3. Статус репозитория и выявленные пробелы

Анализ 10 документов из репозитория wolfguard (REFACTORING_PLAN.md, MODERN_ARCHITECTURE.md, PROTOCOL_REFERENCE.md, WOLFSSL_ECOSYSTEM.md и 6 черновиков) выявил следующую картину:

**Хорошо проработано в репозитории:**

- Миграция GnuTLS → wolfSSL с dual-build стратегией и абстракцией
- PoC валидирован: 50% улучшение handshake (1200 hs/s vs 800)
- Совместимость с Cisco Secure Client (протокол, headers, quirks)
- eBPF/XDP программы для fast path фильтрации
- Risk management с 10 рисками и rollback triggers
- Миграция mimalloc v2 → v3 с планом тестирования

**Критические пробелы (не адресовано ни в одном документе):**

- Обфускация трафика / обход ТСПУ — полностью отсутствует
- Per-user / per-group firewall через nftables — нет библиотек
- Traffic shaping — нет реализации
- Split DNS — нет реализации
- RADIUS-аутентификация — нет конкретной библиотеки
- TOTP — упоминается в черновиках, отсутствует в основном плане
- LDAP — упоминается, но без деталей интеграции
- Собственный клиент — не рассматривается

**Расхождения с исследованием:**

- Event loop: repo выбрал libuv (кроссплатформенный), исследование рекомендует io_uring (max perf Linux)
- JSON: repo — cJSON (простота), исследование — yyjson (производительность)
- Аллокатор: repo — mimalloc (per-heap), исследование — jemalloc (масштабируемость)
- C23: repo не использует `<stdckdint.h>`, `<stdbit.h>`, `enum : type`

Все эти пробелы и расхождения адресованы в данном документе.

---

## 2. Стандарт C23: возможности для VPN-сервера

### 2.1. Обзор стандарта

Стандарт ISO/IEC 9899:2024 (C23) опубликован 31 октября 2024 года. Идентификатор: `__STDC_VERSION__ == 202311L`. Свободно доступен черновик N3220.

### 2.2. Поддержка компиляторами

Рекомендуемая конфигурация для проекта:

```bash
# GCC 15 (C23 по умолчанию) или Clang 19+
CFLAGS="-std=c23 -Wall -Wextra -Wpedantic -Wconversion -Wformat=2 \
        -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fcf-protection=full \
        -fPIE -pie -O2 -march=native"
```

Таблица поддержки ключевых возможностей:

| Возможность                | GCC           | Clang | Важность для VPN |
| -------------------------- | ------------- | ----- | ---------------- |
| `constexpr` объекты        | 13+           | 19+   | Средняя          |
| `nullptr` / `nullptr_t`    | 13+           | 16+   | Средняя          |
| `typeof` / `typeof_unqual` | 13+           | 16+   | Средняя          |
| `_BitInt(N)`               | 14+ (x86/ARM) | 15+   | Средняя          |
| `[[nodiscard]]`            | 10+           | 9+    | **Высокая**      |
| `#embed`                   | 15+           | 19+   | Средняя          |
| `<stdckdint.h>`            | 14+           | 16+   | **Критическая**  |
| `<stdbit.h>`               | 14+           | 18+   | **Высокая**      |
| Enum с фикс. типом         | 13+           | 20+   | **Высокая**      |
| `static_assert` без msg    | 13+           | 16+   | Средняя          |

### 2.3. Критические возможности для безопасности

#### `<stdckdint.h>` — проверяемая целочисленная арифметика

**Статус в репозитории:** Не упоминается ни в одном документе. **Это самый важный пробел.**

Каждая операция с длиной пакета, размером буфера, смещением или порядковым номером в VPN-сервере — потенциальное целочисленное переполнение. Функции `ckd_add`, `ckd_sub`, `ckd_mul` превращают неопределённое поведение в детерминированную проверку:

```c
#include <stdckdint.h>

[[nodiscard]]
static bool safe_parse_packet_header(const uint8_t *buf, size_t buf_len,
                                      uint32_t *payload_offset,
                                      uint32_t *payload_len) {
    uint32_t hdr_len = read_u16_be(buf);
    uint32_t data_len = read_u32_be(buf + 2);
    uint32_t total;

    // Каждая операция проверяется на переполнение
    if (ckd_add(&total, hdr_len, data_len))
        return false;  // Переполнение: пакет отвергнут
    if (total > buf_len)
        return false;  // Пакет длиннее буфера

    *payload_offset = hdr_len;
    *payload_len = data_len;
    return true;
}
```

**Рекомендация:** Внедрить `<stdckdint.h>` как обязательный стандарт кодирования. Все арифметические операции с данными из сети — только через `ckd_*`. Добавить правило в CI: `grep -rn '[^c]ckd_' src/ | wc -l` должен расти при каждом коммите.

#### `<stdbit.h>` — битовые операции и порядок байтов

84 функции для работы с битами и макросы определения endianness:

```c
#include <stdbit.h>

// Определение порядка байтов без #ifdef
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
    // x86_64: нужен bswap для сетевого порядка
#elif __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
    // Нативный сетевой порядок
#endif

// Подсчёт ведущих нулей для определения длины маски подсети
unsigned prefix_len = stdc_leading_zeros(~subnet_mask);
```

**Предостережение:** Доступно в glibc 2.39+, но НЕ в musl libc. Проверять через `__has_include(<stdbit.h>)`.

#### `[[nodiscard]]` — принудительная проверка ошибок

**Статус в репозитории:** Используется в MODERN_ARCHITECTURE.md. Нужно расширить применение.

```c
// Все функции шифрования, отправки и приёма — [[nodiscard]]
typedef enum [[nodiscard]] vpn_result : int32_t {
    VPN_OK = 0,
    VPN_ERR_NOMEM = -1,
    VPN_ERR_CRYPTO = -2,
    VPN_ERR_NETWORK = -3,
    VPN_ERR_TIMEOUT = -4,
    VPN_ERR_AUTH = -5,
    VPN_ERR_OVERFLOW = -6,
} vpn_result_t;

[[nodiscard("TLS handshake может не удаться — обязательно проверьте результат")]]
vpn_result_t tls_handshake(tls_session_t *session);
```

#### Перечисления с фиксированным базовым типом

Идеальны для описания проводного протокола:

```c
// Гарантированный размер 1 байт — совпадает с форматом на проводе
enum vpn_opcode : uint8_t {
    VPN_OP_DATA     = 0x00,
    VPN_OP_DPD_REQ  = 0x03,
    VPN_OP_DPD_RESP = 0x04,
    VPN_OP_DISCO    = 0x05,
    VPN_OP_KEEPALIVE = 0x07,
    VPN_OP_COMPRESS  = 0x08,
    VPN_OP_TERMINATE = 0x09,
};
static_assert(sizeof(enum vpn_opcode) == 1);
```

### 2.4. Важные предостережения C23

`realloc(ptr, 0)` стал **неопределённым поведением** (ранее — определяемым реализацией). Необходим полный аудит всех вызовов `realloc` в кодовой базе:

```c
// ❌ ОПАСНО в C23
void *ptr = realloc(old_ptr, 0);  // UB!

// ✅ Безопасная замена
if (new_size == 0) {
    free(old_ptr);
    return nullptr;
}
void *ptr = realloc(old_ptr, new_size);
```

`unreachable()` (из `<stddef.h>`) — компилятор использует его для агрессивного удаления «недостижимого» кода. Неправильное использование приводит к тихим ошибкам безопасности.

---

## 3. WolfSSL: конфигурация и лучшие практики

### 3.1. Обзор и обоснование выбора

**WolfSSL v5.8.4+** — компактная TLS-библиотека с полной поддержкой DTLS 1.3 (RFC 9147). Ключевые преимущества для wolfguard:

- Единственная зрелая реализация DTLS 1.3 в open-source
- FIPS 140-3 Certificate #5041 (действителен до July 2030)
- 38 КБ RAM на соединение (vs 800+ КБ у OpenSSL 3.0)
- 20–100 КБ размер кода (до 20x компактнее OpenSSL)
- Нативная интеграция с WolfSentry

**Статус в репозитории:** Хорошо проработан (REFACTORING_PLAN.md, WOLFSSL_ECOSYSTEM.md). PoC валидирован с 50% улучшением handshake.

### 3.2. Оптимальная конфигурация сборки

Объединённая рекомендация (repo + исследование):

```bash
./configure \
  --enable-tls13 --enable-dtls13 \
  --enable-intelasm --enable-sp --enable-sp-asm --enable-aesni \
  --enable-intelrand \
  --enable-session-ticket --enable-earlydata \
  --enable-hugecache \
  --enable-curve25519 --enable-ed25519 \
  --enable-chacha --enable-poly1305 \
  --enable-harden \
  --enable-alpn --enable-sni \
  --enable-wolfsentry \
  --enable-keying-material \
  CPPFLAGS="-DENABLE_SESSION_CACHE_ROW_LOCK -DNO_SESSION_CACHE_REF"
```

Пояснения к флагам, отсутствующим в репозитории:

- `--enable-hugecache` — кэш на ~65 000 сессий. Для сотен пользователей достаточно; для тысяч — использовать `--enable-titancache` (2M+ сессий)
- `ENABLE_SESSION_CACHE_ROW_LOCK` — **критически важно для многопоточности**: создаёт отдельный замок на строку кэша сессий вместо глобального, минимизируя конкуренцию
- `--enable-keying-material` — нужно для `X-DTLS-Master-Secret` в протоколе OpenConnect

### 3.3. Два режима работы: совместимость и нативный

Для поддержки двух режимов по ТЗ:

```c
// Режим совместимости с Cisco Secure Client
WOLFSSL_CTX *compat_tls_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
WOLFSSL_CTX *compat_dtls_ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());

// Нативный режим (собственный клиент)
WOLFSSL_CTX *native_tls_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
WOLFSSL_CTX *native_dtls_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
```

Для DTLS 1.3 нативного режима: Connection ID, 1-RTT handshake, зашифрованные порядковые номера. Cookie для защиты от DoS:

```c
wolfSSL_send_hrr_cookie(ssl, cookie_secret, sizeof(cookie_secret));
```

### 3.4. Производительность: WolfSSL vs OpenSSL vs GnuTLS

| Метрика                | WolfSSL (с AES-NI) | OpenSSL 3.0 | GnuTLS     |
| ---------------------- | ------------------ | ----------- | ---------- |
| P-256 ECDHE+ECDSA      | **35–40% быстрее** | Baseline    | ~= OpenSSL |
| X25519                 | **20–30% быстрее** | Baseline    | ~= OpenSSL |
| RAM на соединение      | **38 КБ**          | 800+ КБ     | ~500 КБ    |
| Размер кода            | 20–100 КБ          | 2+ МБ       | ~1 МБ      |
| HAProxy соединений/сек | **2x OpenSSL**     | Baseline    | N/A        |

**Критично:** Без `--enable-intelasm` и `--enable-sp-asm` производительность AES-256-GCM может быть в **десятки раз ниже** OpenSSL. Эти флаги обеспечивают ускорение до 5800%.

### 3.5. Потокобезопасность

- `WOLFSSL_CTX` после инициализации — read-only, безопасно делить между потоками
- Каждый `WOLFSSL` — один поток-владелец
- Кэш сессий: с v5.6.0 доступен `pthread_rwlock_t` для параллельного чтения
- Пользовательский аллокатор: `wolfSSL_SetAllocators(myMalloc, myFree, myRealloc)` для интеграции с mimalloc

### 3.6. WolfSentry: интеграция IDPS

**Статус в репозитории:** Запланирован на Sprint 8+. Детальная документация в WOLFSSL_ECOSYSTEM.md.

WolfSentry v1.6.3 — встраиваемый IDPS с O(log n) поиском. Интегрируется с wolfSSL через callbacks при каждом подключении. Ключевое дополнение из исследования:

```c
// Регистрация callback wolfSentry при подключении
wolfSSL_CTX_set_AcceptFilter(ctx, wolfsentry_accept_filter, ws_context);

// В callback — проверка IP, порт, протокол
static int wolfsentry_accept_filter(WOLFSSL *ssl, void *ctx) {
    struct wolfsentry_context *ws = (struct wolfsentry_context *)ctx;
    wolfsentry_action_res_t action;

    // Получить IP клиента из SSL
    struct sockaddr_in peer;
    wolfSSL_dtls_get_peer(ssl, (struct sockaddr *)&peer, nullptr);

    // Проверить по правилам wolfSentry
    wolfsentry_route_event_dispatch(ws, &peer, &action);

    if (action & WOLFSENTRY_ACTION_RES_REJECT)
        return WOLFSSL_FAILURE;  // Отклонить до TLS handshake

    return WOLFSSL_SUCCESS;
}
```

---

## 4. Стек рекомендуемых библиотек

### 4.1. Интегрированная таблица (repo + исследование)

Чистый C, никаких C++ зависимостей. Для каждой библиотеки указан статус в репозитории:

| Категория            | Библиотека          | Версия   | Лицензия      | Статус в repo      | Примечание               |
| -------------------- | ------------------- | -------- | ------------- | ------------------ | ------------------------ |
| **Крипто/TLS**       | wolfSSL             | 5.8.4+   | Dual GPL/Comm | ✅ Есть            | Обновить версию          |
| **IDPS**             | wolfSentry          | 1.6.3+   | GPLv2         | ✅ Sprint 8+       | Без изменений            |
| **Event loop**       | libuv               | 1.51+    | MIT           | ✅ Есть            | Основной выбор           |
| **Event loop (opt)** | liburing            | 2.7+     | MIT/LGPL      | ⚠️ Phase 2         | Linux-only, +50% к epoll |
| **HTTP parser**      | llhttp              | 9.2+     | MIT           | ✅ Есть            | Без изменений            |
| **JSON**             | cJSON               | 1.7.19+  | MIT           | ✅ Есть            | Достаточно для конфига   |
| **Аллокатор**        | mimalloc            | 3.1.5+   | MIT           | ✅ В миграции      | Per-heap isolation       |
| **Логирование**      | zlog                | 1.2.18+  | LGPL-2.1      | ✅ Есть            | Без изменений            |
| **Конфигурация**     | tomlc99             | 1.0+     | MIT           | ✅ Есть            | Без изменений            |
| **IPC**              | protobuf-c          | существ. | BSD           | ✅ Keep            | Не менять                |
| **Метрики**          | libprom             | 0.1.3+   | MIT           | ✅ Есть            | Без изменений            |
| **CLI**              | linenoise           | latest   | BSD           | ✅ Есть            | Для occtl                |
| **RADIUS**           | **radcli**          | 1.3+     | BSD           | ❌ **Отсутствует** | Создана для ocserv       |
| **TOTP**             | **liboath**         | 2.6+     | LGPLv2+       | ❌ **Отсутствует** | RFC 6238                 |
| **LDAP**             | **libldap**         | 2.6+     | BSD-like      | ⚠️ Упоминается     | Нет деталей              |
| **nftables**         | **libnftnl+libmnl** | latest   | GPL-2.0       | ❌ **Отсутствует** | Per-user firewall        |
| **DNS**              | **c-ares**          | 1.34+    | MIT           | ❌ **Отсутствует** | Async DNS для Split DNS  |
| **Netlink**          | **libmnl**          | 1.0+     | LGPL-2.1      | ❌ **Отсутствует** | Маршруты, TC, nftables   |
| **Сжатие**           | LZ4                 | 1.10+    | BSD           | ⚠️ Упоминается     | Для туннельных пакетов   |
| **PAM**              | libpam              | 1.5+     | Varies        | ✅ Из ocserv       | Async через thread pool  |
| **Sandbox**          | libseccomp          | 2.5+     | LGPL-2.1      | ✅ Упоминается     | seccomp-bpf              |
| **Capabilities**     | libcap              | 2.70+    | BSD           | ✅ Упоминается     | Dropping privileges      |

### 4.2. Обоснование ключевых расхождений

**cJSON vs yyjson.** yyjson показывает 2.39 ГБ/с парсинга (40x быстрее cJSON). Однако для wolfguard JSON используется только для конфигурации wolfSentry и управляющего API — парсинг происходит редко и не на горячем пути. **Решение: оставить cJSON** (как в repo). Если появится JSON-heavy API — добавить yyjson опционально.

**mimalloc vs jemalloc.** Репозиторий уже инвестировал в миграцию mimalloc v3 (MIMALLOC_V3_MIGRATION.md). mimalloc предоставляет `mi_heap_t` для per-connection isolation, что идеально для VPN. **Решение: оставить mimalloc** (как в repo).

**libuv vs liburing.** libuv проверен в Node.js, кроссплатформенный, хорошо документирован. liburing (io_uring) даёт 24–50% преимущество над epoll на Linux, поддерживает zero-copy send, multishot recv, предоставляемые буферы. **Решение: libuv для MVP (Phase 1–5), опциональный бэкенд liburing для Linux production (Phase 6+)**. Это совпадает с планом repo («io_uring integration Linux 5.19+» в Phase 2).

### 4.3. Новые библиотеки — обоснование

**radcli (RADIUS):** Эта библиотека была буквально разработана для OpenConnect VPN-сервера. Модернизированный форк freeradius-client с поддержкой IPv6, TLS/DTLS и тестами. Альтернатива — писать RADIUS-клиент с нуля (нерационально).

**liboath (TOTP):** Используется в оригинальном ocserv для 2FA через PAM (pam_oath). RFC 6238 совместимость, window ±1 для clock skew.

**libnftnl + libmnl (nftables):** Единственный путь для программного управления nftables из C. Необходимы для per-user/per-group firewall. iptables-legacy не рассматривается — nftables заменяет iptables в Linux 6+.

**c-ares (DNS):** Асинхронный DNS-резолвер, используется в libcurl. Необходим для Split DNS: корпоративные домены → внутренний DNS, остальные → публичный DNS.

---

## 5. Максимальная сетевая производительность

### 5.1. UDP GSO/GRO — главная оптимизация

**Статус в репозитории:** Упоминается в нескольких документах, но без деталей. **Это самая импактная единичная оптимизация для VPN.**

Результаты Tailscale: wireguard-go без UDP GSO/GRO — ~3 Гбит/с; с UDP GSO/GRO — свыше 10 Гбит/с на bare-metal, превзойдя ядерный WireGuard (2.67 Гбит/с на аналогичном оборудовании).

```c
#include <linux/udp.h>

// UDP GSO: отправить один буфер до 64 КБ,
// ядро сегментирует на датаграммы указанного размера
static int send_with_gso(int fd, const void *buf, size_t len,
                          const struct sockaddr *dst, socklen_t dst_len,
                          uint16_t segment_size) {
    char cmsg_buf[CMSG_SPACE(sizeof(uint16_t))];
    struct msghdr msg = {
        .msg_name = (void *)dst,
        .msg_namelen = dst_len,
        .msg_iov = &(struct iovec){ .iov_base = (void *)buf, .iov_len = len },
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    memcpy(CMSG_DATA(cm), &segment_size, sizeof(segment_size));

    return sendmsg(fd, &msg, 0);
}

// UDP GRO: получить объединённые входящие пакеты
static void enable_gro(int fd) {
    int val = 1;
    setsockopt(fd, SOL_UDP, UDP_GRO, &val, sizeof(val));
}
```

В ядре 6.2+ расширения virtio включают GSO/GRO на TUN-интерфейсах — критично для VPN.

### 5.2. io_uring: текущее состояние и рекомендации

**Статус в репозитории:** Примеры кода в MODERN_ARCHITECTURE.md. Запланирован как Phase 2 оптимизация.

Ключевые возможности io_uring для VPN по версиям ядра:

| Ядро | Возможность                                  | Значение для VPN                                |
| ---- | -------------------------------------------- | ----------------------------------------------- |
| 6.0  | Multishot recv + zero-copy send              | Одна SQE → множество CQE при поступлении данных |
| 6.1  | `IORING_SETUP_DEFER_TASKRUN`                 | **Критично**: минимальный джиттер задержки      |
| 6.7  | `IORING_RECVSEND_BUNDLE` (recv bundles)      | Группировка входящих пакетов                    |
| 6.11 | Нативные bind/listen, инкрементальные буферы | Упрощение кода сервера                          |
| 6.15 | Zero-copy RX                                 | Истинный zero-copy приём                        |

Рекомендуемая конфигурация:

```c
struct io_uring_params params = {
    .flags = IORING_SETUP_DEFER_TASKRUN |
             IORING_SETUP_SINGLE_ISSUER |
             IORING_SETUP_COOP_TASKRUN |
             IORING_SETUP_CQSIZE,
    .cq_entries = 4096,
};
```

`IORING_SETUP_DEFER_TASKRUN` (ядро 6.1+) — предпочтительнее SQPOLL для VPN: обеспечивает полный контроль над батчингом завершений без выделенного CPU-ядра.

### 5.3. SO_REUSEPORT с eBPF

**Статус в репозитории:** Не упоминается. Важное дополнение.

Множество рабочих процессов/потоков привязываются к одному порту. eBPF-программа типа `BPF_PROG_TYPE_SK_REUSEPORT` выбирает сокет на основе хеша клиентского IP или Connection ID:

```c
// eBPF программа для привязки сессий к конкретным воркерам
SEC("sk_reuseport")
int select_worker(struct sk_reuseport_md *ctx) {
    __u32 key = ctx->hash;  // Хеш 4-tuple клиента
    __u32 *worker_idx = bpf_map_lookup_elem(&session_map, &key);

    if (worker_idx) {
        return bpf_sk_select_reuseport(ctx, &worker_sockets,
                                        worker_idx, 0);
    }
    // Новая сессия — round-robin
    __u32 rr = bpf_ktime_get_ns() % NUM_WORKERS;
    return bpf_sk_select_reuseport(ctx, &worker_sockets, &rr, 0);
}
```

Масштабирование линейно по числу ядер. Для сотен пользователей — 4–8 воркеров достаточно.

### 5.4. Multi-queue TUN

**Статус в репозитории:** Хорошо проработан. Код в MODERN_ARCHITECTURE.md и networking draft.

Бенчмарки: 1 очередь = 818 kpps, 2 очереди = 1926 kpps (+135%), 4 очереди = 3536 kpps (+332%).

Из исследования добавляется: TUN offload для GSO/GRO:

```c
// Включить offload на TUN для работы GSO/GRO
int offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;
ioctl(tun_fd, TUNSETOFFLOAD, offload);

// Включить VNET header для GSO информации
int vnet_hdr = 1;
ioctl(tun_fd, TUNSETVNETHDRSZ, &(int){sizeof(struct virtio_net_hdr_v1)});
```

### 5.5. NUMA-осведомлённость

**Статус в репозитории:** Упоминается mimalloc per-heap. Нет деталей по IRQ binding.

Данные из исследования: неправильная привязка к узлу NUMA даёт до 2x замедления на 40G/100G. Оптимальная схема:

```
NUMA Node 0:
  NIC Queue 0 (IRQ) → CPU 0 → VPN Worker 0 → TUN Queue 0
  NIC Queue 1 (IRQ) → CPU 1 → VPN Worker 1 → TUN Queue 1

NUMA Node 1:
  NIC Queue 2 (IRQ) → CPU 4 → VPN Worker 2 → TUN Queue 2
  NIC Queue 3 (IRQ) → CPU 5 → VPN Worker 3 → TUN Queue 3
```

Каждый воркер использует `mi_heap_new()` на своём NUMA-узле, `sched_setaffinity()` для привязки к CPU.

### 5.6. nftables flowtables — обход connection tracking

**Статус в репозитории:** Не упоминается. Важное дополнение.

Flowtables позволяют установленным потокам обойти полную цепочку netfilter (prerouting → forward → postrouting). Для VPN — после установления соединения трафик обрабатывается на уровне ingress hook. Снижение CPU на 20–50%.

```nft
table inet vpn {
    flowtable vpn_offload {
        hook ingress priority 0;
        devices = { eth0, tun0 };
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        meta l4proto { tcp, udp } flow add @vpn_offload
    }
}
```

---

## 6. Архитектура VPN-сервера

### 6.1. Сравнение моделей: repo vs исследование

**Репозиторий (wolfguard):** Worker pool с libuv. Несколько клиентов на один воркер. Event-driven + thread pool для CPU-задач. Инспирировано Lightway.

**Исследование:** Трёхпроцессная модель с fork() на клиента. Privilege separation: main → sec-mod → workers. Управление через netlink/nftables из main.

**Оптимальная гибридная модель:**

```
ГЛАВНЫЙ ПРОЦЕСС (root → CAP_NET_ADMIN + CAP_NET_BIND_SERVICE)
│
├── Конфигурация (TOML, hot-reload через inotify/SIGHUP)
├── Менеджер сессий (cookie→session, пул IP)
├── Netlink-менеджер (маршруты, nftables, TC)
├── Слушатели TCP:443 + UDP:443 (SO_REUSEPORT × N_WORKERS)
│
├── IPC (protobuf-c) ←→ МОДУЛЬ БЕЗОПАСНОСТИ (привилегированный)
│                        ├── Закрытые ключи (RSA/ECDSA — никогда не покидают процесс)
│                        ├── PAM / RADIUS (radcli) / LDAP (libldap) / TOTP (liboath)
│                        ├── Проверка сертификатов
│                        └── Песочница: seccomp-bpf
│
└── РАБОЧИЕ ПОТОКИ / ПРОЦЕССЫ (непривилегированные, N на CPU ядро)
    ├── libuv event loop (Phase 1) / io_uring (Phase 2+)
    ├── wolfSSL TLS/DTLS
    ├── Обработка пакетов (TUN ↔ шифрованный канал)
    ├── UDP GSO/GRO для batch I/O
    ├── Per-worker mimalloc heap
    └── Песочница: seccomp + Landlock + namespaces
```

**Ключевое отличие от repo:** Вместо чистого worker pool (thread-per-core) используется **гибридная модель** — worker threads обрабатывают множество клиентов каждый (как в repo), но модуль безопасности остаётся отдельным процессом (как в оригинальном ocserv). Это сохраняет privilege separation без накладных расходов fork-per-client.

### 6.2. Управление TUN

Два подхода:

**Shared TUN (как в WireGuard):** Один TUN-интерфейс с multi-queue, все клиенты через него. Проще маршрутизация, но сложнее per-user isolation.

**Per-user TUN (как в ocserv):** Отдельный TUN на клиента. Проще per-user firewall, но больше накладных расходов.

**Рекомендация:** Per-user TUN для режима совместимости (Cisco ожидает этого), shared multi-queue TUN для нативного режима (собственный клиент). Выбор через конфигурацию.

### 6.3. Управление сессиями

Cookie-based resumption: после аутентификации клиент получает HMAC-cookie. При переподключении (смена сети, wake from sleep) — предъявление cookie без повторной аутентификации. Реализация из repo (PROTOCOL_REFERENCE.md) — корректна, дополнений не требует.

---

## 7. Возможности ядра Linux 6+

### 7.1. Рекомендуемая минимальная версия: 6.7+

**Статус в репозитории:** Указан kernel 6.1+ как минимум. Исследование рекомендует 6.7+ из-за Landlock ABI v4.

| Возможность                  | Ядро                | Статус в repo  | Значение    |
| ---------------------------- | ------------------- | -------------- | ----------- |
| io_uring multishot + ZC send | 6.0                 | ⚠️ Phase 2     | Высокое     |
| DEFER_TASKRUN                | 6.1                 | ❌ Не указано  | Критическое |
| UDP GSO/GRO на TUN           | 6.2                 | ⚠️ Упоминается | Критическое |
| eBPF SK_REUSEPORT            | 5.9+                | ❌ Не указано  | Высокое     |
| nftables flowtables          | 5.x+ (зрелые в 6.x) | ❌ Не указано  | Высокое     |
| **Landlock ABI v4 (сеть)**   | **6.7**             | ❌ Не указано  | **Высокое** |
| Landlock ABI v6 (IPC)        | 6.12                | ❌             | Среднее     |
| io_uring recv bundles        | 6.7                 | ❌             | Среднее     |
| io_uring ZC RX               | 6.15                | ❌             | Будущее     |

### 7.2. Landlock: непривилегированная песочница

**Статус в репозитории:** Не упоминается. Важное дополнение для безопасности.

Landlock (ядро 5.13+, ABI v4 в 6.7) — LSM для непривилегированного контроля доступа. ABI v4 добавляет `LANDLOCK_ACCESS_NET_BIND_TCP` и `LANDLOCK_ACCESS_NET_CONNECT_TCP`:

```c
#include <linux/landlock.h>

static void sandbox_worker(void) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_WRITE_FILE,
        .handled_access_net =
            LANDLOCK_ACCESS_NET_BIND_TCP |
            LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };

    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);

    // Разрешить привязку только к VPN-порту
    struct landlock_net_port_attr port_attr = {
        .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP,
        .port = 443,
    };
    landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port_attr, 0);

    // Применить
    landlock_restrict_self(ruleset_fd, 0);
    close(ruleset_fd);
}
```

**Ограничение:** UDP пока не контролируется Landlock — только TCP bind/connect. Для UDP используется seccomp-bpf.

### 7.3. pidfd — безопасное управление процессами

```c
// Создание дочернего процесса с pidfd
int pidfd;
struct clone_args args = {
    .flags = CLONE_PIDFD,
    .pidfd = (uint64_t)&pidfd,
    .exit_signal = SIGCHLD,
};
pid_t child = clone3(&args, sizeof(args));

// Ожидание завершения без гонки PID
struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
poll(&pfd, 1, timeout_ms);

// Передача fd между процессами (ядро 5.4+)
int stolen_fd = pidfd_getfd(pidfd, target_fd, 0);
```

### 7.4. kTLS — разгрузка TLS в ядро

После TLS-рукопожатия в пользовательском пространстве ключи передаются ядру. Далее `sendfile()`/`splice()` работают с шифрованием на уровне ядра. NGINX сообщает о 8–29% улучшении. wolfSSL поддерживает kTLS. **Применимо только для управляющего канала TLS, не для туннельных DTLS-данных.**

---

## 8. Обфускация трафика и обход ТСПУ

### 8.1. Критический пробел

**Ни один из 10 документов репозитория не адресует это требование ТЗ.** Это единственный полностью отсутствующий раздел.

### 8.2. Текущее состояние ТСПУ (2024–2026)

ТСПУ установлены на всех крупных российских провайдерах. Роскомнадзор планирует 96% эффективности блокировки VPN к 2030. К февралю 2026 заблокировано 469 VPN-сервисов.

Методы обнаружения: сигнатурный анализ (OpenVPN, WireGuard, IPSec), активное зондирование (подключение к подозрительным серверам), анализ TLS-отпечатков (JA3/JA4), статистическое обнаружение TLS-в-TLS.

### 8.3. Многоуровневая архитектура обфускации

```
Уровень 1: REALITY-аутентификация
  Клиент → ECDH-HMAC в session_id TLS ClientHello → Сервер
  Если HMAC валиден → VPN-туннель
  Если невалиден → прозрачный reverse proxy к реальному сайту

Уровень 2: TLS-отпечаток (uTLS)
  ClientHello имитирует Chrome/Firefox/Safari
  Включая GREASE, порядок расширений, кривые

Уровень 3: Антидетекция TLS-в-TLS (XTLS-Vision)
  Когда внутренний трафик уже TLS 1.3 → снятие внешнего слоя
  Устранение характерного двойного шифрования

Уровень 4: Traffic padding + timing jitter
  TLS record padding (RFC 8446 §5.4): случайное дополнение
  Временной джиттер ±50–200 мс
  Пакетная коалесценция

Уровень 5: CDN fallback (WebSocket через Cloudflare)
  Домен → Cloudflare → WebSocket → VPN-сервер
  Блокировка IP невозможна без нарушения работы Cloudflare
```

### 8.4. Реализация в wolfguard

Новая подсистема:

```
src/obfuscation/
├── reality_auth.c          # ECDH-HMAC проверка в ClientHello session_id
├── reality_auth.h
├── tls_fingerprint.c       # Формирование ServerHello, имитирующего реальный сервер
├── traffic_padding.c       # TLS record padding + timing jitter
├── fallback_proxy.c        # Reverse proxy к реальному сайту при неверном HMAC
├── ws_transport.c          # WebSocket-транспорт для CDN fallback
└── obfuscation.h           # Общий API
```

REALITY-аутентификация (упрощённо):

```c
// При получении ClientHello
static bool verify_reality_auth(const uint8_t *session_id,
                                 size_t session_id_len,
                                 const uint8_t *server_private_key) {
    if (session_id_len < 32)
        return false;

    // Первые 16 байт — ephemeral public key клиента
    // Последние 16 байт — HMAC(ECDH_shared_secret, timestamp)
    uint8_t shared_secret[32];
    curve25519(shared_secret, server_private_key, session_id);

    uint8_t expected_hmac[16];
    uint32_t timestamp = time(nullptr) / 60;  // 1-минутное окно
    hmac_sha256_truncated(expected_hmac, 16, shared_secret, 32,
                          &timestamp, sizeof(timestamp));

    return timing_safe_compare(expected_hmac, session_id + 16, 16);
}
```

### 8.5. Накладные расходы

| Техника                    | CPU   | Полоса | Задержка  |
| -------------------------- | ----- | ------ | --------- |
| TLS 1.3 (AES-GCM + AES-NI) | ~1–3% | ~1%    | +1 RTT    |
| Random padding (avg 128Б)  | ~0%   | ~5–15% | ~0        |
| Timing jitter              | ~0%   | 0%     | +50–100мс |
| WebSocket framing          | ~1%   | ~2%    | ~0        |
| REALITY auth               | ~0%   | 0%     | 0         |

### 8.6. Оценка трудоёмкости

8–12 недель. Отдельная фаза после базовой миграции wolfSSL. **Приоритет P1** — без обфускации сервер бесполезен при наличии DPI.

---

## 9. Совместимость с Cisco Secure Client

### 9.1. Статус в репозитории

**Хорошо проработано.** PROTOCOL_REFERENCE.md содержит детальный анализ протокола OpenConnect v1.2, HTTP headers, DTLS quirks, XML format, authentication flow. REFACTORING_PLAN.md включает тестирование Cisco Secure Client 5.0–5.5 как обязательное.

### 9.2. Дополнения из исследования

Минимальные — repo покрывает эту область хорошо. Одно уточнение: wolfSSL `--enable-keying-material` необходим для генерации `X-DTLS-Master-Secret`, используемого в протоколе OpenConnect для установления DTLS-сессии на основе TLS master secret.

---

## 10. Аутентификация: полный стек

### 10.1. Текущий статус

**Репозиторий:** Архитектура аутентификации описана в контексте sec-mod ocserv. PAM, RADIUS, OIDC упоминаются. Конкретные библиотеки не указаны.

**ТЗ требует:** логин/пароль, TOTP, сертификаты, LDAP, RADIUS.

### 10.2. Подсистема аутентификации

```
src/auth/
├── auth_manager.c          # Менеджер цепочек аутентификации (AND/OR)
├── auth_manager.h
├── auth_password.c         # Простая проверка пароля (файл, htpasswd)
├── auth_pam.c              # PAM через async thread pool (решение проблемы #404)
├── auth_radius.c           # radcli — асинхронный RADIUS клиент
├── auth_ldap.c             # libldap — LDAP/Active Directory
├── auth_totp.c             # liboath — RFC 6238 TOTP
├── auth_cert.c             # wolfSSL certificate authentication
├── auth_chain.c            # Цепочки: [password AND totp], [cert OR radius]
└── auth.h                  # Общий API
```

### 10.3. Async PAM — решение проблемы #404

Проблема #404 из ocserv: PAM-модули, которые блокируют (pam_duo для 2FA), замораживают всю систему. Решение — выделенный thread pool для PAM:

```c
// Async PAM через thread pool libuv
typedef struct {
    uv_work_t work;
    char username[256];
    char password[256];
    int result;
    void (*callback)(int result, void *ctx);
    void *callback_ctx;
} pam_auth_request_t;

static void pam_work_cb(uv_work_t *req) {
    pam_auth_request_t *r = (pam_auth_request_t *)req;
    // Блокирующий PAM-вызов выполняется в worker thread
    r->result = pam_authenticate_user(r->username, r->password);
}

static void pam_done_cb(uv_work_t *req, int status) {
    pam_auth_request_t *r = (pam_auth_request_t *)req;
    r->callback(r->result, r->callback_ctx);
    mi_free(r);
}

void auth_pam_async(const char *user, const char *pass,
                     void (*cb)(int, void*), void *ctx) {
    pam_auth_request_t *r = mi_calloc(1, sizeof(*r));
    strncpy(r->username, user, sizeof(r->username) - 1);
    strncpy(r->password, pass, sizeof(r->password) - 1);
    r->callback = cb;
    r->callback_ctx = ctx;

    uv_queue_work(loop, &r->work, pam_work_cb, pam_done_cb);
}
```

### 10.4. TOTP с liboath

```c
#include <liboath/oath.h>

[[nodiscard]]
static vpn_result_t verify_totp(const char *base32_secret,
                                 const char *user_code) {
    oath_init();

    char *secret_raw;
    size_t secret_len;
    oath_base32_decode(base32_secret, strlen(base32_secret),
                       &secret_raw, &secret_len);

    // Проверяем с окном ±1 для clock skew
    int rc = oath_totp_validate(secret_raw, secret_len,
                                 time(nullptr), 30, 0, 1, user_code);
    free(secret_raw);
    oath_done();

    return (rc >= 0) ? VPN_OK : VPN_ERR_AUTH;
}
```

---

## 11. Per-User/Per-Group Firewall и Traffic Shaping

### 11.1. Текущий статус

**Репозиторий:** eBPF для fast-path фильтрации на TUN (DDoS, rate limiting). Нет интеграции с nftables для policy enforcement.

**ТЗ требует:** firewall-per-user, firewall-per-group, traffic shaping per user, traffic shaping per group.

### 11.2. Архитектура per-user firewall через nftables

nftables предоставляет именованные множества и verdict maps:

```nft
table inet vpn_policy {
    # Verdict map: IP клиента → политика (jump к нужной цепочке)
    map user_policy {
        type ipv4_addr : verdict;
    }

    # Политики по группам
    chain group_full_access {
        # Полный доступ
        accept
    }

    chain group_restricted {
        # Только HTTP/HTTPS
        tcp dport { 80, 443 } accept
        udp dport 53 accept
        drop
    }

    chain vpn_forward {
        type filter hook forward priority 0; policy drop;
        # Пакеты от VPN-клиентов маршрутизируются через verdict map
        iifname "tun*" ip saddr vmap @user_policy
    }
}
```

Программное управление через libnftnl + libmnl:

```c
#include <libnftnl/set.h>
#include <libmnl/libmnl.h>

// При подключении клиента: добавить в verdict map
static vpn_result_t nft_add_user_policy(const char *client_ip,
                                         const char *group_chain) {
    struct nftnl_set_elem *elem = nftnl_set_elem_alloc();

    // Ключ: IP клиента
    uint32_t ip = inet_addr(client_ip);
    nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, &ip, sizeof(ip));

    // Значение: verdict (jump к цепочке группы)
    struct nftnl_expr *verdict = nftnl_expr_alloc("verdict");
    // ... настройка jump к group_chain ...

    // Отправить через netlink
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    // ... отправка batch message ...

    return VPN_OK;
}

// При отключении: удалить из verdict map
static vpn_result_t nft_remove_user_policy(const char *client_ip) {
    // Аналогично, но nftnl_set_elem_del
}
```

### 11.3. Traffic shaping через TC (netlink)

HTB + FQ_CODEL:

```c
// Создание корневого HTB qdisc на TUN-интерфейсе
static int tc_setup_htb(int ifindex, uint32_t total_bandwidth_kbps) {
    // RTM_NEWQDISC: htb на root
    // RTM_NEWTCLASS: корневой класс с total_bandwidth
}

// Per-user класс с индивидуальным лимитом
static int tc_add_user_class(int ifindex, uint32_t class_id,
                              uint32_t rate_kbps, uint32_t ceil_kbps) {
    // RTM_NEWTCLASS: дочерний класс с rate/ceil
    // RTM_NEWQDISC: fq_codel на этом классе
}

// Классификация через nftables marks
// nftables: ip saddr 10.8.0.5 meta mark set 0x100
// TC: fw filter classid 1:0x100
```

Для per-group: все пользователи группы попадают в один класс TC с общим лимитом.

---

## 12. Split DNS и Split Tunneling

### 12.1. Split DNS

**Статус в репозитории:** Не адресовано.

Split DNS: запросы к корпоративным доменам → внутренний DNS, остальные → публичный DNS. Реализация на клиенте (через конфигурацию, push от сервера) и опционально на сервере (DNS-прокси).

Конфигурация push:

```toml
[dns]
# Split DNS: корпоративные домены через внутренний DNS
internal_dns = "10.0.0.53"
internal_domains = ["corp.example.com", "internal.example.com"]

# Публичный DNS для всего остального
public_dns = ["1.1.1.1", "8.8.8.8"]
```

Для реализации DNS-прокси на сервере (опционально): c-ares для асинхронного резолвинга, перенаправление запросов на основе имени домена.

### 12.2. Split Tunneling

**Статус в репозитории:** Упоминается в контексте Cisco compatibility. Стандартная функция ocserv.

В OpenConnect-протоколе Split Tunneling реализуется через push маршрутов (route/no-route). Дополнительно для нативного клиента: поддержка exclude-routes (no-route) и include-routes (route).

```toml
[routing]
# Split tunneling: только эти сети через VPN
route = ["10.0.0.0/8", "172.16.0.0/12"]

# Исключения: эти сети НЕ через VPN
no_route = ["10.0.100.0/24"]

# Full tunnel (без split)
# route = ["0.0.0.0/0", "::/0"]
```

---

## 13. Собственный клиент: мультиплатформенная стратегия

### 13.1. Текущий статус

**Репозиторий:** Не рассматривается. Фокус на серверной стороне и совместимости с Cisco/OpenConnect.

**ТЗ требует:** Собственный клиент для Windows, Mac, Linux, iPhone, Android с TLS 1.3 / DTLS 1.3 без режима совместимости.

### 13.2. Рекомендуемый подход

Разработка собственного клиента — отдельный крупный проект. Рекомендуемая стратегия:

**Core library на C (кроссплатформенная):**

- wolfSSL + DTLS 1.3
- Обфускация (REALITY, padding, fingerprinting)
- Протокол OpenConnect v1.2 (для серверной совместимости)
- Расширенный протокол v2.0 (нативный, без ограничений Cisco)

**Platform wrappers:**

- Windows: WinTUN (как WireGuard), C# GUI
- macOS/iOS: Network Extension framework, Swift UI
- Linux: TUN, GTK/Qt GUI, NetworkManager plugin
- Android: VpnService API, Kotlin UI

**Фаза реализации:** После стабилизации сервера (Phase 7+, после MVP). Первый приоритет — CLI-клиент на Linux (минимальные усилия, максимальная полезность для тестирования).

---

## 14. Безопасность и изоляция

### 14.1. Многоуровневая защита (объединённая модель)

```
Уровень 0: eBPF/XDP (ядро, до стека)
  └── DDoS фильтрация, rate limiting, IP blacklist

Уровень 1: wolfSentry (user space, до TLS)
  └── Поведенческий анализ, brute-force detection, per-IP limits

Уровень 2: wolfSSL (TLS/DTLS)
  └── Шифрование, аутентификация, PFS, post-quantum

Уровень 3: Privilege separation
  └── main (root) → sec-mod (crypto) → workers (unprivileged)

Уровень 4: Sandbox (worker processes)
  └── seccomp-bpf: только read/write/recvmsg/sendmsg/close
  └── Landlock: ограничение файловой системы и TCP-портов
  └── Namespaces: PID, mount isolation

Уровень 5: nftables (per-user policy)
  └── Firewall rules per user/group

Уровень 6: Компилятор
  └── -fstack-protector-strong, -D_FORTIFY_SOURCE=3
  └── -fcf-protection=full, PIE, RELRO, NOW
```

### 14.2. seccomp-bpf для рабочих процессов

Минимальный набор syscall'ов для воркера:

```c
// Разрешённые syscalls для worker процесса
static const int allowed_syscalls[] = {
    __NR_read, __NR_write, __NR_close,
    __NR_recvmsg, __NR_sendmsg, __NR_recvfrom, __NR_sendto,
    __NR_epoll_wait, __NR_epoll_ctl,
    __NR_io_uring_enter, __NR_io_uring_register,  // Если io_uring
    __NR_mmap, __NR_munmap, __NR_mprotect,        // Для mimalloc
    __NR_clock_gettime, __NR_gettimeofday,
    __NR_exit_group, __NR_exit,
    // Всё остальное — SIGKILL
};
```

---

## 15. Мониторинг и наблюдаемость

### 15.1. Статус в репозитории

libprom для Prometheus метрик. Docker Compose с Prometheus + Grafana.

### 15.2. Рекомендуемые метрики для VPN

```c
// Основные метрики
prom_counter_t *vpn_connections_total;        // По типам: tls, dtls, ws
prom_gauge_t   *vpn_connections_active;       // Текущие соединения
prom_gauge_t   *vpn_connections_per_group;    // По группам
prom_histogram_t *vpn_handshake_duration;     // TLS/DTLS handshake
prom_histogram_t *vpn_auth_duration;          // Аутентификация
prom_counter_t *vpn_bytes_total;              // rx/tx байты
prom_counter_t *vpn_packets_total;            // rx/tx пакеты
prom_counter_t *vpn_auth_failures;            // По типам ошибок
prom_counter_t *vpn_wolfsentry_blocks;        // Блокировки IDPS
prom_gauge_t   *vpn_memory_per_connection;    // Потребление RAM

// eBPF метрики (через BPF maps)
// vpn_xdp_packets_total: пакеты обработанные/отброшенные XDP
// vpn_ebpf_rate_limited: соединения ограниченные rate limiter
```

---

## 16. Сравнение с существующей документацией

### 16.1. Сводная таблица

| Направление         | Repo                 | Исследование                | Результат                                             |
| ------------------- | -------------------- | --------------------------- | ----------------------------------------------------- |
| C23 features        | ✅ Частично          | ✅ Полно                    | **Объединить**: добавить stdckdint, stdbit, enum:type |
| wolfSSL конфиг      | ✅ Хорошо            | ✅ + row-lock, hugecache    | **Объединить**: добавить флаги оптимизации            |
| Библиотеки core     | ✅ Полно             | ✅ Совпадает                | **Без изменений**                                     |
| Библиотеки auth     | ⚠️ Пробел            | ✅ radcli, liboath, libldap | **Добавить**                                          |
| Библиотеки firewall | ❌ Отсутствует       | ✅ libnftnl, libmnl         | **Добавить**                                          |
| Библиотеки DNS      | ❌ Отсутствует       | ✅ c-ares                   | **Добавить**                                          |
| Event loop          | ✅ libuv             | ✅ + io_uring optional      | **Принять подход repo**                               |
| Аллокатор           | ✅ mimalloc v3       | ✅ (jemalloc отклонён)      | **Без изменений**                                     |
| UDP GSO/GRO         | ⚠️ Упоминается       | ✅ Детально                 | **Дополнить repo**                                    |
| io_uring детали     | ⚠️ Примеры кода      | ✅ DEFER_TASKRUN и др.      | **Дополнить repo**                                    |
| Multi-queue TUN     | ✅ Код есть          | ✅ + GSO offload            | **Объединить**                                        |
| eBPF/XDP            | ✅ Код есть          | ✅ + SK_REUSEPORT           | **Объединить**                                        |
| nftables flowtables | ❌ Отсутствует       | ✅ Детально                 | **Добавить**                                          |
| NUMA affinity       | ⚠️ mimalloc heap     | ✅ + IRQ binding            | **Дополнить**                                         |
| **Обфускация**      | ❌ **Отсутствует**   | ✅ **Полный раздел**        | **Критично: добавить**                                |
| Cisco compat        | ✅ Детально          | Минимально                  | **Без изменений**                                     |
| Landlock            | ❌ Отсутствует       | ✅ ABI v4+                  | **Добавить**                                          |
| pidfd               | ❌ Отсутствует       | ✅                          | **Добавить**                                          |
| kTLS                | ❌ Отсутствует       | ✅                          | **Добавить** (для control plane)                      |
| Traffic shaping     | ❌ Отсутствует       | ✅ TC/HTB                   | **Добавить**                                          |
| Split DNS           | ❌ Отсутствует       | ✅ c-ares                   | **Добавить**                                          |
| Собственный клиент  | ❌ Отсутствует       | ✅ Стратегия                | **Добавить** (Phase 7+)                               |
| Risk management     | ✅ 10 рисков         | Не рассматривается          | **Без изменений**                                     |
| Budget/timeline     | ✅ $200K, 50-70 нед. | Не рассматривается          | **Без изменений**                                     |
| Security audit      | ✅ $50-100K          | Не рассматривается          | **Без изменений**                                     |

### 16.2. Ключевые выводы

**Документация repo** — это зрелый, прагматичный план миграции ocserv → wolfSSL с фокусом на Cisco compatibility и постепенную модернизацию. Сильные стороны: реалистичный timeline, validated PoC, risk management, dual-build стратегия.

**Данное исследование** — архитектурное видение с фокусом на максимальную производительность, безопасность ядра Linux 6+ и обход цензуры. Сильные стороны: UDP GSO/GRO бенчмарки, обфускация, Landlock, nftables, полный стек аутентификации.

**Они не противоречат** друг другу, а дополняют: repo даёт «как мигрировать безопасно», исследование даёт «куда двигаться потом» и закрывает пробелы ТЗ.

---

## 17. Интегрированная дорожная карта

Объединение фаз из REFACTORING_PLAN.md с новыми компонентами:

### Phase 0: Подготовка и PoC (3 недели) — ✅ ВЫПОЛНЕНО

Статус: PoC валидирован (50% улучшение handshake).

### Phase 1: Инфраструктура и абстракция (3 недели)

Из repo: TLS abstraction layer, dual-build, testing infrastructure.
**Добавить:** Интеграция `<stdckdint.h>` в coding standards, `<stdbit.h>` для сетевых операций.

### Phase 2: Core TLS миграция (12–14 недель)

Из repo: wolfSSL wrapper, TLS connection handling, certificate auth, DTLS.
**Добавить:** `--enable-hugecache`, `ENABLE_SESSION_CACHE_ROW_LOCK`, `--enable-keying-material`.

### Phase 3: Тестирование и валидация (8 недель)

Из repo: unit testing, integration testing, security testing, client compatibility.
**Без существенных изменений.**

### Phase 4: Оптимизация (6 недель)

Из repo: profiling, bug fixing, security review.
**Добавить:** UDP GSO/GRO, nftables flowtables, NUMA binding.

### Phase 5: Документация и релиз (5 недель)

Из repo: documentation, release preparation, beta/RC.
**Без существенных изменений.**

### Phase 6 (НОВАЯ): Аутентификация и политики (6–8 недель)

- RADIUS через radcli (2 недели)
- LDAP через libldap (2 недели)
- TOTP через liboath (1 неделя)
- Per-user/per-group firewall через libnftnl (2 недели)
- Traffic shaping через TC/netlink (1 неделя)

### Phase 7 (НОВАЯ): Обфускация трафика (8–12 недель)

- REALITY-аутентификация (3 недели)
- TLS fingerprint имитация (2 недели)
- Traffic padding + timing (1 неделя)
- Fallback proxy (2 недели)
- WebSocket-транспорт для CDN (2 недели)
- Тестирование против ТСПУ (2 недели)

### Phase 8: wolfSentry IDPS (4–6 недель)

Из repo: Sprint 8+.
**Без существенных изменений.**

### Phase 9 (НОВАЯ): Расширенные оптимизации (4–6 недель)

- io_uring бэкенд (опциональный)
- SO_REUSEPORT + eBPF steering
- Landlock sandbox для воркеров
- kTLS для управляющего канала
- Split DNS через c-ares

### Phase 10 (НОВАЯ): Собственный клиент — MVP (12+ недель)

- Core library на C (wolfSSL + DTLS 1.3 + обфускация)
- Linux CLI-клиент
- Тестирование с собственным сервером
- GUI-клиенты (Windows/macOS/iOS/Android) — отдельный проект

### Итого обновлённый timeline

| Фаза                     | Недели     | Приоритет |
| ------------------------ | ---------- | --------- |
| Phase 0–5 (repo)         | 37         | P0 — MVP  |
| Phase 6: Auth + Firewall | 6–8        | P1 — ТЗ   |
| Phase 7: Обфускация      | 8–12       | P1 — ТЗ   |
| Phase 8: wolfSentry      | 4–6        | P2        |
| Phase 9: Оптимизации     | 4–6        | P2        |
| Phase 10: Клиент         | 12+        | P3        |
| **Итого (без клиента)**  | **59–69**  |           |
| **Итого (с клиентом)**   | **71–81+** |           |

---

## 18. Выводы и рекомендации

### 18.1. Архитектурная стратегия

wolfguard находится на пересечении нескольких технологических волн: зрелости io_uring, DTLS 1.3 в wolfSSL, eBPF/nftables подсистем Linux 6.7+ и усложняющегося противостояния с ТСПУ.

**Переход на C23** даёт реальное повышение безопасности: `<stdckdint.h>` закрывает класс уязвимостей переполнения, `[[nodiscard]]` предотвращает игнорирование ошибок, enum с фиксированным типом гарантирует корректность проводного протокола.

**WolfSSL + DTLS 1.3** — единственная зрелая реализация в open-source. С аппаратным ускорением и titan-кэшем — производительность превосходит OpenSSL при 20x меньше памяти.

**UDP GSO/GRO** — самая импактная единичная оптимизация: доказанный рост с 3 до 10+ Гбит/с.

**Обфускация на уровне протокола** — не опция, а необходимость. REALITY + uTLS + XTLS-Vision + CDN fallback обеспечивают устойчивость даже при эволюции ТСПУ.

### 18.2. Немедленные действия

1. **Добавить в backlog** Phase 6 (Auth + Firewall) и Phase 7 (Обфускация) — это блокеры ТЗ
2. **Обновить coding standards**: обязательное использование `<stdckdint.h>` для арифметики с сетевыми данными
3. **Добавить библиотеки** в CMakeLists.txt: radcli, liboath, libldap, libnftnl, libmnl, c-ares
4. **Обновить wolfSSL конфигурацию**: `--enable-hugecache`, `ENABLE_SESSION_CACHE_ROW_LOCK`
5. **Аудит realloc(ptr, 0)**: поиск и замена всех вызовов для совместимости с C23

### 18.3. Целевая платформа

- Ядро: **6.7+** (для Landlock ABI v4, зрелый io_uring, flowtables)
- Компилятор: **GCC 15** (C23 по умолчанию) или **Clang 19+**
- wolfSSL: **5.8.4+** с полной оптимизацией
- glibc: **2.39+** (для `<stdbit.h>`)

---

## Приложение A: Полная конфигурация wolfSSL

```bash
./configure \
  --enable-tls13 --enable-dtls13 \
  --enable-intelasm --enable-sp --enable-sp-asm --enable-aesni \
  --enable-intelrand \
  --enable-session-ticket --enable-earlydata \
  --enable-hugecache \
  --enable-curve25519 --enable-ed25519 \
  --enable-chacha --enable-poly1305 \
  --enable-harden \
  --enable-alpn --enable-sni \
  --enable-wolfsentry \
  --enable-keying-material \
  --enable-postauth \
  --enable-certgen \
  --enable-certreq \
  --enable-ocsp \
  --enable-crl \
  --enable-supportedcurves \
  --enable-tlsx \
  --enable-pkcs11 \
  CPPFLAGS="-DENABLE_SESSION_CACHE_ROW_LOCK \
            -DNO_SESSION_CACHE_REF \
            -DWOLFSSL_MIN_RSA_BITS=2048 \
            -DWOLFSSL_MIN_ECC_BITS=256"
```

## Приложение B: Минимальный набор syscalls (seccomp)

Для worker process:

```
read, write, close, recvmsg, sendmsg, recvfrom, sendto,
epoll_wait, epoll_ctl, epoll_create1,
io_uring_enter, io_uring_register, io_uring_setup,
mmap, munmap, mprotect, madvise, mremap,
clock_gettime, gettimeofday, clock_nanosleep,
futex, sched_yield,
exit_group, exit,
rt_sigreturn, rt_sigaction, rt_sigprocmask
```

Все остальные (включая open, socket, connect, fork, exec) — SIGKILL.

## Приложение C: Пример конфигурации TOML

```toml
[server]
bind = "0.0.0.0"
tcp_port = 443
udp_port = 443
workers = 0  # auto: по числу CPU cores
kernel_min = "6.7"

[crypto]
cert_file = "/etc/wolfguard/server.crt"
key_file = "/etc/wolfguard/server.key"
ca_cert = "/etc/wolfguard/ca.crt"
tls_min_version = "1.2"      # Для Cisco совместимости
dtls_version = "1.3"          # Нативный режим
cipher_suites = [
    "TLS13-AES256-GCM-SHA384",
    "TLS13-CHACHA20-POLY1305-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",  # Для Cisco совместимости
]

[auth]
# Цепочка: (пароль AND totp) OR сертификат
methods = [
    { type = "password", backend = "radius" },
    { type = "totp", required_with = "password" },
    { type = "certificate", standalone = true },
]

[auth.radius]
server = "10.0.0.10:1812"
secret = "/etc/wolfguard/radius.secret"
timeout = 5
retries = 3

[auth.ldap]
uri = "ldaps://ad.corp.example.com"
base_dn = "dc=corp,dc=example,dc=com"
bind_dn = "cn=vpn-service,ou=services,dc=corp,dc=example,dc=com"
bind_password_file = "/etc/wolfguard/ldap.secret"

[network]
ipv4_pool = "10.8.0.0/16"
ipv6_pool = "fd00:vpn::/48"
mtu = 1400

[dns]
internal_dns = ["10.0.0.53"]
internal_domains = ["corp.example.com", "internal.example.com"]
public_dns = ["1.1.1.1", "8.8.8.8"]

[routing]
# Split tunneling
routes = ["10.0.0.0/8", "172.16.0.0/12"]
no_routes = ["10.0.100.0/24"]

[groups.engineers]
routes = ["0.0.0.0/0"]  # Full tunnel
firewall = "full_access"
bandwidth_down = "100mbit"
bandwidth_up = "50mbit"

[groups.contractors]
routes = ["10.10.0.0/16"]
firewall = "restricted"
bandwidth_down = "10mbit"
bandwidth_up = "5mbit"
dns_domains = ["project.internal"]

[obfuscation]
enabled = true
mode = "reality"
# Реальный сайт для маскировки (при неверном HMAC)
fallback_server = "www.google.com:443"
# Ключ для REALITY-аутентификации
reality_private_key_file = "/etc/wolfguard/reality.key"
# Padding
tls_padding = true
padding_range = [64, 256]
# CDN fallback
ws_enabled = true
ws_path = "/ws"

[security]
wolfsentry_enabled = true
wolfsentry_config = "/etc/wolfguard/wolfsentry.json"
seccomp_enabled = true
landlock_enabled = true
max_clients = 1024
max_same_clients = 10

[performance]
udp_gso = true
udp_gro = true
multiqueue_tun = true
flowtable = true
numa_aware = true
```

---

**Конец документа**

---

_Документ подготовлен на основе объединённого анализа: независимого технического исследования (март 2026) и документации репозитория wolfguard (октябрь 2025). Все рекомендации учитывают текущее состояние проекта и требования технического задания._
