# Комплексное исследование для проекта wolfguard: от C23 до ядра Linux

**Проект wolfguard — рефакторинг OpenConnect VPN-сервера (ocserv) на C23 с wolfSSL** — имеет мощный технологический фундамент, но требует точной калибровки каждого компонента. Это исследование охватывает четыре ключевых направления: инструментарий Clang/C23, агентную разработку через Claude Code, экосистему зависимостей и оптимизации сетевого стека Linux. Главный вывод: комбинация **Clang 20 + io_uring + UDP GSO/GRO + wolfSSL 5.8.4** позволяет построить VPN-сервер с пропускной способностью **7–13 Гбит/с** на bare metal, что конкурирует с WireGuard в ядре.

---

## НАПРАВЛЕНИЕ 1: Clang и C23 — инструментарий разработки

### Clang 20 покрывает все ключевые фичи C23 для wolfguard

Последние стабильные версии: **Clang/LLVM 20.1.2** (апрель 2025) и серия **21.x/22.x** (2026). Clang 19.1.7 — финальный релиз серии 19. Для wolfguard рекомендуется **Clang 20+** как основной компилятор с **GCC 15** в качестве вторичного для CI.

Поддержка C23 в Clang 20 достаточна для проекта:

| Фича C23                             | Clang 19 | Clang 20 | GCC 14   | GCC 15 |
| ------------------------------------ | -------- | -------- | -------- | ------ |
| `[[nodiscard]]`                      | ✅       | ✅       | ✅       | ✅     |
| `nullptr`                            | ✅       | ✅       | ✅       | ✅     |
| `constexpr` объекты                  | ✅       | ✅       | ✅       | ✅     |
| `_BitInt`                            | ✅       | ✅       | частично | ✅     |
| `typeof` / `typeof_unqual`           | ✅       | ✅       | ✅       | ✅     |
| `#embed`                             | ✅       | ✅       | ❌       | ✅     |
| `auto` type inference                | ✅       | ✅       | ✅       | ✅     |
| `bool`/`true`/`false` keywords       | ✅       | ✅       | ✅       | ✅     |
| Enum fixed underlying type           | ❌       | ✅       | ✅       | ✅     |
| `[[unsequenced]]`/`[[reproducible]]` | ❌       | ❌       | ❌       | ✅     |

**Критическое отличие Clang 19 → 20**: добавлена поддержка enum с фиксированным underlying type (N3030). **GCC 15** — единственный компилятор с `[[unsequenced]]`/`[[reproducible]]`, но эти атрибуты пока не стоит использовать в wolfguard для кросс-компиляторной совместимости. Режим C23 активируется флагом `-std=c23` (с Clang 18+). GCC 15 использует `gnu23` по умолчанию — **первый компилятор с C23 «из коробки»**.

### Конфигурация clang-format и clang-tidy для security-critical кода

Для wolfguard рекомендуется `.clang-format` с `Standard: Latest` (покрывает C23-синтаксис), `ColumnLimit: 100`, `IndentWidth: 4`, `PointerAlignment: Right` (стиль ядра Linux: `int *ptr`), и `InsertBraces: true` для автоматической вставки фигурных скобок — критично для безопасности.

Конфигурация `.clang-tidy` должна включать проверки **bugprone-\*** (обнаружение `strcpy`, `sprintf`, `sizeof` ошибок), **cert-\*** (CERT C Coding Standard: проверка возвращаемых значений, запрет `system()`), **clang-analyzer-security.\*** (tainted данные, insecure API), **clang-analyzer-unix.\*** (malloc/free несоответствия, блокировки в критических секциях). Для security-critical VPN-кода рекомендуется `WarningsAsErrors` для всех проверок категорий `security.*`, `core.*` и `cert-err33-c`.

### Санитайзеры — обязательный элемент CI для wolfguard

Стратегия для CI: **ASan + UBSan** — базовый набор (совместимы, overhead ~2–3x), **TSan** — отдельный build target (overhead ~5–15x, критически важен для многопоточного VPN-сервера), **MSan** — периодически (требует пересборки всех зависимостей: wolfSSL, libuv, mimalloc). Новинка Clang 20 — **TySan** (Type Sanitizer) для обнаружения type-based aliasing violations.

Интеграция с CMake через опции:

```cmake
option(WOLFGUARD_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(WOLFGUARD_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(WOLFGUARD_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
endif()
```

### clangd, compile_commands.json и CMake 4.1.2

Для clangd LSP необходим `compile_commands.json` — генерируется через `CMAKE_EXPORT_COMPILE_COMMANDS ON`. Файл `.clangd` в корне проекта должен указывать `-std=c23`, включать `InlayHints: DeducedTypes: true` (критично для C23 `auto`), и активировать `UnusedIncludes: Strict`. Рекомендуется использовать clangd из того же LLVM, что и компилятор (20+), чтобы корректно распознавать C23-синтаксис.

**C23 модули в Clang**: стандарт C23 (ISO/IEC 9899:2024) **не определяет модульную систему** — это фича C++20, не C. `-fmodules` в Clang — проприетарное расширение, не рекомендуется для production. Использовать традиционную модель `#include` + header guards.

CMake 4.1.2 полностью поддерживает `C_STANDARD 23`. Рекомендуется `CMakePresets.json` с пресетами `clang-debug`, `clang-release`, `clang-asan`, `clang-tsan`, `gcc-debug` для систематизированной сборки. Проект должен использовать `-std=c23` (без расширений: `CMAKE_C_EXTENSIONS OFF`) и hardening-флаги: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, `-Wl,-z,relro,-z,now`.

---

## НАПРАВЛЕНИЕ 2: Claude Code как агентная среда разработки

### Claude Code обеспечивает полный workflow для C23-проекта

Claude Code — агентный CLI от Anthropic, работающий в терминале, VS Code, JetBrains и браузере. Текущие модели: **Claude Opus 4.6** и **Sonnet 4.6**. Контекстное окно: **200K токенов** стандартно, **1M токенов** в расширенном режиме для организаций tier 4+. C-компетенция Anthropic подтверждена проектом «Claude's C Compiler» (CCC) — полный C-компилятор на 100 000 строк, скомпилировавший ядро Linux 6.9.

Ценообразование: подписка **Max $100/мес** (5x Pro) оптимальна для активной разработки, средняя стоимость ~$6/разработчик/день. Для команды — **Team $25–150/seat/мес**. API: Opus $5/$25, Sonnet $3/$15 за 1M токенов.

### MCP-серверы для навигации по C-коду и документации

Для wolfguard рекомендуется набор из **4 MCP-серверов**, настраиваемых через `.mcp.json` в корне проекта:

**clangd MCP-сервер** — три варианта реализации существуют. Лучший выбор — `felipeerias/clangd-mcp-server` (GitHub) с инструментами `find_definition`, `find_references`, `get_hover`, `search_symbols`, `get_diagnostics`. Альтернатива — `mpsm/mcp-cpp` с поддержкой CMake/Meson, множественных компонентов и call hierarchy. Оба требуют `compile_commands.json`.

**CMake MCP-сервер** — `hiono/mcp-cmake` с инструментами `configure_project` (с поддержкой presets), `build_project`, `run_tests`. Автоопределение компилятора и структурированная диагностика.

**Context7** (`@upstash/context7-mcp`) — загрузка актуальной документации библиотек в контекст. Необходимо проверить наличие wolfSSL и libuv в базе; при отсутствии использовать **Fetch MCP-сервер** (`@modelcontextprotocol/server-fetch`) для загрузки документации напрямую.

**Memory MCP** (`@modelcontextprotocol/server-memory`) — персистентная память между сессиями через Knowledge Graph.

### LSP-интеграция: нативная поддержка с декабря 2025

Claude Code поддерживает LSP нативно с версии **2.0.74** через систему плагинов. Установка clangd-плагина: `/plugin marketplace add boostvolt/claude-code-lsps`, затем `/plugin install clangd@claude-code-lsps`. Два режима работы: **LSP Tool** (9 операций: goToDefinition, findReferences, hover и др.) и **Automatic Diagnostics** (анализ после каждого редактирования файла). Производительность навигации: **~50 мс** вместо ~45 секунд текстового поиска.

Рекомендуется использовать **оба подхода**: LSP-плагин для автодиагностики + MCP clangd для глубокой навигации и символьного поиска.

### Skills, hooks и CLAUDE.md — архитектура знаний проекта

**Skills** — markdown-документы в `.claude/skills/`, обучающие Claude специфичным паттернам. Для wolfguard рекомендуются 5 skills:

- **wolfssl-api** — TLS 1.3/DTLS handshake, certificate management, FIPS 140-3 constrained API
- **libuv-patterns** — event loop lifecycle, uv_tcp_t/uv_udp_t, memory management в callbacks
- **security-coding** — constant-time сравнения (`wolfSSL_ConstantCompare`), зануление секретов, валидация входных данных
- **ocprotocol** — DTLS/TCP tunneling, XML configuration exchange, cookie-based authentication
- **c23-standards** — `typeof`, `auto`, `nullptr`, `#embed`, `constexpr` — конвенции проекта

**Hooks** — детерминистические shell-скрипты на событиях. Ключевые: `PreToolUse` с матчером `Bash(git commit*)` для блокировки коммитов без прохождения clang-format; `PostToolUse` с матчером `Edit|Write` для автоматического запуска clang-tidy после каждого редактирования.

**CLAUDE.md** — основной файл инструкций. Должен содержать: Quick Facts (язык, зависимости), Build Commands (cmake, ctest, lint, format), Key Directories, Code Standards (`wg_` prefix, snake_case, Doxygen-комментарии), Security Requirements (FIPS 140-3, constant-time, zeroing secrets). Максимум **200 строк** — детали вынесены в skills.

Структура `.claude/`:

```
.claude/
├── settings.json          # Hooks, разрешения
├── skills/                # 5 skills (commit в git)
│   ├── wolfssl-api/SKILL.md
│   ├── libuv-patterns/SKILL.md
│   ├── security-coding/SKILL.md
│   ├── ocprotocol/SKILL.md
│   └── c23-standards/SKILL.md
├── commands/              # /build, /test, /lint, /review
└── agents/                # security-reviewer, test-runner
```

---

## НАПРАВЛЕНИЕ 3: Экосистема wolfSSL и зависимости проекта

### wolfSSL 5.8.4 — обязательное обновление из-за CVE

wolfSSL активно развивается с обновлениями каждые ~3 месяца. Текущая версия wolfguard (5.8.2) содержит **CVE-2025-7395** (High, Apple native cert validation), **CVE-2025-7394** (Medium, RAND_bytes после fork()). Версия **5.8.4** (20 ноября 2025) исправляет эти и дополнительные CVE, включая DoS через KeyShareEntry (CVE-2025-11936) и timing-атаки на Curve25519.

Ключевые возможности wolfSSL для wolfguard:

- **DTLS 1.3** (RFC 9147) — **production ready**, критично для data channel OpenConnect
- **Post-quantum криптография**: ML-KEM (Kyber) и ML-DSA (Dilithium) с новыми `_new/_delete` API; **SLH-DSA** (FIPS 205); полная поддержка **CNSA 2.0**
- **FIPS 140-3**: сертификаты **#4718** и **#5041** (первый SP800-140Br1-совместимый); разрабатывается новый сертификат с ML-KEM/ML-DSA
- **QUIC**: поддерживается через интеграцию с ngtcp2 — перспективно для будущего QUIC-based VPN
- **Kernel module**: wolfSSL загружается как **LKM** (`--enable-linuxkm`), предоставляя полный TLS/DTLS стек в ядре — уникальная возможность

**⚠️ Критическое изменение лицензии**: wolfSSL перешёл с **GPLv2 на GPLv3**. GPLv3 имеет более строгие требования (anti-tivoization). Для коммерческого продукта необходима лицензия: **$7,500 за продукт/SKU**, безлимитное royalty-free распространение. wolfSentry пока остаётся на GPLv2.

### Сводная таблица зависимостей: что обновить

| Компонент      | Текущая | Последняя                | Статус        | Действие              |
| -------------- | ------- | ------------------------ | ------------- | --------------------- |
| **wolfSSL**    | 5.8.2   | **5.8.4**                | ✅ Active     | ⬆️ Обновить (CVE)     |
| **libuv**      | 1.51.0  | **1.52.0** (02.2026)     | ✅ Active     | ⬆️ Обновить           |
| **llhttp**     | 9.3.0   | **9.3.1** (02.2026)      | ✅ Active     | ⬆️ Обновить           |
| **cJSON**      | 1.7.19  | 1.7.19                   | ✅ Maintained | ✅ Актуально          |
| **mimalloc**   | 3.1.5   | 3.1.5 stable / 3.2.8 rc3 | ✅ Active     | ✅ Ждать 3.2.x stable |
| **protobuf-c** | ?       | ~1.5.x                   | ⚠️ Медленно   | Рассмотреть nanopb    |
| **Ceedling**   | 1.0.1   | 1.0.1                    | ✅ Active     | ✅ Актуально          |

### Рекомендации по дополнительным компонентам

**wolfSentry 1.6.3** — рекомендуется интегрировать как встроенный IDPS/firewall: динамическая блокировка вредоносного трафика, JSON-конфигурация, транзакционная семантика. Лицензия GPLv2 (отдельно от wolfSSL).

**mimalloc v3** с `MI_SECURE=ON` — лучший выбор аллокатора для VPN: guard pages, рандомизированное выделение, зашифрованные free lists (~10% overhead). Превосходит jemalloc по производительности и snmalloc по зрелости.

**yyjson 0.12.0** — в **5–7x быстрее cJSON** (2.39 vs 0.48 ГБ/с), поддерживает JSON Pointer, JSON Patch, custom allocator. Рекомендация: cJSON для конфигурации (простота), yyjson для API/метрик (скорость).

**tomlc99** — de facto стандарт TOML-парсера для C. TOML — лучший формат для VPN-конфигурации: строгая типизация, комментарии, человекочитаемость. JSON оставить для runtime (wolfSentry), YAML не рекомендуется (нет хорошего C-парсера).

**Логирование**: zlog **заброшен** (~2020–2021). Рекомендуется написать собственную lightweight обёртку на основе log.c/microlog с поддержкой structured logging (JSON), per-модульных уровней и async-вывода через libuv.

**Prometheus-метрики**: libprom от DigitalOcean минимально поддерживается. Рекомендуется использовать libprom для core API (counters, gauges, histograms), но написать собственный HTTP exposition handler через llhttp (~200 строк) вместо libpromhttp.

---

## НАПРАВЛЕНИЕ 4: Сетевой стек Linux — путь к 10+ Гбит/с

### Текущие версии ядра и целевые платформы

Стабильное ядро: **Linux 6.19** (февраль 2026). LTS-ядра: **6.18** (EOL декабрь 2028), **6.12** (EOL декабрь 2028), **6.6** (EOL декабрь 2027). Для wolfguard: минимум **6.6 LTS** (широко распространено), оптимально **6.12 LTS** (максимум возможностей io_uring, kTLS, BIG TCP).

### io_uring: мощный, но с оговорками по безопасности

io_uring обеспечивает completion-based I/O с батчингом операций через shared memory rings. Ключевые сетевые возможности по версиям ядра:

| Операция          | Ядро     | Значение для VPN                              |
| ----------------- | -------- | --------------------------------------------- |
| Multishot accept  | **5.19** | Один SQE → множество CQE для новых соединений |
| Multishot recv    | **6.0**  | Один SQE → множество CQE при получении данных |
| Zero-copy send    | **6.0**  | Отправка без копирования в kernel space       |
| Zero-copy sendmsg | **6.1**  | Scatter/gather zero-copy                      |
| Recv bundles      | **6.10** | Заполнение нескольких буферов за один receive |
| Zero-copy recv    | **6.12** | Экспериментально, требует HW поддержку NIC    |

**io_uring + kTLS** — поддерживается: после TLS handshake в userspace и установки kTLS через `setsockopt(SOL_TCP, TCP_ULP, "tls")`, io_uring используется для шифрованного send/recv без дополнительных syscall'ов.

**⚠️ Безопасность io_uring** — серьёзный риск. Google отключил io_uring на ChromeOS, Android и серверах: **60% заявок** в bug bounty kCTF касались io_uring (~$1M выплат). Ключевые CVE: CVE-2024-0582 (use-after-free, LPE), CVE-2023-2598 (LPE). io_uring **обходит seccomp-фильтрацию** — операции выполняются через SQE, а не syscall'ы. Docker v25+ блокирует io_uring по умолчанию.

**libuv и io_uring**: libuv поддерживает io_uring **только для файловых операций** (read, write, fsync — 8x прирост). Сетевые операции по-прежнему через **epoll**. Полная замена сетевого I/O на io_uring — в процессе разработки. Для wolfguard: если нужен io_uring для сети, потребуется **прямое использование liburing** параллельно с libuv, либо ожидание завершения работы над libuv.

### UDP GSO/GRO — ключевая оптимизация, доказавшая 264% прирост

**UDP GSO** (Generic Segmentation Offload, `UDP_SEGMENT`, ядро 4.18) позволяет отправлять «гигантский» UDP-датаграм, который ядро разбивает на сегменты по указанному размеру. **UDP GRO** (ядро 5.0) коалесцирует мелкие UDP-пакеты одного потока в один крупный. **TUN-драйвер получил поддержку GSO** в ядре **6.2** — критический момент для userspace VPN.

Результаты Tailscale (wireguard-go на 10 GbE bare metal): без GSO/GRO — **3 Гбит/с**, с GSO/GRO — **7.32 Гбит/с** (i5-12400 bare metal — **13 Гбит/с**). Это **превышает** kernel WireGuard (2.6 Гбит/с в том же тесте). Для DTLS в wolfguard: один `sendmsg()` с `UDP_SEGMENT` вместо N вызовов, batch encryption/decryption.

```c
int gso_size = 1400; // размер DTLS-сегмента
setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size));

// TUN с GSO через IFF_VNET_HDR:
ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE;
unsigned int features = TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6;
ioctl(tun_fd, TUNSETOFFLOAD, features);
```

### eBPF/XDP и kTLS — дополнительные уровни оптимизации

**XDP** работает на физическом интерфейсе для DDoS-предфильтрации UDP-пакетов VPN-порта (до TCP/IP стека). **На TUN-устройствах XDP не работает нативно** — только `xdpgeneric` без выигрыша. Для TUN рекомендуется **TC BPF** (до 21–23 Гбит/с по данным Loophole Labs). BPF CO-RE полностью зрел: BTF в `/sys/kernel/btf/vmlinux`, поддержка во всех основных дистрибутивах.

**kTLS** (kernel TLS) поддерживает AES-128/256-GCM, ChaCha20-Poly1305 для TLS 1.2/1.3. wolfSSL **не имеет встроенной kTLS-интеграции** (нет аналога OpenSSL `SSL_sendfile`), но существует рабочий подход: wolfSSL handshake → извлечение ключей → передача ядру через `setsockopt(SOL_TLS, TLS_TX/TLS_RX)` → стандартные `send()`/`recv()` с шифрованием в ядре. Для DTLS (UDP) kTLS неприменим — использовать wolfSSL напрямую.

### Multi-queue TUN масштабируется линейно до 4 очередей

**IFF_MULTI_QUEUE** (ядро 3.8+, до 256 очередей) демонстрирует почти линейный рост: 1 очередь — 818 kpps, 2 очереди — 1926 kpps (+135%), 4 очереди — **3536 kpps (+332%)**. Для wolfguard: число очередей TUN = число worker-потоков, выбор TX-очереди через eBPF (`TUNSETSTEERINGEBPF`).

### WireGuard: что заимствовать для userspace VPN

WireGuard быстр благодаря работе в ядре, NAPI polling, GSO/GRO, SIMD-ускоренному ChaCha20-Poly1305 (AVX-512) и lockless `ptr_ring`. Для userspace VPN **применимы**: UDP GSO/GRO (Tailscale доказал превосходство над kernel WireGuard), `recvmmsg`/`sendmmsg` batch 32–64 (до **6x** роста pps), checksum offloading через TUN + `IFF_VNET_HDR`, SIMD-криптография (wolfCrypt поддерживает AVX2/AVX-512 для AES-GCM).

### Практическая архитектура сетевого стека wolfguard

**Рекомендуемая стратегия производительности** (в порядке приоритета внедрения):

1. **UDP GSO/GRO** (ядро 4.18+/5.0+, TUN GSO — 6.2+) — наибольший прирост, реализация через `setsockopt(UDP_SEGMENT)` + `IFF_VNET_HDR` на TUN. Ожидаемый эффект: **3–7x** рост throughput.

2. **recvmmsg/sendmmsg** batch 32–64 — амортизация syscall overhead. Cloudflare: с `SO_REUSEPORT` + 4 процесса + `recvmmsg` → **1.1M pps** на хост.

3. **Multi-queue TUN** (`IFF_MULTI_QUEUE`) — 1 worker = 1 CPU = 1 TUN-очередь. Линейное масштабирование до 4–8 ядер.

4. **SO_REUSEPORT + eBPF dispatch** — кастомный load balancing UDP-пакетов между worker'ами через `SO_ATTACH_REUSEPORT_EBPF`. Overhead eBPF: ~30–40 нс/пакет.

5. **NUMA-aware binding** — `SO_INCOMING_CPU` + `sched_setaffinity()` + RPS/RFS в пределах одного NUMA-домена. Отключить irqbalance.

6. **io_uring** (multishot accept/recv) — для control channel (TLS). Требует прямое использование liburing (libuv не поддерживает io_uring для сети).

7. **XDP на физическом интерфейсе** — DDoS-предфильтрация. **TC BPF на TUN** — QoS и мониторинг.

### VPN-бенчмарки: wolfguard может конкурировать с WireGuard

| VPN                        | Throughput (типичный)                    | Latency overhead | CPU usage |
| -------------------------- | ---------------------------------------- | ---------------- | --------- |
| **WireGuard** (kernel)     | 920–960 Мбит/с (AWS), 2.6 Гбит/с (10GbE) | +1–3 мс          | 8–15%     |
| **wireguard-go + GSO/GRO** | **7.3–13 Гбит/с** (bare metal)           | +2–5 мс          | 20–40%    |
| **OpenVPN**                | 650–780 Мбит/с (AWS)                     | +8–12 мс         | 45–60%    |
| **Lightway** (DTLS 1.3)    | Сопоставимо с WireGuard                  | Низкий           | Средний   |

Главные ограничения userspace VPN: **4 копирования** на пакет (kernel→TUN→userspace→encrypt→kernel→NIC), **~5 мкс** overhead на syscall (с Spectre/Meltdown mitigations). UDP GSO/GRO + recvmmsg/sendmmsg устраняют основные bottleneck'и. wolfguard с полным стеком оптимизаций может достичь **5–10 Гбит/с** на bare metal.

Рекомендуемые sysctl-параметры для VPN-сервера:

```bash
net.ipv4.ip_forward = 1
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_budget = 600
net.core.busy_poll = 50
net.core.rps_sock_flow_entries = 32768
net.core.somaxconn = 8192
```

---

## Заключение: дорожная карта wolfguard

Исследование выявило несколько неочевидных инсайтов. Во-первых, **userspace VPN с UDP GSO/GRO превосходит kernel WireGuard** (данные Tailscale: 7.3 vs 2.6 Гбит/с) — wolfguard не обречён проигрывать kernel VPN. Во-вторых, **wolfSSL сменил лицензию на GPLv3** — это требует немедленного решения по лицензированию ($7,500 за коммерческую лицензию). В-третьих, libuv **не поддерживает io_uring для сети** — потребуется архитектурное решение: либо прямое использование liburing, либо гибридный подход (libuv для event loop + liburing для hot path).

Приоритетные шаги внедрения: **(1)** обновить wolfSSL до 5.8.4 и решить вопрос лицензирования; **(2)** настроить полный toolchain (Clang 20 + CMake presets + clang-tidy + санитайзеры); **(3)** создать `.claude/` инфраструктуру (CLAUDE.md, skills, hooks, MCP-серверы); **(4)** реализовать UDP GSO/GRO + multi-queue TUN + recvmmsg/sendmmsg как первую волну сетевых оптимизаций; **(5)** интегрировать wolfSentry для IDPS; **(6)** добавить eBPF-мониторинг и XDP-фильтрацию как вторую волну.
