# wolfguard: Рекомендации по выбору компилятора и инструментов сборки

**Версия документа**: 1.0
**Дата**: 2025-03-07
**Проект**: wolfguard v2.0.0 (C23, ISO/IEC 9899:2024)
**Статус**: Рекомендации на основе архитектурного анализа

---

## 1. Резюме

wolfguard — проект на **чистом C23** с критическими требованиями к безопасности, производительности и совместимости с Cisco Secure Client 5.x+. На основании анализа архитектуры проекта, стека библиотек и целевых платформ, рекомендуется **двухкомпиляторная стратегия** с разделением ролей: **Clang как основной компилятор разработки**, **GCC как дополнительный компилятор для CI и release-сборок**.

---

## 2. Анализ требований wolfguard к компилятору

### 2.1. Язык: C23 (ISO/IEC 9899:2024)

Архитектура wolfguard активно использует возможности C23:

| Возможность C23  | Применение в wolfguard                             | GCC 15 | Clang 22    |
| ---------------- | -------------------------------------------------- | ------ | ----------- |
| `[[nodiscard]]`  | Все API-функции (`crypto_tls_*`, `nvm_*`, `dpd_*`) | ✅     | ✅          |
| `nullptr`        | Замена `NULL` во всех проверках указателей         | ✅     | ✅          |
| `constexpr`      | Константы конфигурации, размеры буферов            | ✅     | ✅          |
| `typeof`         | Обобщённые макросы памяти (mimalloc)               | ✅     | ✅          |
| `_BitInt(N)`     | Криптографические операции (wolfSSL)               | ✅     | ✅          |
| `_Static_assert` | Валидация структур (`session_cookie_t`)            | ✅     | ✅          |
| `_Atomic`        | Lock-free счётчики соединений                      | ✅     | ✅          |
| `#embed`         | Встроенные ресурсы (сертификаты, конфигурации)     | ✅     | ⚠️ Частично |

**Ключевой момент**: GCC 15 переключил режим C по умолчанию на C23 (`-std=gnu23`), тогда как Clang по-прежнему использует C17. Для wolfguard потребуется явный `-std=c23` или `-std=gnu23` в обоих случаях. GCC здесь имеет преимущество в полноте реализации C23, особенно `#embed` — что может быть полезно для встраивания корневых сертификатов или конфигурационных шаблонов.

### 2.2. Стек библиотек

wolfguard использует чисто C-библиотеки, все из которых отлично собираются обоими компиляторами:

| Библиотека       | Роль        | Особенности сборки                             |
| ---------------- | ----------- | ---------------------------------------------- |
| wolfSSL 5.8.2+   | TLS/DTLS    | Поддерживает GCC и Clang; callback-архитектура |
| wolfSentry 1.6.3 | IDPS        | GPLv2, чистый C                                |
| libuv 1.51.0+    | Event loop  | CMake, отлично собирается обоими               |
| llhttp 9.2+      | HTTP-парсер | Генерируется llparse, C-код                    |
| mimalloc 3.1.5+  | Аллокатор   | CMake; требует тонкой оптимизации              |
| cJSON 1.7.19+    | JSON        | Single-file, тривиальная сборка                |
| protobuf-c       | IPC         | Существующая интеграция                        |
| zlog 1.2.18      | Логирование | Makefile, стандартный C                        |

### 2.3. Целевые платформы

Из REFACTORING_PLAN.md и CISCO_COMPATIBILITY_GUIDE.md:

- Ubuntu 22.04, 24.04
- Fedora 39, 40
- RHEL 9.x
- Debian 12
- FreeBSD 13.x, 14.x
- OpenBSD 7.x

**Примечание**: На FreeBSD и OpenBSD Clang является системным компилятором. На Linux-дистрибутивах GCC — системный по умолчанию.

---

## 3. Рекомендации по компилятору

### 3.1. Основная стратегия: Clang для разработки, GCC для валидации

```
┌─────────────────────────────────────────────────────────┐
│                   CI/CD Pipeline                        │
│                                                         │
│  ┌─────────────────┐    ┌─────────────────┐            │
│  │  Clang 22+      │    │  GCC 15+        │            │
│  │  (основной)     │    │  (валидация)    │            │
│  │                  │    │                  │            │
│  │  • Debug-сборки │    │  • Release LTO  │            │
│  │  • Санитайзеры  │    │  • -fanalyzer   │            │
│  │  • clang-tidy   │    │  • Доп. warnings│            │
│  │  • Фаззинг      │    │  • Портируемость│            │
│  │  • clang-format │    │                  │            │
│  └────────┬────────┘    └────────┬────────┘            │
│           │                      │                      │
│           ▼                      ▼                      │
│  ┌──────────────────────────────────────────┐          │
│  │       Единая тестовая матрица            │          │
│  │  • Unit tests (Check framework)          │          │
│  │  • Integration tests (Cisco 5.x+)       │          │
│  │  • Performance benchmarks                │          │
│  │  • Compatibility matrix                  │          │
│  └──────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

### 3.2. Обоснование выбора Clang как основного

**3.2.1. Скорость компиляции (критично для итеративной разработки)**

wolfguard — проект на C, но включает зависимости C++ (wolfSSL внутренне использует часть C++-инфраструктуры при тестах). По бенчмаркам PostgreSQL (сопоставимый по размеру C-проект), Clang 18 компилировал **в 2 раза быстрее** GCC 14 в однопоточном режиме. При параллельной сборке (`-j8`) разница сохранялась: 20 секунд Clang vs 45 секунд GCC.

Для wolfguard с его 12–14 неделями core TLS-миграции (Phase 2) скорость цикла edit→compile→test непосредственно влияет на производительность команды.

**3.2.2. MemorySanitizer (MSan) — только Clang**

Это **критическое** преимущество для проекта с миграцией криптобиблиотеки. MSan обнаруживает чтение неинициализированной памяти — один из наиболее опасных классов ошибок при замене GnuTLS на wolfSSL:

```bash
# Типичный сценарий ошибки при миграции TLS-библиотеки:
# wolfSSL инициализирует структуру иначе, чем GnuTLS,
# и часть полей остаётся неинициализированной
clang -fsanitize=memory -fno-omit-frame-pointer -g \
    -o wolfguard_msan src/*.c -lwolfssl -luv
```

GCC **не поддерживает MSan**. Это единственный инструмент, способный надёжно обнаружить тонкие ошибки при работе с `WOLFSSL_CTX`, `session_cookie_t`, `nvm_flow_t` и другими структурами, где инициализация неочевидна.

**3.2.3. Экосистема инструментов для безопасности VPN-сервера**

| Инструмент                | Значение для wolfguard                                                                                            |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **clang-tidy**            | Автоматический аудит кода: `bugprone-*`, `cert-*`, `security-*` проверки. Критично при миграции 94 GnuTLS-функций |
| **Clang Static Analyzer** | Символическое исполнение для обнаружения use-after-free, double-free в TLS-путях                                  |
| **clangd**                | LSP-сервер для навигации по 50+ исходным файлам wolfguard                                                         |
| **clang-format**          | Единый стиль кода в команде из 2 разработчиков                                                                    |
| **LibFuzzer**             | Интегрированный фаззер для TLS handshake, IPFIX-парсера, XML-аутентификации                                       |
| **SanitizerCoverage**     | Покрытие кода при фаззинге — критично для 72-часовой кампании (Phase 3.3)                                         |

**3.2.4. Фаззинг — обязательное требование проекта**

REFACTORING_PLAN.md явно требует:

> - TLS handshake fuzzing (AFL, libFuzzer)
> - HTTP request fuzzing
> - Configuration file fuzzing
> - DTLS packet fuzzing
> - Fuzzing campaign (minimum 72 hours)

LibFuzzer нативно интегрирован с Clang и не требует внешних инструментов. Для GCC потребуется AFL++ с инструментацией, что добавляет сложность.

```c
// Пример фаззинг-цели для IPFIX-декодера NVM
// Компилируется только Clang + LibFuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nvm_process_ipfix_message(data, size, NULL);
    return 0;
}
```

```bash
clang -g -fsanitize=fuzzer,address -o fuzz_ipfix \
    fuzz_ipfix.c src/nvm/ipfix_decoder.c -lwolfssl
./fuzz_ipfix corpus/ -max_total_time=259200  # 72 часа
```

### 3.3. Обоснование GCC как валидационного компилятора

**3.3.1. `-fanalyzer` для чистого C-кода**

GCC `-fanalyzer` — статический анализатор, работающий **только с C** (не C++). Для wolfguard, написанного на чистом C23, это идеальный инструмент:

```bash
gcc-15 -fanalyzer -Wall -Wextra -Werror \
    -Wduplicated-branches -Wduplicated-cond -Wlogical-op \
    -o wolfguard_analysis src/*.c
```

В GCC 14–15 анализатор значительно улучшен: обнаружение double-free, use-after-free, бесконечных циклов, переполнений буфера с ASCII-арт визуализацией путей исполнения. Это дополняет Clang Static Analyzer, находя иные классы ошибок.

**3.3.2. Уникальные предупреждения GCC**

GCC предлагает предупреждения, отсутствующие в Clang, которые важны для C VPN-сервера:

- `-Wduplicated-branches` — одинаковые ветви if/else (копипаст при миграции)
- `-Wduplicated-cond` — дублированные условия
- `-Wlogical-op` — логические ошибки в выражениях
- `-Wformat-overflow` — переполнение при форматировании строк (критично для `snprintf` в cookie-генерации)

**3.3.3. Release-сборки с LTO**

Для production-бинарника wolfguard GCC LTO предпочтителен:

- Более глубокая межпроцедурная оптимизация
- **Уменьшение** размера бинарника (в отличие от Clang LTO, который может увеличить его до +15%)
- Лучшее качество кода на целочисленных операциях (парсинг IPFIX, обработка пакетов)

```bash
# Release-сборка wolfguard
gcc-15 -O3 -flto=auto -march=native \
    -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
    -fPIE -pie \
    -o wolfguard src/*.c -lwolfssl -luv -lmimalloc
```

**3.3.4. GCC 16 и рефлексия C++26**

Хотя wolfguard — проект на C, будущая интеграция с C++-инструментами и потенциальные плагины могут потребовать C++26. GCC 16 (2026) реализует рефлексию (P2996), expansion statements и constexpr-исключения — это стоит учитывать в долгосрочной перспективе.

---

## 4. Конфигурация сборки

### 4.1. Флаги компиляции

```meson
# meson.build для wolfguard

project('wolfguard', 'c',
  version: '2.0.0',
  default_options: [
    'c_std=c23',
    'warning_level=3',
    'werror=true',
    'b_pie=true',
    'b_lto=true',
  ]
)

# Общие флаги безопасности
security_flags = [
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=3',
  '-fstack-clash-protection',
  '-fcf-protection=full',
]

# Специфичные флаги для каждого компилятора
cc = meson.get_compiler('c')

if cc.get_id() == 'clang'
  # Clang-специфичные
  add_project_arguments([
    '-Weverything',            # Все предупреждения (отключить ненужные)
    '-Wno-padded',             # Выравнивание структур — информационное
    '-Wno-declaration-after-statement',  # C23 разрешает
    '-Wno-unsafe-buffer-usage',          # Слишком строгое для C
    '-fcolor-diagnostics',
  ], language: 'c')

elif cc.get_id() == 'gcc'
  # GCC-специфичные
  add_project_arguments([
    '-Wall', '-Wextra',
    '-Wduplicated-branches',
    '-Wduplicated-cond',
    '-Wlogical-op',
    '-Wformat-overflow=2',
    '-Wnull-dereference',
    '-Wjump-misses-init',
    '-fdiagnostics-color=always',
  ], language: 'c')

  # -fanalyzer для debug-сборок
  if get_option('buildtype') == 'debug'
    add_project_arguments(['-fanalyzer'], language: 'c')
  endif
endif

add_project_arguments(security_flags, language: 'c')
```

### 4.2. Профили сборки

```meson
# meson_options.txt

option('crypto_backend', type: 'combo',
  choices: ['wolfssl', 'gnutls', 'both'],
  value: 'wolfssl',
  description: 'TLS/DTLS backend')

option('sanitizers', type: 'combo',
  choices: ['none', 'address', 'memory', 'thread', 'undefined', 'all'],
  value: 'none',
  description: 'Sanitizer profile')

option('fuzzing', type: 'boolean',
  value: false,
  description: 'Build with LibFuzzer support (Clang only)')
```

### 4.3. Конфигурация CI/CD

```yaml
# .github/workflows/build.yml

name: wolfguard CI

on: [push, pull_request]

jobs:
  # ═══════════════════════════════════════════
  # Clang: основная сборка + санитайзеры
  # ═══════════════════════════════════════════
  clang-debug:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        sanitizer: [address, memory, thread, undefined]
    steps:
      - uses: actions/checkout@v4
      - name: Build with sanitizer
        env:
          CC: clang-22
        run: |
          meson setup build \
            --buildtype=debug \
            -Dsanitizers=${{ matrix.sanitizer }}
          ninja -C build
          ninja -C build test

  clang-tidy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Run clang-tidy
        run: |
          meson setup build --buildtype=debug
          run-clang-tidy -p build \
            -checks='bugprone-*,cert-*,security-*,performance-*' \
            src/

  clang-fuzz:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Build fuzz targets
        env:
          CC: clang-22
        run: |
          meson setup build -Dfuzzing=true
          ninja -C build
      - name: Run fuzzing (10 min per target)
        run: |
          ./build/fuzz_tls_handshake corpus/tls -max_total_time=600
          ./build/fuzz_ipfix corpus/ipfix -max_total_time=600
          ./build/fuzz_http corpus/http -max_total_time=600

  # ═══════════════════════════════════════════
  # GCC: валидация + release
  # ═══════════════════════════════════════════
  gcc-analysis:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Build with GCC analyzer
        env:
          CC: gcc-15
        run: |
          meson setup build --buildtype=debug
          ninja -C build 2>&1 | tee gcc-analysis.log
      - name: Check for analyzer warnings
        run: |
          if grep -E '\[-Wanalyzer' gcc-analysis.log; then
            echo "::error::GCC analyzer found issues"
            exit 1
          fi

  gcc-release:
    runs-on: ubuntu-24.04
    needs: [clang-debug, gcc-analysis]
    steps:
      - uses: actions/checkout@v4
      - name: Build release with LTO
        env:
          CC: gcc-15
        run: |
          meson setup build \
            --buildtype=release \
            -Db_lto=true
          ninja -C build
      - name: Run benchmarks
        run: |
          ./build/bench_tls_handshake
          ./build/bench_throughput

  # ═══════════════════════════════════════════
  # Кросс-платформа
  # ═══════════════════════════════════════════
  freebsd:
    runs-on: ubuntu-24.04
    steps:
      - uses: cross-platform-actions/action@v0.25.0
        with:
          operating_system: freebsd
          version: "14.1"
          run: |
            # FreeBSD использует Clang системный
            meson setup build
            ninja -C build
            ninja -C build test
```

---

## 5. Рекомендации по линковщику

### 5.1. Матрица выбора линковщика

| Сценарий                      | Линковщик    | Обоснование                                     |
| ----------------------------- | ------------ | ----------------------------------------------- |
| **Debug-сборка (Clang)**      | mold         | Мгновенная линковка, ускорение цикла разработки |
| **CI с санитайзерами**        | lld          | Нативная совместимость с Clang                  |
| **Release (GCC + LTO)**       | GNU ld (bfd) | Единственный совместимый с GCC LTO              |
| **Release (Clang + ThinLTO)** | lld          | Нативная интеграция ThinLTO                     |
| **FreeBSD/OpenBSD**           | lld          | Системный линковщик                             |

### 5.2. Конфигурация

```bash
# Debug: Clang + mold (максимальная скорость итераций)
CC=clang-22 LDFLAGS="-fuse-ld=mold" meson setup build-debug --buildtype=debug

# Release (вариант A): GCC + GNU ld + полный LTO
CC=gcc-15 meson setup build-release --buildtype=release -Db_lto=true

# Release (вариант B): Clang + lld + ThinLTO (быстрее сборка, ~0.2% потеря)
CC=clang-22 LDFLAGS="-fuse-ld=lld -flto=thin" meson setup build-release-thin
```

### 5.3. Критическое ограничение: mold и LTO

mold **не поддерживает LTO** — ни GCC GIMPLE, ни LLVM bitcode. Для wolfguard это означает:

- Debug-сборки: mold (скорость линковки)
- Release-сборки: lld или GNU ld (LTO-оптимизация)

Поскольку wolfguard будет обслуживать 10,000+ одновременных соединений, LTO-оптимизация на hot paths (TLS handshake, packet forwarding, IPFIX parsing) даёт ощутимый прирост производительности и не должна приноситься в жертву.

---

## 6. Рекомендации по санитайзерам

### 6.1. Матрица санитайзеров для wolfguard

| Санитайзер | Компилятор       | Когда использовать | Что ищет в wolfguard                                    |
| ---------- | ---------------- | ------------------ | ------------------------------------------------------- |
| **ASan**   | Clang/GCC        | Каждый коммит      | Buffer overflow в IPFIX-парсере, cookie-генерации       |
| **MSan**   | **Только Clang** | Каждый коммит      | Неинициализированная память при миграции GnuTLS→wolfSSL |
| **TSan**   | Clang/GCC        | Перед merge        | Race conditions в worker pool, atomic-операциях         |
| **UBSan**  | Clang/GCC        | Каждый коммит      | Integer overflow, null-deref в протокольной обработке   |
| **CFI**    | **Только Clang** | Release builds     | Control Flow Integrity — защита от ROP-атак             |

### 6.2. Приоритетные сценарии для MSan

MSan критически важен для следующих компонентов wolfguard:

```
src/crypto/tls_wolfssl.c    — Все структуры wolfSSL инициализируются иначе, чем GnuTLS
src/auth/session_cookie.c   — session_cookie_t содержит криптоданные
src/nvm/ipfix_decoder.c     — Парсинг бинарных IPFIX-пакетов из сети
src/tunnel/dpd.c            — DPD-фреймы из UDP (ненадёжная доставка)
src/dns/split_dns.c         — DNS-пакеты произвольного содержания
```

---

## 7. Рекомендации по фаззингу

### 7.1. Фаззинг-цели (LibFuzzer, только Clang)

| Цель                  | Файл                        | Приоритет | Время    |
| --------------------- | --------------------------- | --------- | -------- |
| TLS Handshake         | `fuzz/fuzz_tls_handshake.c` | CRITICAL  | 24 часа  |
| DTLS Packet           | `fuzz/fuzz_dtls_packet.c`   | CRITICAL  | 24 часа  |
| HTTP Request (llhttp) | `fuzz/fuzz_http_request.c`  | HIGH      | 12 часов |
| IPFIX Message (NVM)   | `fuzz/fuzz_ipfix.c`         | HIGH      | 12 часов |
| XML Auth Message      | `fuzz/fuzz_xml_auth.c`      | HIGH      | 8 часов  |
| TOML Config           | `fuzz/fuzz_config.c`        | MEDIUM    | 4 часа   |
| Session Cookie        | `fuzz/fuzz_cookie.c`        | MEDIUM    | 4 часа   |
| Split DNS Query       | `fuzz/fuzz_dns.c`           | LOW       | 2 часа   |

**Итого**: ~90 часов — превышает минимум 72 часа из REFACTORING_PLAN.md.

### 7.2. Структура фаззинг-сборки

```meson
# fuzz/meson.build
if get_option('fuzzing')
  assert(cc.get_id() == 'clang', 'Fuzzing requires Clang (LibFuzzer)')

  fuzz_deps = [wolfssl_dep, libuv_dep, cjson_dep]
  fuzz_flags = ['-fsanitize=fuzzer,address']

  fuzz_targets = {
    'fuzz_tls_handshake': 'fuzz_tls_handshake.c',
    'fuzz_dtls_packet': 'fuzz_dtls_packet.c',
    'fuzz_http_request': 'fuzz_http_request.c',
    'fuzz_ipfix': 'fuzz_ipfix.c',
    'fuzz_xml_auth': 'fuzz_xml_auth.c',
  }

  foreach name, src : fuzz_targets
    executable(name,
      src,
      dependencies: fuzz_deps,
      c_args: fuzz_flags,
      link_args: fuzz_flags,
    )
  endforeach
endif
```

---

## 8. Статический анализ: двойной барьер

### 8.1. Clang-tidy (основной)

```yaml
# .clang-tidy
Checks: >
  bugprone-*,
  cert-*,
  clang-analyzer-security.*,
  clang-analyzer-core.*,
  clang-analyzer-deadcode.*,
  clang-analyzer-unix.*,
  concurrency-*,
  performance-*,
  portability-*,
  -bugprone-easily-swappable-parameters,
  -cert-err33-c

# Важные проверки для VPN-сервера:
# cert-err34-c      — проверка результатов atoi/scanf
# bugprone-signal-handler — безопасность обработчиков сигналов
# concurrency-mt-unsafe — потоконебезопасные функции
# security-insecureAPI — опасные функции (strcpy, sprintf)
```

### 8.2. GCC `-fanalyzer` (дополнительный)

```bash
# GCC-анализатор особенно хорош для:
# - Путей исполнения через несколько функций (interprocedural)
# - Double-free в обработчиках ошибок TLS
# - Use-after-free при закрытии соединений
# - Утечки файловых дескрипторов (TUN/UDP сокеты)

gcc-15 -fanalyzer \
    -Wanalyzer-double-free \
    -Wanalyzer-use-after-free \
    -Wanalyzer-fd-leak \
    -Wanalyzer-malloc-leak \
    -Wanalyzer-null-dereference \
    -Wanalyzer-tainted-array-index \
    src/crypto/tls_wolfssl.c \
    src/tunnel/*.c \
    src/nvm/*.c
```

### 8.3. Coverity Scan (третий уровень)

Бесплатен для open-source проектов. Дополняет оба анализатора, находя уникальные классы дефектов.

---

## 9. Производительность release-сборки

### 9.1. Рекомендуемая стратегия оптимизации

Для wolfguard, где hot paths — это TLS handshake, packet forwarding и event loop, рекомендуется:

```bash
# Вариант 1 (рекомендуемый): GCC + Full LTO
# Лучшее качество кода, уменьшение бинарника
gcc-15 -O3 -flto=auto -march=x86-64-v3 \
    -fno-semantic-interposition \
    -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
    -fPIE -pie

# Вариант 2: Clang + ThinLTO (если приоритет — скорость сборки)
# Потеря ~0.2% производительности, но 5x быстрее линковка
clang-22 -O3 -flto=thin -march=x86-64-v3 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
    -fPIE -pie
```

### 9.2. PGO (Profile-Guided Optimization)

Для wolfguard с его предсказуемым профилем нагрузки PGO может дать дополнительные 5–15%:

```bash
# Шаг 1: Инструментация
gcc-15 -O3 -flto=auto -fprofile-generate=./pgo-data \
    -o wolfguard_instrumented src/*.c

# Шаг 2: Профилирование (реалистичная нагрузка)
./wolfguard_instrumented &
# Запуск 1000 одновременных Cisco-клиентов на 10 минут
./bench/cisco_load_test --clients=1000 --duration=600

# Шаг 3: Оптимизированная сборка
gcc-15 -O3 -flto=auto -fprofile-use=./pgo-data \
    -o wolfguard_optimized src/*.c
```

---

## 10. Итоговая матрица решений

| Аспект                       | Рекомендация                | Обоснование                          |
| ---------------------------- | --------------------------- | ------------------------------------ |
| **Основной компилятор**      | Clang 22+                   | Скорость, MSan, фаззинг, инструменты |
| **Валидационный компилятор** | GCC 15+                     | -fanalyzer, уникальные warnings, LTO |
| **Debug-линковщик**          | mold                        | Мгновенная линковка                  |
| **Release-линковщик**        | GNU ld (GCC) / lld (Clang)  | LTO-совместимость                    |
| **Стандарт языка**           | `-std=c23` (явно)           | Обоим компиляторам                   |
| **Фаззинг**                  | LibFuzzer (Clang)           | Нативная интеграция                  |
| **Статический анализ**       | clang-tidy + GCC -fanalyzer | Дополняют друг друга                 |
| **Release-оптимизация**      | GCC LTO + PGO               | Лучшее качество кода                 |
| **FreeBSD/OpenBSD**          | Системный Clang             | Нативная поддержка                   |
| **Санитайзеры**              | Все через Clang             | MSan — только Clang                  |

---

## 11. Интеграция с wolfSSL

### 11.1. Особенности сборки wolfSSL

wolfSSL рекомендует собирать с теми же флагами, что и основной проект:

```bash
# wolfSSL: собирать тем же компилятором, что и wolfguard
./configure \
    CC=clang-22 \
    --enable-tls13 \
    --enable-dtls \
    --enable-dtls13 \
    --enable-sni \
    --enable-alpn \
    --enable-session-ticket \
    --enable-secure-renegotiation \
    --enable-supportedcurves \
    --enable-aesni \
    --enable-intelasm \
    --enable-sp-asm \
    CFLAGS="-O3 -march=x86-64-v3"
```

### 11.2. wolfSentry: только GCC или Clang

wolfSentry (v1.6.3) использует стандартный Makefile и собирается обоими компиляторами без проблем. GPLv2 лицензия совместима с wolfguard (GPLv2+).

---

## 12. Дорожная карта

| Фаза проекта          | Компилятор    | Линковщик | Санитайзеры          | Анализ                  |
| --------------------- | ------------- | --------- | -------------------- | ----------------------- |
| Phase 0: PoC          | Clang         | mold      | ASan, UBSan          | clang-tidy              |
| Phase 1: Абстракция   | Clang + GCC   | mold / ld | ASan, MSan, UBSan    | clang-tidy + -fanalyzer |
| Phase 2: Миграция     | Clang + GCC   | mold / ld | Все (MSan приоритет) | Оба + Coverity          |
| Phase 3: Тестирование | Clang         | lld       | Все                  | LibFuzzer 72ч+          |
| Phase 4: Оптимизация  | GCC (PGO)     | GNU ld    | -                    | Profiling (perf)        |
| Phase 5: Release      | GCC (LTO)     | GNU ld    | -                    | Финальный аудит         |
| Phase 6: Production   | Оба бинарника | -         | -                    | Мониторинг              |

---

## Заключение

Двухкомпиляторная стратегия для wolfguard не является компромиссом — это **усиление безопасности**. Каждый компилятор находит уникальные классы ошибок, и для VPN-сервера, обрабатывающего TLS/DTLS-трафик с Cisco-клиентами, это не роскошь, а необходимость. Clang обеспечивает скорость разработки и глубину инструментации (MSan, LibFuzzer, clang-tidy), GCC — качество release-сборки и дополнительный уровень статического анализа.

Ядро Linux, Chromium и PostgreSQL используют ту же стратегию. wolfguard должен следовать этому проверенному подходу.

---

**Автор**: Рекомендации подготовлены на основе анализа архитектурной документации wolfguard и сравнительного исследования GCC 15 / Clang 22.

**Статус**: Готов к рассмотрению Technical Lead
