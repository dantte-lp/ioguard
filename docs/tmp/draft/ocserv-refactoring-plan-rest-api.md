# Архитектура API для удалённого управления OpenConnect VPN Server

**Текущая архитектура ocserv допускает встраивание REST API, что обеспечит оптимальный баланс между простотой реализации на C и функциональностью для WebUI**. Анализ показывает, что **REST API предпочтительнее gRPC** для управления VPN-сервером, поскольку обеспечивает прямую интеграцию с браузерами, имеет зрелую экосистему для C и достаточную производительность для управляющих операций.

## Текущая архитектура occtl и механизмы взаимодействия

OpenConnect Server реализует **управление через Unix-сокеты с Protocol Buffers** для структурированной передачи данных. Главный процесс ocserv создаёт управляющий сокет `/var/run/occtl.socket`, к которому подключается утилита occtl для отправки команд.

### Протокол IPC и структура взаимодействия

Взаимодействие основано на **бинарном протоколе Protocol Buffers** (protobuf-c). Архитектура клиент-серверная: occtl выступает клиентом, ocserv — сервером. Все сообщения сериализуются через функции `send_msg()` и `recv_msg()`, использующие protobuf для упаковки команд и ответов. Это обеспечивает эффективную передачу структурированных данных без текстового парсинга.

**Расположение сокетов:**
- Управляющий сокет occtl: `/var/run/occtl.socket` (настраивается через `occtl-socket-file`)
- Внутренний IPC-сокет: `/var/run/ocserv-socket` (для межпроцессного взаимодействия)

Многопроцессная архитектура включает главный процесс (координация, обработка команд occtl), security module (аутентификация, масштабируется через `sec-mod-scale`), worker-процессы (обслуживание VPN-подключений). Коммуникация между компонентами происходит через Unix-сокеты с protobuf.

### Функциональные возможности occtl

Утилита предоставляет **17 основных команд** для управления сервером:

**Управление пользователями**: `disconnect user/id` (принудительное отключение), `show user/id` (детальная информация о подключениях), `show users` (список активных сессий с трафиком).

**Мониторинг подключений**: `show sessions` (активные сессии с статистикой), `show iroutes` (внутренние маршруты), `list cookies` (токены аутентификации), `list banned` (заблокированные IP).

**Серверная статистика**: `show status` (общее состояние сервера), статистика по байтам (STATS_BYTES_IN/OUT), длительность сессий (STATS_DURATION), информация о клиентах.

**Управление конфигурацией**: `reload` (перезагрузка конфигурации без остановки), `stop` (остановка сервера).

Поддерживается **вывод в JSON** через флаг `-j`, что критически важно для API-интеграции — существующая функциональность легко переиспользуется REST API.

### Модель безопасности текущей реализации

Безопасность обеспечивается исключительно **разрешениями Unix-сокета** без встроенной аутентификации. Контроль доступа базируется на файловой системе: root имеет полный доступ, другие пользователи требуют членства в группе владельца сокета. Это простая, но эффективная модель для локального управления.

Ключевые аспекты:
- **Отсутствие аутентификации в протоколе** — безопасность делегируется ОС
- **Изоляция процессов** — worker-процессы работают от непривилегированного пользователя
- **Опциональность** — можно полностью отключить через `use-occtl = false`

Для удалённого управления эта модель недостаточна и требует дополнительного уровня безопасности.

### Архитектура исходного кода

Реализация разделена между клиентом и сервером:

**Клиентская часть** (occtl):
- `src/occtl/occtl.c` — основная логика, парсинг команд, readline-интерфейс
- `src/occtl/occtl.h` — структуры команд (`commands_st`), прототипы функций

**Серверная часть** (ocserv):
- `src/main-ctl-unix.c` — обработчик Unix-сокета, диспетчер команд
- Функции `ctl_handler_init()` для инициализации, `method_*()` для обработки конкретных команд
- Использует talloc для управления памятью, что упрощает работу с protobuf

Структура команды включает имя, формат аргументов, указатель на обработчик и документацию. Паттерн команда-ответ: клиент отправляет protobuf-сообщение с ID команды, сервер обрабатывает, возвращает protobuf-ответ.

## Встраивание API в ocserv: архитектурные варианты

Анализ реализаций других VPN-серверов выявил **три основных подхода** к управлению: встроенный API, плагинная архитектура, полное разделение. Каждый имеет trade-offs для ocserv.

### Встроенный API-сервер (рекомендуется)

Подход OpenVPN и SoftEther: API-сервер работает в том же процессе, что и основной демон. **OpenVPN** использует текстовый протокол через TCP/Unix-сокет с асинхронными уведомлениями (префикс `>`), поддержкой real-time событий и простейшей интеграцией. **SoftEther** внедряет HTTPS-сервер с JSON-RPC 2.0, предоставляя 100+ методов API с полной поддержкой браузеров через CORS.

**Преимущества встраивания**:
- Простое развёртывание — единый бинарник, отсутствие дополнительных процессов
- Нулевые IPC-издержки — прямой доступ к внутреннему состоянию
- Упрощённое управление состоянием — API видит актуальные данные без синхронизации
- Меньше точек отказа — нет отдельного демона управления

**Недостатки**:
- Меньшая изоляция — ошибки в API могут повлиять на главный демон
- Увеличение complexity главного процесса
- Потенциальное влияние на производительность VPN (если API неоптимален)

Для ocserv это **оптимальный вариант**: архитектура уже включает управляющий сокет, достаточно добавить HTTP-обработчик параллельно существующему Unix-сокету.

### Плагинная архитектура

Подход strongSwan с VICI (Versatile IKE Control Interface): плагин загружается в основной демон charon, обеспечивая модульность. Плагин vici предоставляет **бинарный протокол** с структурированными данными (key-value, списки, вложенные секции), поддержкой событий и стриминга.

**Преимущества плагинов**:
- Опциональность — можно отключить, если не требуется
- Умеренная изоляция — отдельный модуль с чёткими границами
- Общий процесс — доступ к внутренним структурам данных

**Недостатки**:
- Всё ещё в одном процессе — сбой плагина может уронить демон
- Сложнее разработка — требуется инфраструктура плагинов
- Для ocserv потребует значительного рефакторинга

### Полное разделение компонентов

Подход WireGuard: ядро (kernel module) предоставляет Netlink-интерфейс, userspace-инструменты (`wg`) общаются через netlink/ioctl. Сторонние решения (wireguard-ui, wg-portal, wg-easy) строят **REST API поверх этого интерфейса**. Tailscale развивает концепцию дальше — облачная control plane отделена от data plane.

**Преимущества полного разделения**:
- Чистая архитектура — независимые компоненты
- Изоляция сбоев — падение API не влияет на VPN
- Гибкость — можно создавать множество разных UI/API для одного ядра

**Недостатки**:
- Требует IPC-механизм — добавляет latency
- Сложность развёртывания — больше процессов для управления
- Фрагментация — нет стандартного API (как у WireGuard)
- Для ocserv избыточно — текущий IPC уже работает хорошо

### Рекомендация для ocserv

**Встроить REST API-сервер в главный процесс ocserv** параллельно существующему Unix-сокету. Использовать libmicrohttpd для HTTP-обработки, сохранив occtl для локального CLI-управления. Это минимально инвазивное изменение, сохраняющее обратную совместимость.

Архитектура:
```
ocserv main process
├── Unix socket handler (существующий, для occtl)
├── HTTP/REST API server (новый, для WebUI/удалённого управления)
├── Security module communication
└── Worker process management
```

Опционально: WebSocket-обработчик для real-time мониторинга в том же процессе.

## Выбор протокола для management API

Сравнение четырёх протоколов (gRPC, REST, GraphQL, WebSocket) показывает, что **REST + WebSocket** оптимальны для VPN-управления.

### gRPC: производительность vs сложность

**Производительность**: gRPC демонстрирует **7-10x преимущество** над REST для больших payload (1000+ объектов) благодаря Protocol Buffers (~33% размера JSON), HTTP/2-мультиплексированию и бинарной сериализации. Latency: 1.71ms (gRPC) vs 15ms (REST). Однако для управляющих операций VPN эта разница **несущественна** — админские действия нечасты (создание пользователя, изменение конфигурации).

**Интеграция с C**: Официальная C API (gRPC C-Core) низкоуровневая, требует экспертизы. Рекомендуемый подход — **C++ обёртка** с `extern "C"`, что добавляет complexity. Сторонние C-реализации (Juniper/grpc-c, linimbus/grpc-c) находятся в pre-alpha и не production-ready. Требуется protoc-компиляция .proto-файлов в build-процессе.

**Сложность разработки** (7/10): крутая кривая обучения, отсутствие браузерной поддержки (требуется gRPC-Web proxy), невозможность тестирования через curl/Postman, специализированные инструменты.

**Применимость**: gRPC оправдан для **высоконагруженных сценариев** с частыми API-вызовами или микросервисной архитектуры. Для VPN management это **overkill** — преимущества производительности не компенсируют сложность реализации.

### REST API: баланс простоты и функциональности

**Простота интеграции** (9/10): нативная браузерная поддержка (Fetch API), тестирование через curl/Postman/DevTools, универсальная совместимость. Зрелые C-библиотеки: **libmicrohttpd** (HTTP-сервер, 3KB overhead), **cJSON/json-c** (парсинг), **jwt-c** (JWT-аутентификация).

**Производительность**: 50-200ms для типичных управляющих операций — **приемлемо** для админских задач. User creation, disconnect, config update не требуют микросекундных latencies. HTTP-кеширование улучшает read-heavy операции.

**Экосистема**: OpenAPI/Swagger для документации, автогенерация клиентов, стандартные паттерны аутентификации (JWT, OAuth 2.0, mTLS). **Существующий проект** ocserv-users-management (mmtaee) уже реализует Django REST API с Swagger, доказывая жизнеспособность подхода.

**Паттерны аутентификации**:
- **JWT** — stateless, масштабируемая аутентификация с самодостаточными токенами
- **mTLS** — сертификатная аутентификация, естественна для VPN-контекста
- **OAuth 2.0** — для SSO и enterprise-интеграций

**Примеры проектов**: OpenVPN Access Server (REST + XML-RPC), NetBox (industry-standard для сетевого management), OpenWISP (OpenWrt management), ocserv-users-management.

### GraphQL: избыточность для VPN-управления

**Сложность** (8/10): overkill для CRUD-операций, ограниченная C-экосистема (libgraphqlparser недостаточна), сложный мониторинг (single endpoint затрудняет метрики). Преимущества (точная выборка данных, subscriptions) не критичны для админ-интерфейса.

**Не рекомендуется** для ocserv: добавляет complexity без значимых преимуществ.

### WebSocket: real-time мониторинг

**Производительность**: **98.5% быстрее** REST-polling для real-time данных благодаря persistent connection и server push. Bidirectional full-duplex коммуникация с низким overhead после handshake.

**Use cases для VPN**:
- Live список подключений с автообновлением
- Real-time графики трафика (bandwidth charts)
- Streaming логов
- Мгновенные уведомления о событиях

**C-библиотеки**: libwebsockets (production-grade), wslay. Сложность (6/10) — требует управление connection state.

**Применение**: **дополнение к REST**, не замена. REST обрабатывает CRUD, WebSocket — мониторинг.

### Итоговая рекомендация по протоколу

**Гибридный подход REST + WebSocket**:

**REST API** для основного функционала:
- User management (CRUD операции)
- Конфигурация сервера (создание/изменение/удаление)
- Batch-операции
- Исторические данные и статистика

**WebSocket** для real-time мониторинга:
- Активные подключения (live updates)
- Bandwidth графики (streaming metrics)
- Лог-стриминг
- Health metrics сервера

**Пример API-дизайна**:
```
REST Endpoints:
GET    /api/v1/users              - Список пользователей
POST   /api/v1/users              - Создание пользователя
GET    /api/v1/users/{id}         - Детали пользователя
DELETE /api/v1/connections/{id}   - Отключение сессии
PUT    /api/v1/config             - Обновление конфигурации
GET    /api/v1/stats              - Агрегированная статистика

WebSocket Endpoint:
WS     /api/v1/stream/connections - Live-обновления подключений
WS     /api/v1/stream/logs        - Streaming логов
```

Этот подход максимизирует преимущества: простота разработки и тестирования (REST), real-time возможности (WebSocket), стандартная экосистема, прямая браузерная интеграция.

## Реализация WebUI: существующие решения и best practices

Анализ WebUI для VPN-серверов выявил зрелые паттерны и готовые решения, применимые к ocserv.

### Существующие WebUI для ocserv

**mmtaee/ocserv-users-management** — наиболее зрелое решение:
- **Tech stack**: Python/Django (backend), Vue.js (frontend), SQLite (database)
- **Функционал**: полное управление пользователями (CRUD, блокировка, disconnect), группы, лимиты трафика (GB/месяц), статистика RX/TX, интеграция с occtl, Swagger API-документация
- **Развёртывание**: Docker Compose, systemd-service, install-скрипт для Ubuntu 20.04
- **Статус**: production-ready, активно поддерживается

Другие проекты (HamedAp/Ocserv-Ubuntu, dchidell/docker-vpnweb) предоставляют базовую функциональность, но менее зрелы.

### Best practices из других VPN WebUI

**OpenVPN:**

**Pritunl** (enterprise-grade): распределённая архитектура с MongoDB, SSO-интеграция (множество провайдеров), 2FA (Google Authenticator), кластеризация, RESTful API, LDAP/AD, site-to-site VPN. Профессиональный dashboard с comprehensive мониторингом.

**ovpn-admin** (palark/flant, Go + Vue.js): управление сертификатами (rotate, revoke), Prometheus metrics, CCD-поддержка, master/slave синхронизация, Kubernetes LoadBalancer. Real-time статус (обновление каждые 28 секунд через polling).

**WireGuard:**

**wg-portal** (h44z, Enterprise-фичи): multi-language, OAuth/LDAP/AD аутентификация, WebAuthn/Passkey, автоматический IP-выбор, email-уведомления с QR, peer expiry, Prometheus export, REST API, webhooks, dark mode. Go + Vue.js + Bootstrap, поддержка множества БД (SQLite, MySQL, PostgreSQL, MsSQL).

**wg-easy** (23K stars, проще всего в развёртывании): Node.js all-in-one решение, QR-генерация, connection stats с TX/RX графиками, password-защита, real-time connected clients, Docker one-line install. Чистый minimalist UI.

**strongSwan:**

**strongMan** (официальный): Django-based, certificate/key management (RSA/ECDSA), EAP-аутентификация, использует VICI-протокол. Требует экспертизы strongSwan для настройки.

### Общая функциональность VPN WebUI

**Ядро управления пользователями**: создание с генерацией сертификатов, редактирование данных, удаление с отзывом сертификатов, disable/enable без удаления, bulk-операции (import/export), группировка, role-based access (admin/user).

**Мониторинг подключений**: real-time список подключённых, статус (online/offline индикаторы), длительность сессий, виртуальные и реальные IP, last connection time, принудительный disconnect, история подключений.

**Трафик и bandwidth**: real-time upload/download speeds, TX/RX per user, визуальные графики (time-series), квоты (GB/month enforcement), агрегированная и per-user статистика.

**Серверная статистика**: server health (CPU, memory, network), uptime tracking, connection trends (historical patterns), performance metrics (latency, throughput), dashboard widgets с key metrics.

**Управление конфигурацией**: настройки сервера (port, protocol, network ranges, DNS), global defaults (MTU, keepalive), route management, certificate settings (CA, expiration policies), config file editor, применение изменений с reload/restart.

**Логи**: system/connection/authentication/audit logs, real-time streaming, фильтрация (date, user, event type), export для анализа.

**Сертификаты**: генерация client/server, CA management, revocation, rotation для renewal, expiry tracking с alerts, QR-генерация для mobile enrollment, download configs с embedded certificates.

**Enterprise-функции** (premium решения): 2FA (TOTP, SMS, hardware keys), SSO (LDAP, AD, OAuth, SAML), multi-server clustering, high availability с failover, REST API для автоматизации, webhooks, backup/restore, email notifications.

### Архитектурные паттерны

**Backend:**

**Стек языков**: Go/Golang доминирует (ovpn-admin, wg-portal, wireguard-ui) благодаря производительности, single binary, отличной concurrency. Python/Django — альтернатива (ocserv-users-management, strongMan). Node.js для simple deployments (wg-easy).

**API-паттерн**: RESTful с OpenAPI/Swagger документацией, stateless JWT-аутентификация, стандартные HTTP-коды, JSON request/response.

**Базы данных**: SQLite (простые развёртывания), MySQL/MariaDB (traditional web apps), PostgreSQL (enterprise с async), MongoDB (distributed systems как Pritunl), file-based configs (wg-easy).

**Frontend:**

**Vue.js — most popular** для VPN UIs: wg-portal, ovpn-admin, ocserv-users-management. Component-based, reactive data binding, maintainable, хорошая производительность. React реже встречается. Angular редок. Vanilla JS/jQuery в legacy-проектах.

**Real-time обновления:**

**WebSocket** (best for real-time): 98.5% быстрее polling, persistent connection, bidirectional, server push. Используется в advanced dashboards для live connection status, traffic graphs, instant notifications.

**Server-Sent Events** (SSE): unidirectional server→client, проще WebSocket, автореконнект, подходит для log streaming.

**Polling** (traditional): intervals 500ms-30s, простейший подход, но неэффективен. ovpn-admin использует 28-секундный интервал.

**Hybrid approach (рекомендуется)**: REST для CRUD, WebSocket для мониторинга, SSE для логов.

**Аутентификация**: JWT (stateless, современные решения), session cookies (Django, PHP), Basic Auth (simple deployments), OAuth 2.0/LDAP/AD (enterprise), Passkey/WebAuthn (modern passwordless в wg-portal v2.1).

### UI/UX best practices

**Dashboard layout**: key metrics at-a-glance (total/connected users, uptime, bandwidth), информационная иерархия (важное сверху, детали по требованию), максимум 7-9 визуальных элементов (cognitive load limit), card-based группировка информации.

**Типы графиков**:
- **Line charts** — traffic over time, trends, непрерывные time-series
- **Area charts** — bandwidth (stacked TX/RX), cumulative metrics
- **Bar charts** — usage per user, discrete comparisons
- **Gauges** — current utilization, CPU/memory

**Цветовая схема**: Green (active/healthy), Red (error/critical), Yellow (warning), Blue (info), Gray (disabled). Color-blind-friendly палитры.

**Формы**: clear labels, placeholders с примерами, real-time validation, required fields indication, auto-generation (passwords, IPs), preview перед сохранением.

**Mobile responsiveness**: touch-friendly targets (44x44px minimum), collapsible menus (hamburger), responsive tables, QR-коды критичны для mobile enrollment.

**Performance**: lazy loading, pagination для больших списков, virtual scrolling, debounced search, кешированные данные, API pagination, compression.

### Рекомендуемый tech stack для ocserv WebUI (2025)

**Backend**:
- **Язык**: Go (производительность, single binary, concurrency)
- **API**: REST с OpenAPI/Swagger
- **Real-time**: WebSocket для мониторинга
- **Database**: PostgreSQL (production) или SQLite (simple deployments)
- **Auth**: JWT + опционально OAuth/LDAP
- **Metrics**: Prometheus endpoint

**Frontend**:
- **Framework**: Vue.js 3 (Composition API)
- **UI**: Bootstrap 5 или Tailwind CSS
- **Charts**: Chart.js или Apache ECharts
- **Build**: Vite (быстрая сборка)
- **State**: Pinia (Vue 3 state management)

**Deployment**:
- Docker + Docker Compose
- Kubernetes-ready (опционально)
- Nginx/Traefik reverse proxy
- Let's Encrypt для TLS

**Примеры проектов с этим стеком**: wg-portal, ovpn-admin успешно используют Go + Vue.js для production VPN management.

## Безопасность management API

Анализ OWASP API Security Top 10 2023, Kubernetes/Docker security models выявил критические требования для VPN management API.

### Аутентификация: JWT + mTLS

**JWT Implementation (RFC 8725):**

**Критические требования**:
- **Explicit algorithm verification** — НИКОГДА не доверять `alg` заголовку, reject "none" algorithm
- **Рекомендуемые алгоритмы** (по приоритету): EdDSA (лучшая производительность), ES256 (ECDSA), RS256 (широкая поддержка). НЕ использовать HS256 с человеко-читаемыми паролями
- **Claims validation**: проверка `iss` (issuer allowlist), `aud` (audience должен соответствовать API endpoint), `exp` (reject expired), `nbf` (not before), `iat` (issued at, reject future tokens)

**C-библиотека**: **libjwt** (github.com/benmcollins/libjwt) — полная поддержка JWS/JWE/JWK, OpenSSL 3.0+/GnuTLS/MbedTLS, реализует все RFC.

**Claims для VPN management**:
```json
{
  "sub": "admin@example.com",
  "roles": ["admin", "user_manager"],
  "iat": 1609459200,
  "exp": 1609545600,
  "iss": "ocserv-api",
  "aud": "https://vpn-api.example.com",
  "vpn_groups": ["administrators"]
}
```

**Практики**:
- Short-lived access tokens (15 минут)
- Refresh tokens для продлённых сессий
- Key rotation каждые 90 дней
- JWKS endpoints для public key distribution
- Key Revocation Lists для compromised keys

**Mutual TLS (mTLS) — рекомендуется для высокой безопасности:**

**Преимущества**: bidirectional authentication (server И client verification), устранение password vulnerabilities, MITM prevention, стандарт zero-trust архитектур.

**Реализация с OpenSSL**:
```c
SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

// Загрузка server certificate
SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);

// Требование client certificates
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);

// TLS 1.3 minimum
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

// Strong ciphers
SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
```

**Certificate management**: автоматическая ротация (365-day validity max), CRL или OCSP для revocation, раздельные сертификаты для dev/staging/prod, strong encryption (AES-256, SHA-384 minimum).

### Авторизация: RBAC и OWASP Top 10

**OWASP API1:2023 — Broken Object Level Authorization (BOLA):**

Критическая уязвимость — API expose endpoints с object IDs без проверки прав. **Обязательные меры**:
- Проверка владения ресурсом или explicit permission на КАЖДЫЙ endpoint
- Database-level checks, не только application logic
- Deny-by-default policies
- UUID вместо predictable IDs (против enumeration)

```c
int check_resource_access(user_id, resource_id) {
    if (!user_has_permission(user_id, resource_id)) {
        log_unauthorized_access(user_id, resource_id);
        return 403;  // Forbidden
    }
    return 200;
}
```

**OWASP API5:2023 — Broken Function Level Authorization:**
- Чёткое разделение admin и regular функций
- Deny by default — explicit grants требуются
- Разные токены для admin vs user операций
- Регулярные audits permission hierarchies

**RBAC Framework**:
```c
typedef enum {
    ROLE_ADMIN = 1,           // Полный контроль
    ROLE_VPN_MANAGER = 2,     // Управление пользователями, не конфигурация
    ROLE_USER = 4,            // Доступ к собственному профилю
    ROLE_READ_ONLY = 8        // Только просмотр статистики
} user_role_t;

typedef struct {
    char *resource_type;      // "vpn_config", "user_profile"
    char *action;             // "read", "write", "delete"
    user_role_t required_role;
} permission_t;

int authorize_action(user_t *user, permission_t *perm) {
    return (user->roles & perm->required_role) != 0;
}
```

### Защита от атак: rate limiting

**Token Bucket Algorithm (рекомендуется для management APIs):**

Позволяет burst traffic до bucket capacity, гибкий, memory-efficient (O(1) per user).

**C Implementation**:
```c
typedef struct {
    uint64_t tokens;              // Текущее количество токенов
    uint64_t max_tokens;          // Ёмкость bucket
    uint64_t refill_rate;         // Токенов в секунду
    uint64_t last_refill_time;    // Timestamp последнего refill (ms)
    pthread_mutex_t lock;
} token_bucket_t;

int token_bucket_consume(token_bucket_t *bucket, uint64_t tokens_needed) {
    pthread_mutex_lock(&bucket->lock);
    
    uint64_t now = get_current_time_ms();
    uint64_t elapsed = now - bucket->last_refill_time;
    uint64_t tokens_to_add = (elapsed * bucket->refill_rate) / 1000;
    
    if (tokens_to_add > 0) {
        bucket->tokens = MIN(bucket->tokens + tokens_to_add, bucket->max_tokens);
        bucket->last_refill_time = now;
    }
    
    int result = (bucket->tokens >= tokens_needed);
    if (result) bucket->tokens -= tokens_needed;
    
    pthread_mutex_unlock(&bucket->lock);
    return result;
}
```

**Рекомендуемые лимиты**:
- Normal operations: 100 req/min, burst 20
- Admin operations: 20 req/min, burst 5
- Authentication attempts: 5 req/min, burst 3

**OWASP API4:2023 — Unrestricted Resource Consumption:**
- Per-user rate limits (Redis для distributed systems)
- Max payload size (1MB для API requests)
- Timeouts для long operations (30-second default)
- Concurrent connections limits per IP/user
- Circuit breakers для external dependencies

**OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows:**
- Separate rate limits для critical operations (VPN config changes)
- CAPTCHA/proof-of-work для destructive actions
- Мониторинг automated/scripted patterns

**OWASP API7:2023 — Server-Side Request Forgery (SSRF):**
- Validation и sanitization всех URLs в requests
- Allowlists для permitted hosts
- Block internal network ranges (RFC 1918)
- Disable HTTP redirects при fetching external resources

### Audit logging: Kubernetes-inspired model

**Что логировать**:

**Authentication events**: успех/fail login attempts с source IP, token generation/validation, certificate auth results.

**Authorization decisions**: access granted/denied с user/resource/action, role/permission changes, policy violations.

**Resource access**: CRUD на VPN configs, user management operations, system configuration changes.

**Security events**: rate limit violations, malformed requests, suspicious patterns, certificate errors.

**Audit Entry Structure**:
```c
typedef struct {
    char timestamp[32];        // ISO 8601
    char event_id[64];         // UUID
    char user_id[128];         // Authenticated user/service
    char source_ip[46];        // IPv4 or IPv6
    char action[32];           // "read", "write", "delete"
    char resource_type[64];    // "vpn_config", "user"
    char resource_id[128];     // Resource ID
    int response_code;         // HTTP status
    char decision[16];         // "allow" or "deny"
    char reason[256];          // Denial reason
} audit_entry_t;

void log_audit_event(audit_entry_t *entry) {
    // JSON format для парсинга
    syslog(LOG_INFO, "{\"timestamp\":\"%s\",\"user\":\"%s\","
           "\"action\":\"%s\",\"resource\":\"%s\",\"decision\":\"%s\"}",
           entry->timestamp, entry->user_id, entry->action,
           entry->resource_id, entry->decision);
}
```

**Best practices**:
- Write-only append files или external log aggregators (защита от tampering)
- Log rotation (90 дней retention minimum)
- SIEM integration для critical events
- Correlation IDs для tracing requests
- НИКОГДА не логировать sensitive data (passwords, keys, tokens)
- Cryptographic signatures для tamper-evidence

### Security headers и misconfiguration prevention

**OWASP API8:2023 — Security Misconfiguration:**

**Обязательные HTTP headers**:
```c
"Strict-Transport-Security: max-age=31536000; includeSubDomains"
"X-Content-Type-Options: nosniff"
"X-Frame-Options: DENY"
"Content-Security-Policy: default-src 'none'"
"X-XSS-Protection: 1; mode=block"
"Cache-Control: no-store, no-cache, must-revalidate"
```

**Rate limiting headers**:
```c
"X-RateLimit-Limit: 100"           // Total allowed
"X-RateLimit-Remaining: 45"        // Remaining
"X-RateLimit-Reset: 1641234567"    // Unix timestamp for reset
"Retry-After: 60"                  // Seconds (429 response)
```

**Конфигурация**:
- Disable unnecessary HTTP methods
- Remove debug endpoints в production
- TLS 1.3 or TLS 1.2 minimum (disable 1.0, 1.1)

### Приоритеты implementation

**Phase 1 — Critical (немедленно)**:
- mTLS с client certificate validation
- JWT authentication (RFC 8725 compliant)
- BOLA/BFLA authorization checks
- Basic rate limiting (token bucket)
- Comprehensive audit logging

**Phase 2 — High (2 недели)**:
- Automated certificate rotation
- Per-user/endpoint rate limiting granularity
- RBAC policy framework
- Input validation/sanitization
- Security headers + HSTS

**Phase 3 — Medium (1 месяц)**:
- SIEM integration
- Anomaly detection для API access
- API versioning/deprecation strategy
- Penetration testing
- Incident response procedures

**Phase 4 — Ongoing**:
- Quarterly security reviews
- Dependency vulnerability scanning
- Certificate expiration monitoring
- Log analysis и threat hunting
- Developer security training

## Технические детали реализации

### Интеграция с существующей кодовой базой ocserv

**Архитектурная интеграция**: Добавить HTTP/REST handler параллельно существующему Unix socket handler в `src/main-ctl-unix.c`. Оба обработчика используют общий backend — функции `method_*()` для команд.

**Event loop архитектура**: ocserv уже использует event-driven модель для обработки VPN-подключений. REST API-сервер интегрируется в этот же event loop:

```c
// Псевдокод интеграции
struct main_server_st {
    // Существующие компоненты
    int ctl_unix_fd;              // Unix socket для occtl
    
    // Новые компоненты
    struct MHD_Daemon *api_daemon; // libmicrohttpd HTTP daemon
    int api_fd;                    // File descriptor для event loop
};

int main_loop(struct main_server_st *s) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(s->ctl_unix_fd, &read_fds);
    FD_SET(s->api_fd, &read_fds);
    
    // Обработка событий от обоих источников
    select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
    
    if (FD_ISSET(s->ctl_unix_fd, &read_fds)) {
        handle_unix_command(s);  // Существующий обработчик
    }
    if (FD_ISSET(s->api_fd, &read_fds)) {
        MHD_run(s->api_daemon);  // REST API обработчик
    }
}
```

**Переиспользование occtl JSON output**: Команды occtl уже поддерживают флаг `-j` для JSON-вывода. REST API endpoints вызывают те же backend-функции:

```c
// REST endpoint handler
int api_get_users(struct MHD_Connection *connection) {
    // Вызов той же функции, что и occtl
    char *json_output = method_list_users_json(server_context);
    
    // Возврат JSON через HTTP
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json_output), json_output, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    return MHD_queue_response(connection, 200, response);
}
```

### Библиотеки и зависимости

**HTTP Server**: **libmicrohttpd** — lightweight (3KB overhead), используется в GNU проектах, поддерживает HTTPS/TLS, thread-per-connection или epoll modes, минимальные зависимости.

**JSON**: **cJSON** (lightweight, single-file) или **json-c** (more features, widely used). ocserv уже может иметь JSON-зависимость для occtl output.

**JWT**: **libjwt** — полная RFC 7515-7519 поддержка, OpenSSL/GnuTLS/MbedTLS, production-ready.

**WebSocket** (опционально): **libwebsockets** — production-grade, supports TLS, multiple platforms.

**Rate limiting storage** (distributed): **hiredis** (Redis client) для per-user limits across multiple instances.

### Async операции и event loop

**libmicrohttpd modes**:
- **Thread-per-connection**: простой, но не масштабируется для многих одновременных connections
- **Select/poll mode**: integration с existing event loop (рекомендуется)
- **epoll mode** (Linux): наилучшая производительность для high-scale

**Рекомендация**: select mode для интеграции с существующим ocserv event loop. Для масштабирования позже — переход на epoll.

**Async обработка long-running operations**: некоторые операции (reload config, массовые изменения) могут занимать время. Использовать background threads:

```c
// Async pattern для долгих операций
struct async_task {
    void (*handler)(void *);
    void *data;
    pthread_t thread;
};

void api_reload_config_async(struct MHD_Connection *conn) {
    // Запуск background task
    struct async_task *task = malloc(sizeof(*task));
    task->handler = reload_config_worker;
    pthread_create(&task->thread, NULL, task->handler, task->data);
    
    // Немедленный ответ клиенту
    return_json(conn, 202, "{\"status\":\"accepted\",\"task_id\":\"...\"}\");
}
```

### Пример проектов с похожей архитектурой

**OpenVPN** (src/openvpn/manage.c): встроенный management interface в main event loop, простой text protocol, async event notifications. Демонстрирует embedded approach без отдельного процесса.

**strongSwan vici plugin**: плагин в charon daemon, использует libvici для IPC, event-driven architecture с callbacks. Показывает plugin pattern с хорошей изоляцией.

**Prometheus node_exporter**: Go-based HTTP server для системных метрик, встроенный в single binary, используется как reference для metrics endpoints. Хотя на Go, архитектурные принципы применимы.

**wg-portal** (github.com/h44z/wg-portal): Go REST API для WireGuard management, single binary, встроенный web server, JWT auth, WebSocket для updates. Отличный reference для полного VPN management solution.

### Совместимость и план миграции

**Обратная совместимость**: сохранить occtl Unix socket interface — existing deployments продолжают работать. REST API как опциональная фича (enable via `api-server = true` в конфигурации).

**Поэтапное внедрение**:

**Milestone 1**: Basic REST API (user management, connection control) с JWT auth, libmicrohttpd integration, OpenAPI docs. 2-4 недели разработки.

**Milestone 2**: Enhanced REST API (config management, statistics), rate limiting, audit logging. 2-3 недели.

**Milestone 3** (опционально): WebSocket для real-time updates, log streaming. 2-3 недели.

**Milestone 4** (опционально): Advanced features (webhooks, batch operations, advanced filtering). 3-4 недели.

**Конфигурационные директивы**:
```
# ocserv.conf additions
api-server = true
api-listen-address = 0.0.0.0
api-port = 8443
api-tls-cert = /path/to/cert.pem
api-tls-key = /path/to/key.pem
api-require-client-cert = true  # mTLS
api-jwt-secret-file = /path/to/jwt-secret
api-rate-limit = 100/minute
```

**Тестирование**: unit tests для API endpoints (curl-based), integration tests с ocserv, security testing (OWASP ZAP, Burp Suite), load testing (wrk, hey) для rate limits.

## Заключение и практические рекомендации

Оптимальная архитектура для ocserv management API — **встроенный REST API-сервер** с дополнительным WebSocket endpoint для real-time мониторинга. Этот подход обеспечивает минимальную invasiveness к существующей кодовой базе, сохраняет обратную совместимость с occtl, предоставляет простую интеграцию для WebUI.

**Ключевые решения:**

**Протокол**: REST API (HTTP/JSON) — не gRPC. REST предоставляет оптимальный баланс: простота C-интеграции (libmicrohttpd + cJSON), нативная браузерная поддержка, зрелая экосистема, достаточная производительность для management операций. gRPC излишне сложен и избыточен для данного сценария.

**Архитектура**: Embedded API server в main ocserv process параллельно существующему Unix socket. Переиспользует backend functions от occtl, интегрируется в event loop, сохраняет простоту развёртывания (single binary).

**Безопасность**: JWT для stateless аутентификации + mTLS для высокобезопасных deployments. Token bucket rate limiting. RBAC для авторизации. Comprehensive audit logging. Соответствие OWASP API Security Top 10 2023.

**WebUI stack**: Go + Vue.js 3 — проверенная комбинация (wg-portal, ovpn-admin). Docker deployment, OpenAPI documentation, Prometheus metrics, responsive design.

**Этапность**: начать с базового REST API (Milestone 1), затем enhanced features, опционально WebSocket для advanced monitoring. Incremental approach минимизирует риски.

**Существующий базис**: ocserv-users-management (mmtaee) доказывает жизнеспособность REST API для ocserv, предоставляет reference implementation для архитектурных решений.

Этот подход позволяет создать modern, secure, user-friendly management interface для ocserv, сохраняя совместимость с существующими deployments и минимизируя complexity добавляемого кода.