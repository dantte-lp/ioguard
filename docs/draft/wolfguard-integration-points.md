## Точки интеграции ocserv-modern

У VPN-сервера есть четыре принципиально разных integration point, и для каждого — свой оптимальный подход:

**1. CLI утилита (occtl-modern) → daemon** — управление и мониторинг с localhost
**2. Внешние модули → сервер** — auth backends, accounting, policy engines
**3. Внешние системы → сервер** — оркестрация, Ansible, Terraform, web-панели
**4. Мониторинг** — Prometheus, health checks, observability

---

## 1. CLI утилита: protobuf-c over UDS — лучший выбор

Для CLI утилиты gRPC избыточен. Все зрелые VPN/network серверы используют простой custom protocol over unix socket:

occtl использует unix domain sockets для подключения к ocserv, с поддержкой JSON-вывода (`--json`). strongSwan VICI реализует IPC-протокол для конфигурации, мониторинга и управления IKE-демоном charon, используя request/response и event-сообщения поверх надёжного потокового транспорта. Протокол прост: каждая последовательность байтов предваряется 32-битным заголовком длины в сетевом порядке байтов, за которым следуют данные. WireGuard использует generic netlink на Linux для конфигурации.

Ключевое наблюдение: strongSwan VICI — самый продуманный management API среди VPN-серверов, и он **не использует gRPC**. При этом для клиентской стороны любой язык программирования может использоваться для коммуникации с демоном через VICI протокол — strongSwan поставляется с клиентскими библиотеками для C, Perl, Python и Ruby. Есть также Go-реализация и npm-пакеты для JavaScript.

**Для ocserv-modern оптимальный подход:**

Твои `.proto`-схемы уже определяют все сообщения. CLI-утилита использует тот же protobuf-c + SOCK_STREAM (не SEQPACKET — CLI подключается к listen-сокету, а не через socketpair). Wire protocol минимален: `[4 байта длина][1 байт тип сообщения][N байт protobuf payload]`. Это по сути то же, что VICI, только с protobuf вместо custom encoding.

Преимущества перед gRPC для CLI: запуск `occtl-modern show users` — **~5 мс** (connect + request + response + disconnect) vs **~170+ мс** с gRPC (инициализация HTTP/2, TLS negotiation если есть, HPACK warmup). Для интерактивного CLI каждый лишний ~150 мс — ощутимая задержка.

---

## 2. Внешние модули (auth/accounting): plugin API + optional UDS

Для auth backends, accounting и policy engines есть два подхода, и ни один из них — не gRPC:

**Вариант A: In-process plugins (shared library).** Модуль загружается через `dlopen()`, реализует определённый C API. Нулевая сериализация, нулевой IPC overhead. Так делает оригинальный ocserv (PAM, radius, certificate auth — всё in-process). Так же делает nginx (модули), HAProxy (Lua/SPOE).

**Вариант B: Out-of-process через UDS + protobuf.** Для модулей, которые нужно изолировать (sandbox) или которые написаны на другом языке. Демон подключается к сокету модуля и отправляет auth request, модуль отвечает auth response. Протокол — тот же protobuf с минимальным framing.

gRPC здесь не нужен, потому что обе стороны — часть одной системы, на одной машине, под контролем одного администратора.

---

## 3. Внешние системы: вот здесь gRPC имеет смысл (но есть альтернатива лучше)

Когда к VPN-серверу обращаются **внешние системы** — web-панель управления, Ansible/Terraform провайдер, Kubernetes operator, мобильное приложение администратора — вот тут появляется реальная потребность в стандартизированном API.

**Аргументы за gRPC:**

- Schema-first design: `.proto` файлы — это контракт API, из них генерируются клиенты на Go, Python, Rust, TypeScript
- Bi-directional streaming: подписка на real-time события (подключения, отключения, alerts)
- Встроенный TLS: важно если API доступен по сети
- Ecosystem: grpcurl, grpc-gateway (автоматический REST-proxy), Postman поддерживает gRPC

**Но есть альтернатива лучше: protobuf over UDS/TCP + REST-gateway**

Вместо полноценного gRPC с HTTP/2 фреймингом можно сделать **двухуровневую архитектуру**:

**Уровень 1 — Native API**: protobuf-c over UDS (для localhost — CLI, local scripts, Ansible local). Тот же протокол, что для CLI. Быстрый, простой, без зависимостей.

**Уровень 2 — HTTP REST API**: лёгкий HTTP/1.1 сервер (встроенный, ~500 строк на C с libmicrohttpd или встроенным HTTP-парсером). Принимает JSON, транслирует в protobuf команды на native API. Это даёт:

- Совместимость с curl, wget, любым HTTP-клиентом
- Простая интеграция с Ansible (uri module), Terraform (http provider)
- Web-панель может обращаться напрямую
- Никаких grpc-gateway прокси

Этот паттерн используют многие: strongSwan VICI протокол рекомендуется запускать через UNIX сокет с соответствующими правами доступа, а для удалённого доступа есть TCP-fallback. ocserv использует отдельный occtl-socket-file для IPC с occtl.

---

## 4. Мониторинг: Prometheus endpoint — проще простого

Для мониторинга gRPC точно не нужен. Стандарт — HTTP endpoint `/metrics` в формате Prometheus text exposition. Это ~100 строк C:

```
# TYPE ocserv_connections_active gauge
ocserv_connections_active 42
# TYPE ocserv_bytes_rx_total counter
ocserv_bytes_rx_total 1234567890
```

Плюс `/health` для liveness/readiness probes. Оба — plain HTTP/1.1, парсятся любым мониторингом.

---

## Итоговая архитектура интерфейсов

```
┌─────────────────────────────────────────────────────┐
│                  ocserv-modern daemon                │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Native API  │  │  HTTP API    │  │ /metrics  │  │
│  │ protobuf-c  │  │  REST/JSON   │  │ Prometheus│  │
│  │ UDS socket  │  │  TCP :8443   │  │ TCP :9100 │  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬─────┘  │
└─────────┼────────────────┼─────────────────┼────────┘
          │                │                 │
    ┌─────┴─────┐   ┌─────┴──────┐    ┌─────┴─────┐
    │ occtl CLI │   │ Web panel  │    │Prometheus │
    │ Ansible   │   │ Terraform  │    │ Grafana   │
    │ scripts   │   │ K8s oper.  │    │ Alertmgr  │
    │ auth mods │   │ REST API   │    │           │
    └───────────┘   └────────────┘    └───────────┘
```

---

## Когда всё-таки стоит добавить gRPC

Есть **один конкретный сценарий**, при котором gRPC оправдан: если ты планируешь, что ocserv-modern станет **платформой** с экосистемой сторонних интеграций, написанных на разных языках, и при этом нужен bi-directional streaming для real-time событий по сети (не localhost). Тогда gRPC даёт готовую кодогенерацию клиентов, streaming, и экосистему инструментов.

Но даже в этом случае gRPC должен быть **внешним слоем поверх native API**, а не заменой внутреннего IPC. Паттерн strongSwan идеален: VICI — это попытка улучшить ситуацию для системных интеграторов, предоставляя стабильный IPC-интерфейс, позволяющий внешним инструментам запрашивать, конфигурировать и управлять IKE-демоном. Самый известный потребитель VICI — swanctl (CLI), но тот же протокол используют Go, Python, Ruby, Perl, JavaScript клиенты.

**Мой совет**: начни с Native API (protobuf-c over UDS) + HTTP REST. Если появится реальная потребность в gRPC — добавь его как тонкий proxy-слой поверх native API, не трогая ядро сервера. `.proto`-схемы у тебя уже есть — они одинаково работают и для raw protobuf IPC, и для gRPC service definitions.
