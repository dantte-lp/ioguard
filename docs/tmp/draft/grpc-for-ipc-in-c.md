# gRPC для IPC в VPN-сервере на C: не стоит свеч

**Raw protobuf-c over SOCK_SEQPACKET — правильный выбор для вашего use case.** gRPC добавляет **100–170 µs latency** на каждый unary call поверх UDS (против **4–11 µs** для raw UDS), тянет за собой ~300 МБ зависимостей, не имеет стабильного C API, не совместим с SOCK_SEQPACKET и не интегрируется с io_uring. Реальные высокопроизводительные сетевые серверы (nginx, WireGuard, HAProxy, OpenVPN) единогласно используют socketpair + shared memory для IPC, а containerd специально создал ttrpc как лёгкую замену gRPC для локального IPC. Для C23 VPN-сервера с io_uring gRPC — это архитектурный мисмэтч.

## gRPC over UDS: измеримый overhead в 10–40 раз

gRPC нативно поддерживает Unix Domain Sockets через URI-схему `unix:///path/to/socket` — конфигурация тривиальна. Однако бенчмарки Макса Планка (F. Werner, gRPC v1.40.0, AMD EPYC 7402P, 1 млн вызовов) показывают жёсткую реальность:

| Метод | Median | P99 |
|---|---|---|
| Raw UDS (blocking I/O), разные ядра | **11 µs** | 13 µs |
| gRPC over UDS (unary), разные ядра | **116 µs** | 142 µs |
| Raw UDS, одно ядро | **4 µs** | 6 µs |
| gRPC over UDS, одно ядро | **167 µs** | 200 µs |

Overhead складывается из нескольких слоёв. **HTTP/2 framing** добавляет 9 байт заголовка на каждый фрейм, HPACK-кодирование заголовков (`:method POST`, `:path`, `content-type: application/grpc`, `te: trailers`) — от **80 до 200 байт** на вызов после прогрева HPACK dynamic table. gRPC length-prefix framing — ещё **5 байт** на сообщение (1 байт compression flag + 4 байта длина). Итого на один unary RPC поверх raw protobuf: **~100–200 байт overhead** на wire + три HTTP/2 фрейма (request HEADERS, response HEADERS, Trailers). Для стриминговых RPC overhead амортизируется: после первоначального обмена заголовками каждое сообщение стоит только **14 байт** (9 HTTP/2 frame header + 5 gRPC prefix).

Принципиальное ограничение: **gRPC не может работать через SOCK_SEQPACKET**. HTTP/2 — stream-oriented протокол, требующий TCP-подобной семантики byte stream. Это значит, что при переходе на gRPC вы теряете SOCK_SEQPACKET с его автоматическим сохранением границ сообщений и вынуждены переключиться на SOCK_STREAM с ручным фреймингом внутри gRPC.

## gRPC на чистом C: стабильного решения не существует

gRPC C-core — фундамент всех «wrapped» языковых реализаций (Python, Ruby, PHP, C#), но его C API **явно не стабилен для внешних потребителей**. Мейнтейнер gRPC в issue #9656 подтвердил: *«We make changes (mostly for performance) periodically... every minor revision has included a breaking change to the core API»*. API описан как «quite rough» — это внутренний интерфейс, не предназначенный для прямого использования.

Три community-проекта обёрток (Juniper/grpc-c, linimbus/grpc-c, lixiangyun/grpc-c) находятся в статусе от «pre-alpha» до заброшенных. **Ни один не рекомендуется для production.** Официальная рекомендация gRPC team — использовать C++ API (`grpc++`), что для C23 проекта означает написание C++ wrapper-слоя.

Дерево зависимостей gRPC C++ — отдельная проблема:

| Зависимость | Назначение | Размер исходников |
|---|---|---|
| BoringSSL | TLS/SSL | ~75 МБ |
| protobuf | Сериализация + protoc | ~60 МБ |
| abseil-cpp | STL-расширения | ~15 МБ |
| re2 | Регулярные выражения (xDS routing) | ~10 МБ |
| c-ares | Async DNS | ~5 МБ |
| zlib, upb, utf8_range, xxhash | Утилиты | ~3 МБ |

`git clone --recurse-submodules` занимает **300–500 МБ**. Скомпилированные статические библиотеки — **50–100 МБ**. С gRPC 1.70+ требуется **C++17**. Для сравнения: libprotobuf-c — это **~60 КБ** shared library с единственной зависимостью (protoc для кодогенерации). Разница — **три порядка величины** в размере dependency footprint.

## In-process transport и io_uring: тупики для C

gRPC C++ имеет in-process transport через `grpc::Server::InProcessChannel()` — настоящий shared-memory транспорт, минующий HTTP/2 и сокеты. Но он работает **только внутри одного процесса** (ссылка на объект Server), что бесполезно для IPC между fork()-ed процессами. Исследователи из UC Santa Cruz (NotNets, arxiv:2404.06581) построили прототип shared-memory gRPC транспорта между процессами, но это **исследовательская работа**, не production-решение.

Что касается io_uring: **в gRPC C core нет io_uring EventEngine**. По состоянию на v1.78.x, поддерживаются только epoll1 (Linux, default), poll (fallback), IOCP (Windows). В октябре 2024 мейнтейнер AJ Heller подтвердил: *«There are no immediate plans to add io_uring support, but it has been considered in the context of the EventEngine API.»* EventEngine API экспериментальный и позволяет написать свою реализацию — но это **серьёзный инженерный проект** (нужно реализовать Listener, Endpoint, DNS resolver, task scheduler). Для VPN-сервера, где io_uring уже является core event loop, интеграция gRPC означала бы либо два параллельных event loop (gRPC epoll + ваш io_uring), либо написание custom EventEngine с нуля.

Отдельная проблема: **gRPC плохо совместим с fork()**. C-core использует потоки и мьютексы внутри; fork() после `grpc_init()` вызывает deadlocks. Есть `grpc_prefork()`/`grpc_postfork_child()`, но рекомендация — fork **до** инициализации gRPC, затем инициализировать отдельно в каждом процессе.

## Реальные проекты: уроки containerd и Kubernetes CRI

Самый показательный пример — **containerd**. Проект начал использовать gRPC over UDS для всех коммуникаций, но для IPC между демоном и shim-процессами (по одному на контейнер) **создал ttrpc** — Tiny Transport RPC. ttrpc использует те же protobuf service definitions, но заменяет HTTP/2 лёгким custom framing. Результат: меньше бинарники, меньше resident memory, ниже latency. Это **прямое свидетельство** того, что gRPC избыточен для per-process IPC.

**Kubernetes CRI** — одно из самых масштабных применений gRPC over UDS: kubelet общается с container runtime через `unix:///run/containerd/containerd.sock`. Но здесь gRPC оправдан: CRI — это **стандартизированный интерфейс** между независимыми проектами (kubelet, containerd, CRI-O), где schema evolution, service definition и cross-language support критически важны. Это принципиально другой use case, чем IPC внутри одного приложения.

Другие примеры: **Istio** использует gRPC over UDS для SDS (Secret Discovery Service) между envoy и istio-agent в одном pod. **Falco** предоставляет gRPC output stream через UDS. **Cisco IOS XR** использует gRPC over UDS для container-to-router communication. Во всех случаях gRPC выбран для **inter-component** IPC (между разными проектами/компонентами), а не для внутреннего IPC одного приложения.

Ключевой факт: **ни один из высокопроизводительных сетевых серверов не использует gRPC для внутреннего IPC**. nginx — socketpair() + shared memory. HAProxy — shared memory между потоками. WireGuard — Netlink sockets. OpenVPN — Netlink для DCO. Паттерн единообразен: минимальная сериализация, минимальная абстракция.

## Альтернативы gRPC: что реально подходит для structured IPC в C

**Cap'n Proto RPC** — наиболее интересная альтернатива для zero-copy IPC. Формат данных совпадает с in-memory представлением — нет этапа encode/decode. Promise pipelining сокращает round-trips. Нативная поддержка UDS. Однако reference-реализация — C++, а C-реализация (`c-capnproto`) **не поддерживается** и предоставляет только сериализацию без RPC. Для C23 проекта Cap'n Proto потребует C++ wrapper-слой — аналогичная проблема, что и с gRPC.

**FlatBuffers + gRPC** даёт zero-copy сериализацию внутри gRPC фреймворка (генерация через `flatc --cpp --grpc`). Десериализация FlatBuffers: **~80 ns** vs protobuf **~350 ns**. Но HTTP/2 overhead остаётся.

**protobuf-c-rpc** существует как отдельный проект, поддерживает TCP и UDS, использует простой wire protocol (12-байтный заголовок: method_index + message_length + request_id). Но проект **фактически заброшен**, имеет свой event loop (не совместимый с io_uring), и минимальную документацию.

| Подход | Latency (UDS) | Overhead на wire | Размер зависимостей | C support |
|---|---|---|---|---|
| Raw protobuf-c + SOCK_SEQPACKET | **~10–15 µs** | 0 байт framing | ~60 КБ | Нативный |
| ttrpc-подобный (protobuf + custom frame) | ~20–40 µs | ~12 байт header | ~100 КБ | Нужен порт |
| Cap'n Proto RPC | ~10–30 µs | 0 (zero-copy) | ~2 МБ (C++) | Только C++ |
| msgpack-rpc (libmpack) | ~15–30 µs | Минимальный | ~50 КБ (C89) | Нативный |
| gRPC over UDS | **~100–170 µs** | ~100–200 байт | **~300 МБ** | Нет стабильного |

Для вашего use case **libmpack** (C89, zero system dependencies, transport-agnostic) заслуживает внимания как альтернатива protobuf-c, если schema evolution не критична. Но protobuf-c с его `.proto`-driven кодогенерацией и обратной совместимостью остаётся лучшим балансом.

## Оптимальная архитектура: protobuf-c + SOCK_SEQPACKET + io_uring

Текущий выбор — raw protobuf-c over SOCK_SEQPACKET — оптимален для этого use case. Вот конкретная архитектура:

**Wire protocol**: `socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds)` — ядро гарантирует границы сообщений. Каждый `send()` = один `recv()`. Никакого length-prefix framing, никакого буферизирования, никакого парсинга границ. Для control-plane сообщений (\<4 КБ) лимит SEQPACKET на Linux (~212 КБ, настраивается через `net.core.wmem_max`) нерелевантен.

**Dispatch**: wrapper protobuf message с `request_id`, `method_id` и `oneof payload` для всех типов запросов/ответов. Dispatch table — массив function pointers по `method_id`. Это ~200–300 строк C, заменяющих весь gRPC framework.

**io_uring интеграция**: worker выставляет multishot recv (`io_uring_prep_recv_multishot`) с provided buffers на свой конец socketpair. Каждый CQE содержит полное protobuf-сообщение (гарантия SEQPACKET). Ответы отправляются через `io_uring_prep_send()`. Всё работает в едином event loop вместе с tunnel I/O — никаких двух конкурирующих event engine.

**Что gRPC дал бы поверх этого**: автоматическую кодогенерацию стубов (экономия ~200 строк), streaming с flow control (не нужен для control-plane IPC), deadline propagation (реализуется за ~20 строк), interceptors/middleware (избыточно для internal IPC), стандартизированные error codes (тривиально реализуются через enum в proto). Ни одна из этих функций не оправдывает 10–40x latency penalty, 300 МБ зависимостей, несовместимость с SOCK_SEQPACKET и io_uring, и отсутствие стабильного C API.

## Заключение

gRPC оправдан для **стандартизированных inter-component API** (как Kubernetes CRI или xDS), где участвуют разные проекты, разные языки, и возможен переход на сетевой RPC. Для **внутреннего IPC одного приложения** на C с io_uring gRPC — архитектурный антипаттерн. Containerd пришёл к этому выводу и создал ttrpc; все высокопроизводительные сетевые серверы используют raw socketpair/shared memory. Единственный сценарий, при котором стоит пересмотреть решение: если VPN-сервер в будущем должен предоставлять **внешний management API** — тогда gRPC имеет смысл для этого API, но внутренний IPC между main и worker всё равно должен оставаться на raw protobuf-c over SOCK_SEQPACKET.