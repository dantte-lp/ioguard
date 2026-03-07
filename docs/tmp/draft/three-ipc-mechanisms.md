# Три механизма IPC для io_uring VPN-сервера: что выбрать

**Для высокопроизводительного VPN-сервера с io_uring оптимальный выбор IPC зависит от характера трафика между main и worker процессами.** Unix socket + protobuf-c даёт лучший баланс простоты и производительности для control-plane сообщений (конфиг, сессии, статистика), типичных для VPN. Shared memory + eventfd обеспечивает на два порядка большую пропускную способность (**112M msg/s** vs **~1.7M msg/s**), но оправдана только при data-plane IPC с миллионами сообщений в секунду. io_uring msg_ring — элегантный механизм уведомлений, но передаёт лишь **128 бит** за операцию и требует shared memory для реальных данных, превращаясь фактически в вариант третьего подхода с другим механизмом нотификации.

Ниже — детальный разбор каждого подхода с конкретными цифрами, подводными камнями и рекомендациями.

---

## Unix socket + protobuf-c: надёжная классика с неожиданно низкой латентностью

Unix domain sockets показывают **~1.4 μs** p50 round-trip latency для мелких сообщений — это в 3 раза быстрее pipe и в 5 раз быстрее TCP loopback. При этом протокол зрелый, отлично отлаживается через `strace` и `ss -x`, а io_uring добавляет существенные оптимизации поверх.

**Ключевые io_uring-оптимизации для unix socket.** Multishot recv (ядро 6.0+) позволяет подать один SQE и получать CQE при каждом поступлении данных без повторной подачи запроса. Provided buffer rings (5.19+) устраняют аллокации на recv-path. Registered file descriptors (`IOSQE_FIXED_FILE`) убирают fget/fput на каждой операции. SQ Polling (`IORING_SETUP_SQPOLL`) полностью устраняет syscall на подачу — Red Hat продемонстрировал 5000 socket I/O операций за 23 системных вызова. Recv bundles (6.10+) заполняют несколько буферов за один проход через сетевой стек.

**Важный нюанс: send_zc (IORING_OP_SEND_ZC) бесполезен для AF_UNIX.** По словам Jens Axboe, zero-copy send «falls back to copying when data doesn't leave the machine». Для AF_UNIX ядро всегда копирует данные между socket-буферами. Проверить можно флагом `IORING_SEND_ZC_REPORT_USAGE` — CQE уведомления покажет `IORING_NOTIF_USAGE_ZC_COPIED`. Используйте обычный `IORING_OP_SEND`.

**SOCK_SEQPACKET — золотая рекомендация для IPC.** В отличие от SOCK_STREAM, он сохраняет границы сообщений: каждый send() соответствует ровно одному recv(). Это полностью устраняет необходимость message framing (length-prefix headers, обработка partial reads). В сочетании с multishot recv каждый CQE содержит ровно одно полное сообщение. Единственное ограничение: сообщение, превышающее размер receive-буфера, будет **молча обрезано** — размер provided-буферов должен быть ≥ максимального размера protobuf-сообщения.

| Свойство               | SOCK_STREAM  | SOCK_SEQPACKET | SOCK_DGRAM |
| ---------------------- | ------------ | -------------- | ---------- |
| Границы сообщений      | Нет          | **Да**         | **Да**     |
| Connection-oriented    | Да           | Да             | Нет        |
| Макс. размер сообщения | Не ограничен | SO_SNDBUF      | SO_SNDBUF  |
| socketpair()           | Да           | Да             | Да         |
| SCM_RIGHTS             | Да           | Да             | Да         |

**Overhead protobuf-c для IPC-сообщений пренебрежимо мал.** Сериализация 50–500 байт занимает **~200–500 ns**, десериализация **~300–800 ns** — это 20–55% от socket round-trip latency в ~1.4 μs. Для сравнения: FlatBuffers обеспечивают zero-copy десериализацию (~18–80 ns), но сериализация медленнее (~850 ns), а wire size на 2–3× больше. Raw struct copy мгновенный, но лишён версионирования — любое изменение структуры ломает совместимость.

**Главная проблема protobuf-c — malloc на каждый unpack().** По умолчанию `unpack()` вызывает malloc для верхнего структурного уровня, для каждого string/bytes поля и для каждого repeated-массива. Сообщение с 3 строковыми полями генерирует ~4 malloc(). Решение — **custom arena allocator** через `ProtobufCAllocator`:

```c
// Arena: все аллокации из pre-allocated буфера, free — no-op
// Между сообщениями: arena.next_free_index = 0
ProtobufCAllocator arena_alloc = { .alloc = bump_alloc, .free = noop_free, .allocator_data = &arena };
MyMessage *msg = my_message__unpack(&arena_alloc, len, data);
```

Это полностью устраняет malloc/free overhead. Для сериализации используйте `ProtobufCBufferSimple` со стековым буфером — pack() не аллоцирует вовсе.

**Подводные камни.** Передача fd через SCM_RIGHTS с io_uring имела серьёзную уязвимость (CVE-2022-2602: use-after-free) — используйте ядро 6.1+. Multishot recvmsg плохо совместим с ancillary data (SCM_RIGHTS); для fd passing используйте single-shot recvmsg. Дефолтный AF_UNIX socket buffer — **~208 KB**; при заполнении io_uring SEND паркует операцию до освобождения места, но без `MSG_DONTWAIT` это может блокировать SQE-слот.

**Минимальное ядро:** 6.0 для multishot recv + provided buffer rings. **Рекомендуемое: 6.1+** для security-фиксов SCM_RIGHTS.

---

## io_uring msg_ring: элегантное уведомление, но не полноценный IPC

IORING_OP_MSG_RING (ядро 5.18+) позволяет одному io_uring кольцу напрямую записать CQE в completion queue другого кольца. Это **не замена каналу данных**, а механизм уведомлений: передаётся максимум **128 бит** — 32-bit `res` + 64-bit `user_data` + 32-bit `flags` (с флагом `IORING_MSG_RING_FLAGS_PASS`, ядро ~6.2+).

**Критический вопрос: да, msg_ring работает между процессами.** Man page явно указывает: «The targeted ring may be any ring that the user has access to, even the ring itself.» В ядре нет проверки на принадлежность одному процессу. Три способа получить fd чужого кольца:

- **fork()** — дочерний процесс наследует ring fd родителя (простейший случай для VPN-сервера)
- **SCM_RIGHTS** — передать ring fd через unix socket (для несвязанных процессов)
- **pidfd_getfd()** — продублировать fd через pidfd_open(), но требует root или `ptrace_scope=0`

Проект **Mulling/io-uring-ipc** на GitHub демонстрирует полноценный cross-process IPC: shared memory allocator на `/dev/shm` + msg_ring для нотификаций. Метаданные кольца кодируются в имени shm-файла: `hring_shm:<pid>:<uring_fd>:<sq_size>:<cq_size>`, а ring fd получается через pidfd_getfd(). Автор проекта отмечает: «all the synchronization machinery is already provided — for free — by io_uring. You only need a shared memory allocator.»

**Паттерн использования — shared memory + msg_ring notification:**

1. Producer записывает данные в shared memory ring buffer
2. Producer отправляет `IORING_OP_MSG_RING` с `IORING_MSG_DATA`, кодируя offset в shared memory через `user_data` (64 бит)
3. Consumer получает CQE, извлекает offset, читает данные

Это фактически **третий подход (shared memory) с msg_ring вместо eventfd для нотификаций**. Преимущество msg_ring: нет отдельного syscall на eventfd_write, нотификация батчится с другими io_uring операциями в одном `io_uring_enter()`, а при SQPOLL — zero-syscall вовсе.

**Передача файловых дескрипторов (IORING_MSG_SEND_FD, ядро 6.0+)** позволяет перемещать fixed/direct дескрипторы между кольцами. Оба кольца должны иметь registered file table. Важное ограничение: получатель видит fd только как fixed descriptor в io_uring, для обычных syscall нужен `IORING_OP_FIXED_FD_INSTALL`. Если CQ получателя переполнена — возвращается `-EOVERFLOW`, но fd уже установлен; отправитель обязан повторить уведомление.

| Версия ядра | Что добавлено                                   |
| ----------- | ----------------------------------------------- |
| **5.18**    | IORING_OP_MSG_RING (MSG_DATA only)              |
| **6.0**     | IORING_MSG_SEND_FD + CQE_SKIP                   |
| **~6.2**    | IORING_MSG_RING_FLAGS_PASS                      |
| **6.11**    | Оптимизация для DEFER_TASKRUN колец             |
| **6.13**    | IORING_REGISTER_SEND_MSG_RING (без source ring) |

**Зрелость и стабильность.** MSG_DATA API стабилен с мая 2022 (3.5+ лет). API входит в stable UAPI headers. Однако io_uring в целом имеет непростую репутацию по безопасности — Google сообщал, что 60% bug bounty эксплойтов в 2022 были io_uring. Рекомендуемое ядро для production: **6.6 LTS или 6.11+**.

**Главное ограничение:** msg_ring передаёт только 128 бит. Для любых реальных данных нужна shared memory, что превращает этот подход в «shared memory + msg_ring» — усложнение по сравнению с «shared memory + eventfd», оправданное только если вся архитектура уже построена на io_uring и нужна максимальная интеграция уведомлений в event loop.

---

## Shared memory + eventfd: максимальная производительность ценой сложности

SPSC lock-free ring buffer в shared memory с оптимизацией cached indices достигает **112M items/s** на x86 — это на два порядка больше, чем ~1.7M msg/s через unix socket. Латентность **sub-microsecond** при горячем кэше. Ядро полностью исключено из data path после начального mmap.

**Анатомия высокопроизводительного SPSC ring buffer.** Наивная реализация даёт ~5.5M items/s. Ключевая оптимизация — **кэширование удалённого индекса**: producer хранит локальную копию `readIdx` и перечитывает атомарный `readIdx` только когда кэшированное значение показывает, что буфер может быть полон. Это снижает cross-core cache coherency traffic с ~300M cache misses до ~15M для 100M элементов, давая **20× ускорение**.

```c
struct spsc_ring {
    alignas(64) _Atomic size_t writeIdx;      // Только producer пишет
    alignas(64) size_t          readIdxCached; // Локальная копия у producer
    alignas(64) _Atomic size_t readIdx;        // Только consumer пишет
    alignas(64) size_t          writeIdxCached; // Локальная копия у consumer
    alignas(64) uint8_t         data[];         // Степень двойки
};
```

**Каждое поле на отдельной cache line (64 байта)** — это критично для предотвращения false sharing. Без этого выравнивания producer и consumer конкурируют за одну cache line, и производительность падает на порядок. Обнаружить false sharing можно через `perf c2c` (Remote HITM события).

**Memory ordering — минимально достаточный:** producer делает `store(writeIdx, memory_order_release)` после записи данных; consumer делает `load(writeIdx, memory_order_acquire)` перед чтением данных. На x86 (TSO) acquire/release компилируются в **нулевые аппаратные барьеры** (только compiler barriers). На ARM — в LDAR/STLR инструкции. CAS-операции для SPSC **не нужны** — достаточно простых load/store. Код, корректный на x86, может **молча ломаться на ARM** при использовании `memory_order_relaxed` вместо acquire/release.

**eventfd + io_uring poll — рабочая связка.** Consumer подаёт `IORING_OP_POLL_ADD` на eventfd с POLLIN. Producer после записи в ring buffer вызывает `eventfd_write(efd, 1)`. Семантика counter mode: множественные write() аккумулируются, один read() возвращает общий счётчик и сбрасывает его — это естественный coalescing уведомлений. Оптимизация: проверять shared-флаг `consumer_sleeping` перед eventfd_write() — если consumer активно обрабатывает данные, syscall не нужен.

**Подводный камень с eventfd + io_uring:** если зарегистрировать eventfd через `IORING_REGISTER_EVENTFD` для CQ-нотификаций И одновременно poll'ить тот же eventfd через io_uring — возможен **deadlock**. Ядро детектирует это, но лучше использовать разные eventfd для разных целей.

**Crash recovery — ахиллесова пята.** Shared memory переживает крэш процесса (shm_open объекты остаются в `/dev/shm` до явного unlink). Если producer упал между записью данных и обновлением writeIdx — consumer не увидит partial write (release-семантика гарантирует). Если consumer упал — producer увидит stale readIdx и будет считать буфер более полным, чем он есть (безопасно, теряется только capacity). Для детекции крэша: PID + heartbeat timestamp в заголовке shared memory, проверка `kill(pid, 0)` (ESRCH = процесс мёртв).

**Готовые библиотеки:**

- **DPDK rte_ring** — индустриальный стандарт, поддерживает SPSC/MPMC, требует hugepages
- **rigtorp/SPSCQueue** (C++) — максимально оптимизированный SPSC, header-only, 112M items/s
- **rmind/ringbuf** (C11) — MPSC, BSD-лицензия, явно рассчитан на shared memory между процессами
- **CloudWeGo/shmipc** — production у ByteDance (3000+ сервисов), shared memory ring + unix socket для синхронизации

**Минимальное ядро:** 5.1 для io_uring poll на eventfd. Фактически самые низкие требования из трёх подходов.

---

## Сравнительная таблица трёх подходов

| Критерий                      | Unix socket + protobuf-c   | io_uring msg_ring (+shm)          | Shared memory + eventfd          |
| ----------------------------- | -------------------------- | --------------------------------- | -------------------------------- |
| **Латентность (round-trip)**  | ~1.4–4.5 μs                | Sub-μs (нотификация) + shm access | **Sub-μs**                       |
| **Пропускная способность**    | ~1.7M msg/s                | Зависит от shm ring               | **112M+ items/s** (SPSC)         |
| **Макс. размер сообщения**    | Не ограничен (stream)      | 128 бит (без shm)                 | Ограничен буфером ring           |
| **Сложность реализации**      | **Низкая**                 | Средняя–Высокая                   | **Высокая**                      |
| **Отладка**                   | strace, ss, Wireshark      | ftrace tracepoints, bpftrace      | /proc/maps, perf c2c, нет strace |
| **Crash recovery**            | Ядро очищает socket        | Ядро очищает ring                 | Ручная (shm переживает крэш)     |
| **Версионирование сообщений** | protobuf schema evolution  | Нет (raw bits)                    | Нет (ручное)                     |
| **Мин. ядро**                 | 6.0 (multishot recv)       | 5.18 (msg_ring), 6.0 (fd pass)    | 5.1 (io_uring poll)              |
| **Рек. ядро**                 | **6.1+**                   | **6.6 LTS / 6.11+**               | **5.1+**                         |
| **fd passing**                | SCM_RIGHTS (зрелый)        | IORING_MSG_SEND_FD (6.0+)         | Отдельный механизм нужен         |
| **Backpressure**              | Встроенная (socket buffer) | CQ overflow → EOVERFLOW           | Ручная (ring full)               |

---

## Что выбирают production-системы

**DPDK** использует shared memory + rte_ring (lock-free) для data-plane IPC между primary и secondary процессами. Для control-plane — unix domain sockets (через `rte_mp_action_register()`). Ring buffers передают **дескрипторы пакетов** (указатели в shared hugepage memory), а не сами данные — истинный zero-copy.

**Seastar/ScyllaDB** строит shared-nothing архитектуру с одним потоком на ядро. Cross-core communication реализован через **SPSC ring buffers в shared memory**. Примечательная оптимизация: дорогой MFENCE перенесён с fast-path producer'а на sleep-path consumer'а — когда ядро готовится уснуть, оно инжектирует memory barrier на все остальные ядра.

**strongSwan** (IPsec VPN) использует **unix domain sockets** (SOCK_STREAM) с 32-bit length-prefix framing для VICI протокола. **OpenVPN** запускает независимые процессы без IPC между ними, масштабируясь через iptables DNAT. **WireGuard** работает в ядре и не нуждается в IPC для data-plane.

Jens Axboe о msg_ring (июнь 2024): _«This series greatly improves both latency, overhead, and throughput of sending messages to other rings»_ — и противопоставляет msg_ring подходу «some kind of queue with serialization, and then a remote wakeup with eg epoll on the other end and using eventfd. That isn't very efficient.» Однако на форуме Phoronix уточняется: _«io_uring is a single producer single consumer queue... For IPC you would be far better off using something else, like your own ring queue in shared memory.»_

---

## Рекомендации для VPN-сервера

Для VPN-сервера характер IPC — **control-plane**: обновления конфигурации (раз в секунды-минуты), управление сессиями (при подключении/отключении), обмен ключами (раз в минуты-часы), сбор статистики (раз в секунды). Это **тысячи, не миллионы** сообщений в секунду. Bottleneck VPN — криптография и kernel-userspace transitions, не IPC.

**Оптимальный выбор: Unix socket (SOCK_SEQPACKET) + protobuf-c с arena allocator.** SOCK_SEQPACKET устраняет message framing. protobuf-c даёт schema evolution при незначительном overhead (~500–800 ns на фоне ~1.4 μs socket latency). Arena allocator устраняет malloc. Multishot recv через io_uring минимизирует syscall overhead при мультиплексировании нескольких worker'ов. Отладка тривиальна через strace. Crash recovery — бесплатная (ядро закрывает socket).

**Когда имеет смысл shared memory + msg_ring:** если архитектура предполагает передачу пакетных дескрипторов между main и worker (DPDK-style data-plane), и IPC находится на критическом пути с миллионами сообщений в секунду. В этом случае SPSC ring buffer в shared memory с msg_ring нотификациями даёт sub-μs латентность и 100M+ msg/s пропускную способность — но ценой значительно большей сложности реализации, отладки и crash recovery.
