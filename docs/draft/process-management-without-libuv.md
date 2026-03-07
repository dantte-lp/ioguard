# Управление процессами без libuv: полное руководство для ocserv-modern

Замена процессного менеджмента libuv (`uv_spawn`, `uv_process_t`) на нативные Linux API не только возможна, но и даёт значительные преимущества для VPN-сервера, ориентированного исключительно на Linux. **Оптимальная стратегия — комбинация `pidfd_spawn`/`clone3(CLONE_PIDFD)` для создания процессов, `IORING_OP_WAITID` для асинхронного сбора статусов завершения и `signalfd` через io_uring для обработки сигналов.** Такой подход устраняет гонки PID-рециклирования, полностью интегрирует управление процессами в единый цикл событий io_uring и обеспечивает race-free семантику на всех уровнях. Ни nginx, ни HAProxy, ни OpenSSH, ни оригинальный ocserv не используют libuv для управления процессами — все полагаются на прямые POSIX-вызовы, интегрированные в собственные циклы событий. Этот же путь является наиболее правильным для ocserv-modern.

---

## Нативное управление процессами через io_uring и pidfd

Современное ядро Linux (5.3+) предоставляет **pidfd** — файловые дескрипторы процессов, которые кардинально меняют подход к управлению дочерними процессами. В отличие от традиционных PID-номеров, pidfd является стабильной ссылкой на конкретный процесс, которая никогда не может указать на другой процесс после рециклирования PID. Кристиан Брайнер, автор pidfd в ядре, явно проектировал этот API для систем вроде systemd и Android LMK, которым нужно надёжное наблюдение за процессами и безгоночная отправка сигналов.

**IORING_OP_WAITID** (ядро 6.7+, liburing 2.6+) — это асинхронный вариант системного вызова `waitid(2)`, добавленный Йенсом Аксбоэ. Он позволяет родительскому процессу получать уведомления о завершении дочерних процессов непосредственно через completion queue io_uring, без блокировки и без сигналов:

```c
// Создание дочернего процесса с pidfd
struct clone_args args = {
    .pidfd    = (uint64_t)(uintptr_t)&child_pidfd,
    .flags    = CLONE_PIDFD,
    .exit_signal = SIGCHLD,
};
pid_t pid = syscall(SYS_clone3, &args, sizeof(args));

if (pid == 0) {
    execve("/usr/lib/ocserv/worker", argv, envp);
    _exit(127);
}

// Асинхронный сбор статуса через io_uring
siginfo_t info;
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_waitid(sqe, P_PID, pid, &info, WEXITED, 0);
io_uring_sqe_set_data64(sqe, WORKER_EXIT_TAG);
io_uring_submit(&ring);
```

Внутри SQE поля отображаются следующим образом: `sqe->len` содержит `idtype` (P_PID, P_ALL, P_PIDFD), `sqe->fd` — идентификатор процесса, `sqe->file_index` — опции ожидания (WEXITED, WSTOPPED), а `sqe->addr2` — указатель на `siginfo_t`. Когда CQE возвращается с `res == 0`, структура `siginfo_t` уже заполнена полной информацией о завершении: `si_pid`, `si_status`, `si_code` (CLD_EXITED, CLD_KILLED, CLD_DUMPED).

Для ядер **5.3–6.6** альтернативный подход — поллинг pidfd через `IORING_OP_POLL_ADD`. Pidfd становится читаемым (`POLLIN`/`EPOLLIN`), когда процесс завершается и становится зомби:

```c
int pidfd = syscall(SYS_pidfd_open, child_pid, 0);
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_poll_add(sqe, pidfd, POLLIN);
io_uring_sqe_set_data64(sqe, CHILD_EXIT_TAG);
io_uring_submit(&ring);
// После получения CQE — вызвать waitid(P_PIDFD, pidfd, &info, WEXITED)
```

| Механизм               | Мин. ядро | Гранулярность            | Требует SIGCHLD | Гонки PID  |
| ---------------------- | --------- | ------------------------ | --------------- | ---------- |
| `signalfd` + `waitpid` | 2.6.22    | Все дети (коалесценция!) | Да              | Возможны   |
| `pidfd` + `POLL_ADD`   | 5.3       | Один процесс             | Нет             | Невозможны |
| `IORING_OP_WAITID`     | **6.7**   | Один процесс или P_ALL   | Нет             | Невозможны |

**Рекомендация для ocserv-modern**: установить минимальное требование ядра 6.7 и использовать `IORING_OP_WAITID` как основной механизм. Для каждого дочернего процесса (worker, sec-mod, connect-script) подаётся отдельный SQE, а завершение обрабатывается в едином цикле событий наравне с сетевым I/O. Это устраняет необходимость в `uv_process_t` и всей инфраструктуре libuv для управления процессами.

---

## posix_spawn как безопасная замена fork/exec для вспомогательных процессов

Для запуска скриптов подключения/отключения и вспомогательных утилит аутентификации `posix_spawn` является оптимальным выбором. Начиная с **glibc 2.24**, `posix_spawn` никогда не вызывает `fork()` — он использует `clone(CLONE_VM | CLONE_VFORK)` с отдельным стеком для дочернего процесса, что делает его по производительности сопоставимым с `vfork+exec` и **в 12 раз быстрее** `fork+exec` для процессов с большим потреблением памяти. Начиная с **glibc ~2.37**, используется `clone3()` с флагом `CLONE_CLEAR_SIGHAND`, который атомарно сбрасывает все обработчики сигналов в ядре без итерации в пространстве пользователя.

Ключевые расширения для безопасного VPN-сервера:

```c
posix_spawn_file_actions_t fa;
posix_spawn_file_actions_init(&fa);
// Закрыть ВСЕ унаследованные дескрипторы >= 3
// (туннельные fd, крипто-ключи, управляющие сокеты)
posix_spawn_file_actions_addclosefrom_np(&fa, 3);  // glibc 2.34+
// Настроить коммуникационный канал
posix_spawn_file_actions_adddup2(&fa, control_pipe[0], 3);

posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
posix_spawnattr_setflags(&attr,
    POSIX_SPAWN_SETSID |        // Новая сессия, без терминала
    POSIX_SPAWN_SETPGROUP |      // Собственная группа процессов
    POSIX_SPAWN_SETSIGMASK |     // Чистая маска сигналов
    POSIX_SPAWN_SETSIGDEF);      // Сброс всех обработчиков

sigset_t empty, all;
sigemptyset(&empty);
sigfillset(&all);
posix_spawnattr_setsigmask(&attr, &empty);
posix_spawnattr_setsigdefault(&attr, &all);
posix_spawnattr_setpgroup(&attr, 0);
```

**`pidfd_spawn`** (glibc 2.39+) — это революционное расширение, возвращающее pidfd вместо PID. Внутренне оно использует `clone3(CLONE_PIDFD)` и позволяет немедленно начать race-free наблюдение за процессом через io_uring:

```c
int pidfd;
int ret = pidfd_spawn(&pidfd, "/usr/lib/ocserv/auth-helper",
                      &fa, &attr, argv, envp);
// pidfd можно сразу передать в IORING_OP_WAITID с P_PIDFD
// или в IORING_OP_POLL_ADD
```

Главное ограничение `posix_spawn` — **невозможность произвольных pre-exec действий**: нельзя вызвать `prctl(PR_SET_NO_NEW_PRIVS)`, установить seccomp-фильтры, сделать `chroot` или сбросить capabilities. Для worker-процессов, требующих песочницы, нужен **паттерн трамплина** (helper binary): `posix_spawn` запускает минимальный бинарник-трамплин, который сам выполняет привилегированные действия перед `exec` целевой программы.

| Возможность                      | glibc    | Ядро              | musl      |
| -------------------------------- | -------- | ----------------- | --------- |
| `clone`-based (без fork)         | 2.24     | 2.6+              | Поддержка |
| `POSIX_SPAWN_SETSID`             | 2.26     | Любое             | Поддержка |
| `addclosefrom_np`                | 2.34     | 5.9+ (оптимально) | Нет       |
| `clone3` + `CLONE_CLEAR_SIGHAND` | ~2.37    | 5.5+              | Нет       |
| `pidfd_spawn` / `pidfd_spawnp`   | **2.39** | 5.2+              | Нет       |

---

## Как nginx, OpenSSH и ocserv управляют процессами без libuv

Ни один из крупных серверных проектов на C не использует libuv для управления процессами. Каждый реализует собственный тонкий слой над POSIX API, интегрированный со своим циклом событий.

**Nginx** использует модель master + workers, где мастер-процесс управляет массивом `ngx_processes[]` (до 1024 слотов). Каждый слот хранит PID, пару сокетов для IPC («канал»), флаги состояния (`respawn`, `exiting`, `exited`) и указатель на функцию цикла. Сигналы обрабатываются через минимальные обработчики, выставляющие `sig_atomic_t` флаги (`ngx_reap`, `ngx_reconfigure`, `ngx_terminate`), а мастер использует `sigsuspend()` для атомарного ожидания. При SIGHUP nginx парсит новый конфиг, при успехе порождает новых workers, даёт 100мс на старт, затем отправляет SIGQUIT старым. При зависании workers эскалация от SIGTERM к SIGKILL происходит через увеличивающийся таймер (50мс → 1с).

**OpenSSH** реализует **обязательную** (с версии 7.5) привилегированную сепарацию с двумя фазами. До аутентификации: форк, `chroot("/var/empty")`, сброс до пользователя `sshd`, применение seccomp-bpf. IPC между привилегированным монитором и непривилегированным ребёнком — через `socketpair(AF_UNIX, SOCK_STREAM)` с типизированными сообщениями и dispatch-таблицей с флагами `MON_ONCE`, `MON_AUTH`, `MON_AUTHDECIDE`. Монитор валидирует каждый запрос и вызывает `fatal()` при нарушении протокола.

**Оригинальный ocserv** использует **libev** (не libuv) с трёхкомпонентной архитектурой: main-процесс (root, слушает TCP, управляет tun-устройствами), sec-mod (работа с приватными ключами и аутентификация), и per-client workers (непривилегированные, возможна изоляция через seccomp + namespaces при `isolate-workers = true`). IPC осуществляется через protobuf-c сообщения по Unix-сокетам. Состояние передаётся worker'ам через переменные окружения.

**Вывод для ocserv-modern**: нет необходимости в внешних библиотеках для управления процессами. Рекомендуемый паттерн — собственная таблица процессов (аналог nginx), интегрированная с io_uring:

```c
typedef struct {
    pid_t       pid;
    int         pidfd;          // pidfd для race-free управления
    int         channel[2];     // socketpair для IPC
    uint32_t    generation;     // Номер поколения конфига
    time_t      spawn_time;     // Для экспоненциального backoff
    int         restart_count;  // Счётчик перезапусков
    unsigned    respawn:1;
    unsigned    exiting:1;
    unsigned    exited:1;
} process_slot_t;
```

---

## Обработка сигналов через signalfd и io_uring

Замена `uv_signal_t` на `signalfd` + io_uring обеспечивает синхронную доставку сигналов в единый цикл событий без reentrancy-проблем и ограничений async-signal-safe функций. Ключевое правило: **сигналы должны быть заблокированы через `sigprocmask` до создания signalfd**.

```c
sigset_t mask;
sigemptyset(&mask);
sigaddset(&mask, SIGHUP);    // Перезагрузка конфигурации
sigaddset(&mask, SIGTERM);   // Корректное завершение
sigaddset(&mask, SIGINT);    // Прерывание
sigaddset(&mask, SIGCHLD);   // Завершение дочерних процессов

sigprocmask(SIG_BLOCK, &mask, NULL);
int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

// Подключение к io_uring через POLL_ADD
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_poll_add(sqe, sfd, POLLIN);
io_uring_sqe_set_data64(sqe, SIGNAL_TAG);
io_uring_submit(&ring);
```

Историческая ошибка: в ядре ~5.3 signalfd + io_uring POLL не работал из-за проверки маски сигналов в контексте рабочего потока io_uring вместо основного процесса. **Исправлено начиная с ядра 5.4.** На целевых ядрах 6.7+ проблема отсутствует.

**Критическая деталь: коалесценция сигналов.** Стандартные POSIX-сигналы коалесцируются — если два SIGCHLD пришли до обработки первого, signalfd сообщит только об одном. Поэтому после получения SIGCHLD через signalfd **обязательно** вызывать `waitpid(-1, &status, WNOHANG)` в цикле до возврата 0 или ECHILD. Если используется `IORING_OP_WAITID` с отдельным SQE на каждого ребёнка, эта проблема устраняется — каждый pidfd/waitid является per-process и не подвержен коалесценции.

Альтернативный подход — **`io_uring_enter` с сигнальной маской** (ядро 5.11+, `IORING_ENTER_EXT_ARG`), аналог `epoll_pwait`: атомарная установка маски сигналов при ожидании CQE. Это позволяет обойтись без signalfd, используя традиционные обработчики, но усложняет архитектуру.

**Рекомендуемая стратегия для ocserv-modern**: signalfd для SIGHUP/SIGTERM/SIGINT (сигналы управления сервером) + `IORING_OP_WAITID` для каждого дочернего процесса индивидуально (без SIGCHLD). Так достигается максимальная надёжность: управляющие сигналы обрабатываются через signalfd, а завершения процессов — через race-free механизм без коалесценции.

---

## Привилегированная сепарация и песочница для worker-процессов

Архитектура ocserv-modern должна сохранить трёхкомпонентную модель оригинала (main, sec-mod, workers), но усилить изоляцию с помощью современных Linux API.

**Многослойная защита worker-процессов:**

1. **`prctl(PR_SET_NO_NEW_PRIVS, 1)`** (ядро 3.5+) — необратимо запрещает повышение привилегий через execve. Setuid/setgid биты игнорируются, file capabilities не добавляются. Обязательный предшественник seccomp-bpf.

2. **seccomp-bpf** — BPF-программа, фильтрующая системные вызовы. Для VPN-worker'а белый список должен включать: `read`, `write`, `recvmsg`, `sendmsg`, `close`, `io_uring_enter`, `io_uring_setup`, `io_uring_register`, `mmap`, `munmap`, `clock_gettime`, `exit_group` и минимальный набор для сетевых операций. Всё остальное — `SECCOMP_RET_KILL_PROCESS`. Библиотека **libseccomp** предоставляет высокоуровневый API (`seccomp_rule_add`, `seccomp_load`).

3. **Landlock LSM** (ядро 5.13+, ABI v1–v7) — непривилегированный механизм ограничения доступа к файловой системе, аналог `unveil()` из OpenBSD. Worker может ограничить себя до чтения `/etc/ocserv/` и записи в `/var/log/ocserv/`, запретив доступ к остальной ФС. С **ABI v4** (ядро 6.7) добавлены сетевые правила (TCP bind/connect), с **ABI v6** (ядро 6.11) — ограничение абстрактных Unix-сокетов и сигналов.

4. **Linux namespaces** — `CLONE_NEWUSER` + `CLONE_NEWNS` для полной изоляции файловой системы (оригинальный ocserv поддерживает это через `isolate-workers = true`).

**IPC между привилегированным и непривилегированным процессами** наилучшим образом реализуется через `socketpair(AF_UNIX, SOCK_SEQPACKET)` — `SOCK_SEQPACKET` сохраняет границы сообщений, упрощая протокол фрейминга. Для передачи файловых дескрипторов (например, tun-устройств от main к worker) используется `sendmsg`/`recvmsg` с `SCM_RIGHTS`:

```c
// Отправка fd через Unix-сокет
struct iovec iov = { .iov_base = "x", .iov_len = 1 };
union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
struct msghdr msg = {
    .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = u.buf, .msg_controllen = sizeof(u.buf)
};
struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type  = SCM_RIGHTS;
cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
memcpy(CMSG_DATA(cmsg), &tun_fd, sizeof(tun_fd));
sendmsg(channel_fd, &msg, 0);
```

Начиная с ядра 5.6, **`pidfd_getfd()`** позволяет переносить дескрипторы между процессами без Unix-сокетов, но требует `CAP_SYS_PTRACE`.

---

## Паттерны перезагрузки конфигурации и корректного завершения

**Перезагрузка по SIGHUP** должна следовать модели nginx: мастер получает сигнал через signalfd → парсит новый конфиг → при ошибке валидации продолжает работу со старым → при успехе порождает новых workers → отправляет MSG_SHUTDOWN_REQUEST старым → старые дренируют активные соединения → выходят. Каждый worker хранит номер поколения конфигурации; мастер отслеживает, когда все workers старого поколения завершились, и освобождает старую структуру конфига.

```c
void handle_sighup(server_t *srv) {
    config_t *new_cfg = config_load(srv->config_path);
    if (!new_cfg || !config_validate(new_cfg)) {
        log_error("Config reload failed, keeping current config");
        config_free(new_cfg);
        return;
    }
    uint32_t new_gen = ++srv->generation;
    for (int i = 0; i < new_cfg->worker_count; i++)
        spawn_worker(srv, new_cfg, new_gen);
    for (int i = 0; i < srv->nprocs; i++) {
        if (srv->procs[i].generation < new_gen && !srv->procs[i].exiting) {
            // Отправка по IPC-каналу, а не kill — более надёжно
            send_msg(srv->procs[i].channel[0], MSG_SHUTDOWN_REQUEST, NULL, 0);
            srv->procs[i].exiting = 1;
        }
    }
    config_free(srv->old_config);
    srv->old_config = srv->config;
    srv->config = new_cfg;
}
```

**Корректное завершение** по SIGTERM: мастер прекращает приём новых соединений (отмена accept SQE через `io_uring_prep_cancel`), отправляет SIGTERM всем workers через `pidfd_send_signal(pidfd, SIGTERM, NULL, 0)` (race-free!), запускает таймер graceful-периода. Workers прекращают приём, дренируют активные VPN-сессии, отправляют MSG_DRAIN_COMPLETE. По истечении таймера — `pidfd_send_signal(pidfd, SIGKILL, NULL, 0)` для оставшихся. Экспоненциальный backoff для перезапуска упавших workers: начальная задержка 100мс, удвоение до 30с, сброс после 60с стабильной работы.

**Интеграция с systemd** через `sd_notify()`: `READY=1` после инициализации, `RELOADING=1`/`READY=1` при перезагрузке конфига, `WATCHDOG=1` с периодичностью `WatchdogSec/2`, `STOPPING=1` при завершении. Рекомендуемый `KillMode=mixed` — systemd отправляет SIGTERM только мастеру, позволяя ему координировать завершение workers.

---

## Итоговая архитектура управления процессами

Комплексная замена libuv для ocserv-modern реализуется следующим набором Linux API без каких-либо внешних библиотек управления процессами:

| Задача libuv        | Замена для ocserv-modern                                        | Мин. ядро |
| ------------------- | --------------------------------------------------------------- | --------- |
| `uv_spawn`          | `pidfd_spawn` (glibc 2.39) или `clone3(CLONE_PIDFD)` + `execve` | 5.2       |
| `uv_process_t`      | Собственная таблица `process_slot_t` с pidfd                    | 5.3       |
| `uv_process_kill`   | `pidfd_send_signal(pidfd, sig, NULL, 0)`                        | 5.1       |
| Ожидание завершения | `IORING_OP_WAITID` (per-process SQE)                            | **6.7**   |
| `uv_signal_t`       | `signalfd` + `IORING_OP_POLL_ADD`                               | 5.4       |
| `uv_pipe_t` для IPC | `socketpair(AF_UNIX, SOCK_SEQPACKET)` через io_uring            | 5.1       |

Рекомендуемое минимальное ядро для ocserv-modern: **6.7** (для IORING_OP_WAITID и Landlock ABI v4 с сетевыми правилами). Рекомендуемый glibc: **2.39+** (для `pidfd_spawn`). Вся архитектура собирается из нативных системных вызовов, не требуя ни одной сторонней библиотеки управления процессами — именно так работают nginx, HAProxy, OpenSSH и оригинальный ocserv. Разница в том, что ocserv-modern использует на порядок более современные API, устраняющие целые классы гонок и упрощающие интеграцию с io_uring.
