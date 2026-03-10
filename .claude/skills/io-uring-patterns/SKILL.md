---
name: io-uring-patterns
description: Use when writing io_uring code in ioguard — SQE/CQE patterns, provided buffers, multishot ops, error handling, send serialization, fd lifecycle, backpressure, memory domains, anti-patterns. MANDATORY for all src/io/ and src/network/ code.
---

# io_uring Development Patterns for ioguard

## Core Rule

io_uring is NOT a transport backend — it IS the core runtime. All I/O, timers, signals,
and process management go through the ring. No epoll fallback. Minimum kernel: 6.7+.

## Ring Setup

```c
// Ring-per-worker model: each worker process owns one ring
struct io_uring_params params = {
    .flags = IORING_SETUP_COOP_TASKRUN     // >= 5.19: reduce forced interrupts
           | IORING_SETUP_SINGLE_ISSUER    // >= 6.0: enforced single submitter
           | IORING_SETUP_DEFER_TASKRUN,   // >= 6.1: completions only on enter()
};
// SQPOLL: optional, NOT default (burns CPU core, mutually exclusive with DEFER_TASKRUN)
// SIGPIPE: MUST ignore — wolfSSL can trigger via internal writes
signal(SIGPIPE, SIG_IGN);
```

## Ring Hardening (IORING_REGISTER_RESTRICTIONS)

**WHY:** io_uring ops bypass seccomp BPF (shared memory ring, not syscalls).
Without restrictions, a compromised parser can issue arbitrary kernel operations.

```c
struct io_uring_restriction restrictions[] = {
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_RECV },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_SEND },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_ACCEPT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_READ },      // TUN device
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_WRITE },     // TUN device
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_TIMEOUT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_LINK_TIMEOUT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_CANCEL },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_CLOSE },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_MSG_RING },  // inter-ring IPC
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_NOP },
};
io_uring_register_restrictions(&ring, restrictions, ARRAY_SIZE(restrictions));
io_uring_enable_rings(&ring);
```

## SQE Patterns

### Multishot Accept
```c
io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
io_uring_sqe_set_data64(sqe, RW_ENCODE_UD(0, RW_OP_ACCEPT));
// MUST check IORING_CQE_F_MORE — if absent, re-arm immediately
```

### Provided Buffer Rings
```c
struct io_uring_buf_ring *br = io_uring_setup_buf_ring(ring, nentries, bgid, 0, &ret);
io_uring_buf_ring_add(br, buf, buf_size, bid, mask, idx);
io_uring_buf_ring_advance(br, count);

// Recv with provided buffer:
io_uring_prep_recv(sqe, fd, nullptr, 0, 0);
sqe->flags |= IOSQE_BUFFER_SELECT;
sqe->buf_group = bgid;
// CQE: buffer id = cqe->flags >> IORING_CQE_BUFFER_SHIFT
// -ENOBUFS: pool exhausted — apply backpressure, do NOT drop connection
```

### Linked Timeouts
```c
// SQE 1: the operation
io_uring_prep_recv(sqe, fd, buf, len, 0);
sqe->flags |= IOSQE_IO_LINK;
// SQE 2: auto-cancel if expired
io_uring_prep_link_timeout(tsqe, &ts, 0);
```

### Zero-Copy Send
```c
io_uring_prep_send_zc(sqe, fd, buf, len, 0, 0);
// Generates 2 CQEs: completion + IORING_CQE_F_NOTIF (buffer release)
// NEVER free/reuse buffer until NOTIF CQE received
```

## CQE Dispatch

```c
// user_data encoding: conn_id (56 bits) | op_type (8 bits)
#define RW_ENCODE_UD(conn, op)  (((uint64_t)(conn) << 8) | (uint8_t)(op))
#define RW_DECODE_OP(ud)        ((uint8_t)((ud) & 0xFF))
#define RW_DECODE_CONN(ud)      ((ud) >> 8)

// Batch processing loop — NEVER process CQE one-by-one
unsigned head;
struct io_uring_cqe *cqe;
unsigned count = 0;
io_uring_for_each_cqe(ring, head, cqe) {
    uint8_t op = RW_DECODE_OP(cqe->user_data);
    // dispatch...
    count++;
}
io_uring_cq_advance(ring, count);
```

## CRITICAL: Error Handling

`cqe->res < 0` is `-errno`. io_uring does NOT use global `errno`.

| Error | Meaning | Action |
|-------|---------|--------|
| `-ECANCELED` | Operation cancelled (timeout or explicit) | Cleanup, don't retry |
| `-ETIME` | Linked timeout expired | Close idle connection |
| `-EPIPE` | Peer reset / write to closed socket | Close connection |
| `-ENOBUFS` | Provided buffer pool exhausted | Backpressure, retry later |
| `-EAGAIN` | Transient | Retry with POLL_FIRST |
| `res == 0` on recv | Peer closed (EOF) | Graceful close |
| `0 < res < requested` | Short read/write | Handle partial I/O |

**Every CQE must be handled.** Ignoring errors = silent data loss or leaks.

## CRITICAL: fd Close Ordering

```
1. Cancel all pending ops on fd  (IORING_OP_ASYNC_CANCEL)
2. Wait for ALL CQE (including -ECANCELED)
3. Close fd  (IORING_OP_CLOSE or close())
4. Free connection structures
```

**WRONG:** close fd while ops are in-flight = kernel use-after-free.
Track in-flight op count per fd. Only close when count reaches 0.

## CRITICAL: Send Serialization

**ONE active send per TCP connection.** Kernel may reorder concurrent sends.

```c
// Per-connection bounded send queue
typedef struct {
    rw_send_item_t queue[RW_MAX_SEND_DEPTH];
    uint32_t head, tail, count;
    bool send_active;  // true while send CQE pending
} rw_send_ctx_t;

// On send completion CQE:
conn->send_ctx.send_active = false;
if (conn->send_ctx.count > 0) {
    // Dequeue next, arm send
    conn->send_ctx.send_active = true;
}
```

For ordered multi-buffer sends: `IOSQE_IO_LINK` chains.

## Backpressure

- **Per-connection send queue**: bounded depth (e.g., 16). Reject/drop if full.
- **SQ ring sizing**: cover max in-flight ops (accept + recv*N + send*N + timeouts + cancels).
- **Multishot accept**: stop accepting when connection pool full. Re-arm when freed.
- **-ENOBUFS**: double-buffering — maintain two buffer groups, swap on exhaust.

## Memory Domains

| Domain | Allocator | Lifetime | Examples |
|--------|-----------|----------|----------|
| Control plane | mimalloc per-worker heap | Connection lifetime | FSMs, configs, session state |
| Data plane RX | Fixed-size buffer pool | CQE → parse → return | Provided buffer rings |
| Data plane TX | Fixed-size buffer pool | Enqueue → CQE (or NOTIF) → return | Send queue buffers |
| TLS cipher | Per-connection buffers | Connection lifetime | cipher_in/cipher_out |
| TLS plain | Stack or temp alloc | Single operation | wolfSSL_read output |

- **RLIMIT_MEMLOCK**: registered buffers count against memlock limit
- **send_zc**: buffer pinned until `IORING_CQE_F_NOTIF` — use refcount or delayed return
- **mimalloc in hot path**: OK for control plane. NEVER for data plane buffers (fragmentation)

## Performance

- **SQE batching**: submit 16-64 SQE per `io_uring_submit()`. Per-SQE submit = sync I/O perf.
- **CQE batching**: `io_uring_for_each_cqe` processes all available. Cache-friendly.
- **DEFER_TASKRUN**: completion work runs only on `io_uring_enter(GETEVENTS)`. Predictable.
- **Ring-per-worker + CPU pinning**: cache locality, no ring contention.
- **ATTACH_WQ**: share backend io-wq between rings. WARNING: blocking op in one ring delays all.
- **NUMA**: allocate ring memory on local node. `numactl --membind` or `mbind()`.

## Anti-patterns (NEVER DO)

| Anti-pattern | Why it breaks | Fix |
|--------------|---------------|-----|
| Blocking syscall in CQE handler | Head-of-line blocking, latency spikes | Offload to thread pool or io_uring op |
| Mixed sync/async on same fd | Corrupted state, data races | All ops through ring |
| Multiple outstanding sends on TCP | Kernel reordering, corrupt stream | Per-conn send queue |
| Unbounded queues | OOM, latency tails | Fixed-size with backpressure |
| Ignoring CQE_F_MORE | Silent multishot termination | Always check, re-arm |
| WANT_READ/WANT_WRITE as fatal | Dropped TLS connections | Normal — arm recv/send |
| Close fd before all CQE | Kernel use-after-free | Cancel → wait → close |
| Submit per-SQE | No batching benefit | Accumulate, batch submit |
| Single CQE wait in loop | Poor cache locality | Batch with for_each_cqe |

## TLS + io_uring Integration

See `wolfssl-api/SKILL.md` for full patterns. Key points:
- Buffer-based I/O: custom callbacks read/write from cipher buffers
- WANT_READ → arm io_uring recv, resume TLS later
- WANT_WRITE → arm io_uring send (flush cipher_out), resume later
- I/O serialization: one read + one write at a time per SSL object
- Separate cipher buffers (io_uring target) from plaintext (wolfSSL output)

## Library Integration

### c-ares (async DNS)
```c
ares_set_socket_functions(channel, &uring_socket_funcs, ring);
// Map ares sockets to io_uring POLL_ADD for readiness
// ares_timeout() → IORING_OP_TIMEOUT for DNS retry timers
// On timeout/ready CQE → ares_process_fd()
```

### protobuf-c (IPC)
Length-prefix framing over SOCK_SEQPACKET. Accumulate in ring buffer until
full message, then `protobuf_c_message_unpack()`. Proto3 bytes: check `len > 0`.

### stumpless (logging)
Buffer log entries in thread-local ring buffer. Periodic flush via `IORING_OP_WRITEV`.
NEVER call stumpless directly in CQE handler — it may block on disk/syslog I/O.

### libnftnl (firewall)
Netlink sockets via `IORING_OP_SENDMSG`/`IORING_OP_RECVMSG`. Batch rule changes
in single netlink transaction for atomicity.

## Testing Patterns

- **Mock CQE delivery**: inject CQE sequences to test state machines deterministically
- **Negative injection**: `-ECANCELED`, `-EPIPE`, `-ETIMEDOUT`, `-ENOBUFS`, short reads
- **In-flight tracking**: assert op count == 0 after cleanup (detect leaks)
- **tc netem**: `tc qdisc add dev lo root netem delay 50ms loss 1%` for integration tests
- **socketpair**: test data path without real network

## context7 Documentation

Fetch up-to-date liburing API docs: `/axboe/liburing`
