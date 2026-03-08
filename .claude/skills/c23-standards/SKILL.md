---
name: c23-standards
description: Use when writing new C code or reviewing code for C23 compliance — proper usage of C23 features, cross-compiler compatibility (Clang 22 + GCC 15), ringwall coding conventions
---

# C23 Standards for ringwall

## Compiler Compatibility Matrix

| Feature | Clang 22+ | GCC 15+ | Use in ringwall |
|---------|-----------|---------|------------------|
| `[[nodiscard]]` | Yes | Yes | ALL error-returning functions |
| `nullptr` | Yes | Yes | Replace all NULL |
| `constexpr` | Yes | Yes | Constants and buffer sizes |
| `typeof` / `typeof_unqual` | Yes | Yes | Generic macros |
| `_BitInt(N)` | Yes | Yes | Crypto operations |
| `_Static_assert` | Yes | Yes | Structure validation |
| `_Atomic` | Yes | Yes | Lock-free counters |
| `auto` type inference | Yes | Yes | Local variables with obvious types |
| `bool/true/false` keywords | Yes | Yes | Replace stdbool.h macros |
| `#embed` | Partial | Yes | Embedded certs (GCC-only for now) |
| `<stdckdint.h>` | Yes | Yes | Checked integer arithmetic |
| `<stdbit.h>` | Yes | Yes | Bit manipulation |
| `enum : type` | Yes | Yes | Fixed-width enums |

## Mandatory Patterns

### Error Returns with [[nodiscard]]

```c
// EVERY function that can fail MUST use [[nodiscard]]
typedef enum [[nodiscard]] rw_result {
    RW_OK         =  0,
    RW_ERR_NOMEM  = -1,
    RW_ERR_IO     = -2,
    RW_ERR_TLS    = -3,
    RW_ERR_AUTH   = -4,
    RW_ERR_INVALID = -5,
} rw_result_t;

[[nodiscard]]
rw_result_t rw_session_create(rw_session_t **out);
```

### nullptr Instead of NULL

```c
// CORRECT
if (ptr == nullptr) { ... }
rw_session_t *sess = nullptr;

// WRONG — do not use NULL in new code
if (ptr == NULL) { ... }
```

### constexpr for Constants

```c
// CORRECT — compile-time constants
constexpr size_t RW_MAX_CLIENTS = 10000;
constexpr size_t RW_COOKIE_SIZE = 32;
constexpr size_t RW_MTU_DEFAULT = 1406;

// WRONG — runtime overhead
#define RW_MAX_CLIENTS 10000  // Use constexpr instead
```

### Checked Integer Arithmetic

```c
#include <stdckdint.h>

[[nodiscard]]
static rw_result_t rw_calc_buffer_size(size_t header, size_t payload, size_t *total) {
    if (ckd_add(total, header, payload)) {
        return RW_ERR_INVALID;  // Overflow
    }
    return RW_OK;
}
```

### Fixed-Width Enums

```c
// Network protocol values — exact width matters
typedef enum rw_packet_type : uint8_t {
    RW_PKT_DATA       = 0x00,
    RW_PKT_DPD_REQ    = 0x03,
    RW_PKT_DPD_RESP   = 0x04,
    RW_PKT_DISCONNECT = 0x05,
    RW_PKT_KEEPALIVE  = 0x07,
    RW_PKT_COMPRESSED = 0x08,
} rw_packet_type_t;
```

### typeof for Generic Macros

```c
// Type-safe min/max macros
#define rw_min(a, b) ({       \
    typeof(a) _a = (a);       \
    typeof(b) _b = (b);       \
    _a < _b ? _a : _b;        \
})
```

### Structure Validation with _Static_assert

```c
typedef struct rw_session_cookie {
    uint8_t  hmac[32];
    uint64_t timestamp;
    uint32_t client_id;
    uint8_t  nonce[16];
} rw_session_cookie_t;

_Static_assert(sizeof(rw_session_cookie_t) == 60,
               "Cookie structure size changed — breaks protocol");
```

### Atomic Operations (Lock-Free Counters)

```c
#include <stdatomic.h>

typedef struct rw_stats {
    _Atomic size_t active_connections;
    _Atomic size_t total_connections;
    _Atomic uint64_t bytes_sent;
    _Atomic uint64_t bytes_received;
} rw_stats_t;

static void rw_stats_connection_add(rw_stats_t *stats) {
    atomic_fetch_add(&stats->active_connections, 1);
    atomic_fetch_add(&stats->total_connections, 1);
}
```

## Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Public function | `rw_module_action` | `rw_session_create()` |
| Internal function | `module_action` | `session_validate()` |
| Type | `rw_name_t` | `rw_connection_t` |
| Enum value | `RW_PREFIX_NAME` | `RW_PKT_DATA` |
| Macro | `RW_UPPER_CASE` | `RW_MAX_CLIENTS` |
| constexpr | `RW_UPPER_CASE` | `RW_MTU_DEFAULT` |
| Local variable | `snake_case` | `client_addr` |
| Struct member | `snake_case` | `session_id` |

## Cross-Compiler Safety

Do NOT use features unavailable in Clang 22:
- `[[unsequenced]]` / `[[reproducible]]` (GCC 15 only)
- `#embed` in critical paths (use `#ifdef __has_embed` guard)

Use `#ifdef` for compiler-specific features:
```c
#if defined(__clang__)
    // Clang-specific
#elif defined(__GNUC__)
    // GCC-specific (e.g., -fanalyzer annotations)
#endif
```
