---
name: c23-standards
description: Use when writing new C code or reviewing code for C23 compliance — proper usage of C23 features, cross-compiler compatibility (Clang 22 + GCC 15), ioguard coding conventions
---

# C23 Standards for ioguard

## Compiler Compatibility Matrix

| Feature | Clang 22+ | GCC 15+ | Use in ioguard |
|---------|-----------|---------|------------------|
| `[[nodiscard]]` | Yes | Yes | ALL error-returning functions |
| `nullptr` | Yes | Yes | Replace all NULL |
| `constexpr` | Yes | Yes | Constants and buffer sizes |
| `typeof` / `typeof_unqual` | Yes | Yes | Generic macros |
| `_BitInt(N)` | Yes | Yes | Avoid — non-portable, limited debugger support |
| `_Static_assert` | Yes | Yes | Structure validation |
| `_Atomic` | Yes | Yes | Lock-free counters |
| `auto` type inference | Yes | Yes | Avoid — obscures types in C, unlike C++ |
| `bool/true/false` keywords | Yes | Yes | Replace stdbool.h macros |
| `#embed` | Partial | Yes | Avoid — Clang partial support only |
| `<stdckdint.h>` | Yes | Yes | Checked integer arithmetic |
| `<stdbit.h>` | Yes | Yes | Bit manipulation |
| `enum : type` | Yes | Yes | Fixed-width enums |

## Mandatory Patterns

### Error Returns with [[nodiscard]]

```c
// EVERY function that can fail MUST use [[nodiscard]]
typedef enum [[nodiscard]] iog_result {
    IOG_OK         =  0,
    IOG_ERR_NOMEM  = -1,
    IOG_ERR_IO     = -2,
    IOG_ERR_TLS    = -3,
    IOG_ERR_AUTH   = -4,
    IOG_ERR_INVALID = -5,
} iog_result_t;

[[nodiscard]]
iog_result_t iog_session_create(iog_session_t **out);
```

### nullptr Instead of NULL

```c
// CORRECT
if (ptr == nullptr) { ... }
iog_session_t *sess = nullptr;

// WRONG — do not use NULL in new code
if (ptr == NULL) { ... }
```

### constexpr for Constants

```c
// CORRECT — compile-time constants
constexpr size_t IOG_MAX_CLIENTS = 10000;
constexpr size_t IOG_COOKIE_SIZE = 32;
constexpr size_t IOG_MTU_DEFAULT = 1406;

// WRONG — runtime overhead
#define IOG_MAX_CLIENTS 10000  // Use constexpr instead
```

### Checked Integer Arithmetic

```c
#include <stdckdint.h>

[[nodiscard]]
static iog_result_t iog_calc_buffer_size(size_t header, size_t payload, size_t *total) {
    if (ckd_add(total, header, payload)) {
        return IOG_ERR_INVALID;  // Overflow
    }
    return IOG_OK;
}
```

### Fixed-Width Enums

```c
// Network protocol values — exact width matters
typedef enum iog_packet_type : uint8_t {
    IOG_PKT_DATA       = 0x00,
    IOG_PKT_DPD_REQ    = 0x03,
    IOG_PKT_DPD_RESP   = 0x04,
    IOG_PKT_DISCONNECT = 0x05,
    IOG_PKT_KEEPALIVE  = 0x07,
    IOG_PKT_COMPRESSED = 0x08,
} iog_packet_type_t;
```

### typeof for Generic Macros

```c
// Type-safe min/max macros
// NOTE: ({...}) is a GNU extension (GCC + Clang), not standard C23
#define iog_min(a, b) ({       \
    typeof(a) _a = (a);       \
    typeof(b) _b = (b);       \
    _a < _b ? _a : _b;        \
})

// Standard C23 typeof usage — type-safe swap
void iog_swap(typeof(int) *a, typeof(int) *b) {
    typeof(*a) tmp = *a;
    *a = *b;
    *b = tmp;
}
```

### Structure Validation with _Static_assert

```c
typedef struct iog_session_cookie {
    uint8_t  hmac[32];
    uint64_t timestamp;
    uint32_t client_id;
    uint8_t  nonce[16];
} iog_session_cookie_t;

_Static_assert(sizeof(iog_session_cookie_t) == 60,
               "Cookie structure size changed — breaks protocol");
```

### Atomic Operations (Lock-Free Counters)

```c
#include <stdatomic.h>

typedef struct iog_stats {
    _Atomic size_t active_connections;
    _Atomic size_t total_connections;
    _Atomic uint64_t bytes_sent;
    _Atomic uint64_t bytes_received;
} iog_stats_t;

static void iog_stats_connection_add(iog_stats_t *stats) {
    atomic_fetch_add(&stats->active_connections, 1);
    atomic_fetch_add(&stats->total_connections, 1);
}
```

### [[fallthrough]] Attribute

Use for intentional switch case fall-through, especially in CQE processing:

```c
switch (op_type) {
    case IOG_OP_ACCEPT:
        iog_handle_accept(conn);
        [[fallthrough]];
    case IOG_OP_READ:
        iog_prep_read(conn);
        break;
}
```

### [[maybe_unused]] Attribute

Use for debug-only variables and callback parameters:

```c
static void iog_on_timeout([[maybe_unused]] void *ctx, int result) {
    // ctx used only in debug builds
}
```

### unreachable()

From `<stdnoreturn.h>`, for exhaustive switches:

```c
#include <stdnoreturn.h>
switch (state) {
    case IOG_STATE_NEW: ... break;
    case IOG_STATE_ACTIVE: ... break;
    case IOG_STATE_CLOSED: ... break;
}
unreachable();  // tells compiler all cases handled
```

### Digit Separators

For readability of large numeric constants:

```c
constexpr size_t IOG_MAX_BUFFER = 16'384;
constexpr uint64_t IOG_SESSION_TTL_NS = 3'600'000'000'000ULL;  // 1 hour
```

### Error Handling Pattern — goto cleanup with [[nodiscard]]

```c
[[nodiscard]]
int iog_session_init(iog_session_t **out) {
    iog_session_t *s = mi_calloc(1, sizeof(*s));
    if (s == nullptr) return -ENOMEM;

    int rc = iog_cookie_generate(&s->cookie);
    if (rc < 0) goto cleanup;

    rc = iog_dpd_init(&s->dpd);
    if (rc < 0) goto cleanup;

    *out = s;
    return 0;

cleanup:
    mi_free(s);
    return rc;
}
```

## Anti-Patterns

- NEVER use `auto` for return types or function parameters (C23 does not support this)
- NEVER use `_BitInt` in public API (debugger support poor, portability concerns)
- NEVER use `#embed` in critical paths (Clang support incomplete)
- NEVER omit `[[nodiscard]]` on functions returning error codes
- NEVER use `memcmp` for secret comparison — use `ConstantCompare` from wolfCrypt
- NEVER use `typeof` on expressions with side effects

## Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Public function | `iog_module_action` | `iog_session_create()` |
| Internal function | `module_action` | `session_validate()` |
| Type | `iog_name_t` | `iog_connection_t` |
| Enum value | `IOG_PREFIX_NAME` | `IOG_PKT_DATA` |
| Macro | `IOG_UPPER_CASE` | `IOG_MAX_CLIENTS` |
| constexpr | `IOG_UPPER_CASE` | `IOG_MTU_DEFAULT` |
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
