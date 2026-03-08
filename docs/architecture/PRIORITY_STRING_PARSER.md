# Priority String Parser Architecture

**Document Version**: 1.0
**Date**: 2025-10-29
**Status**: DESIGN
**User Story**: US-203 (Sprint 2, 8 SP)
**Author**: Claude Code

---

## Executive Summary

This document defines the architecture for parsing GnuTLS priority strings and translating them to wolfSSL cipher configuration. This is a critical compatibility component enabling ringwall to support legacy GnuTLS priority string configurations while using the wolfSSL backend.

**Core Objective**: Maintain 100% backward compatibility with existing ocserv configurations using GnuTLS priority strings.

---

## Table of Contents

1. [Requirements](#requirements)
2. [GnuTLS Priority String Specification](#gnutls-priority-string-specification)
3. [wolfSSL Cipher Configuration](#wolfssl-cipher-configuration)
4. [Architecture Design](#architecture-design)
5. [API Design](#api-design)
6. [Implementation Strategy](#implementation-strategy)
7. [Testing Strategy](#testing-strategy)
8. [Error Handling](#error-handling)

---

## Requirements

### Functional Requirements

1. **FR-1**: Parse GnuTLS priority strings accurately
2. **FR-2**: Translate to equivalent wolfSSL cipher lists
3. **FR-3**: Support all GnuTLS keywords (NORMAL, PERFORMANCE, SECURE128, etc.)
4. **FR-4**: Support all modifiers (%SERVER_PRECEDENCE, %COMPAT, etc.)
5. **FR-5**: Support TLS version specifications (VERS-TLS1.2, VERS-TLS1.3)
6. **FR-6**: Support inclusion (+) and exclusion (-) operators
7. **FR-7**: Handle cipher suite ordering correctly
8. **FR-8**: Validate priority string syntax

### Non-Functional Requirements

1. **NFR-1**: Performance: Parse and translate in <1ms
2. **NFR-2**: Memory: Use <4KB stack, no dynamic allocations if possible
3. **NFR-3**: Security: Constant-time operations where applicable
4. **NFR-4**: Maintainability: Clear separation of concerns
5. **NFR-5**: Testability: 100% code coverage via unit tests

### Compatibility Requirements

1. **CR-1**: Support ocserv priority strings (from /etc/ocserv/ocserv.conf)
2. **CR-2**: Support Cisco Secure Client 5.x+ compatibility requirements
3. **CR-3**: Graceful degradation for unsupported features

---

## GnuTLS Priority String Specification

### Syntax Overview

```
priority_string ::= [initial_keyword] [algorithm_spec]*
initial_keyword ::= "NORMAL" | "PERFORMANCE" | "SECURE128" | "SECURE192"
                  | "SECURE256" | "PFS" | "LEGACY" | "SUITEB128"
                  | "SUITEB192" | "NONE" | "@" system_config
algorithm_spec  ::= operator algorithm
operator        ::= "+" | "-" | "!" | ":"
algorithm       ::= cipher | kx | mac | version | signature | group | modifier
modifier        ::= "%" special_keyword
```

### Initial Keywords

| Keyword | Meaning | wolfSSL Equivalent |
|---------|---------|-------------------|
| `NORMAL` | Secure ciphersuites with 64-bit MAC | DEFAULT:!MD5:!LOW |
| `PERFORMANCE` | Fast 128-bit ciphers | AES128-GCM-SHA256:CHACHA20-POLY1305-SHA256 |
| `SECURE128` | Minimum 128-bit security | DEFAULT:!LOW:!EXPORT:!aNULL |
| `SECURE192` | Minimum 192-bit security | AES256-GCM-SHA384:!AES128 |
| `SECURE256` | Minimum 256-bit security | AES256-GCM-SHA384:CHACHA20-POLY1305-SHA256:!AES128 |
| `PFS` | Perfect forward secrecy only | ECDHE+AESGCM:DHE+AESGCM |
| `NONE` | Start from empty set | (empty string, requires explicit additions) |

### Modifiers (% Keywords)

| Modifier | Meaning | wolfSSL Equivalent |
|----------|---------|-------------------|
| `%SERVER_PRECEDENCE` | Server chooses cipher | `SSL_OP_CIPHER_SERVER_PREFERENCE` flag |
| `%COMPAT` | Tolerate protocol violations | Compatibility settings |
| `%NO_EXTENSIONS` | Disable TLS extensions | Max TLS 1.2, disable extensions |
| `%FORCE_SESSION_HASH` | Require extended master secret | `WOLFSSL_REQUIRE_EXTENDED_MASTER` |
| `%DUMBFW` | Add padding for firewalls | Padding configuration |
| `%FALLBACK_SCSV` | Downgrade protection | `TLS_FALLBACK_SCSV` |

### TLS Version Specifications

| GnuTLS | wolfSSL Method |
|--------|---------------|
| `+VERS-TLS1.3` | `TLSv1_3_server_method()` |
| `+VERS-TLS1.2` | `TLSv1_2_server_method()` |
| `-VERS-TLS1.0` | Exclude via `wolfSSL_CTX_set_options()` |
| `-VERS-SSL3.0` | Exclude SSL 3.0 |

### Cipher Specifications

**TLS 1.3 Ciphers** (GnuTLS → wolfSSL):

| GnuTLS | wolfSSL |
|--------|---------|
| `AES-256-GCM` | `TLS13-AES256-GCM-SHA384` |
| `AES-128-GCM` | `TLS13-AES128-GCM-SHA256` |
| `CHACHA20-POLY1305` | `TLS13-CHACHA20-POLY1305-SHA256` |
| `AES-128-CCM` | `TLS13-AES128-CCM-SHA256` |

**TLS 1.2 and Earlier**:

| GnuTLS | wolfSSL |
|--------|---------|
| `AES-128-CBC` | `AES128-SHA` |
| `AES-256-CBC` | `AES256-SHA256` |
| `AES-128-GCM` | `ECDHE-RSA-AES128-GCM-SHA256` |
| `AES-256-GCM` | `ECDHE-RSA-AES256-GCM-SHA384` |

### Common Priority String Examples

1. **Default ocserv**: `NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0`
2. **Secure TLS 1.3 only**: `SECURE256:+VERS-TLS1.3:-VERS-TLS1.2:-VERS-TLS1.1:-VERS-TLS1.0`
3. **Performance optimized**: `PERFORMANCE:+VERS-TLS1.3:+VERS-TLS1.2`
4. **PFS only**: `PFS:%SERVER_PRECEDENCE`

---

## wolfSSL Cipher Configuration

### wolfSSL Cipher List Format

wolfSSL uses OpenSSL-compatible cipher list syntax:

```
cipher_list ::= cipher_spec [":" cipher_spec]*
cipher_spec ::= [!|-|+][cipher_name]
```

**Operators**:
- `!` : Permanently exclude cipher
- `-` : Remove cipher from current list
- `+` : Add cipher to end of list

### wolfSSL Cipher Names

**TLS 1.3**:
- `TLS13-AES128-GCM-SHA256`
- `TLS13-AES256-GCM-SHA384`
- `TLS13-CHACHA20-POLY1305-SHA256`
- `TLS13-AES128-CCM-SHA256`

**TLS 1.2 ECDHE**:
- `ECDHE-RSA-AES128-GCM-SHA256`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-AES128-GCM-SHA256`
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-CHACHA20-POLY1305`

**TLS 1.2 DHE**:
- `DHE-RSA-AES128-GCM-SHA256`
- `DHE-RSA-AES256-GCM-SHA384`

### wolfSSL Configuration Functions

```c
// Set cipher list
int wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);

// Set TLS 1.3 cipher suites
int wolfSSL_CTX_set_ciphersuites(WOLFSSL_CTX* ctx, const char* list);

// Set minimum TLS version
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);

// Server cipher preference
long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long options);
// Use: SSL_OP_CIPHER_SERVER_PREFERENCE
```

---

## Architecture Design

### Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Public API Layer                     │
│  tls_context_set_priority(ctx, "NORMAL:...")           │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│                 Priority String Parser                  │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────┐ │
│  │  Tokenizer   │ → │    Parser    │ → │   Mapper   │ │
│  │              │   │              │   │            │ │
│  │ Splits into  │   │ Builds AST   │   │ Generates  │ │
│  │ tokens       │   │ of config    │   │ wolfSSL    │ │
│  │              │   │              │   │ cipher     │ │
│  └──────────────┘   └──────────────┘   └────────────┘ │
│                                                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│              wolfSSL Configuration Layer                │
│  wolfSSL_CTX_set_cipher_list()                         │
│  wolfSSL_CTX_set_ciphersuites()                        │
│  wolfSSL_CTX_SetMinVersion()                           │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
Input: "NORMAL:%SERVER_PRECEDENCE:-VERS-TLS1.0"
   │
   v
┌───────────────────────────────────────────────────┐
│ Step 1: Tokenization                             │
│ Tokens: [NORMAL] [%SERVER_PRECEDENCE]            │
│         [-VERS-TLS1.0]                            │
└───────────────┬───────────────────────────────────┘
                │
                v
┌───────────────────────────────────────────────────┐
│ Step 2: Parsing                                   │
│ AST:                                              │
│   base_keyword: NORMAL                            │
│   modifiers: [SERVER_PRECEDENCE]                  │
│   version_exclude: [TLS1.0]                       │
└───────────────┬───────────────────────────────────┘
                │
                v
┌───────────────────────────────────────────────────┐
│ Step 3: Mapping                                   │
│ wolfSSL config:                                   │
│   cipher_list: "DEFAULT:!MD5:!LOW"                │
│   min_version: TLS 1.1                            │
│   options: SSL_OP_CIPHER_SERVER_PREFERENCE        │
└───────────────┬───────────────────────────────────┘
                │
                v
Output: wolfSSL WOLFSSL_CTX configured
```

### Data Structures

```c
// Token types
typedef enum {
    TOKEN_KEYWORD,       // NORMAL, PERFORMANCE, etc.
    TOKEN_MODIFIER,      // %SERVER_PRECEDENCE, etc.
    TOKEN_VERSION,       // VERS-TLS1.3, etc.
    TOKEN_CIPHER,        // AES-128-GCM, etc.
    TOKEN_KX,            // ECDHE-RSA, etc.
    TOKEN_MAC,           // SHA256, etc.
    TOKEN_SIGN,          // SIGN-RSA-SHA256, etc.
    TOKEN_GROUP,         // GROUP-SECP256R1, etc.
    TOKEN_OPERATOR,      // +, -, !, :
    TOKEN_UNKNOWN,
} token_type_t;

// Token structure
typedef struct {
    token_type_t type;
    const char *start;     // Pointer into original string
    size_t length;
    bool is_addition;      // true for +, false for -/!
} token_t;

// Token list (fixed-size array to avoid allocations)
#define MAX_TOKENS 64
typedef struct {
    token_t tokens[MAX_TOKENS];
    size_t count;
} token_list_t;

// Parsed configuration
typedef struct {
    // Base configuration
    const char *base_keyword;  // "NORMAL", "PERFORMANCE", etc.

    // TLS versions
    uint32_t enabled_versions;   // Bitmask of tls_version_t
    uint32_t disabled_versions;

    // Ciphers
    char enabled_ciphers[256][32];  // List of enabled cipher names
    size_t enabled_cipher_count;
    char disabled_ciphers[64][32];  // List of disabled cipher names
    size_t disabled_cipher_count;

    // Modifiers
    bool server_precedence;
    bool compat_mode;
    bool no_extensions;
    bool force_session_hash;
    bool dumb_fw_padding;
    bool fallback_scsv;

    // Key exchange
    bool require_pfs;

    // Security level
    int min_security_bits;  // 128, 192, or 256
} priority_config_t;

// wolfSSL configuration output
typedef struct {
    char cipher_list[512];           // TLS 1.2 cipher list
    char ciphersuites[256];          // TLS 1.3 cipher suites
    int min_version;                 // Minimum TLS version
    int max_version;                 // Maximum TLS version
    long options;                    // wolfSSL options flags
} wolfssl_config_t;
```

---

## API Design

### Public API

```c
/**
 * Parse GnuTLS priority string and configure wolfSSL context
 *
 * This is the main entry point for priority string parsing. It performs
 * complete parsing, translation, and wolfSSL configuration in a single call.
 *
 * @param ctx TLS context (must be wolfSSL backend)
 * @param priority GnuTLS priority string
 * @return TLS_E_SUCCESS on success, negative error code on failure
 *
 * Thread Safety: Not thread-safe (context modification)
 * Performance: Typically <1ms for standard priority strings
 *
 * Example:
 *   tls_context_t *ctx = tls_context_new(true, false);
 *   int ret = tls_set_priority_string(ctx, "NORMAL:%SERVER_PRECEDENCE");
 *   if (ret != TLS_E_SUCCESS) {
 *       fprintf(stderr, "Priority parsing failed: %s\n", tls_strerror(ret));
 *   }
 */
[[nodiscard]] int tls_set_priority_string(tls_context_t *ctx,
                                           const char *priority);

/**
 * Validate GnuTLS priority string without applying it
 *
 * Useful for configuration validation before server start.
 *
 * @param priority GnuTLS priority string
 * @param error_msg Optional output buffer for error message (can be nullptr)
 * @param error_msg_len Buffer size
 * @return TLS_E_SUCCESS if valid, negative error code if invalid
 *
 * Thread Safety: Thread-safe (no state modification)
 *
 * Example:
 *   char errmsg[256];
 *   if (tls_validate_priority_string(priority_str, errmsg, sizeof(errmsg)) != TLS_E_SUCCESS) {
 *       fprintf(stderr, "Invalid priority string: %s\n", errmsg);
 *   }
 */
[[nodiscard]] int tls_validate_priority_string(const char *priority,
                                                char *error_msg,
                                                size_t error_msg_len);
```

### Internal API (src/crypto/priority_parser.h)

```c
/**
 * Tokenize priority string
 *
 * @param priority Priority string
 * @param tokens Output token list
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int priority_tokenize(const char *priority,
                                     token_list_t *tokens);

/**
 * Parse token list into configuration structure
 *
 * @param tokens Token list
 * @param config Output configuration
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int priority_parse(const token_list_t *tokens,
                                  priority_config_t *config);

/**
 * Map priority configuration to wolfSSL configuration
 *
 * @param config Priority configuration
 * @param wolfssl_cfg Output wolfSSL configuration
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int priority_map_to_wolfssl(const priority_config_t *config,
                                           wolfssl_config_t *wolfssl_cfg);

/**
 * Apply wolfSSL configuration to context
 *
 * @param ctx wolfSSL context
 * @param wolfssl_cfg wolfSSL configuration
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int priority_apply_wolfssl_config(WOLFSSL_CTX *ctx,
                                                 const wolfssl_config_t *wolfssl_cfg);
```

---

## Implementation Strategy

### Phase 1: Tokenizer (File: priority_tokenizer.c)

**Responsibility**: Split priority string into tokens

**Algorithm**:
```
1. Initialize token list
2. Current position = start of string
3. While not end of string:
   a. Skip whitespace
   b. Check for operator (+, -, !, :)
   c. If operator found, record it
   d. Read token until next operator or end
   e. Classify token type (keyword, modifier, version, etc.)
   f. Add token to list
4. Return token list
```

**Complexity**: O(n) where n = string length
**Memory**: Stack-only (no allocations)

### Phase 2: Parser (File: priority_parser.c)

**Responsibility**: Build configuration from tokens

**Algorithm**:
```
1. Initialize priority_config_t to defaults
2. Process base keyword (if present):
   - Set default cipher list based on keyword
   - Set default version range
   - Set default security level
3. Process each token:
   - If modifier: Set corresponding flag
   - If version: Update enabled/disabled version mask
   - If cipher: Add to enabled/disabled cipher list
   - If operator: Track addition vs removal
4. Validate configuration:
   - Check for conflicts (e.g., +VERS-TLS1.3 and -VERS-TLS1.3)
   - Check for unsupported combinations
5. Return parsed configuration
```

**Complexity**: O(m) where m = token count
**Memory**: Stack-only (fixed-size structures)

### Phase 3: Mapper (File: priority_mapper.c)

**Responsibility**: Convert priority config to wolfSSL config

**Algorithm**:
```
1. Initialize wolfssl_config_t
2. Build TLS 1.3 cipher suite string:
   - Start with base keyword defaults
   - Apply enabled/disabled cipher filters
   - Format as wolfSSL TLS 1.3 syntax
3. Build TLS 1.2 cipher list:
   - Start with base keyword defaults
   - Apply PFS requirement if set
   - Apply security level filter
   - Apply enabled/disabled cipher filters
   - Format as wolfSSL cipher list syntax
4. Set version range:
   - Convert enabled_versions mask to min/max version
5. Set options flags:
   - Map modifiers to wolfSSL options
   - SSL_OP_CIPHER_SERVER_PREFERENCE
   - SSL_OP_NO_TLSv1, etc.
6. Return wolfSSL configuration
```

**Complexity**: O(c) where c = cipher count
**Memory**: Stack-only (fixed-size structures)

### Phase 4: Integration (File: tls_abstract.c extension)

**Responsibility**: Public API implementation

**Integration with existing tls_context_set_priority()**:
```c
int tls_context_set_priority(tls_context_t *ctx, const char *priority)
{
    // Backend dispatch
    tls_backend_t backend = tls_get_backend();

    if (backend == TLS_BACKEND_GNUTLS) {
        // Pass through to GnuTLS
        return tls_gnutls_set_priority(ctx, priority);
    } else if (backend == TLS_BACKEND_WOLFSSL) {
        // Parse and translate
        return tls_set_priority_string(ctx, priority);
    }

    return TLS_E_BACKEND_ERROR;
}
```

---

## Testing Strategy

### Unit Tests (test_priority_parser.c)

**Test Categories**:

1. **Tokenizer Tests**:
   - Empty string
   - Single keyword
   - Keyword with modifiers
   - Complex strings with all operator types
   - Invalid syntax detection
   - Buffer overflow protection

2. **Parser Tests**:
   - Each base keyword (NORMAL, PERFORMANCE, etc.)
   - Each modifier (%SERVER_PRECEDENCE, etc.)
   - Version inclusions and exclusions
   - Cipher inclusions and exclusions
   - Conflict detection
   - Invalid combinations

3. **Mapper Tests**:
   - Correct TLS 1.3 cipher suite generation
   - Correct TLS 1.2 cipher list generation
   - Version range mapping
   - Options flag mapping
   - Security level enforcement

4. **Integration Tests**:
   - End-to-end parsing and configuration
   - Real-world priority strings from ocserv
   - Cisco Secure Client compatibility strings

**Test Data**:
```c
// Common ocserv priority strings
static const char *test_priority_strings[] = {
    "NORMAL",
    "NORMAL:%SERVER_PRECEDENCE",
    "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0",
    "SECURE256:+VERS-TLS1.3:-VERS-TLS1.2",
    "PERFORMANCE:+VERS-TLS1.3:+VERS-TLS1.2",
    "PFS:%SERVER_PRECEDENCE",
    "NONE:+VERS-TLS1.3:+AES-256-GCM:+AEAD:+SHA384",
    // Invalid strings for error testing
    "INVALID_KEYWORD",
    "+VERS-TLS1.3:-VERS-TLS1.3",  // Conflict
    "",  // Empty
    nullptr,  // nullptr
};
```

### Integration Tests with PoC

**Test Scenarios**:
1. Start PoC server with priority string
2. Connect with PoC client
3. Verify TLS version negotiation
4. Verify cipher suite negotiation
5. Verify handshake success
6. Measure performance

**Priority Strings to Test**:
- Default ocserv: `NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0`
- TLS 1.3 only: `SECURE256:+VERS-TLS1.3:-VERS-TLS1.2:-VERS-TLS1.1:-VERS-TLS1.0`
- Performance: `PERFORMANCE:+VERS-TLS1.3:+VERS-TLS1.2`

### Compatibility Tests

**Cisco Secure Client 5.x Priority Strings**:
- Test connection with various priority configurations
- Verify cipher suite compatibility
- Verify version negotiation
- Document any incompatibilities

---

## Error Handling

### Error Codes

```c
// Priority parser specific errors (extension of tls_error_t)
typedef enum {
    TLS_E_PRIORITY_SYNTAX_ERROR = -200,      // Invalid syntax
    TLS_E_PRIORITY_UNKNOWN_KEYWORD = -201,   // Unknown keyword
    TLS_E_PRIORITY_UNKNOWN_MODIFIER = -202,  // Unknown modifier
    TLS_E_PRIORITY_CONFLICT = -203,          // Conflicting specifications
    TLS_E_PRIORITY_UNSUPPORTED = -204,       // Unsupported feature
    TLS_E_PRIORITY_TOO_COMPLEX = -205,       // Too many tokens
} priority_error_t;
```

### Error Reporting

```c
// Error message structure
typedef struct {
    int error_code;
    size_t error_position;  // Position in original string
    char error_token[64];   // Token that caused error
    char error_message[256]; // Human-readable error
} priority_error_info_t;

// Get detailed error information
[[nodiscard]] int priority_get_error_info(priority_error_info_t *info);
```

### Error Messages

```c
static const char *priority_error_messages[] = {
    [TLS_E_PRIORITY_SYNTAX_ERROR] = "Invalid priority string syntax",
    [TLS_E_PRIORITY_UNKNOWN_KEYWORD] = "Unknown priority keyword",
    [TLS_E_PRIORITY_UNKNOWN_MODIFIER] = "Unknown priority modifier",
    [TLS_E_PRIORITY_CONFLICT] = "Conflicting priority specifications",
    [TLS_E_PRIORITY_UNSUPPORTED] = "Unsupported priority feature (wolfSSL limitation)",
    [TLS_E_PRIORITY_TOO_COMPLEX] = "Priority string too complex (too many tokens)",
};
```

### Unsupported Features

Some GnuTLS priority string features may not have direct wolfSSL equivalents:

| Feature | Status | Mitigation |
|---------|--------|------------|
| `%NO_EXTENSIONS` | Partial | Disable extensions where possible, log warning |
| `SUITEB128/192` | Unsupported | Map to closest equivalent, log warning |
| Some SIGN-* specifications | Partial | Map to supported signatures, log warning |
| Legacy ciphers (3DES, RC4) | Unsupported | Exclude, log warning |

**Strategy**: Log warning and use closest supported equivalent, never fail silently.

---

## Implementation Checklist

### Tokenizer
- [ ] Token type enum
- [ ] Token structure
- [ ] Token list structure
- [ ] Tokenization function
- [ ] Operator detection
- [ ] Keyword classification
- [ ] Unit tests

### Parser
- [ ] Priority config structure
- [ ] Base keyword mapping table
- [ ] Modifier parsing
- [ ] Version parsing
- [ ] Cipher parsing
- [ ] Conflict detection
- [ ] Unit tests

### Mapper
- [ ] wolfSSL config structure
- [ ] TLS 1.3 cipher suite builder
- [ ] TLS 1.2 cipher list builder
- [ ] Version range mapper
- [ ] Options flag mapper
- [ ] Unit tests

### Integration
- [ ] Public API implementation
- [ ] Backend dispatch in tls_context_set_priority()
- [ ] Validation function
- [ ] Error reporting
- [ ] Integration tests
- [ ] PoC tests

### Documentation
- [ ] API documentation
- [ ] Priority string migration guide
- [ ] Compatibility matrix
- [ ] Known limitations

---

## Implementation Notes

### TLS Version Tracking (C23 Best Practice)

**Original Design (Incorrect)**:
The initial implementation used `uint32_t` bitmask with TLS version enum values as shift indices:
```c
// INCORRECT - Causes undefined behavior!
uint32_t enabled_versions;
config->enabled_versions |= (1U << TLS_VERSION_TLS12);  // TLS_VERSION_TLS12 = 0x33 (51)
```

**Problem**:
- TLS version values are protocol-defined: `TLS_VERSION_TLS12 = 0x33 = 51 decimal`
- Shift operation `(1U << 51)` exceeds 32-bit integer size
- Results in undefined behavior per C standard
- Compiler warning: `shift-count-overflow`
- Not safe for values 0x30-0x34 (48-52)

**Current Design (C23 Best Practice)**:
Uses bool array with direct indexing by protocol value:
```c
// CORRECT - Safe, fast, and C23-idiomatic
bool enabled_versions[256];   // Direct indexing by protocol value
bool disabled_versions[256];  // Direct indexing by protocol value
tls_version_t min_version;    // For efficient range checking
tls_version_t max_version;    // For efficient range checking

// Usage:
config->enabled_versions[TLS_VERSION_TLS12] = true;

// Helper functions for safe manipulation:
static inline void enable_tls_version(priority_config_t *config,
                                       const tls_version_t version)
{
    config->enabled_versions[version] = true;
    config->disabled_versions[version] = false;
    if (version < config->min_version) config->min_version = version;
    if (version > config->max_version) config->max_version = version;
}

// Efficient O(1) lookup with range checking:
static inline bool is_version_enabled(const tls_version_t version,
                                       const priority_config_t *config)
{
    if (version < config->min_version || version > config->max_version) {
        return false;
    }
    return config->enabled_versions[version];
}
```

**Benefits**:
1. **Safety**: No undefined behavior, works for any protocol value 0x00-0xFF
2. **Performance**: O(1) lookup and update operations
3. **Readability**: Direct array indexing is more intuitive than bitmasking
4. **Maintainability**: Clear intent, easier to debug
5. **C23 Compliance**: Uses C23 `bool` type and compile-time assertions
6. **Compiler-Friendly**: No shift-count-overflow warnings
7. **Range Optimization**: min/max fields enable fast range checking before array access

**Compile-Time Safety**:
```c
// C23 _Static_assert ensures protocol values fit in array
_Static_assert(TLS_VERSION_TLS12 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
```

**Memory Impact**:
- Old design: 2 × 4 bytes = 8 bytes (uint32_t bitmasks)
- New design: 2 × 256 bytes + 2 × 4 bytes = 520 bytes (bool arrays + min/max)
- Trade-off: 512 additional bytes for safety, clarity, and correctness
- Total struct size: ~23KB (dominated by cipher name arrays, not version tracking)

**Related Commits**:
- `be5664f`: Header file refactoring with C23 bool arrays
- `c7399c2`: Implementation file bitmask replacement
- `27695ac`: Const correctness improvements

---

## References

1. **GnuTLS Priority Strings**: https://gnutls.org/manual/html_node/Priority-Strings.html
2. **wolfSSL Cipher Suite Documentation**: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter03.html
3. **RFC 8446**: TLS 1.3 Specification
4. **RFC 9147**: DTLS 1.3 Specification
5. **ocserv Configuration Reference**: /etc/ocserv/ocserv.conf

---

**Document Status**: APPROVED FOR IMPLEMENTATION
**Next Steps**: Create priority_parser.h header file
**Estimated Implementation**: 5-8 hours (aligns with 8 SP estimate)

---

Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
