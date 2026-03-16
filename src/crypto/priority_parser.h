/*
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ioguard.
 *
 * ioguard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ioguard is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef IOGUARD_PRIORITY_PARSER_H
#define IOGUARD_PRIORITY_PARSER_H

/**
 * GnuTLS Priority String Parser for ioguard
 *
 * This module parses GnuTLS priority strings and translates them to wolfSSL
 * cipher configuration. This enables backward compatibility with existing
 * ioguard configurations while using the wolfSSL backend.
 *
 * Architecture:
 * 1. Tokenizer: Splits priority string into tokens
 * 2. Parser: Builds configuration structure from tokens
 * 3. Mapper: Translates configuration to wolfSSL cipher lists
 * 4. Applicator: Applies configuration to wolfSSL context
 *
 * Design Goals:
 * - Zero dynamic allocations (stack-only)
 * - O(n) complexity where n = string length
 * - Comprehensive error reporting
 * - Thread-safe (no global state)
 *
 * Reference:
 * - GnuTLS Priority Strings: https://gnutls.org/manual/html_node/Priority-Strings.html
 * - Architecture Document: docs/architecture/PRIORITY_STRING_PARSER.md
 */

#include <stddef.h>
#include <stdint.h>
#include "tls_abstract.h"

// C23 standard compliance
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

// Maximum limits (designed to avoid heap allocations)
constexpr size_t PRIORITY_MAX_TOKENS = 64;
constexpr size_t PRIORITY_MAX_TOKEN_LEN = 64;
constexpr size_t PRIORITY_MAX_CIPHERS = 128;
constexpr size_t PRIORITY_MAX_CIPHER_NAME = 64;
constexpr size_t PRIORITY_MAX_CIPHER_LIST = 1024;
constexpr size_t PRIORITY_MAX_ERROR_MSG = 256;

/* ============================================================================
 * Error Codes
 * ============================================================================ */

/**
 * Priority parser error codes
 *
 * These extend the TLS abstraction error codes (tls_error_t) with
 * priority-string-specific errors.
 */
typedef enum {
    PRIORITY_E_SUCCESS = 0,             // Success
    PRIORITY_E_SYNTAX_ERROR = -200,     // Invalid syntax
    PRIORITY_E_UNKNOWN_KEYWORD = -201,  // Unknown keyword
    PRIORITY_E_UNKNOWN_MODIFIER = -202, // Unknown modifier
    PRIORITY_E_CONFLICT = -203,         // Conflicting specifications
    PRIORITY_E_UNSUPPORTED = -204,      // Unsupported feature
    PRIORITY_E_TOO_COMPLEX = -205,      // Too many tokens
    PRIORITY_E_BUFFER_TOO_SMALL = -206, // Output buffer too small
    PRIORITY_E_NULL_POINTER = -207,     // nullptr parameter
    PRIORITY_E_INVALID_VERSION = -208,  // Invalid TLS version
    PRIORITY_E_INVALID_CIPHER = -209,   // Invalid cipher name
    PRIORITY_E_MAPPER_FAILED = -210,    // Mapping to wolfSSL failed
} priority_error_t;

/* ============================================================================
 * Token Types and Structures
 * ============================================================================ */

/**
 * Token types
 *
 * Classifies each token in the priority string based on its role in the
 * configuration.
 */
typedef enum {
    TOKEN_UNKNOWN = 0, // Unknown/unclassified token
    TOKEN_KEYWORD,     // Base keyword (NORMAL, PERFORMANCE, etc.)
    TOKEN_MODIFIER,    // Modifier keyword (%SERVER_PRECEDENCE, etc.)
    TOKEN_VERSION,     // TLS version (VERS-TLS1.3, etc.)
    TOKEN_CIPHER,      // Cipher algorithm (AES-128-GCM, etc.)
    TOKEN_KX,          // Key exchange (ECDHE-RSA, DHE-DSS, etc.)
    TOKEN_MAC,         // MAC algorithm (SHA256, SHA384, etc.)
    TOKEN_SIGN,        // Signature algorithm (SIGN-RSA-SHA256, etc.)
    TOKEN_GROUP,       // Elliptic curve group (GROUP-SECP256R1, etc.)
    TOKEN_OPERATOR,    // Operator (+, -, !, :)
} token_type_t;

/**
 * Token structure
 *
 * Represents a single token in the priority string. Uses pointers into
 * the original string to avoid allocations.
 */
typedef struct {
    token_type_t type; // Token type
    const char *start; // Pointer to token start in original string
    size_t length;     // Token length
    bool is_addition;  // true for + operator, false for -/! operators
    bool is_negation;  // true for - or ! operator
} token_t;

/**
 * Token list
 *
 * Fixed-size array of tokens to avoid dynamic allocation.
 */
typedef struct {
    token_t tokens[PRIORITY_MAX_TOKENS];
    size_t count;      // Number of tokens
    const char *input; // Original input string (for error reporting)
} token_list_t;

/* ============================================================================
 * Configuration Structures
 * ============================================================================ */

/**
 * Priority configuration
 *
 * Parsed representation of GnuTLS priority string. This is the intermediate
 * format before translation to wolfSSL configuration.
 */
typedef struct {
    // Base configuration
    const char *base_keyword; // "NORMAL", "PERFORMANCE", etc. (or nullptr)

    // TLS versions (C23 bool array - safe direct indexing by protocol value)
    bool enabled_versions[256];  // Direct indexing: enabled_versions[TLS_VERSION_TLS12]
    bool disabled_versions[256]; // Direct indexing: disabled_versions[TLS_VERSION_TLS12]
    tls_version_t min_version;   // Minimum enabled version (for efficient range checking)
    tls_version_t max_version;   // Maximum enabled version (for efficient range checking)

    // Ciphers
    char enabled_ciphers[PRIORITY_MAX_CIPHERS][PRIORITY_MAX_CIPHER_NAME];
    size_t enabled_cipher_count;
    char disabled_ciphers[PRIORITY_MAX_CIPHERS][PRIORITY_MAX_CIPHER_NAME];
    size_t disabled_cipher_count;

    // Key exchange
    char enabled_kx[32][PRIORITY_MAX_CIPHER_NAME];
    size_t enabled_kx_count;
    char disabled_kx[32][PRIORITY_MAX_CIPHER_NAME];
    size_t disabled_kx_count;

    // MAC algorithms
    char enabled_mac[16][PRIORITY_MAX_CIPHER_NAME];
    size_t enabled_mac_count;
    char disabled_mac[16][PRIORITY_MAX_CIPHER_NAME];
    size_t disabled_mac_count;

    // Modifiers (flags)
    bool server_precedence;  // %SERVER_PRECEDENCE
    bool compat_mode;        // %COMPAT
    bool no_extensions;      // %NO_EXTENSIONS
    bool force_session_hash; // %FORCE_SESSION_HASH
    bool dumb_fw_padding;    // %DUMBFW
    bool fallback_scsv;      // %FALLBACK_SCSV

    // Security requirements
    bool require_pfs;      // Perfect forward secrecy required
    int min_security_bits; // 128, 192, or 256 (0 = no minimum)

    // Parsing metadata
    bool has_base_keyword; // true if base keyword specified
    bool explicit_none;    // true if "NONE" keyword used
} priority_config_t;

// C23 compile-time assertions for TLS version value safety
_Static_assert(TLS_VERSION_SSL3 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_TLS10 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_TLS11 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_TLS12 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_TLS13 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_DTLS10 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_DTLS12 < 256,
               "TLS version values must fit in uint8_t range for array indexing");
_Static_assert(TLS_VERSION_DTLS13 < 256,
               "TLS version values must fit in uint8_t range for array indexing");

/**
 * Check if TLS version is enabled (inline helper)
 *
 * This function performs efficient O(1) lookup with range checking.
 *
 * @param version TLS version to check
 * @param config Priority configuration
 * @return true if version is enabled, false otherwise
 *
 * Thread Safety: Thread-safe (read-only operation)
 * Complexity: O(1)
 */
static inline bool is_version_enabled(const tls_version_t version, const priority_config_t *config)
{
    // Fast path: range check using min/max
    if (version < config->min_version || version > config->max_version) {
        return false;
    }
    // Direct array lookup (O(1))
    return config->enabled_versions[version];
}

/**
 * Check if TLS version is disabled (inline helper)
 *
 * @param version TLS version to check
 * @param config Priority configuration
 * @return true if version is disabled, false otherwise
 *
 * Thread Safety: Thread-safe (read-only operation)
 * Complexity: O(1)
 */
static inline bool is_version_disabled(const tls_version_t version, const priority_config_t *config)
{
    return config->disabled_versions[version];
}

/**
 * wolfSSL configuration
 *
 * Translated configuration ready to apply to wolfSSL context.
 */
typedef struct {
    // Cipher configuration
    char cipher_list[PRIORITY_MAX_CIPHER_LIST];  // TLS 1.2 cipher list
    char ciphersuites[PRIORITY_MAX_CIPHER_LIST]; // TLS 1.3 cipher suites

    // Version range
    int min_version; // Minimum TLS version (wolfSSL constant)
    int max_version; // Maximum TLS version (wolfSSL constant)

    // Options flags
    long options; // wolfSSL options (SSL_OP_* flags)

    // Metadata
    bool has_cipher_list;   // true if cipher_list is set
    bool has_ciphersuites;  // true if ciphersuites is set
    bool has_version_range; // true if version range is set
} wolfssl_config_t;

/**
 * Error information
 *
 * Detailed error reporting for debugging and user feedback.
 */
typedef struct {
    int error_code;                             // priority_error_t value
    size_t error_position;                      // Position in original string
    char error_token[PRIORITY_MAX_TOKEN_LEN];   // Token that caused error
    char error_message[PRIORITY_MAX_ERROR_MSG]; // Human-readable message
} priority_error_info_t;

/* ============================================================================
 * Public API
 * ============================================================================ */

/**
 * Parse GnuTLS priority string and configure wolfSSL context
 *
 * This is the main entry point for priority string processing. It performs
 * tokenization, parsing, mapping, and application in a single call.
 *
 * @param ctx TLS context (must be wolfSSL backend)
 * @param priority GnuTLS priority string
 * @return TLS_E_SUCCESS (0) on success, negative error code on failure
 *
 * Thread Safety: Not thread-safe (modifies context)
 * Performance: Typically <1ms for standard priority strings
 * Memory: Stack-only, no heap allocations
 *
 * Error Codes:
 * - PRIORITY_E_NULL_POINTER: nullptr parameter
 * - PRIORITY_E_SYNTAX_ERROR: Invalid syntax
 * - PRIORITY_E_UNKNOWN_KEYWORD: Unknown keyword
 * - PRIORITY_E_TOO_COMPLEX: Too many tokens
 * - PRIORITY_E_MAPPER_FAILED: wolfSSL configuration failed
 *
 * Example:
 *   tls_context_t *ctx = tls_context_new(true, false);
 *   int ret = tls_set_priority_string(ctx, "NORMAL:%SERVER_PRECEDENCE");
 *   if (ret != TLS_E_SUCCESS) {
 *       priority_error_info_t error_info;
 *       priority_get_last_error(&error_info);
 *       fprintf(stderr, "Priority parsing failed: %s\n", error_info.error_message);
 *   }
 */
[[nodiscard]] int tls_set_priority_string(tls_context_t *ctx, const char *priority);

/**
 * Validate GnuTLS priority string without applying it
 *
 * Useful for configuration validation before server start. Does not modify
 * any context or global state.
 *
 * @param priority GnuTLS priority string
 * @param error_msg Optional output buffer for error message (can be nullptr)
 * @param error_msg_len Buffer size
 * @return PRIORITY_E_SUCCESS (0) if valid, negative error code if invalid
 *
 * Thread Safety: Thread-safe (no state modification)
 * Performance: Typically <1ms
 * Memory: Stack-only
 *
 * Example:
 *   char errmsg[256];
 *   int ret = tls_validate_priority_string(priority_str, errmsg, sizeof(errmsg));
 *   if (ret != PRIORITY_E_SUCCESS) {
 *       fprintf(stderr, "Invalid priority string: %s\n", errmsg);
 *       return -1;
 *   }
 */
[[nodiscard]] int tls_validate_priority_string(const char *priority, char *error_msg,
                                               size_t error_msg_len);

/**
 * Get detailed error information for last priority parsing error
 *
 * @param error_info Output structure for error information
 * @return PRIORITY_E_SUCCESS if error info retrieved, negative error code otherwise
 *
 * Thread Safety: Thread-safe (uses thread-local storage)
 *
 * Note: Error information is stored in thread-local storage and is valid
 *       until the next priority parsing operation in the same thread.
 */
[[nodiscard]] int priority_get_last_error(priority_error_info_t *error_info);

/* ============================================================================
 * Internal API (for testing and advanced use)
 * ============================================================================ */

/**
 * Tokenize priority string
 *
 * Splits priority string into tokens for parsing. This is the first phase
 * of priority string processing.
 *
 * @param priority Priority string (must not be nullptr)
 * @param tokens Output token list (must not be nullptr)
 * @return PRIORITY_E_SUCCESS on success, negative error code on failure
 *
 * Thread Safety: Thread-safe (no shared state)
 * Complexity: O(n) where n = string length
 * Memory: Stack-only
 *
 * Example:
 *   token_list_t tokens;
 *   int ret = priority_tokenize("NORMAL:%SERVER_PRECEDENCE", &tokens);
 *   if (ret == PRIORITY_E_SUCCESS) {
 *       printf("Token count: %zu\n", tokens.count);
 *   }
 */
[[nodiscard]] int priority_tokenize(const char *priority, token_list_t *tokens);

/**
 * Parse token list into configuration structure
 *
 * Builds priority_config_t from tokenized priority string. This is the
 * second phase of priority string processing.
 *
 * @param tokens Token list (must not be nullptr)
 * @param config Output configuration (must not be nullptr)
 * @return PRIORITY_E_SUCCESS on success, negative error code on failure
 *
 * Thread Safety: Thread-safe (no shared state)
 * Complexity: O(m) where m = token count
 * Memory: Stack-only
 *
 * Example:
 *   priority_config_t config;
 *   int ret = priority_parse(&tokens, &config);
 *   if (ret == PRIORITY_E_SUCCESS) {
 *       printf("Base keyword: %s\n", config.base_keyword);
 *       printf("Server precedence: %d\n", config.server_precedence);
 *   }
 */
[[nodiscard]] int priority_parse(const token_list_t *tokens, priority_config_t *config);

/**
 * Map priority configuration to wolfSSL configuration
 *
 * Translates priority_config_t to wolfssl_config_t. This is the third
 * phase of priority string processing.
 *
 * @param config Priority configuration (must not be nullptr)
 * @param wolfssl_cfg Output wolfSSL configuration (must not be nullptr)
 * @return PRIORITY_E_SUCCESS on success, negative error code on failure
 *
 * Thread Safety: Thread-safe (no shared state)
 * Complexity: O(c) where c = cipher count
 * Memory: Stack-only
 *
 * Example:
 *   wolfssl_config_t wolfssl_cfg;
 *   int ret = priority_map_to_wolfssl(&config, &wolfssl_cfg);
 *   if (ret == PRIORITY_E_SUCCESS) {
 *       printf("TLS 1.3 ciphersuites: %s\n", wolfssl_cfg.ciphersuites);
 *       printf("TLS 1.2 cipher list: %s\n", wolfssl_cfg.cipher_list);
 *   }
 */
[[nodiscard]] int priority_map_to_wolfssl(const priority_config_t *config,
                                          wolfssl_config_t *wolfssl_cfg);

/**
 * Apply wolfSSL configuration to context
 *
 * Applies wolfssl_config_t to wolfSSL WOLFSSL_CTX. This is the final
 * phase of priority string processing.
 *
 * @param wolf_ctx wolfSSL context (must not be nullptr)
 * @param wolfssl_cfg wolfSSL configuration (must not be nullptr)
 * @return PRIORITY_E_SUCCESS on success, negative error code on failure
 *
 * Thread Safety: Not thread-safe (modifies context)
 *
 * Example:
 *   WOLFSSL_CTX *wolf_ctx = ctx->wolf_ctx;
 *   int ret = priority_apply_wolfssl_config(wolf_ctx, &wolfssl_cfg);
 *   if (ret != PRIORITY_E_SUCCESS) {
 *       fprintf(stderr, "Failed to apply wolfSSL configuration\n");
 *   }
 */
[[nodiscard]] int priority_apply_wolfssl_config(void *wolf_ctx,
                                                const wolfssl_config_t *wolfssl_cfg);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error string for priority error code
 *
 * @param error_code priority_error_t value
 * @return Error string (static buffer, do not free)
 *
 * Thread Safety: Thread-safe (returns static string)
 */
[[nodiscard]] const char *priority_strerror(int error_code);

/**
 * Get token type name
 *
 * @param type token_type_t value
 * @return Type name string (static buffer, do not free)
 *
 * Thread Safety: Thread-safe (returns static string)
 */
[[nodiscard]] const char *priority_token_type_name(token_type_t type);

/**
 * Initialize priority_config_t to defaults
 *
 * Sets all fields to safe default values. Should be called before parsing.
 *
 * @param config Configuration structure to initialize
 *
 * Thread Safety: Thread-safe (no shared state)
 */
void priority_config_init(priority_config_t *config);

/**
 * Initialize wolfssl_config_t to defaults
 *
 * Sets all fields to safe default values. Should be called before mapping.
 *
 * @param wolfssl_cfg wolfSSL configuration structure to initialize
 *
 * Thread Safety: Thread-safe (no shared state)
 */
void wolfssl_config_init(wolfssl_config_t *wolfssl_cfg);

/**
 * Dump priority configuration to string (for debugging)
 *
 * @param config Priority configuration
 * @param buffer Output buffer
 * @param buffer_len Buffer size
 * @return Number of bytes written (excluding null terminator)
 *
 * Thread Safety: Thread-safe (no shared state)
 */
[[nodiscard]] size_t priority_config_dump(const priority_config_t *config, char *buffer,
                                          size_t buffer_len);

/**
 * Dump wolfSSL configuration to string (for debugging)
 *
 * @param wolfssl_cfg wolfSSL configuration
 * @param buffer Output buffer
 * @param buffer_len Buffer size
 * @return Number of bytes written (excluding null terminator)
 *
 * Thread Safety: Thread-safe (no shared state)
 */
[[nodiscard]] size_t wolfssl_config_dump(const wolfssl_config_t *wolfssl_cfg, char *buffer,
                                         size_t buffer_len);

#endif // IOGUARD_PRIORITY_PARSER_H
