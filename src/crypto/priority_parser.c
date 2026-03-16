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

/**
 * GnuTLS Priority String Parser Implementation
 *
 * This file implements the four-phase priority string processing:
 * 1. Tokenization: Split string into tokens
 * 2. Parsing: Build configuration from tokens
 * 3. Mapping: Translate to wolfSSL configuration
 * 4. Application: Apply to wolfSSL context
 *
 * Design Principles:
 * - Zero heap allocations (stack-only)
 * - Thread-safe (no global state except thread-local error info)
 * - Comprehensive error reporting
 * - Efficient O(n) algorithms
 */

#include "priority_parser.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <ctype.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "tls_wolfssl.h"

// C23 standard compliance
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Thread-Local Error Storage
 * ============================================================================ */

// Thread-local storage for error information
static _Thread_local priority_error_info_t tls_last_error = {0};

/**
 * Set last error information (internal helper)
 */
static inline void set_last_error(int error_code, size_t error_position, const char *error_token,
                                  const char *error_message)
{
    tls_last_error.error_code = error_code;
    tls_last_error.error_position = error_position;

    if (error_token != nullptr) {
        snprintf(tls_last_error.error_token, sizeof(tls_last_error.error_token), "%s", error_token);
    } else {
        tls_last_error.error_token[0] = '\0';
    }

    if (error_message != nullptr) {
        snprintf(tls_last_error.error_message, sizeof(tls_last_error.error_message), "%s",
                 error_message);
    } else {
        tls_last_error.error_message[0] = '\0';
    }
}

int priority_get_last_error(priority_error_info_t *error_info)
{
    if (error_info == nullptr) {
        return PRIORITY_E_NULL_POINTER;
    }

    *error_info = tls_last_error;
    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Error Message Strings
 * ============================================================================ */

static const char *priority_error_strings[] = {
    [0] = "Success",
    [-PRIORITY_E_SYNTAX_ERROR] = "Invalid priority string syntax",
    [-PRIORITY_E_UNKNOWN_KEYWORD] = "Unknown priority keyword",
    [-PRIORITY_E_UNKNOWN_MODIFIER] = "Unknown priority modifier",
    [-PRIORITY_E_CONFLICT] = "Conflicting priority specifications",
    [-PRIORITY_E_UNSUPPORTED] = "Unsupported priority feature",
    [-PRIORITY_E_TOO_COMPLEX] = "Priority string too complex (too many tokens)",
    [-PRIORITY_E_BUFFER_TOO_SMALL] = "Output buffer too small",
    [-PRIORITY_E_NULL_POINTER] = "nullptr parameter",
    [-PRIORITY_E_INVALID_VERSION] = "Invalid TLS version specification",
    [-PRIORITY_E_INVALID_CIPHER] = "Invalid cipher name",
    [-PRIORITY_E_MAPPER_FAILED] = "Failed to map to wolfSSL configuration",
};

const char *priority_strerror(int error_code)
{
    if (error_code == PRIORITY_E_SUCCESS) {
        return priority_error_strings[0];
    }

    int index = -error_code;
    if (index < 0 || index >= (int)(sizeof(priority_error_strings) / sizeof(char *))) {
        return "Unknown error";
    }

    const char *msg = priority_error_strings[index];
    return (msg != nullptr) ? msg : "Unknown error";
}

/* ============================================================================
 * Token Type Classification
 * ============================================================================ */

static const char *token_type_names[] = {
    [TOKEN_UNKNOWN] = "UNKNOWN",   [TOKEN_KEYWORD] = "KEYWORD", [TOKEN_MODIFIER] = "MODIFIER",
    [TOKEN_VERSION] = "VERSION",   [TOKEN_CIPHER] = "CIPHER",   [TOKEN_KX] = "KEY_EXCHANGE",
    [TOKEN_MAC] = "MAC",           [TOKEN_SIGN] = "SIGNATURE",  [TOKEN_GROUP] = "GROUP",
    [TOKEN_OPERATOR] = "OPERATOR",
};

const char *priority_token_type_name(token_type_t type)
{
    if (type < 0 || type >= (int)(sizeof(token_type_names) / sizeof(char *))) {
        return "INVALID";
    }
    return token_type_names[type];
}

/**
 * Known base keywords
 */
static const char *base_keywords[] = {
    "NORMAL", "PERFORMANCE", "SECURE128", "SECURE192", "SECURE256", "PFS",
    "LEGACY", "SUITEB128",   "SUITEB192", "NONE",      "SYSTEM",
    nullptr // Sentinel
};

/**
 * Known modifiers (% prefix)
 */
static const char *known_modifiers[] = {
    "%SERVER_PRECEDENCE",
    "%COMPAT",
    "%NO_EXTENSIONS",
    "%FORCE_SESSION_HASH",
    "%DUMBFW",
    "%FALLBACK_SCSV",
    "%NO_TICKETS",
    "%DISABLE_SAFE_RENEGOTIATION",
    "%UNSAFE_RENEGOTIATION",
    "%PARTIAL_RENEGOTIATION",
    "%PROFILE_LOW",
    "%PROFILE_MEDIUM",
    "%PROFILE_HIGH",
    "%PROFILE_ULTRA",
    "%PROFILE_FUTURE",
    "%PROFILE_SUITEB128",
    "%PROFILE_SUITEB192",
    nullptr // Sentinel
};

/**
 * Classify token based on content
 */
static token_type_t classify_token(const char *const start, const size_t length)
{
    // Create null-terminated string for comparison
    char token[PRIORITY_MAX_TOKEN_LEN];
    if (length >= sizeof(token)) {
        return TOKEN_UNKNOWN;
    }
    memcpy(token, start, length);
    token[length] = '\0';

    // Check if it's a modifier (starts with %)
    if (token[0] == '%') {
        for (const char **mod = known_modifiers; *mod != nullptr; mod++) {
            if (strcmp(token, *mod) == 0) {
                return TOKEN_MODIFIER;
            }
        }
        return TOKEN_UNKNOWN; // Unknown modifier
    }

    // Check if it's a base keyword
    for (const char **kw = base_keywords; *kw != nullptr; kw++) {
        if (strcmp(token, *kw) == 0) {
            return TOKEN_KEYWORD;
        }
    }

    // Check if it's a version specification (VERS-*)
    if (strncmp(token, "VERS-", 5) == 0) {
        return TOKEN_VERSION;
    }

    // Check if it's a signature specification (SIGN-*)
    if (strncmp(token, "SIGN-", 5) == 0) {
        return TOKEN_SIGN;
    }

    // Check if it's a group specification (GROUP-*)
    if (strncmp(token, "GROUP-", 6) == 0) {
        return TOKEN_GROUP;
    }

    // Check for cipher keywords
    if (strstr(token, "AES") != nullptr || strstr(token, "CHACHA20") != nullptr ||
        strstr(token, "CAMELLIA") != nullptr || strstr(token, "ARCFOUR") != nullptr ||
        strstr(token, "3DES") != nullptr || strstr(token, "NULL") != nullptr ||
        strstr(token, "CIPHER") != nullptr) {
        return TOKEN_CIPHER;
    }

    // Check for key exchange keywords
    if (strstr(token, "ECDHE") != nullptr || strstr(token, "DHE") != nullptr ||
        strstr(token, "RSA") != nullptr || strstr(token, "ECDSA") != nullptr ||
        strstr(token, "PSK") != nullptr || strcmp(token, "KX-ALL") == 0) {
        return TOKEN_KX;
    }

    // Check for MAC keywords
    if (strstr(token, "SHA") != nullptr || strstr(token, "MD5") != nullptr ||
        strcmp(token, "AEAD") == 0 || strcmp(token, "MAC-ALL") == 0) {
        return TOKEN_MAC;
    }

    return TOKEN_UNKNOWN;
}

/* ============================================================================
 * Phase 1: Tokenization
 * ============================================================================ */

int priority_tokenize(const char *priority, token_list_t *tokens)
{
    if (priority == nullptr || tokens == nullptr) {
        set_last_error(PRIORITY_E_NULL_POINTER, 0, nullptr,
                       "nullptr parameter to priority_tokenize");
        return PRIORITY_E_NULL_POINTER;
    }

    // Initialize token list
    memset(tokens, 0, sizeof(*tokens));
    tokens->input = priority;

    const char *p = priority;
    bool is_addition = true; // Default operator is implicit addition
    bool is_negation = false;

    while (*p != '\0') {
        // Skip whitespace
        while (isspace((unsigned char)*p)) {
            p++;
        }

        if (*p == '\0') {
            break;
        }

        // Check for operator
        if (*p == '+' || *p == '-' || *p == '!' || *p == ':') {
            // Record operator
            if (tokens->count >= PRIORITY_MAX_TOKENS) {
                set_last_error(PRIORITY_E_TOO_COMPLEX, p - priority, nullptr,
                               "Too many tokens in priority string");
                return PRIORITY_E_TOO_COMPLEX;
            }

            // Determine operator semantics
            if (*p == '+') {
                is_addition = true;
                is_negation = false;
            } else if (*p == '-' || *p == '!') {
                is_addition = false;
                is_negation = true;
            } else if (*p == ':') {
                // Colon is a separator, doesn't change addition/negation state
                // but resets to default (addition) for next token
                is_addition = true;
                is_negation = false;
            }

            p++; // Skip operator
            continue;
        }

        // Read token until next operator, colon, or end
        // Note: '-' is NOT a delimiter inside tokens (e.g., VERS-TLS1.3, AES-128-GCM)
        // The '-' operator is only recognized at operator position (after ':' or at start)
        const char *token_start = p;
        while (*p != '\0' && *p != '+' && *p != '!' && *p != ':' && !isspace((unsigned char)*p)) {
            p++;
        }

        size_t token_len = (size_t)(p - token_start);
        if (token_len == 0) {
            continue; // Empty token, skip
        }

        if (token_len >= PRIORITY_MAX_TOKEN_LEN) {
            char long_token[64];
            snprintf(long_token, sizeof(long_token), "%.*s...", (int)40, token_start);
            set_last_error(PRIORITY_E_SYNTAX_ERROR, token_start - priority, long_token,
                           "Token too long");
            return PRIORITY_E_SYNTAX_ERROR;
        }

        // Add token to list
        if (tokens->count >= PRIORITY_MAX_TOKENS) {
            set_last_error(PRIORITY_E_TOO_COMPLEX, token_start - priority, nullptr,
                           "Too many tokens in priority string");
            return PRIORITY_E_TOO_COMPLEX;
        }

        token_t *token = &tokens->tokens[tokens->count++];
        token->start = token_start;
        token->length = token_len;
        token->is_addition = is_addition;
        token->is_negation = is_negation;
        token->type = classify_token(token_start, token_len);

        // Reset operator state to default for next token (implicit addition)
        is_addition = true;
        is_negation = false;
    }

    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Phase 2: Parsing
 * ============================================================================ */

void priority_config_init(priority_config_t *config)
{
    if (config == nullptr) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->min_security_bits = 0; // No minimum by default

    // Initialize version range to invalid values (will be set when versions are enabled)
    config->min_version = 0xFF; // Max possible value (will be decreased)
    config->max_version = 0x00; // Min possible value (will be increased)
}

/**
 * Enable TLS version in configuration (internal helper)
 *
 * This function safely enables a TLS version and updates the min/max range.
 *
 * @param config Priority configuration
 * @param version TLS version to enable
 */
static inline void enable_tls_version(priority_config_t *config, const tls_version_t version)
{
    config->enabled_versions[version] = true;
    config->disabled_versions[version] = false;

    // Update version range for efficient range checking
    if (version < config->min_version) {
        config->min_version = version;
    }
    if (version > config->max_version) {
        config->max_version = version;
    }
}

/**
 * Disable TLS version in configuration (internal helper)
 *
 * @param config Priority configuration
 * @param version TLS version to disable
 */
static inline void disable_tls_version(priority_config_t *config, const tls_version_t version)
{
    config->enabled_versions[version] = false;
    config->disabled_versions[version] = true;
}

/**
 * Parse base keyword and set defaults
 */
static int parse_base_keyword(const char *const keyword, const size_t keyword_len,
                              priority_config_t *const config)
{
    char kw[PRIORITY_MAX_TOKEN_LEN];
    if (keyword_len >= sizeof(kw)) {
        return PRIORITY_E_SYNTAX_ERROR;
    }
    memcpy(kw, keyword, keyword_len);
    kw[keyword_len] = '\0';

    config->base_keyword = nullptr; // Will be set to static string

    if (strcmp(kw, "NORMAL") == 0) {
        config->base_keyword = "NORMAL";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 64;
    } else if (strcmp(kw, "PERFORMANCE") == 0) {
        config->base_keyword = "PERFORMANCE";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 128;
    } else if (strcmp(kw, "SECURE128") == 0) {
        config->base_keyword = "SECURE128";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 128;
    } else if (strcmp(kw, "SECURE192") == 0) {
        config->base_keyword = "SECURE192";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 192;
    } else if (strcmp(kw, "SECURE256") == 0) {
        config->base_keyword = "SECURE256";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 256;
    } else if (strcmp(kw, "PFS") == 0) {
        config->base_keyword = "PFS";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->require_pfs = true;
        config->min_security_bits = 128;
    } else if (strcmp(kw, "NONE") == 0) {
        config->base_keyword = "NONE";
        config->has_base_keyword = true;
        config->explicit_none = true;
        // Nothing enabled by default - arrays already zeroed by memset
    } else if (strcmp(kw, "LEGACY") == 0) {
        config->base_keyword = "LEGACY";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS10);
        enable_tls_version(config, TLS_VERSION_TLS11);
        enable_tls_version(config, TLS_VERSION_TLS12);
        config->min_security_bits = 0;
    } else if (strcmp(kw, "SYSTEM") == 0) {
        // SYSTEM is special - use system-wide policy
        // For now, treat as NORMAL
        config->base_keyword = "SYSTEM";
        config->has_base_keyword = true;
        enable_tls_version(config, TLS_VERSION_TLS12);
        enable_tls_version(config, TLS_VERSION_TLS13);
        config->min_security_bits = 64;
    } else {
        return PRIORITY_E_UNKNOWN_KEYWORD;
    }

    return PRIORITY_E_SUCCESS;
}

/**
 * Parse TLS version specification
 */
static int parse_version(const char *const version_str, const size_t version_len,
                         const bool is_addition, priority_config_t *const config)
{
    char ver[PRIORITY_MAX_TOKEN_LEN];
    if (version_len >= sizeof(ver)) {
        return PRIORITY_E_SYNTAX_ERROR;
    }
    memcpy(ver, version_str, version_len);
    ver[version_len] = '\0';

    tls_version_t version = TLS_VERSION_UNKNOWN;

    if (strcmp(ver, "VERS-SSL3.0") == 0 || strcmp(ver, "VERS-SSL3") == 0) {
        version = TLS_VERSION_SSL3;
    } else if (strcmp(ver, "VERS-TLS1.0") == 0) {
        version = TLS_VERSION_TLS10;
    } else if (strcmp(ver, "VERS-TLS1.1") == 0) {
        version = TLS_VERSION_TLS11;
    } else if (strcmp(ver, "VERS-TLS1.2") == 0) {
        version = TLS_VERSION_TLS12;
    } else if (strcmp(ver, "VERS-TLS1.3") == 0) {
        version = TLS_VERSION_TLS13;
    } else if (strcmp(ver, "VERS-DTLS1.0") == 0) {
        version = TLS_VERSION_DTLS10;
    } else if (strcmp(ver, "VERS-DTLS1.2") == 0) {
        version = TLS_VERSION_DTLS12;
    } else if (strcmp(ver, "VERS-DTLS1.3") == 0) {
        version = TLS_VERSION_DTLS13;
    } else {
        return PRIORITY_E_INVALID_VERSION;
    }

    if (is_addition) {
        enable_tls_version(config, version);
    } else {
        disable_tls_version(config, version);
    }

    return PRIORITY_E_SUCCESS;
}

/**
 * Parse modifier (% keyword)
 */
static int parse_modifier(const char *const modifier_str, const size_t modifier_len,
                          priority_config_t *const config)
{
    char mod[PRIORITY_MAX_TOKEN_LEN];
    if (modifier_len >= sizeof(mod)) {
        return PRIORITY_E_SYNTAX_ERROR;
    }
    memcpy(mod, modifier_str, modifier_len);
    mod[modifier_len] = '\0';

    if (strcmp(mod, "%SERVER_PRECEDENCE") == 0) {
        config->server_precedence = true;
    } else if (strcmp(mod, "%COMPAT") == 0) {
        config->compat_mode = true;
    } else if (strcmp(mod, "%NO_EXTENSIONS") == 0) {
        config->no_extensions = true;
    } else if (strcmp(mod, "%FORCE_SESSION_HASH") == 0) {
        config->force_session_hash = true;
    } else if (strcmp(mod, "%DUMBFW") == 0) {
        config->dumb_fw_padding = true;
    } else if (strcmp(mod, "%FALLBACK_SCSV") == 0) {
        config->fallback_scsv = true;
    } else {
        // Unknown modifier - log warning but don't fail
        // Some modifiers may not have wolfSSL equivalents
        return PRIORITY_E_SUCCESS; // Tolerate unknown modifiers
    }

    return PRIORITY_E_SUCCESS;
}

/**
 * Parse cipher specification
 */
static int parse_cipher(const char *const cipher_str, const size_t cipher_len,
                        const bool is_addition, priority_config_t *const config)
{
    if (cipher_len >= PRIORITY_MAX_CIPHER_NAME) {
        return PRIORITY_E_INVALID_CIPHER;
    }

    if (is_addition) {
        if (config->enabled_cipher_count >= PRIORITY_MAX_CIPHERS) {
            return PRIORITY_E_TOO_COMPLEX;
        }
        memcpy(config->enabled_ciphers[config->enabled_cipher_count], cipher_str, cipher_len);
        config->enabled_ciphers[config->enabled_cipher_count][cipher_len] = '\0';
        config->enabled_cipher_count++;
    } else {
        if (config->disabled_cipher_count >= PRIORITY_MAX_CIPHERS) {
            return PRIORITY_E_TOO_COMPLEX;
        }
        memcpy(config->disabled_ciphers[config->disabled_cipher_count], cipher_str, cipher_len);
        config->disabled_ciphers[config->disabled_cipher_count][cipher_len] = '\0';
        config->disabled_cipher_count++;
    }

    return PRIORITY_E_SUCCESS;
}

int priority_parse(const token_list_t *tokens, priority_config_t *config)
{
    if (tokens == nullptr || config == nullptr) {
        set_last_error(PRIORITY_E_NULL_POINTER, 0, nullptr, "nullptr parameter to priority_parse");
        return PRIORITY_E_NULL_POINTER;
    }

    // Initialize configuration to defaults
    priority_config_init(config);

    // Process tokens
    for (size_t i = 0; i < tokens->count; i++) {
        const token_t *token = &tokens->tokens[i];

        switch (token->type) {
        case TOKEN_KEYWORD: {
            int ret = parse_base_keyword(token->start, token->length, config);
            if (ret != PRIORITY_E_SUCCESS) {
                char kw[PRIORITY_MAX_TOKEN_LEN];
                size_t copy_len = (token->length < sizeof(kw) - 1) ? token->length : sizeof(kw) - 1;
                memcpy(kw, token->start, copy_len);
                kw[copy_len] = '\0';
                set_last_error(ret, token->start - tokens->input, kw, "Unknown or invalid keyword");
                return ret;
            }
        } break;

        case TOKEN_MODIFIER: {
            int ret = parse_modifier(token->start, token->length, config);
            if (ret != PRIORITY_E_SUCCESS) {
                char mod[PRIORITY_MAX_TOKEN_LEN];
                size_t copy_len = (token->length < sizeof(mod) - 1) ? token->length
                                                                    : sizeof(mod) - 1;
                memcpy(mod, token->start, copy_len);
                mod[copy_len] = '\0';
                set_last_error(ret, token->start - tokens->input, mod,
                               "Unknown or invalid modifier");
                return ret;
            }
        } break;

        case TOKEN_VERSION: {
            int ret = parse_version(token->start, token->length, token->is_addition, config);
            if (ret != PRIORITY_E_SUCCESS) {
                char ver[PRIORITY_MAX_TOKEN_LEN];
                size_t copy_len = (token->length < sizeof(ver) - 1) ? token->length
                                                                    : sizeof(ver) - 1;
                memcpy(ver, token->start, copy_len);
                ver[copy_len] = '\0';
                set_last_error(ret, token->start - tokens->input, ver,
                               "Invalid TLS version specification");
                return ret;
            }
        } break;

        case TOKEN_CIPHER:
        case TOKEN_KX:
        case TOKEN_MAC: {
            int ret = parse_cipher(token->start, token->length, token->is_addition, config);
            if (ret != PRIORITY_E_SUCCESS) {
                char cipher[PRIORITY_MAX_TOKEN_LEN];
                size_t copy_len = (token->length < sizeof(cipher) - 1) ? token->length
                                                                       : sizeof(cipher) - 1;
                memcpy(cipher, token->start, copy_len);
                cipher[copy_len] = '\0';
                set_last_error(ret, token->start - tokens->input, cipher,
                               "Invalid cipher specification");
                return ret;
            }
        } break;

        case TOKEN_SIGN:
        case TOKEN_GROUP:
            // For now, we don't process these - they're advanced features
            // that may not have direct wolfSSL equivalents
            break;

        case TOKEN_UNKNOWN:
        case TOKEN_OPERATOR:
            // Operators are already processed during tokenization
            break;

        default:
            break;
        }
    }

    // Validate configuration for conflicts
    // Check if any version is both enabled and disabled
    bool has_conflict = false;
    for (size_t i = 0; i < 256; i++) {
        if (config->enabled_versions[i] && config->disabled_versions[i]) {
            has_conflict = true;
            break;
        }
    }
    if (has_conflict) {
        set_last_error(PRIORITY_E_CONFLICT, 0, nullptr, "TLS version both enabled and disabled");
        return PRIORITY_E_CONFLICT;
    }

    // If no base keyword and explicit NONE, ensure versions are explicitly set
    // Check if any version is enabled
    bool has_enabled_version = false;
    for (size_t i = 0; i < 256; i++) {
        if (config->enabled_versions[i]) {
            has_enabled_version = true;
            break;
        }
    }
    if (config->explicit_none && !has_enabled_version) {
        // This is valid - user must explicitly add versions
    }

    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Phase 3: Mapping
 * ============================================================================ */

void wolfssl_config_init(wolfssl_config_t *wolfssl_cfg)
{
    if (wolfssl_cfg == nullptr) {
        return;
    }

    memset(wolfssl_cfg, 0, sizeof(*wolfssl_cfg));
    wolfssl_cfg->min_version = 0; // Will be set based on config
    wolfssl_cfg->max_version = 0;
}

/**
 * Map base keyword to wolfSSL cipher list
 */
static const char *map_base_keyword_to_ciphers(const char *keyword)
{
    if (keyword == nullptr) {
        return "DEFAULT";
    }

    if (strcmp(keyword, "NORMAL") == 0) {
        // NORMAL: Modern secure ciphers
        return "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-CHACHA20-POLY1305:"
               "DHE-RSA-AES128-GCM-SHA256:"
               "DHE-RSA-AES256-GCM-SHA384";
    } else if (strcmp(keyword, "PERFORMANCE") == 0) {
        // PERFORMANCE: Fast ciphers first
        return "AES128-GCM-SHA256:"
               "CHACHA20-POLY1305-SHA256:"
               "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-CHACHA20-POLY1305";
    } else if (strcmp(keyword, "SECURE128") == 0) {
        // SECURE128: Minimum 128-bit security
        return "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-AES256-GCM-SHA384";
    } else if (strcmp(keyword, "SECURE192") == 0 || strcmp(keyword, "SECURE256") == 0) {
        // SECURE192/256: 192/256-bit security (AES-256 only)
        return "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-CHACHA20-POLY1305:"
               "DHE-RSA-AES256-GCM-SHA384";
    } else if (strcmp(keyword, "PFS") == 0) {
        // PFS: Perfect forward secrecy (ECDHE/DHE only)
        return "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-CHACHA20-POLY1305:"
               "DHE-RSA-AES128-GCM-SHA256:"
               "DHE-RSA-AES256-GCM-SHA384";
    } else if (strcmp(keyword, "NONE") == 0) {
        // NONE: Empty cipher list
        return "";
    } else if (strcmp(keyword, "LEGACY") == 0) {
        // LEGACY: Include older ciphers
        return "AES128-SHA:"
               "AES256-SHA:"
               "ECDHE-RSA-AES128-SHA:"
               "ECDHE-RSA-AES256-SHA:"
               "DHE-RSA-AES128-SHA:"
               "DHE-RSA-AES256-SHA";
    } else {
        // Default (including SYSTEM)
        return "DEFAULT";
    }
}

/**
 * Map base keyword to TLS 1.3 cipher suites
 */
static const char *map_base_keyword_to_tls13_ciphers(const char *keyword)
{
    if (keyword == nullptr) {
        return "TLS13-AES128-GCM-SHA256:"
               "TLS13-AES256-GCM-SHA384:"
               "TLS13-CHACHA20-POLY1305-SHA256";
    }

    if (strcmp(keyword, "PERFORMANCE") == 0) {
        return "TLS13-AES128-GCM-SHA256:"
               "TLS13-CHACHA20-POLY1305-SHA256";
    } else if (strcmp(keyword, "SECURE192") == 0 || strcmp(keyword, "SECURE256") == 0) {
        return "TLS13-AES256-GCM-SHA384:"
               "TLS13-CHACHA20-POLY1305-SHA256";
    } else if (strcmp(keyword, "NONE") == 0) {
        return "";
    } else {
        // Default for NORMAL, SECURE128, PFS, etc.
        return "TLS13-AES128-GCM-SHA256:"
               "TLS13-AES256-GCM-SHA384:"
               "TLS13-CHACHA20-POLY1305-SHA256";
    }
}

/**
 * Determine version range from configuration
 */
static void map_version_range(const priority_config_t *config, int *min_version, int *max_version)
{
    *min_version = 0;
    *max_version = 0;

    // Determine minimum version (lowest enabled)
    if (config->enabled_versions[TLS_VERSION_SSL3]) {
        *min_version = 0x0300; // SSL 3.0 (not recommended!)
    } else if (config->enabled_versions[TLS_VERSION_TLS10]) {
        *min_version = 0x0301; // TLS 1.0
    } else if (config->enabled_versions[TLS_VERSION_TLS11]) {
        *min_version = 0x0302; // TLS 1.1
    } else if (config->enabled_versions[TLS_VERSION_TLS12]) {
        *min_version = 0x0303; // TLS 1.2
    } else if (config->enabled_versions[TLS_VERSION_TLS13]) {
        *min_version = 0x0304; // TLS 1.3
    }

    // Determine maximum version (highest enabled)
    if (config->enabled_versions[TLS_VERSION_TLS13]) {
        *max_version = 0x0304; // TLS 1.3
    } else if (config->enabled_versions[TLS_VERSION_TLS12]) {
        *max_version = 0x0303; // TLS 1.2
    } else if (config->enabled_versions[TLS_VERSION_TLS11]) {
        *max_version = 0x0302; // TLS 1.1
    } else if (config->enabled_versions[TLS_VERSION_TLS10]) {
        *max_version = 0x0301; // TLS 1.0
    } else if (config->enabled_versions[TLS_VERSION_SSL3]) {
        *max_version = 0x0300; // SSL 3.0
    }
}

/**
 * Build options flags from modifiers
 */
static long map_options_flags(const priority_config_t *config)
{
    long options = 0;

    if (config->server_precedence) {
        options |= 0x00400000L; // SSL_OP_CIPHER_SERVER_PREFERENCE
    }

    // Disable specific versions if excluded
    if (config->disabled_versions[TLS_VERSION_SSL3]) {
        options |= 0x02000000L; // SSL_OP_NO_SSLv3
    }
    if (config->disabled_versions[TLS_VERSION_TLS10]) {
        options |= 0x04000000L; // SSL_OP_NO_TLSv1
    }
    if (config->disabled_versions[TLS_VERSION_TLS11]) {
        options |= 0x10000000L; // SSL_OP_NO_TLSv1_1
    }
    if (config->disabled_versions[TLS_VERSION_TLS12]) {
        options |= 0x08000000L; // SSL_OP_NO_TLSv1_2
    }

    // Other options
    if (config->compat_mode) {
        options |= 0x00000004L; // SSL_OP_ALL (compatibility mode)
    }

    return options;
}

int priority_map_to_wolfssl(const priority_config_t *config, wolfssl_config_t *wolfssl_cfg)
{
    if (config == nullptr || wolfssl_cfg == nullptr) {
        set_last_error(PRIORITY_E_NULL_POINTER, 0, nullptr,
                       "nullptr parameter to priority_map_to_wolfssl");
        return PRIORITY_E_NULL_POINTER;
    }

    // Initialize output
    wolfssl_config_init(wolfssl_cfg);

    // Build TLS 1.2 cipher list
    if (config->enabled_versions[TLS_VERSION_TLS10] ||
        config->enabled_versions[TLS_VERSION_TLS11] ||
        config->enabled_versions[TLS_VERSION_TLS12]) {
        const char *base_ciphers = map_base_keyword_to_ciphers(config->base_keyword);
        snprintf(wolfssl_cfg->cipher_list, sizeof(wolfssl_cfg->cipher_list), "%s", base_ciphers);
        wolfssl_cfg->has_cipher_list = true;
    }

    // Build TLS 1.3 cipher suites
    if (config->enabled_versions[TLS_VERSION_TLS13]) {
        const char *tls13_ciphers = map_base_keyword_to_tls13_ciphers(config->base_keyword);
        snprintf(wolfssl_cfg->ciphersuites, sizeof(wolfssl_cfg->ciphersuites), "%s", tls13_ciphers);
        wolfssl_cfg->has_ciphersuites = true;
    }

    // Set version range
    map_version_range(config, &wolfssl_cfg->min_version, &wolfssl_cfg->max_version);
    if (wolfssl_cfg->min_version != 0 || wolfssl_cfg->max_version != 0) {
        wolfssl_cfg->has_version_range = true;
    }

    // Build options flags
    wolfssl_cfg->options = map_options_flags(config);

    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Phase 4: Application
 * ============================================================================ */

int priority_apply_wolfssl_config(void *wolf_ctx, const wolfssl_config_t *wolfssl_cfg)
{
    if (wolf_ctx == nullptr || wolfssl_cfg == nullptr) {
        set_last_error(PRIORITY_E_NULL_POINTER, 0, nullptr,
                       "nullptr parameter to priority_apply_wolfssl_config");
        return PRIORITY_E_NULL_POINTER;
    }

    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)wolf_ctx;

    // Apply TLS 1.2 cipher list
    if (wolfssl_cfg->has_cipher_list && wolfssl_cfg->cipher_list[0] != '\0') {
        int ret = wolfSSL_CTX_set_cipher_list(ctx, wolfssl_cfg->cipher_list);
        if (ret != SSL_SUCCESS) {
            set_last_error(PRIORITY_E_MAPPER_FAILED, 0, nullptr,
                           "Failed to set wolfSSL cipher list");
            return PRIORITY_E_MAPPER_FAILED;
        }
    }

    // Apply TLS 1.3 cipher suites
    if (wolfssl_cfg->has_ciphersuites && wolfssl_cfg->ciphersuites[0] != '\0') {
#ifdef WOLFSSL_TLS13
        int ret = wolfSSL_CTX_set_cipher_list(ctx, wolfssl_cfg->ciphersuites);
        if (ret != SSL_SUCCESS) {
            set_last_error(PRIORITY_E_MAPPER_FAILED, 0, nullptr,
                           "Failed to set wolfSSL TLS 1.3 cipher suites");
            return PRIORITY_E_MAPPER_FAILED;
        }
#endif
    }

    // Apply version range
    if (wolfssl_cfg->has_version_range) {
        if (wolfssl_cfg->min_version != 0) {
            int ret = wolfSSL_CTX_SetMinVersion(ctx, wolfssl_cfg->min_version);
            if (ret != SSL_SUCCESS) {
                set_last_error(PRIORITY_E_MAPPER_FAILED, 0, nullptr,
                               "Failed to set minimum TLS version");
                return PRIORITY_E_MAPPER_FAILED;
            }
        }
        // Note: wolfSSL doesn't have SetMaxVersion, so we use options flags
        // to disable unwanted versions
    }

    // Apply options flags
    if (wolfssl_cfg->options != 0) {
        long result = wolfSSL_CTX_set_options(ctx, wolfssl_cfg->options);
        (void)result; // wolfSSL_CTX_set_options returns new options, not error code
    }

    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int tls_set_priority_string(tls_context_t *ctx, const char *priority)
{
    if (ctx == nullptr || priority == nullptr) {
        set_last_error(PRIORITY_E_NULL_POINTER, 0, nullptr,
                       "nullptr parameter to tls_set_priority_string");
        return PRIORITY_E_NULL_POINTER;
    }

    // Get wolfSSL context
    // Note: This requires access to tls_context internals
    // For now, we assume ctx->wolf_ctx is accessible
    // In production, this would use a proper accessor function
    struct tls_context *ctx_internal = (struct tls_context *)ctx;
    if (ctx_internal->wolf_ctx == nullptr) {
        set_last_error(PRIORITY_E_MAPPER_FAILED, 0, nullptr,
                       "Context does not have wolfSSL backend");
        return PRIORITY_E_MAPPER_FAILED;
    }

    // Phase 1: Tokenize
    token_list_t tokens;
    int ret = priority_tokenize(priority, &tokens);
    if (ret != PRIORITY_E_SUCCESS) {
        return ret;
    }

    // Phase 2: Parse
    priority_config_t config;
    ret = priority_parse(&tokens, &config);
    if (ret != PRIORITY_E_SUCCESS) {
        return ret;
    }

    // Phase 3: Map to wolfSSL
    wolfssl_config_t wolfssl_cfg;
    ret = priority_map_to_wolfssl(&config, &wolfssl_cfg);
    if (ret != PRIORITY_E_SUCCESS) {
        return ret;
    }

    // Phase 4: Apply to context
    ret = priority_apply_wolfssl_config(ctx_internal->wolf_ctx, &wolfssl_cfg);
    if (ret != PRIORITY_E_SUCCESS) {
        return ret;
    }

    // Store priority string in context for reference
    if (ctx_internal->priority_string != nullptr) {
        free(ctx_internal->priority_string);
    }
    ctx_internal->priority_string = strdup(priority);

    return PRIORITY_E_SUCCESS;
}

int tls_validate_priority_string(const char *priority, char *error_msg, size_t error_msg_len)
{
    if (priority == nullptr) {
        if (error_msg != nullptr && error_msg_len > 0) {
            snprintf(error_msg, error_msg_len, "nullptr priority string");
        }
        return PRIORITY_E_NULL_POINTER;
    }

    // Phase 1: Tokenize
    token_list_t tokens;
    int ret = priority_tokenize(priority, &tokens);
    if (ret != PRIORITY_E_SUCCESS) {
        if (error_msg != nullptr && error_msg_len > 0) {
            priority_error_info_t err_info;
            (void)priority_get_last_error(&err_info);
            snprintf(error_msg, error_msg_len, "%s", err_info.error_message);
        }
        return ret;
    }

    // Phase 2: Parse
    priority_config_t config;
    ret = priority_parse(&tokens, &config);
    if (ret != PRIORITY_E_SUCCESS) {
        if (error_msg != nullptr && error_msg_len > 0) {
            priority_error_info_t err_info;
            (void)priority_get_last_error(&err_info);
            snprintf(error_msg, error_msg_len, "%s", err_info.error_message);
        }
        return ret;
    }

    // Phase 3: Map to wolfSSL (validation only, don't apply)
    wolfssl_config_t wolfssl_cfg;
    ret = priority_map_to_wolfssl(&config, &wolfssl_cfg);
    if (ret != PRIORITY_E_SUCCESS) {
        if (error_msg != nullptr && error_msg_len > 0) {
            priority_error_info_t err_info;
            (void)priority_get_last_error(&err_info);
            snprintf(error_msg, error_msg_len, "%s", err_info.error_message);
        }
        return ret;
    }

    // Validation successful
    if (error_msg != nullptr && error_msg_len > 0) {
        snprintf(error_msg, error_msg_len, "Valid priority string");
    }

    return PRIORITY_E_SUCCESS;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

size_t priority_config_dump(const priority_config_t *config, char *buffer, size_t buffer_len)
{
    if (config == nullptr || buffer == nullptr || buffer_len == 0) {
        return 0;
    }

    size_t offset = 0;

    // Base keyword
    if (config->has_base_keyword && config->base_keyword != nullptr) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Base keyword: %s\n",
                           config->base_keyword);
    }

    // Enabled versions (print all enabled versions in hex format)
    bool has_enabled = false;
    for (size_t i = 0; i < 256; i++) {
        if (config->enabled_versions[i]) {
            has_enabled = true;
            break;
        }
    }
    if (has_enabled) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Enabled versions: ");
        if (config->enabled_versions[TLS_VERSION_SSL3]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "SSL3.0 ");
        }
        if (config->enabled_versions[TLS_VERSION_TLS10]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.0 ");
        }
        if (config->enabled_versions[TLS_VERSION_TLS11]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.1 ");
        }
        if (config->enabled_versions[TLS_VERSION_TLS12]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.2 ");
        }
        if (config->enabled_versions[TLS_VERSION_TLS13]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.3 ");
        }
        offset += snprintf(buffer + offset, buffer_len - offset, "\n");
        // Also print min/max range
        offset += snprintf(buffer + offset, buffer_len - offset,
                           "Version range: min=0x%02x max=0x%02x\n", config->min_version,
                           config->max_version);
    }

    // Disabled versions
    bool has_disabled = false;
    for (size_t i = 0; i < 256; i++) {
        if (config->disabled_versions[i]) {
            has_disabled = true;
            break;
        }
    }
    if (has_disabled) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Disabled versions: ");
        if (config->disabled_versions[TLS_VERSION_SSL3]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "SSL3.0 ");
        }
        if (config->disabled_versions[TLS_VERSION_TLS10]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.0 ");
        }
        if (config->disabled_versions[TLS_VERSION_TLS11]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.1 ");
        }
        if (config->disabled_versions[TLS_VERSION_TLS12]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.2 ");
        }
        if (config->disabled_versions[TLS_VERSION_TLS13]) {
            offset += snprintf(buffer + offset, buffer_len - offset, "TLS1.3 ");
        }
        offset += snprintf(buffer + offset, buffer_len - offset, "\n");
    }

    // Modifiers
    if (config->server_precedence) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Server precedence: YES\n");
    }
    if (config->compat_mode) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Compatibility mode: YES\n");
    }
    if (config->require_pfs) {
        offset +=
            snprintf(buffer + offset, buffer_len - offset, "Perfect forward secrecy: REQUIRED\n");
    }

    // Security level
    if (config->min_security_bits > 0) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Minimum security: %d bits\n",
                           config->min_security_bits);
    }

    return offset;
}

size_t wolfssl_config_dump(const wolfssl_config_t *wolfssl_cfg, char *buffer, size_t buffer_len)
{
    if (wolfssl_cfg == nullptr || buffer == nullptr || buffer_len == 0) {
        return 0;
    }

    size_t offset = 0;

    // TLS 1.2 cipher list
    if (wolfssl_cfg->has_cipher_list) {
        offset += snprintf(buffer + offset, buffer_len - offset, "TLS 1.2 cipher list: %s\n",
                           wolfssl_cfg->cipher_list);
    }

    // TLS 1.3 cipher suites
    if (wolfssl_cfg->has_ciphersuites) {
        offset += snprintf(buffer + offset, buffer_len - offset, "TLS 1.3 cipher suites: %s\n",
                           wolfssl_cfg->ciphersuites);
    }

    // Version range
    if (wolfssl_cfg->has_version_range) {
        offset += snprintf(buffer + offset, buffer_len - offset,
                           "Version range: min=0x%04x max=0x%04x\n", wolfssl_cfg->min_version,
                           wolfssl_cfg->max_version);
    }

    // Options
    if (wolfssl_cfg->options != 0) {
        offset += snprintf(buffer + offset, buffer_len - offset, "Options flags: 0x%08lx\n",
                           wolfssl_cfg->options);
    }

    return offset;
}
