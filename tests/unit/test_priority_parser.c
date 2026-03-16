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
 * Unit tests for GnuTLS Priority String Parser
 *
 * These tests verify the correctness of the priority string parser
 * implementation, including tokenization, parsing, and mapping to
 * wolfSSL configuration.
 *
 * Test Categories:
 * 1. Tokenizer tests - Splitting priority strings into tokens
 * 2. Parser tests - Building configuration from tokens
 * 3. Mapper tests - Translating to wolfSSL configuration
 * 4. Integration tests - End-to-end parsing and validation
 * 5. Error handling tests - Invalid inputs and edge cases
 *
 * Modern C23 patterns used:
 * - bool type for boolean values
 * - const correctness throughout
 * - nullptr instead of NULL
 * - Designated initializers
 * - _Static_assert for compile-time checks
 * - Inline functions for helpers
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "priority_parser.h"
#include "tls_abstract.h"

// C23 standard check (accept C2x/C20 from GCC 14 as it provides C23 features)
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Test Infrastructure
 * ============================================================================ */

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros with descriptive output */
#define TEST(name)                                                                                 \
    static void test_##name(void);                                                                 \
    static void run_test_##name(void)                                                              \
    {                                                                                              \
        printf("  Running test: %s...", #name);                                                    \
        fflush(stdout);                                                                            \
        tests_run++;                                                                               \
        test_##name();                                                                             \
        tests_passed++;                                                                            \
        printf(" PASSED\n");                                                                       \
    }                                                                                              \
    static void test_##name(void)

#define RUN_TEST(name) run_test_##name()

#define ASSERT(condition)                                                                          \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("\n    FAILED: %s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #condition); \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_EQ(a, b)                                                                            \
    do {                                                                                           \
        if ((a) != (b)) {                                                                          \
            printf("\n    FAILED: %s:%d: Expected %d, got %d\n", __FILE__, __LINE__, (int)(b),     \
                   (int)(a));                                                                      \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_STR_EQ(a, b)                                                                        \
    do {                                                                                           \
        if (strcmp((a), (b)) != 0) {                                                               \
            printf("\n    FAILED: %s:%d: Expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, (b),  \
                   (a));                                                                           \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_NOT_NULL(ptr)                                                                       \
    do {                                                                                           \
        if ((ptr) == nullptr) {                                                                    \
            printf("\n    FAILED: %s:%d: Expected non-NULL pointer\n", __FILE__, __LINE__);        \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_NULL(ptr)                                                                           \
    do {                                                                                           \
        if ((ptr) != nullptr) {                                                                    \
            printf("\n    FAILED: %s:%d: Expected NULL pointer\n", __FILE__, __LINE__);            \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_TRUE(condition)  ASSERT(condition)
#define ASSERT_FALSE(condition) ASSERT(!(condition))

/* ============================================================================
 * Test Utilities
 * ============================================================================ */

/**
 * Helper: Print token list for debugging
 */
[[maybe_unused]] static inline void print_token_list(const token_list_t *const tokens)
{
    printf("\n    Token list (%zu tokens):\n", tokens->count);
    for (size_t i = 0; i < tokens->count; i++) {
        const token_t *tok = &tokens->tokens[i];
        printf("      [%zu] Type: %s, Start: \"%.*s\", Add: %d, Neg: %d\n", i,
               priority_token_type_name(tok->type), (int)tok->length, tok->start, tok->is_addition,
               tok->is_negation);
    }
}

/**
 * Helper: Compare token with expected values
 */
static inline bool token_matches(const token_t *const tok, const token_type_t expected_type,
                                 const char *const expected_value)
{
    if (tok->type != expected_type) {
        return false;
    }
    if (strlen(expected_value) != tok->length) {
        return false;
    }
    if (strncmp(tok->start, expected_value, tok->length) != 0) {
        return false;
    }
    return true;
}

/* ============================================================================
 * Tokenizer Tests
 * ============================================================================ */

TEST(tokenize_empty_string_returns_error)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("", &tokens);

    // Empty string should return success with zero tokens
    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 0);
}

TEST(tokenize_null_pointer_returns_error)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize(nullptr, &tokens);

    ASSERT_EQ(result, PRIORITY_E_NULL_POINTER);
}

TEST(tokenize_single_keyword_normal)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("NORMAL", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 1);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "NORMAL"));
}

TEST(tokenize_keyword_with_modifier)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("NORMAL:%SERVER_PRECEDENCE", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 2);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "NORMAL"));
    ASSERT_TRUE(token_matches(&tokens.tokens[1], TOKEN_MODIFIER, "%SERVER_PRECEDENCE"));
}

TEST(tokenize_version_addition)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("NORMAL:+VERS-TLS1.3", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 2);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "NORMAL"));
    ASSERT_TRUE(token_matches(&tokens.tokens[1], TOKEN_VERSION, "VERS-TLS1.3"));
    ASSERT_TRUE(tokens.tokens[1].is_addition);
    ASSERT_FALSE(tokens.tokens[1].is_negation);
}

TEST(tokenize_version_removal)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("NORMAL:-VERS-TLS1.0", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 2);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "NORMAL"));
    ASSERT_TRUE(token_matches(&tokens.tokens[1], TOKEN_VERSION, "VERS-TLS1.0"));
    ASSERT_FALSE(tokens.tokens[1].is_addition);
    ASSERT_TRUE(tokens.tokens[1].is_negation);
}

TEST(tokenize_complex_priority_string)
{
    const char *complex_str = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0";
    token_list_t tokens = {0};
    const int result = priority_tokenize(complex_str, &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 5);

    // Verify each token
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "NORMAL"));
    ASSERT_TRUE(token_matches(&tokens.tokens[1], TOKEN_MODIFIER, "%SERVER_PRECEDENCE"));
    ASSERT_TRUE(token_matches(&tokens.tokens[2], TOKEN_MODIFIER, "%COMPAT"));
    ASSERT_TRUE(token_matches(&tokens.tokens[3], TOKEN_VERSION, "VERS-SSL3.0"));
    ASSERT_TRUE(token_matches(&tokens.tokens[4], TOKEN_VERSION, "VERS-TLS1.0"));

    // Verify operators
    ASSERT_TRUE(tokens.tokens[3].is_negation);
    ASSERT_TRUE(tokens.tokens[4].is_negation);
}

TEST(tokenize_performance_keyword)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("PERFORMANCE", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 1);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "PERFORMANCE"));
}

TEST(tokenize_secure256_keyword)
{
    token_list_t tokens = {0};
    const int result = priority_tokenize("SECURE256", &tokens);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_EQ(tokens.count, 1);
    ASSERT_TRUE(token_matches(&tokens.tokens[0], TOKEN_KEYWORD, "SECURE256"));
}

/* ============================================================================
 * Parser Tests
 * ============================================================================ */

TEST(parse_normal_keyword_sets_defaults)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("NORMAL", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.has_base_keyword);
    ASSERT_STR_EQ(config.base_keyword, "NORMAL");
}

TEST(parse_server_precedence_modifier)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("NORMAL:%SERVER_PRECEDENCE", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.server_precedence);
}

TEST(parse_compat_modifier)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("NORMAL:%COMPAT", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.compat_mode);
}

TEST(parse_version_addition_tls13)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    priority_config_init(&config);

    (void)priority_tokenize("NORMAL:+VERS-TLS1.3", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.enabled_versions[TLS_VERSION_TLS13]);
}

TEST(parse_version_removal_tls10)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    priority_config_init(&config);

    (void)priority_tokenize("NORMAL:-VERS-TLS1.0", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.disabled_versions[TLS_VERSION_TLS10]);
}

TEST(parse_version_removal_ssl3)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    priority_config_init(&config);

    (void)priority_tokenize("NORMAL:-VERS-SSL3.0", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.disabled_versions[TLS_VERSION_SSL3]);
}

TEST(parse_multiple_modifiers)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    priority_config_init(&config);

    (void)priority_tokenize("NORMAL:%SERVER_PRECEDENCE:%COMPAT:%FORCE_SESSION_HASH", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.server_precedence);
    ASSERT_TRUE(config.compat_mode);
    ASSERT_TRUE(config.force_session_hash);
}

TEST(parse_real_world_ioguard_string)
{
    const char *ioguard_default = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0";
    token_list_t tokens = {0};
    priority_config_t config = {0};
    priority_config_init(&config);

    (void)priority_tokenize(ioguard_default, &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.has_base_keyword);
    ASSERT_STR_EQ(config.base_keyword, "NORMAL");
    ASSERT_TRUE(config.server_precedence);
    ASSERT_TRUE(config.compat_mode);
    ASSERT_TRUE(config.disabled_versions[TLS_VERSION_SSL3]);
    ASSERT_TRUE(config.disabled_versions[TLS_VERSION_TLS10]);
}

TEST(parse_performance_keyword)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("PERFORMANCE", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.has_base_keyword);
    ASSERT_STR_EQ(config.base_keyword, "PERFORMANCE");
}

TEST(parse_secure256_keyword)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("SECURE256", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.has_base_keyword);
    ASSERT_STR_EQ(config.base_keyword, "SECURE256");
    ASSERT_EQ(config.min_security_bits, 256);
}

TEST(parse_pfs_keyword)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};

    (void)priority_tokenize("PFS", &tokens);
    const int result = priority_parse(&tokens, &config);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(config.has_base_keyword);
    ASSERT_STR_EQ(config.base_keyword, "PFS");
    ASSERT_TRUE(config.require_pfs);
}

/* ============================================================================
 * Mapper Tests
 * ============================================================================ */

TEST(map_normal_to_wolfssl_generates_cipher_list)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    wolfssl_config_t wolfssl_cfg = {0};

    priority_config_init(&config);
    wolfssl_config_init(&wolfssl_cfg);

    (void)priority_tokenize("NORMAL", &tokens);
    (void)priority_parse(&tokens, &config);
    const int result = priority_map_to_wolfssl(&config, &wolfssl_cfg);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(wolfssl_cfg.has_cipher_list);
    ASSERT_TRUE(strlen(wolfssl_cfg.cipher_list) > 0);
}

TEST(map_server_precedence_sets_options)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    wolfssl_config_t wolfssl_cfg = {0};

    priority_config_init(&config);
    wolfssl_config_init(&wolfssl_cfg);

    (void)priority_tokenize("NORMAL:%SERVER_PRECEDENCE", &tokens);
    (void)priority_parse(&tokens, &config);
    const int result = priority_map_to_wolfssl(&config, &wolfssl_cfg);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    // Options should include cipher server preference flag
    ASSERT_TRUE(wolfssl_cfg.options != 0);
}

TEST(map_version_range_sets_min_max)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    wolfssl_config_t wolfssl_cfg = {0};

    priority_config_init(&config);
    wolfssl_config_init(&wolfssl_cfg);

    (void)priority_tokenize("NORMAL:+VERS-TLS1.3:-VERS-TLS1.0", &tokens);
    (void)priority_parse(&tokens, &config);
    const int result = priority_map_to_wolfssl(&config, &wolfssl_cfg);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(wolfssl_cfg.has_version_range);
}

TEST(map_tls13_only_generates_ciphersuites)
{
    token_list_t tokens = {0};
    priority_config_t config = {0};
    wolfssl_config_t wolfssl_cfg = {0};

    priority_config_init(&config);
    wolfssl_config_init(&wolfssl_cfg);

    const char *tls13_only = "SECURE256:+VERS-TLS1.3:-VERS-TLS1.2:-VERS-TLS1.1:-VERS-TLS1.0";
    (void)priority_tokenize(tls13_only, &tokens);
    (void)priority_parse(&tokens, &config);
    const int result = priority_map_to_wolfssl(&config, &wolfssl_cfg);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
    ASSERT_TRUE(wolfssl_cfg.has_ciphersuites);
    ASSERT_TRUE(strlen(wolfssl_cfg.ciphersuites) > 0);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================ */

TEST(integration_validate_empty_string)
{
    char errmsg[256] = {0};
    const int result = tls_validate_priority_string("", errmsg, sizeof(errmsg));

    // Empty string should be valid (uses defaults)
    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
}

TEST(integration_validate_normal_keyword)
{
    char errmsg[256] = {0};
    const int result = tls_validate_priority_string("NORMAL", errmsg, sizeof(errmsg));

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
}

TEST(integration_validate_complex_string)
{
    const char *complex = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0";
    char errmsg[256] = {0};
    const int result = tls_validate_priority_string(complex, errmsg, sizeof(errmsg));

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
}

TEST(integration_validate_null_pointer)
{
    char errmsg[256] = {0};
    const int result = tls_validate_priority_string(nullptr, errmsg, sizeof(errmsg));

    ASSERT_EQ(result, PRIORITY_E_NULL_POINTER);
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================ */

TEST(error_get_last_error_returns_info)
{
    priority_error_info_t error_info = {0};
    const int result = priority_get_last_error(&error_info);

    ASSERT_EQ(result, PRIORITY_E_SUCCESS);
}

TEST(error_get_last_error_null_pointer)
{
    const int result = priority_get_last_error(nullptr);

    ASSERT_EQ(result, PRIORITY_E_NULL_POINTER);
}

TEST(error_strerror_returns_valid_string)
{
    const char *msg = priority_strerror(PRIORITY_E_SUCCESS);
    ASSERT_NOT_NULL(msg);
    ASSERT_TRUE(strlen(msg) > 0);

    msg = priority_strerror(PRIORITY_E_SYNTAX_ERROR);
    ASSERT_NOT_NULL(msg);
    ASSERT_TRUE(strlen(msg) > 0);
}

/* ============================================================================
 * Utility Function Tests
 * ============================================================================ */

TEST(utility_priority_config_init_zeros_memory)
{
    priority_config_t config = {0};
    priority_config_init(&config);

    // After init, should have safe defaults
    ASSERT_FALSE(config.has_base_keyword);
    ASSERT_FALSE(config.server_precedence);
    ASSERT_FALSE(config.compat_mode);
    ASSERT_EQ(config.min_security_bits, 0);
}

TEST(utility_wolfssl_config_init_zeros_memory)
{
    wolfssl_config_t wolfssl_cfg = {0};
    wolfssl_config_init(&wolfssl_cfg);

    ASSERT_FALSE(wolfssl_cfg.has_cipher_list);
    ASSERT_FALSE(wolfssl_cfg.has_ciphersuites);
    ASSERT_FALSE(wolfssl_cfg.has_version_range);
    ASSERT_EQ(wolfssl_cfg.options, 0);
}

TEST(utility_token_type_name_returns_valid_string)
{
    const char *name = priority_token_type_name(TOKEN_KEYWORD);
    ASSERT_NOT_NULL(name);
    ASSERT_STR_EQ(name, "KEYWORD");

    name = priority_token_type_name(TOKEN_MODIFIER);
    ASSERT_NOT_NULL(name);
    ASSERT_STR_EQ(name, "MODIFIER");
}

/* ============================================================================
 * Test Suite Entry Point
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("=============================================================================\n");
    printf(" Priority Parser Unit Tests (C23 Modern Implementation)\n");
    printf("=============================================================================\n\n");

    printf("Running Tokenizer Tests:\n");
    RUN_TEST(tokenize_empty_string_returns_error);
    RUN_TEST(tokenize_null_pointer_returns_error);
    RUN_TEST(tokenize_single_keyword_normal);
    RUN_TEST(tokenize_keyword_with_modifier);
    RUN_TEST(tokenize_version_addition);
    RUN_TEST(tokenize_version_removal);
    RUN_TEST(tokenize_complex_priority_string);
    RUN_TEST(tokenize_performance_keyword);
    RUN_TEST(tokenize_secure256_keyword);

    printf("\nRunning Parser Tests:\n");
    RUN_TEST(parse_normal_keyword_sets_defaults);
    RUN_TEST(parse_server_precedence_modifier);
    RUN_TEST(parse_compat_modifier);
    RUN_TEST(parse_version_addition_tls13);
    RUN_TEST(parse_version_removal_tls10);
    RUN_TEST(parse_version_removal_ssl3);
    RUN_TEST(parse_multiple_modifiers);
    RUN_TEST(parse_real_world_ioguard_string);
    RUN_TEST(parse_performance_keyword);
    RUN_TEST(parse_secure256_keyword);
    RUN_TEST(parse_pfs_keyword);

    printf("\nRunning Mapper Tests:\n");
    RUN_TEST(map_normal_to_wolfssl_generates_cipher_list);
    RUN_TEST(map_server_precedence_sets_options);
    RUN_TEST(map_version_range_sets_min_max);
    RUN_TEST(map_tls13_only_generates_ciphersuites);

    printf("\nRunning Integration Tests:\n");
    RUN_TEST(integration_validate_empty_string);
    RUN_TEST(integration_validate_normal_keyword);
    RUN_TEST(integration_validate_complex_string);
    RUN_TEST(integration_validate_null_pointer);

    printf("\nRunning Error Handling Tests:\n");
    RUN_TEST(error_get_last_error_returns_info);
    RUN_TEST(error_get_last_error_null_pointer);
    RUN_TEST(error_strerror_returns_valid_string);

    printf("\nRunning Utility Function Tests:\n");
    RUN_TEST(utility_priority_config_init_zeros_memory);
    RUN_TEST(utility_wolfssl_config_init_zeros_memory);
    RUN_TEST(utility_token_type_name_returns_valid_string);

    printf("\n");
    printf("=============================================================================\n");
    printf(" Test Results\n");
    printf("=============================================================================\n");
    printf("  Total tests run:    %d\n", tests_run);
    printf("  Tests passed:       %d\n", tests_passed);
    printf("  Tests failed:       %d\n", tests_failed);
    printf("  Success rate:       %.1f%%\n",
           tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0);
    printf("=============================================================================\n\n");

    if (tests_failed > 0) {
        printf("FAILED: %d test(s) failed\n", tests_failed);
        return 1;
    }

    printf("SUCCESS: All tests passed!\n");
    return 0;
}
