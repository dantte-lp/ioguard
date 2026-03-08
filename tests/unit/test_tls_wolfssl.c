/*
 * Copyright (C) 2025 ringwall Contributors
 *
 * This file is part of ringwall.
 *
 * ringwall is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ringwall is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Unit tests for wolfSSL backend implementation
 *
 * These tests verify the correctness of the wolfSSL backend implementation
 * for the TLS abstraction layer.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_abstract.h"
#include "tls_wolfssl.h"

// C23 standard check (accept C2x/C20 from GCC 14 as it provides C23 features)
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros */
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

#define ASSERT_STR_EQ(a, b)                                                                        \
    do {                                                                                           \
        if (strcmp((a), (b)) != 0) {                                                               \
            printf("\n    FAILED: %s:%d: Expected '%s', got '%s'\n", __FILE__, __LINE__, (b),      \
                   (a));                                                                           \
            tests_failed++;                                                                        \
            tests_passed--;                                                                        \
            return;                                                                                \
        }                                                                                          \
    } while (0)

/* ============================================================================
 * Test Cases
 * ============================================================================ */

TEST(library_initialization)
{
    int ret = tls_wolfssl_init();
    ASSERT_EQ(ret, TLS_E_SUCCESS);

    const char *version = tls_wolfssl_get_version();
    ASSERT_NOT_NULL(version);
    printf(" [v%s]", version);

    tls_wolfssl_deinit();
}

TEST(library_double_init)
{
    int ret1 = tls_wolfssl_init();
    ASSERT_EQ(ret1, TLS_E_SUCCESS);

    int ret2 = tls_wolfssl_init();
    ASSERT_EQ(ret2, TLS_E_SUCCESS);

    tls_wolfssl_deinit();
    tls_wolfssl_deinit();
}

TEST(context_creation_server)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT_NOT_NULL(ctx);
    ASSERT(ctx->is_server == true);
    ASSERT(ctx->is_dtls == false);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(context_creation_client)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(false, false);
    ASSERT_NOT_NULL(ctx);
    ASSERT(ctx->is_server == false);
    ASSERT(ctx->is_dtls == false);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(context_creation_dtls_server)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, true);
    ASSERT_NOT_NULL(ctx);
    ASSERT(ctx->is_server == true);
    ASSERT(ctx->is_dtls == true);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(context_creation_dtls_client)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(false, true);
    ASSERT_NOT_NULL(ctx);
    ASSERT(ctx->is_server == false);
    ASSERT(ctx->is_dtls == true);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(session_creation)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT_NOT_NULL(ctx);

    tls_session_t *session = tls_session_new(ctx);
    ASSERT_NOT_NULL(session);
    ASSERT(session->ctx == ctx);
    ASSERT(session->handshake_complete == false);

    tls_session_free(session);
    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(session_set_get_ptr)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    tls_session_t *session = tls_session_new(ctx);

    void *test_ptr = (void *)0x12345678;
    tls_session_set_ptr(session, test_ptr);

    void *retrieved = tls_session_get_ptr(session);
    ASSERT(retrieved == test_ptr);

    tls_session_free(session);
    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(priority_translation_normal)
{
    char output[512];
    int ret = tls_wolfssl_translate_priority("NORMAL", output, sizeof(output));
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT(strlen(output) > 0);
}

TEST(priority_translation_secure256)
{
    char output[512];
    int ret = tls_wolfssl_translate_priority("SECURE256", output, sizeof(output));
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT(strstr(output, "AES256") != nullptr);
}

TEST(priority_translation_performance)
{
    char output[512];
    int ret = tls_wolfssl_translate_priority("PERFORMANCE", output, sizeof(output));
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT(strstr(output, "CHACHA20") != nullptr || strstr(output, "AES128") != nullptr);
}

TEST(context_set_priority)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT_NOT_NULL(ctx);

    int ret = tls_context_set_priority(ctx, "NORMAL");
    ASSERT_EQ(ret, TLS_E_SUCCESS);

    ASSERT_NOT_NULL(ctx->priority_string);
    ASSERT_STR_EQ(ctx->priority_string, "NORMAL");

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(context_set_verify)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT_NOT_NULL(ctx);

    int ret = tls_context_set_verify(ctx, true, nullptr, nullptr);
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT(ctx->verify_peer == true);

    ret = tls_context_set_verify(ctx, false, nullptr, nullptr);
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT(ctx->verify_peer == false);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(context_set_session_timeout)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT_NOT_NULL(ctx);

    int ret = tls_context_set_session_timeout(ctx, 3600);
    ASSERT_EQ(ret, TLS_E_SUCCESS);
    ASSERT_EQ(ctx->session_timeout_secs, 3600);

    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(dtls_set_get_mtu)
{
    (void)tls_wolfssl_init();

    tls_context_t *ctx = tls_context_new(true, true);
    tls_session_t *session = tls_session_new(ctx);

    int ret = tls_dtls_set_mtu(session, 1280);
    ASSERT_EQ(ret, TLS_E_SUCCESS);

    int mtu = tls_dtls_get_mtu(session);
    ASSERT_EQ(mtu, 1280);

    tls_session_free(session);
    tls_context_free(ctx);
    tls_wolfssl_deinit();
}

TEST(error_mapping)
{
    // Test that error mapping returns valid abstraction errors
    int ret;

    ret = tls_wolfssl_map_error(SSL_SUCCESS);
    ASSERT_EQ(ret, TLS_E_SUCCESS);

    ret = tls_wolfssl_map_error(WOLFSSL_ERROR_WANT_READ);
    ASSERT_EQ(ret, TLS_E_AGAIN);

    ret = tls_wolfssl_map_error(MEMORY_E);
    ASSERT_EQ(ret, TLS_E_MEMORY_ERROR);

    ret = tls_wolfssl_map_error(BAD_FUNC_ARG);
    ASSERT_EQ(ret, TLS_E_INVALID_PARAMETER);
}

TEST(error_strings)
{
    const char *str;

    str = tls_strerror(TLS_E_SUCCESS);
    ASSERT_NOT_NULL(str);
    ASSERT(strlen(str) > 0);

    str = tls_strerror(TLS_E_AGAIN);
    ASSERT_NOT_NULL(str);
    ASSERT(strstr(str, "again") != nullptr || strstr(str, "block") != nullptr);

    str = tls_strerror(TLS_E_MEMORY_ERROR);
    ASSERT_NOT_NULL(str);
    ASSERT(strstr(str, "emory") != nullptr);
}

TEST(error_is_fatal)
{
    ASSERT(tls_error_is_fatal(TLS_E_AGAIN) == false);
    ASSERT(tls_error_is_fatal(TLS_E_INTERRUPTED) == false);
    ASSERT(tls_error_is_fatal(TLS_E_MEMORY_ERROR) == true);
    ASSERT(tls_error_is_fatal(TLS_E_HANDSHAKE_FAILED) == true);
}

TEST(hash_fast_sha256)
{
    (void)tls_wolfssl_init();

    const char *data = "Hello, World!";
    uint8_t hash[32];

    int ret = tls_hash_fast(0, data, strlen(data), hash);
    ASSERT_EQ(ret, TLS_E_SUCCESS);

    // Check that hash is non-zero
    bool non_zero = false;
    for (size_t i = 0; i < sizeof(hash); i++) {
        if (hash[i] != 0) {
            non_zero = true;
            break;
        }
    }
    ASSERT(non_zero);

    tls_wolfssl_deinit();
}

TEST(random_generation)
{
    (void)tls_wolfssl_init();

    uint8_t buf1[32];
    uint8_t buf2[32];

    int ret1 = tls_random(buf1, sizeof(buf1));
    ASSERT_EQ(ret1, TLS_E_SUCCESS);

    int ret2 = tls_random(buf2, sizeof(buf2));
    ASSERT_EQ(ret2, TLS_E_SUCCESS);

    // Check that two random buffers are different
    ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0);

    tls_wolfssl_deinit();
}

TEST(memory_allocation)
{
    void *ptr = tls_malloc(1024);
    ASSERT_NOT_NULL(ptr);

    memset(ptr, 0xAA, 1024);

    tls_free(ptr);
}

TEST(null_parameter_checks)
{
    // Test that functions properly handle nullptr parameters
    int ret;

    ret = tls_context_set_cert_file(nullptr, "test.pem");
    ASSERT_EQ(ret, TLS_E_INVALID_PARAMETER);

    ret = tls_context_set_key_file(nullptr, "test.key");
    ASSERT_EQ(ret, TLS_E_INVALID_PARAMETER);

    ret = tls_context_set_ca_file(nullptr, "ca.pem");
    ASSERT_EQ(ret, TLS_E_INVALID_PARAMETER);

    ret = tls_session_set_fd(nullptr, 0);
    ASSERT_EQ(ret, TLS_E_INVALID_PARAMETER);
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void)
{
    printf("===============================================\n");
    printf("wolfSSL Backend Unit Tests\n");
    printf("===============================================\n\n");

    // Run all tests
    RUN_TEST(library_initialization);
    RUN_TEST(library_double_init);
    RUN_TEST(context_creation_server);
    RUN_TEST(context_creation_client);
    RUN_TEST(context_creation_dtls_server);
    RUN_TEST(context_creation_dtls_client);
    RUN_TEST(session_creation);
    RUN_TEST(session_set_get_ptr);
    RUN_TEST(priority_translation_normal);
    RUN_TEST(priority_translation_secure256);
    RUN_TEST(priority_translation_performance);
    RUN_TEST(context_set_priority);
    RUN_TEST(context_set_verify);
    RUN_TEST(context_set_session_timeout);
    RUN_TEST(dtls_set_get_mtu);
    RUN_TEST(error_mapping);
    RUN_TEST(error_strings);
    RUN_TEST(error_is_fatal);
    RUN_TEST(hash_fast_sha256);
    RUN_TEST(random_generation);
    RUN_TEST(memory_allocation);
    RUN_TEST(null_parameter_checks);

    // Print summary
    printf("\n===============================================\n");
    printf("Test Summary:\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("===============================================\n");

    if (tests_failed > 0) {
        printf("\nSome tests FAILED!\n");
        return 1;
    }

    printf("\nAll tests PASSED!\n");
    return 0;
}
