/*
 * Copyright (C) 2025 ringwall Contributors
 *
 * This file is part of ringwall.
 *
 * Unit Tests for GnuTLS Backend
 *
 * Tests the GnuTLS implementation of the TLS abstraction layer.
 * Each test validates a specific aspect of the API.
 */

#include "crypto/tls_gnutls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros */
#define TEST_START(name) \
    printf("Running test: %s...", name); \
    fflush(stdout);

#define TEST_END() \
    printf(" PASSED\n"); \
    tests_passed++;

#define TEST_FAIL(msg) \
    do { \
        printf(" FAILED: %s\n", msg); \
        tests_failed++; \
        return; \
    } while(0)

#define ASSERT(cond, msg) \
    if (!(cond)) { \
        TEST_FAIL(msg); \
    }

/* ============================================================================
 * Test: Global Initialization
 * ============================================================================ */

void test_global_init(void) {
    TEST_START("global_init");

    int ret = tls_global_init(TLS_BACKEND_GNUTLS);
    ASSERT(ret == TLS_E_SUCCESS, "tls_global_init failed");

    tls_backend_t backend = tls_get_backend();
    ASSERT(backend == TLS_BACKEND_GNUTLS, "Backend not set correctly");

    const char *version = tls_get_version_string();
    ASSERT(version != nullptr, "Version string is nullptr");
    ASSERT(strstr(version, "GnuTLS") != nullptr, "Version string doesn't contain 'GnuTLS'");

    // Test double init (should succeed)
    ret = tls_global_init(TLS_BACKEND_GNUTLS);
    ASSERT(ret == TLS_E_SUCCESS, "Double init failed");

    TEST_END();
}

/* ============================================================================
 * Test: Context Creation and Destruction
 * ============================================================================ */

void test_context_lifecycle(void) {
    TEST_START("context_lifecycle");

    // Test server context (TLS)
    tls_context_t *ctx_server = tls_context_new(true, false);
    ASSERT(ctx_server != nullptr, "Failed to create server TLS context");

    // Test client context (TLS)
    tls_context_t *ctx_client = tls_context_new(false, false);
    ASSERT(ctx_client != nullptr, "Failed to create client TLS context");

    // Test DTLS context
    tls_context_t *ctx_dtls = tls_context_new(true, true);
    ASSERT(ctx_dtls != nullptr, "Failed to create DTLS context");

    // Free contexts
    tls_context_free(ctx_server);
    tls_context_free(ctx_client);
    tls_context_free(ctx_dtls);

    // Test freeing nullptr (should not crash)
    tls_context_free(nullptr);

    TEST_END();
}

/* ============================================================================
 * Test: Context Configuration
 * ============================================================================ */

void test_context_configuration(void) {
    TEST_START("context_configuration");

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT(ctx != nullptr, "Failed to create context");

    // Test priority string
    int ret = tls_context_set_priority(ctx, "NORMAL");
    ASSERT(ret == TLS_E_SUCCESS, "Failed to set priority string");

    // Test invalid priority string
    ret = tls_context_set_priority(ctx, "INVALID_PRIORITY_STRING");
    ASSERT(ret != TLS_E_SUCCESS, "Should fail with invalid priority");

    // Test nullptr checks
    ret = tls_context_set_priority(nullptr, "NORMAL");
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr context");

    ret = tls_context_set_priority(ctx, nullptr);
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr priority");

    tls_context_free(ctx);
    TEST_END();
}

/* ============================================================================
 * Test: Session Creation and Destruction
 * ============================================================================ */

void test_session_lifecycle(void) {
    TEST_START("session_lifecycle");

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT(ctx != nullptr, "Failed to create context");

    // Create session
    tls_session_t *session = tls_session_new(ctx);
    ASSERT(session != nullptr, "Failed to create session");

    // Test user pointer
    int user_data = 42;
    tls_session_set_ptr(session, &user_data);
    void *ptr = tls_session_get_ptr(session);
    ASSERT(ptr == &user_data, "User pointer mismatch");
    ASSERT(*(int*)ptr == 42, "User data mismatch");

    // Free session
    tls_session_free(session);

    // Test freeing nullptr (should not crash)
    tls_session_free(nullptr);

    tls_context_free(ctx);
    TEST_END();
}

/* ============================================================================
 * Test: Error Handling
 * ============================================================================ */

void test_error_handling(void) {
    TEST_START("error_handling");

    // Test error strings
    const char *err = tls_strerror(TLS_E_SUCCESS);
    ASSERT(err != nullptr, "Error string is nullptr");
    ASSERT(strcmp(err, "Success") == 0, "Wrong error string for SUCCESS");

    err = tls_strerror(TLS_E_MEMORY_ERROR);
    ASSERT(err != nullptr, "Error string is nullptr");
    ASSERT(strstr(err, "emory") != nullptr, "Wrong error string for MEMORY_ERROR");

    // Test fatal error detection
    ASSERT(!tls_error_is_fatal(TLS_E_SUCCESS), "SUCCESS should not be fatal");
    ASSERT(!tls_error_is_fatal(TLS_E_AGAIN), "AGAIN should not be fatal");
    ASSERT(!tls_error_is_fatal(TLS_E_INTERRUPTED), "INTERRUPTED should not be fatal");
    ASSERT(tls_error_is_fatal(TLS_E_MEMORY_ERROR), "MEMORY_ERROR should be fatal");
    ASSERT(tls_error_is_fatal(TLS_E_CERTIFICATE_ERROR), "CERTIFICATE_ERROR should be fatal");

    TEST_END();
}

/* ============================================================================
 * Test: Utility Functions
 * ============================================================================ */

void test_utility_functions(void) {
    TEST_START("utility_functions");

    // Test memory allocation
    void *ptr = tls_malloc(1024);
    ASSERT(ptr != nullptr, "tls_malloc failed");
    tls_free(ptr);

    // Test nullptr free (should not crash)
    tls_free(nullptr);

    // Test random number generation
    uint8_t random_bytes[32];
    int ret = tls_random(random_bytes, sizeof(random_bytes));
    ASSERT(ret == TLS_E_SUCCESS, "tls_random failed");

    // Check that random bytes are not all zeros (highly unlikely)
    bool has_nonzero = false;
    for (size_t i = 0; i < sizeof(random_bytes); i++) {
        if (random_bytes[i] != 0) {
            has_nonzero = true;
            break;
        }
    }
    ASSERT(has_nonzero, "Random bytes are all zeros");

    // Test hash functions
    const char *test_data = "Hello, World!";
    uint8_t hash_output[64];

    // SHA-256
    ret = tls_hash_fast(0, test_data, strlen(test_data), hash_output);
    ASSERT(ret == TLS_E_SUCCESS, "SHA-256 hash failed");

    // SHA-384
    ret = tls_hash_fast(1, test_data, strlen(test_data), hash_output);
    ASSERT(ret == TLS_E_SUCCESS, "SHA-384 hash failed");

    // SHA-512
    ret = tls_hash_fast(2, test_data, strlen(test_data), hash_output);
    ASSERT(ret == TLS_E_SUCCESS, "SHA-512 hash failed");

    // Invalid algorithm
    ret = tls_hash_fast(999, test_data, strlen(test_data), hash_output);
    ASSERT(ret != TLS_E_SUCCESS, "Should fail with invalid algorithm");

    TEST_END();
}

/* ============================================================================
 * Test: Session Information
 * ============================================================================ */

void test_session_info(void) {
    TEST_START("session_info");

    tls_context_t *ctx = tls_context_new(true, false);
    ASSERT(ctx != nullptr, "Failed to create context");

    tls_session_t *session = tls_session_new(ctx);
    ASSERT(session != nullptr, "Failed to create session");

    // Get connection info (before handshake)
    tls_connection_info_t info;
    int ret = tls_get_connection_info(session, &info);
    ASSERT(ret == TLS_E_SUCCESS, "Failed to get connection info");

    // Test nullptr checks
    ret = tls_get_connection_info(nullptr, &info);
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr session");

    ret = tls_get_connection_info(session, nullptr);
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr info");

    tls_session_free(session);
    tls_context_free(ctx);
    TEST_END();
}

/* ============================================================================
 * Test: C23 Cleanup Attributes
 * ============================================================================ */

void test_cleanup_attributes(void) {
    TEST_START("cleanup_attributes");

    // Test context cleanup
    {
        __attribute__((cleanup(tls_context_cleanup)))
        tls_context_t *ctx = tls_context_new(true, false);
        ASSERT(ctx != nullptr, "Failed to create context");
        // Context should be automatically freed when going out of scope
    }

    // Test session cleanup
    {
        tls_context_t *ctx = tls_context_new(true, false);
        ASSERT(ctx != nullptr, "Failed to create context");

        {
            __attribute__((cleanup(tls_session_cleanup)))
            tls_session_t *session = tls_session_new(ctx);
            ASSERT(session != nullptr, "Failed to create session");
            // Session should be automatically freed when going out of scope
        }

        tls_context_free(ctx);
    }

    TEST_END();
}

/* ============================================================================
 * Test: Invalid Parameters
 * ============================================================================ */

void test_invalid_parameters(void) {
    TEST_START("invalid_parameters");

    // Test session operations with nullptr
    int ret = tls_session_set_fd(nullptr, 0);
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr session");

    ret = tls_session_set_timeout(nullptr, 1000);
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr session");

    // Test I/O operations with nullptr
    char buffer[64];
    ssize_t n = tls_send(nullptr, buffer, sizeof(buffer));
    ASSERT(n < 0, "tls_send should fail with nullptr session");

    n = tls_recv(nullptr, buffer, sizeof(buffer));
    ASSERT(n < 0, "tls_recv should fail with nullptr session");

    size_t pending = tls_pending(nullptr);
    ASSERT(pending == 0, "tls_pending should return 0 for nullptr");

    // Test context operations with nullptr
    ret = tls_context_set_cert_file(nullptr, "/tmp/cert.pem");
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr context");

    ret = tls_context_set_key_file(nullptr, "/tmp/key.pem");
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr context");

    ret = tls_context_set_ca_file(nullptr, "/tmp/ca.pem");
    ASSERT(ret == TLS_E_INVALID_PARAMETER, "Should fail with nullptr context");

    TEST_END();
}

/* ============================================================================
 * Test: Backend Selection
 * ============================================================================ */

void test_backend_selection(void) {
    TEST_START("backend_selection");

    // Test invalid backend
    int ret = tls_global_init(TLS_BACKEND_WOLFSSL);
    ASSERT(ret != TLS_E_SUCCESS, "Should fail with wolfSSL backend in GnuTLS build");

    ret = tls_global_init((tls_backend_t)999);
    ASSERT(ret != TLS_E_SUCCESS, "Should fail with invalid backend");

    // Reinitialize with correct backend
    ret = tls_global_init(TLS_BACKEND_GNUTLS);
    ASSERT(ret == TLS_E_SUCCESS, "Failed to reinitialize");

    TEST_END();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void) {
    printf("\n");
    printf("=================================================================\n");
    printf("GnuTLS Backend Unit Tests\n");
    printf("=================================================================\n\n");

    // Run all tests
    test_global_init();
    test_context_lifecycle();
    test_context_configuration();
    test_session_lifecycle();
    test_error_handling();
    test_utility_functions();
    test_session_info();
    test_cleanup_attributes();
    test_invalid_parameters();
    test_backend_selection();

    // Cleanup
    tls_global_deinit();

    // Print summary
    printf("\n");
    printf("=================================================================\n");
    printf("Test Summary\n");
    printf("=================================================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", tests_passed + tests_failed);

    if (tests_failed == 0) {
        printf("\nAll tests passed!\n");
        return EXIT_SUCCESS;
    } else {
        printf("\nSome tests failed!\n");
        return EXIT_FAILURE;
    }
}
