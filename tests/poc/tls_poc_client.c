/*
 * TLS PoC Client - ioguard
 *
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ringwall.
 *
 * ioguard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * Purpose: Proof of Concept TLS client to test echo server and measure performance.
 */

#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// TLS abstraction layer
#include "../../src/crypto/tls_abstract.h"

/* Configuration */
#define DEFAULT_PORT 4433
#define DEFAULT_HOST "127.0.0.1"

/* Test sizes */
static const size_t test_sizes[] = {
    1,     // 1 byte
    64,    // 64 bytes
    256,   // 256 bytes
    1024,  // 1 KB
    4096,  // 4 KB
    16384, // 16 KB
    65536, // 64 KB
};

#define NUM_TEST_SIZES (sizeof(test_sizes) / sizeof(test_sizes[0]))

/* Statistics */
typedef struct {
    size_t size;
    uint64_t iterations;
    double elapsed_seconds;
    double throughput_mbps;
    double latency_ms;
} test_result_t;

/* Print usage */
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -b, --backend {gnutls|wolfssl}  TLS backend (required)\n");
    fprintf(stderr, "  -H, --host HOST                 Server host (default: %s)\n", DEFAULT_HOST);
    fprintf(stderr, "  -p, --port PORT                 Server port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr,
            "  -n, --iterations N              Number of iterations per test (default: 100)\n");
    fprintf(stderr, "  -s, --size SIZE                 Test single size instead of all sizes\n");
    fprintf(stderr, "  -v, --verbose                   Verbose logging\n");
    fprintf(stderr, "  -h, --help                      Show this help\n");
}

/* Connect to server */
static int connect_to_server(const char *host, int port, bool verbose)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", host);
        close(sockfd);
        return -1;
    }

    if (verbose) {
        printf("Connecting to %s:%d...\n", host, port);
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    if (verbose) {
        printf("TCP connection established\n");
    }

    return sockfd;
}

/* Get current time in seconds */
static double get_time_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Run test for specific size */
static int run_test(tls_session_t *session, size_t size, uint64_t iterations, test_result_t *result,
                    bool verbose)
{
    uint8_t *send_buffer = malloc(size);
    uint8_t *recv_buffer = malloc(size);

    if (send_buffer == nullptr || recv_buffer == nullptr) {
        fprintf(stderr, "Memory allocation failed\n");
        free(send_buffer);
        free(recv_buffer);
        return -1;
    }

    // Fill send buffer with test pattern
    for (size_t i = 0; i < size; i++) {
        send_buffer[i] = (uint8_t)(i & 0xFF);
    }

    if (verbose) {
        printf("\nTesting size: %zu bytes, iterations: %lu\n", size, iterations);
    }

    double start_time = get_time_seconds();

    for (uint64_t i = 0; i < iterations; i++) {
        // Send data
        ssize_t sent = tls_send(session, send_buffer, size);
        if (sent < 0) {
            fprintf(stderr, "Send error: %s\n", tls_strerror(sent));
            free(send_buffer);
            free(recv_buffer);
            return -1;
        }

        if ((size_t)sent != size) {
            fprintf(stderr, "Short send: %zd of %zu bytes\n", sent, size);
            free(send_buffer);
            free(recv_buffer);
            return -1;
        }

        // Receive echo
        size_t total_received = 0;
        while (total_received < size) {
            ssize_t received =
                tls_recv(session, recv_buffer + total_received, size - total_received);

            if (received <= 0) {
                fprintf(stderr, "Receive error: %s\n", tls_strerror(received));
                free(send_buffer);
                free(recv_buffer);
                return -1;
            }

            total_received += received;
        }

        // Verify data
        if (memcmp(send_buffer, recv_buffer, size) != 0) {
            fprintf(stderr, "Data verification failed at iteration %lu\n", i);
            free(send_buffer);
            free(recv_buffer);
            return -1;
        }

        if (verbose && (i % 10 == 0)) {
            printf("  Iteration %lu/%lu\r", i, iterations);
            fflush(stdout);
        }
    }

    double end_time = get_time_seconds();
    double elapsed = end_time - start_time;

    // Calculate statistics
    result->size = size;
    result->iterations = iterations;
    result->elapsed_seconds = elapsed;

    // Throughput: (bytes sent + bytes received) * iterations / elapsed / (1024*1024)
    uint64_t total_bytes = (size * 2) * iterations; // 2x because send + receive
    result->throughput_mbps = ((double)total_bytes / elapsed) / (1024.0 * 1024.0);

    // Latency: elapsed / iterations * 1000 (convert to milliseconds)
    result->latency_ms = (elapsed / (double)iterations) * 1000.0;

    free(send_buffer);
    free(recv_buffer);

    return 0;
}

/* Print test result */
static void print_result(const test_result_t *result)
{
    printf("Size: %8zu bytes | ", result->size);
    printf("Iterations: %6lu | ", result->iterations);
    printf("Elapsed: %8.3f s | ", result->elapsed_seconds);
    printf("Throughput: %8.2f MB/s | ", result->throughput_mbps);
    printf("Latency: %8.3f ms\n", result->latency_ms);
}

/* Print results in JSON format */
static void print_results_json(const test_result_t *results, size_t count, const char *backend_name,
                               double handshake_time_ms)
{
    printf("\n{\n");
    printf("  \"backend\": \"%s\",\n", backend_name);
    printf("  \"handshake_time_ms\": %.3f,\n", handshake_time_ms);
    printf("  \"tests\": [\n");

    for (size_t i = 0; i < count; i++) {
        printf("    {\n");
        printf("      \"size\": %zu,\n", results[i].size);
        printf("      \"iterations\": %lu,\n", results[i].iterations);
        printf("      \"elapsed_seconds\": %.6f,\n", results[i].elapsed_seconds);
        printf("      \"throughput_mbps\": %.2f,\n", results[i].throughput_mbps);
        printf("      \"latency_ms\": %.3f\n", results[i].latency_ms);
        printf("    }%s\n", (i < count - 1) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
}

/* Main function */
int main(int argc, char **argv)
{
    tls_backend_t backend = TLS_BACKEND_NONE;
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    uint64_t iterations = 100;
    ssize_t single_size = -1;
    bool verbose = false;
    bool json_output = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--backend") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --backend requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            if (strcmp(argv[i], "gnutls") == 0) {
                backend = TLS_BACKEND_GNUTLS;
            } else if (strcmp(argv[i], "wolfssl") == 0) {
                backend = TLS_BACKEND_WOLFSSL;
            } else {
                fprintf(stderr, "Error: Invalid backend '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --host requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            host = argv[i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --port requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            port = atoi(argv[i]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--iterations") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --iterations requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            iterations = strtoull(argv[i], nullptr, 10);
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --size requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            single_size = atoi(argv[i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (backend == TLS_BACKEND_NONE) {
        fprintf(stderr, "Error: --backend is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Initialize TLS subsystem
    if (verbose) {
        printf("Initializing TLS subsystem (backend: %s)...\n",
               backend == TLS_BACKEND_GNUTLS ? "GnuTLS" : "wolfSSL");
    }

    int ret = tls_global_init(backend);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to initialize TLS: %s\n", tls_strerror(ret));
        return 1;
    }

    if (verbose) {
        printf("TLS library version: %s\n", tls_get_version_string());
    }

    // Create TLS context with cleanup attribute
    __attribute__((cleanup(tls_context_cleanup)))
    tls_context_t *ctx = tls_context_new(false, false); // client, TLS (not DTLS)

    if (ctx == nullptr) {
        fprintf(stderr, "Failed to create TLS context\n");
        tls_global_deinit();
        return 1;
    }

    // Disable certificate verification for PoC (self-signed certs)
    ret = tls_context_set_verify(ctx, false, nullptr, nullptr);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to disable verification: %s\n", tls_strerror(ret));
        tls_global_deinit();
        return 1;
    }

    // Connect to server
    int sockfd = connect_to_server(host, port, verbose);
    if (sockfd < 0) {
        tls_global_deinit();
        return 1;
    }

    // Create TLS session with cleanup attribute
    __attribute__((cleanup(tls_session_cleanup))) tls_session_t *session = tls_session_new(ctx);

    if (session == nullptr) {
        fprintf(stderr, "Failed to create TLS session\n");
        close(sockfd);
        tls_global_deinit();
        return 1;
    }

    // Associate socket with session
    ret = tls_session_set_fd(session, sockfd);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to set FD: %s\n", tls_strerror(ret));
        close(sockfd);
        tls_global_deinit();
        return 1;
    }

    // Perform TLS handshake
    if (verbose) {
        printf("Starting TLS handshake...\n");
    }

    double handshake_start = get_time_seconds();

    while ((ret = tls_handshake(session)) != TLS_E_SUCCESS) {
        if (ret == TLS_E_AGAIN || ret == TLS_E_INTERRUPTED) {
            continue;
        }
        fprintf(stderr, "Handshake failed: %s\n", tls_strerror(ret));
        close(sockfd);
        tls_global_deinit();
        return 1;
    }

    double handshake_end = get_time_seconds();
    double handshake_time_ms = (handshake_end - handshake_start) * 1000.0;

    // Get connection information
    tls_connection_info_t info;
    if (tls_get_connection_info(session, &info) == TLS_E_SUCCESS) {
        if (verbose) {
            printf("Handshake complete (%.3f ms): %s, resumed=%s\n", handshake_time_ms,
                   info.cipher_name, info.session_resumed ? "yes" : "no");
        }
    }

    // Run tests
    test_result_t results[NUM_TEST_SIZES];
    size_t num_results = 0;

    if (!json_output && !verbose) {
        printf("\n=== TLS Performance Test ===\n");
        printf("Backend: %s\n", backend == TLS_BACKEND_GNUTLS ? "GnuTLS" : "wolfSSL");
        printf("Server: %s:%d\n", host, port);
        printf("Handshake time: %.3f ms\n\n", handshake_time_ms);
    }

    if (single_size > 0) {
        // Test single size
        ret = run_test(session, single_size, iterations, &results[0], verbose);
        if (ret == 0) {
            num_results = 1;
            if (!json_output) {
                print_result(&results[0]);
            }
        }
    } else {
        // Test all sizes
        for (size_t i = 0; i < NUM_TEST_SIZES; i++) {
            ret = run_test(session, test_sizes[i], iterations, &results[i], verbose);
            if (ret != 0) {
                break;
            }
            num_results++;
            if (!json_output) {
                print_result(&results[i]);
            }
        }
    }

    if (json_output && num_results > 0) {
        print_results_json(results, num_results,
                           backend == TLS_BACKEND_GNUTLS ? "gnutls" : "wolfssl", handshake_time_ms);
    }

    // Graceful shutdown
    ret = tls_bye(session);
    if (ret != TLS_E_SUCCESS && verbose) {
        fprintf(stderr, "Warning: TLS shutdown failed: %s\n", tls_strerror(ret));
    }
    close(sockfd);
    tls_global_deinit();

    if (verbose) {
        printf("\nDone!\n");
    }

    return (num_results > 0) ? 0 : 1;
}
