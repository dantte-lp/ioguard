/*
 * TLS PoC Echo Server - ioguard
 *
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ioguard.
 *
 * ioguard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * Purpose: Proof of Concept TLS echo server to validate abstraction layer
 *          and compare GnuTLS vs wolfSSL performance.
 */

#define _POSIX_C_SOURCE 200112L // For nanosleep()

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// TLS abstraction layer
#include "../../src/crypto/tls_abstract.h"

/* Configuration */
constexpr size_t BUFFER_SIZE = 16'384;
constexpr int DEFAULT_PORT = 4433;
constexpr int MAX_CLIENTS = 10;
constexpr int POLL_TIMEOUT_MS = 1000;

/* Statistics */
typedef struct {
    uint64_t connections_accepted;
    uint64_t connections_active;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t handshakes_completed;
    time_t start_time;
} stats_t;

static stats_t g_stats = {0};
static volatile bool g_running = true;

/* Signal handler */
static void signal_handler(int signum)
{
    (void)signum;
    g_running = false;
}

/* Print usage */
static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -b, --backend {gnutls|wolfssl}  TLS backend (required)\n");
    fprintf(stderr, "  -p, --port PORT                 Listen port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -c, --cert FILE                 Certificate file (required)\n");
    fprintf(stderr, "  -k, --key FILE                  Private key file (required)\n");
    fprintf(stderr, "  -v, --verbose                   Verbose logging\n");
    fprintf(stderr, "  -h, --help                      Show this help\n");
}

/* Print statistics */
static void print_stats(void)
{
    time_t now = time(nullptr);
    time_t elapsed = now - g_stats.start_time;

    printf("\n=== Statistics ===\n");
    printf("Uptime: %ld seconds\n", elapsed);
    printf("Total connections: %lu\n", g_stats.connections_accepted);
    printf("Active connections: %lu\n", g_stats.connections_active);
    printf("Handshakes completed: %lu\n", g_stats.handshakes_completed);
    printf("Bytes received: %lu\n", g_stats.bytes_received);
    printf("Bytes sent: %lu\n", g_stats.bytes_sent);

    if (elapsed > 0) {
        printf("Connections/sec: %.2f\n", (double)g_stats.connections_accepted / elapsed);
        printf("Throughput RX: %.2f MB/s\n",
               (double)g_stats.bytes_received / elapsed / 1024 / 1024);
        printf("Throughput TX: %.2f MB/s\n", (double)g_stats.bytes_sent / elapsed / 1024 / 1024);
    }
    printf("==================\n\n");
}

/* Create and bind listening socket */
static int create_listen_socket(int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Set socket options
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sockfd);
        return -1;
    }

    // Bind to address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    // Listen
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    printf("Listening on port %d\n", port);
    return sockfd;
}

/* Handle client connection */
static void handle_client(tls_context_t *ctx, int client_fd, struct sockaddr_in *client_addr,
                          bool verbose)
{
    int ret;
    char buffer[BUFFER_SIZE];

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));

    if (verbose) {
        printf("[%s:%d] Connection accepted\n", client_ip, ntohs(client_addr->sin_port));
    }

    // Create TLS session with cleanup attribute (C23 RAII-like pattern)
    __attribute__((cleanup(tls_session_cleanup))) tls_session_t *session = tls_session_new(ctx);

    if (session == nullptr) {
        fprintf(stderr, "[%s:%d] Failed to create TLS session\n", client_ip,
                ntohs(client_addr->sin_port));
        close(client_fd);
        return;
    }

    // Associate socket with session
    ret = tls_session_set_fd(session, client_fd);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "[%s:%d] Failed to set FD: %s\n", client_ip, ntohs(client_addr->sin_port),
                tls_strerror(ret));
        close(client_fd);
        return;
    }

    // Perform TLS handshake
    if (verbose) {
        printf("[%s:%d] Starting TLS handshake...\n", client_ip, ntohs(client_addr->sin_port));
    }

    while ((ret = tls_handshake(session)) != TLS_E_SUCCESS) {
        if (ret == TLS_E_AGAIN || ret == TLS_E_INTERRUPTED) {
            // Non-blocking I/O - retry
            continue;
        }
        fprintf(stderr, "[%s:%d] Handshake failed: %s\n", client_ip, ntohs(client_addr->sin_port),
                tls_strerror(ret));
        close(client_fd);
        return;
    }

    g_stats.handshakes_completed++;

    // Get connection information
    tls_connection_info_t info;
    if (tls_get_connection_info(session, &info) == TLS_E_SUCCESS) {
        if (verbose) {
            printf("[%s:%d] Handshake complete: %s, resumed=%s\n", client_ip,
                   ntohs(client_addr->sin_port), info.cipher_name,
                   info.session_resumed ? "yes" : "no");
        }
    }

    // Echo loop
    g_stats.connections_active++;

    while (g_running) {
        // Receive data
        ssize_t received = tls_recv(session, buffer, sizeof(buffer));

        if (received == TLS_E_AGAIN || received == TLS_E_INTERRUPTED) {
            // Non-blocking I/O - retry with 10ms delay
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000}; // 10ms
            nanosleep(&ts, nullptr);
            continue;
        }

        if (received <= 0) {
            if (received == 0) {
                if (verbose) {
                    printf("[%s:%d] Connection closed by peer\n", client_ip,
                           ntohs(client_addr->sin_port));
                }
            } else {
                fprintf(stderr, "[%s:%d] Receive error: %s\n", client_ip,
                        ntohs(client_addr->sin_port), tls_strerror(received));
            }
            break;
        }

        g_stats.bytes_received += received;

        if (verbose) {
            printf("[%s:%d] Received %zd bytes\n", client_ip, ntohs(client_addr->sin_port),
                   received);
        }

        // Echo back
        ssize_t sent = tls_send(session, buffer, received);

        if (sent < 0) {
            fprintf(stderr, "[%s:%d] Send error: %s\n", client_ip, ntohs(client_addr->sin_port),
                    tls_strerror(sent));
            break;
        }

        g_stats.bytes_sent += sent;
    }

    g_stats.connections_active--;

    // Graceful shutdown
    (void)tls_bye(session);
    close(client_fd);

    // session will be automatically freed by cleanup attribute
}

/* Main function */
int main(int argc, char **argv)
{
    tls_backend_t backend = TLS_BACKEND_NONE;
    int port = DEFAULT_PORT;
    const char *cert_file = nullptr;
    const char *key_file = nullptr;
    bool verbose = false;

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
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --port requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            char *endptr;
            long val = strtol(argv[i], &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > 65535) {
                fprintf(stderr, "Invalid port: %s\n", argv[i]);
                return 1;
            }
            port = (int)val;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cert") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --cert requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            cert_file = argv[i];
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --key requires an argument\n");
                print_usage(argv[0]);
                return 1;
            }
            key_file = argv[i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
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

    if (cert_file == nullptr) {
        fprintf(stderr, "Error: --cert is required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (key_file == nullptr) {
        fprintf(stderr, "Error: --key is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // Initialize TLS subsystem
    printf("Initializing TLS subsystem (backend: %s)...\n",
           backend == TLS_BACKEND_GNUTLS ? "GnuTLS" : "wolfSSL");

    int ret = tls_global_init(backend);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to initialize TLS: %s\n", tls_strerror(ret));
        return 1;
    }

    printf("TLS library version: %s\n", tls_get_version_string());

    // Create TLS context with cleanup attribute
    __attribute__((cleanup(tls_context_cleanup)))
    tls_context_t *ctx = tls_context_new(true, false); // server, TLS (not DTLS)

    if (ctx == nullptr) {
        fprintf(stderr, "Failed to create TLS context\n");
        tls_global_deinit();
        return 1;
    }

    // Load certificate and key
    printf("Loading certificate from %s...\n", cert_file);
    ret = tls_context_set_cert_file(ctx, cert_file);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to load certificate: %s\n", tls_strerror(ret));
        tls_global_deinit();
        return 1;
    }

    printf("Loading private key from %s...\n", key_file);
    ret = tls_context_set_key_file(ctx, key_file);
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "Failed to load private key: %s\n", tls_strerror(ret));
        tls_global_deinit();
        return 1;
    }

    // Create listening socket
    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        tls_global_deinit();
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    printf("TLS PoC Echo Server ready (press Ctrl+C to stop)\n");
    printf("Backend: %s\n", backend == TLS_BACKEND_GNUTLS ? "GnuTLS" : "wolfSSL");
    printf("Port: %d\n", port);
    printf("Verbose: %s\n\n", verbose ? "yes" : "no");

    g_stats.start_time = time(nullptr);

    // Accept loop
    while (g_running) {
        struct pollfd pfd = {0};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;

        int poll_ret = poll(&pfd, 1, POLL_TIMEOUT_MS);

        if (poll_ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }

        if (poll_ret == 0) {
            // Timeout - print stats
            if (verbose) {
                print_stats();
            }
            continue;
        }

        // Accept connection
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("accept");
            continue;
        }

        g_stats.connections_accepted++;

        // Handle client (simple synchronous handling for PoC)
        // Production code would use fork/thread pool
        handle_client(ctx, client_fd, &client_addr, verbose);
    }

    // Cleanup
    printf("\nShutting down...\n");
    print_stats();

    close(listen_fd);
    tls_global_deinit();

    printf("Goodbye!\n");
    return 0;
}
