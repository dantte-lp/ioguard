/**
 * @file wolfsentry.h
 * @brief wolfSentry IDPS integration — connection checking, JSON config, ban/unban.
 *
 * Wraps wolfSentry 1.6.x for dynamic firewall rules, rate limiting,
 * and connection tracking in front of TLS handshake.
 */

#ifndef IOGUARD_SECURITY_WOLFSENTRY_H
#define IOGUARD_SECURITY_WOLFSENTRY_H

#include <netinet/in.h>
#include <stdint.h>
#include <wolfsentry/wolfsentry.h>

/** Opaque wrapper around a wolfSentry context. */
typedef struct {
    struct wolfsentry_context *ws_ctx;
} iog_wolfsentry_ctx_t;

/** Result of a connection check. */
typedef enum : uint8_t {
    IOG_WS_ACCEPT = 0,
    IOG_WS_REJECT = 1,
    IOG_WS_ERROR = 2,
} iog_ws_result_t;

/**
 * @brief Initialize a wolfSentry context with default configuration.
 * @param ctx Pointer to context wrapper (caller-allocated).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_wolfsentry_init(iog_wolfsentry_ctx_t *ctx);

/**
 * @brief Shut down and free a wolfSentry context.
 * @param ctx Context to close; ws_ctx set to nullptr on return.
 */
void iog_wolfsentry_close(iog_wolfsentry_ctx_t *ctx);

/**
 * @brief Load JSON configuration into the wolfSentry context.
 * @param ctx  Initialized context.
 * @param json JSON config string (not NUL-terminated required).
 * @param json_len Length of @p json in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_wolfsentry_load_json(iog_wolfsentry_ctx_t *ctx, const char *json,
                                           size_t json_len);

/**
 * @brief Check whether a connection should be accepted or rejected.
 * @param ctx         Initialized context.
 * @param af          Address family (AF_INET or AF_INET6).
 * @param remote_addr Pointer to binary remote address (4 or 16 bytes).
 * @param remote_port Remote port in host byte order.
 * @param local_addr  Pointer to binary local address (4 or 16 bytes).
 * @param local_port  Local port in host byte order.
 * @param protocol    IP protocol number (e.g. IPPROTO_TCP).
 * @return IOG_WS_ACCEPT, IOG_WS_REJECT, or IOG_WS_ERROR.
 */
[[nodiscard]] iog_ws_result_t iog_wolfsentry_check_connection(iog_wolfsentry_ctx_t *ctx, int af,
                                                              const void *remote_addr,
                                                              uint16_t remote_port,
                                                              const void *local_addr,
                                                              uint16_t local_port, int protocol);

/**
 * @brief Ban an IP address by inserting a penalty-boxed route.
 * @param ctx  Initialized context.
 * @param af   Address family (AF_INET or AF_INET6).
 * @param addr Pointer to binary address (4 or 16 bytes).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_wolfsentry_ban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr);

/**
 * @brief Remove a ban for an IP address.
 * @param ctx  Initialized context.
 * @param af   Address family (AF_INET or AF_INET6).
 * @param addr Pointer to binary address (4 or 16 bytes).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_wolfsentry_unban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr);

#endif /* IOGUARD_SECURITY_WOLFSENTRY_H */
