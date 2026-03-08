/**
 * @file channel.h
 * @brief CSTP/DTLS channel switching state machine.
 *
 * Pure state machine for routing VPN data over CSTP (TCP/TLS) or
 * DTLS (UDP). CSTP is always active as fallback. DTLS is primary
 * when available.
 */

#ifndef RINGWALL_NETWORK_CHANNEL_H
#define RINGWALL_NETWORK_CHANNEL_H

#include "network/compress.h"
#include "network/dpd.h"

constexpr uint32_t RW_CHANNEL_DEFAULT_MAX_FAILS = 3;

typedef struct {
    rw_channel_state_t state;
    bool cstp_active;
    bool dtls_active;
    uint32_t dtls_fail_count;
    uint32_t dtls_max_fails;
    rw_compress_type_t compress_type;
} rw_channel_ctx_t;

/** Initialize channel context (starts CSTP_ONLY). */
void rw_channel_init(rw_channel_ctx_t *ctx);

/** DTLS handshake succeeded — switch to DTLS_PRIMARY. */
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_up(rw_channel_ctx_t *ctx);

/** DTLS failed (DPD timeout, error) — switch to DTLS_FALLBACK or CSTP_ONLY. */
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_down(rw_channel_ctx_t *ctx);

/** DTLS recovered from fallback — switch back to DTLS_PRIMARY. */
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_recovery(rw_channel_ctx_t *ctx);

/** Should data be sent over DTLS? */
[[nodiscard]] bool rw_channel_use_dtls(const rw_channel_ctx_t *ctx);

/** Get current channel state name. */
[[nodiscard]] const char *rw_channel_state_str(const rw_channel_ctx_t *ctx);

#endif /* RINGWALL_NETWORK_CHANNEL_H */
