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

constexpr uint32_t IOG_CHANNEL_DEFAULT_MAX_FAILS = 3;

typedef struct {
    iog_channel_state_t state;
    bool cstp_active;
    bool dtls_active;
    uint32_t dtls_fail_count;
    uint32_t dtls_max_fails;
    iog_compress_type_t compress_type;
} iog_channel_ctx_t;

/** Initialize channel context (starts CSTP_ONLY). */
void iog_channel_init(iog_channel_ctx_t *ctx);

/** DTLS handshake succeeded — switch to DTLS_PRIMARY. */
[[nodiscard]] iog_channel_state_t iog_channel_on_dtls_up(iog_channel_ctx_t *ctx);

/** DTLS failed (DPD timeout, error) — switch to DTLS_FALLBACK or CSTP_ONLY. */
[[nodiscard]] iog_channel_state_t iog_channel_on_dtls_down(iog_channel_ctx_t *ctx);

/** DTLS recovered from fallback — switch back to DTLS_PRIMARY. */
[[nodiscard]] iog_channel_state_t iog_channel_on_dtls_recovery(iog_channel_ctx_t *ctx);

/** Should data be sent over DTLS? */
[[nodiscard]] bool iog_channel_use_dtls(const iog_channel_ctx_t *ctx);

/** Get current channel state name. */
[[nodiscard]] const char *iog_channel_state_str(const iog_channel_ctx_t *ctx);

#endif /* RINGWALL_NETWORK_CHANNEL_H */
