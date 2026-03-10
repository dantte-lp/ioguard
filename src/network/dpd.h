/**
 * @file dpd.h
 * @brief Dead Peer Detection (DPD) state machine for OpenConnect VPN.
 *
 * Pure state machine — no I/O, no timers, no threads. The caller drives
 * transitions via on_timeout / on_response / on_request and checks flags
 * (need_send_request, need_send_response) to decide what to send.
 */

#ifndef RINGWALL_NETWORK_DPD_H
#define RINGWALL_NETWORK_DPD_H

#include <stdint.h>
#include <time.h>

/** Default DPD probe interval in seconds. */
constexpr uint32_t RW_DPD_DEFAULT_INTERVAL_S = 30;

/** Default maximum retry count before declaring peer dead. */
constexpr uint32_t RW_DPD_DEFAULT_MAX_RETRIES = 3;

/** DPD probe state. */
typedef enum : uint8_t {
    RW_DPD_IDLE,
    RW_DPD_PENDING,
    RW_DPD_DEAD,
} rw_dpd_state_t;

/** VPN channel state (CSTP vs DTLS). */
typedef enum : uint8_t {
    RW_CHANNEL_CSTP_ONLY,
    RW_CHANNEL_DTLS_PRIMARY,
    RW_CHANNEL_DTLS_FALLBACK,
} rw_channel_state_t;

/** DPD context — pure state machine, no I/O. */
typedef struct {
    rw_dpd_state_t state;
    rw_channel_state_t channel;
    uint32_t interval_s;
    uint32_t max_retries;
    uint32_t retry_count;
    uint16_t sequence;
    time_t last_send;
    time_t last_recv;
    bool need_send_response;
    bool need_send_request;
} rw_dpd_ctx_t;

/**
 * @brief Initialize DPD context.
 * @param ctx Context to initialize.
 * @param interval_s Probe interval (0 = use default 30s).
 * @param max_retries Max retries (0 = use default 3).
 */
void rw_dpd_init(rw_dpd_ctx_t *ctx, uint32_t interval_s, uint32_t max_retries);

/** Reset DPD state (e.g., after reconnection). */
void rw_dpd_reset(rw_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD timeout (interval elapsed without response).
 *
 * IDLE -> PENDING (retry=1, need_send_request=true).
 * PENDING -> retry++; if retry > max -> DEAD.
 * @param ctx DPD context.
 * @return New state after transition.
 */
[[nodiscard]] rw_dpd_state_t rw_dpd_on_timeout(rw_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD response received from peer.
 *
 * PENDING -> IDLE (retry=0).
 * @param ctx DPD context.
 * @param sequence Sequence number from the response.
 * @return New state after transition.
 */
[[nodiscard]] rw_dpd_state_t rw_dpd_on_response(rw_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Handle DPD request received from peer.
 *
 * Sets need_send_response=true (any state).
 * @param ctx DPD context.
 * @param sequence Sequence number from the request.
 * @return Current state (unchanged).
 */
[[nodiscard]] rw_dpd_state_t rw_dpd_on_request(rw_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Check if DPD probe should be sent (interval elapsed).
 * @param ctx DPD context.
 * @param now Current time (time(NULL)).
 * @return true if (now - last_send) >= interval_s.
 */
[[nodiscard]] bool rw_dpd_should_probe(const rw_dpd_ctx_t *ctx, time_t now);

/**
 * @brief Get human-readable state name.
 * @param state DPD state value.
 * @return Static string with the state name, or "UNKNOWN".
 */
const char *rw_dpd_state_name(rw_dpd_state_t state);

/**
 * @brief Get human-readable channel state name.
 * @param state Channel state value.
 * @return Static string with the channel state name, or "UNKNOWN".
 */
const char *rw_channel_state_name(rw_channel_state_t state);

#endif /* RINGWALL_NETWORK_DPD_H */
