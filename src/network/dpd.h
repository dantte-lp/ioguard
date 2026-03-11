/**
 * @file dpd.h
 * @brief Dead Peer Detection (DPD) state machine for OpenConnect VPN.
 *
 * Pure state machine — no I/O, no timers, no threads. The caller drives
 * transitions via on_timeout / on_response / on_request and checks flags
 * (need_send_request, need_send_response) to decide what to send.
 */

#ifndef IOGUARD_NETWORK_DPD_H
#define IOGUARD_NETWORK_DPD_H

#include <stdint.h>
#include <time.h>

/** Default DPD probe interval in seconds. */
constexpr uint32_t IOG_DPD_DEFAULT_INTERVAL_S = 30;

/** Default maximum retry count before declaring peer dead. */
constexpr uint32_t IOG_DPD_DEFAULT_MAX_RETRIES = 3;

/** DPD probe state. */
typedef enum : uint8_t {
    IOG_DPD_IDLE,
    IOG_DPD_PENDING,
    IOG_DPD_DEAD,
} iog_dpd_state_t;

/** VPN channel state (CSTP vs DTLS). */
typedef enum : uint8_t {
    IOG_CHANNEL_CSTP_ONLY,
    IOG_CHANNEL_DTLS_PRIMARY,
    IOG_CHANNEL_DTLS_FALLBACK,
} iog_channel_state_t;

/** DPD context — pure state machine, no I/O. */
typedef struct {
    iog_dpd_state_t state;
    iog_channel_state_t channel;
    uint32_t interval_s;
    uint32_t max_retries;
    uint32_t retry_count;
    uint16_t sequence;
    time_t last_send;
    time_t last_recv;
    bool need_send_response;
    bool need_send_request;
} iog_dpd_ctx_t;

/**
 * @brief Initialize DPD context.
 * @param ctx Context to initialize.
 * @param interval_s Probe interval (0 = use default 30s).
 * @param max_retries Max retries (0 = use default 3).
 */
void iog_dpd_init(iog_dpd_ctx_t *ctx, uint32_t interval_s, uint32_t max_retries);

/** Reset DPD state (e.g., after reconnection). */
void iog_dpd_reset(iog_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD timeout (interval elapsed without response).
 *
 * IDLE -> PENDING (retry=1, need_send_request=true).
 * PENDING -> retry++; if retry > max -> DEAD.
 * @param ctx DPD context.
 * @return New state after transition.
 */
[[nodiscard]] iog_dpd_state_t iog_dpd_on_timeout(iog_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD response received from peer.
 *
 * PENDING -> IDLE (retry=0).
 * @param ctx DPD context.
 * @param sequence Sequence number from the response.
 * @return New state after transition.
 */
[[nodiscard]] iog_dpd_state_t iog_dpd_on_response(iog_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Handle DPD request received from peer.
 *
 * Sets need_send_response=true (any state).
 * @param ctx DPD context.
 * @param sequence Sequence number from the request.
 * @return Current state (unchanged).
 */
[[nodiscard]] iog_dpd_state_t iog_dpd_on_request(iog_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Check if DPD probe should be sent (interval elapsed).
 * @param ctx DPD context.
 * @param now Current time (time(NULL)).
 * @return true if (now - last_send) >= interval_s.
 */
[[nodiscard]] bool iog_dpd_should_probe(const iog_dpd_ctx_t *ctx, time_t now);

/**
 * @brief Get human-readable state name.
 * @param state DPD state value.
 * @return Static string with the state name, or "UNKNOWN".
 */
const char *iog_dpd_state_name(iog_dpd_state_t state);

/**
 * @brief Get human-readable channel state name.
 * @param state Channel state value.
 * @return Static string with the channel state name, or "UNKNOWN".
 */
const char *iog_channel_state_name(iog_channel_state_t state);

#endif /* IOGUARD_NETWORK_DPD_H */
