/**
 * @file dpd.h
 * @brief Dead Peer Detection (DPD) state machine for OpenConnect VPN.
 *
 * Pure state machine — no I/O, no timers, no threads. The caller drives
 * transitions via on_timeout / on_response / on_request and checks flags
 * (need_send_request, need_send_response) to decide what to send.
 */

#ifndef WOLFGUARD_NETWORK_DPD_H
#define WOLFGUARD_NETWORK_DPD_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/** Default DPD probe interval in seconds. */
constexpr uint32_t WG_DPD_DEFAULT_INTERVAL_S = 30;

/** Default maximum retry count before declaring peer dead. */
constexpr uint32_t WG_DPD_DEFAULT_MAX_RETRIES = 3;

/** DPD probe state. */
typedef enum : uint8_t {
	WG_DPD_IDLE,
	WG_DPD_PENDING,
	WG_DPD_DEAD,
} wg_dpd_state_t;

/** VPN channel state (CSTP vs DTLS). */
typedef enum : uint8_t {
	WG_CHANNEL_CSTP_ONLY,
	WG_CHANNEL_DTLS_PRIMARY,
	WG_CHANNEL_DTLS_FALLBACK,
} wg_channel_state_t;

/** DPD context — pure state machine, no I/O. */
typedef struct {
	wg_dpd_state_t state;
	wg_channel_state_t channel;
	uint32_t interval_s;
	uint32_t max_retries;
	uint32_t retry_count;
	uint16_t sequence;
	time_t last_send;
	time_t last_recv;
	bool need_send_response;
	bool need_send_request;
} wg_dpd_ctx_t;

/**
 * @brief Initialize DPD context.
 * @param ctx Context to initialize.
 * @param interval_s Probe interval (0 = use default 30s).
 * @param max_retries Max retries (0 = use default 3).
 */
void wg_dpd_init(wg_dpd_ctx_t *ctx, uint32_t interval_s, uint32_t max_retries);

/** Reset DPD state (e.g., after reconnection). */
void wg_dpd_reset(wg_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD timeout (interval elapsed without response).
 *
 * IDLE -> PENDING (retry=1, need_send_request=true).
 * PENDING -> retry++; if retry > max -> DEAD.
 * @param ctx DPD context.
 * @return New state after transition.
 */
[[nodiscard]] wg_dpd_state_t wg_dpd_on_timeout(wg_dpd_ctx_t *ctx);

/**
 * @brief Handle DPD response received from peer.
 *
 * PENDING -> IDLE (retry=0).
 * @param ctx DPD context.
 * @param sequence Sequence number from the response.
 * @return New state after transition.
 */
[[nodiscard]] wg_dpd_state_t wg_dpd_on_response(wg_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Handle DPD request received from peer.
 *
 * Sets need_send_response=true (any state).
 * @param ctx DPD context.
 * @param sequence Sequence number from the request.
 * @return Current state (unchanged).
 */
[[nodiscard]] wg_dpd_state_t wg_dpd_on_request(wg_dpd_ctx_t *ctx, uint16_t sequence);

/**
 * @brief Check if DPD probe should be sent (interval elapsed).
 * @param ctx DPD context.
 * @param now Current time (time(NULL)).
 * @return true if (now - last_send) >= interval_s.
 */
[[nodiscard]] bool wg_dpd_should_probe(const wg_dpd_ctx_t *ctx, time_t now);

/**
 * @brief Get human-readable state name.
 * @param state DPD state value.
 * @return Static string with the state name, or "UNKNOWN".
 */
const char *wg_dpd_state_name(wg_dpd_state_t state);

/**
 * @brief Get human-readable channel state name.
 * @param state Channel state value.
 * @return Static string with the channel state name, or "UNKNOWN".
 */
const char *wg_channel_state_name(wg_channel_state_t state);

#endif /* WOLFGUARD_NETWORK_DPD_H */
