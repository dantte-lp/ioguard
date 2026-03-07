#include "network/dpd.h"

#include <string.h>

void wg_dpd_init(wg_dpd_ctx_t *ctx, uint32_t interval_s, uint32_t max_retries)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = WG_DPD_IDLE;
	ctx->channel = WG_CHANNEL_CSTP_ONLY;
	ctx->interval_s = (interval_s > 0) ? interval_s : WG_DPD_DEFAULT_INTERVAL_S;
	ctx->max_retries = (max_retries > 0) ? max_retries : WG_DPD_DEFAULT_MAX_RETRIES;
}

void wg_dpd_reset(wg_dpd_ctx_t *ctx)
{
	ctx->state = WG_DPD_IDLE;
	ctx->retry_count = 0;
	ctx->need_send_request = false;
	ctx->need_send_response = false;
}

wg_dpd_state_t wg_dpd_on_timeout(wg_dpd_ctx_t *ctx)
{
	switch (ctx->state) {
	case WG_DPD_IDLE:
		ctx->state = WG_DPD_PENDING;
		ctx->retry_count = 1;
		ctx->need_send_request = true;
		ctx->sequence++;
		break;
	case WG_DPD_PENDING:
		ctx->retry_count++;
		if (ctx->retry_count > ctx->max_retries) {
			ctx->state = WG_DPD_DEAD;
		} else {
			ctx->need_send_request = true;
		}
		break;
	case WG_DPD_DEAD:
		break;
	}
	return ctx->state;
}

wg_dpd_state_t wg_dpd_on_response(wg_dpd_ctx_t *ctx, uint16_t sequence)
{
	(void)sequence;
	if (ctx->state == WG_DPD_PENDING) {
		ctx->state = WG_DPD_IDLE;
		ctx->retry_count = 0;
		ctx->last_recv = time(nullptr);
	}
	return ctx->state;
}

wg_dpd_state_t wg_dpd_on_request(wg_dpd_ctx_t *ctx, uint16_t sequence)
{
	(void)sequence;
	ctx->need_send_response = true;
	ctx->last_recv = time(nullptr);
	return ctx->state;
}

bool wg_dpd_should_probe(const wg_dpd_ctx_t *ctx, time_t now)
{
	return (now - ctx->last_send) >= (time_t)ctx->interval_s;
}

const char *wg_dpd_state_name(wg_dpd_state_t state)
{
	switch (state) {
	case WG_DPD_IDLE:    return "IDLE";
	case WG_DPD_PENDING: return "PENDING";
	case WG_DPD_DEAD:    return "DEAD";
	default:             return "UNKNOWN";
	}
}

const char *wg_channel_state_name(wg_channel_state_t state)
{
	switch (state) {
	case WG_CHANNEL_CSTP_ONLY:     return "CSTP_ONLY";
	case WG_CHANNEL_DTLS_PRIMARY:  return "DTLS_PRIMARY";
	case WG_CHANNEL_DTLS_FALLBACK: return "DTLS_FALLBACK";
	default:                       return "UNKNOWN";
	}
}
