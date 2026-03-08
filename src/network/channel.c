#include "network/channel.h"

void wg_channel_init(wg_channel_ctx_t *ctx)
{
	*ctx = (wg_channel_ctx_t){
		.state = WG_CHANNEL_CSTP_ONLY,
		.cstp_active = true,
		.dtls_active = false,
		.dtls_fail_count = 0,
		.dtls_max_fails = WG_CHANNEL_DEFAULT_MAX_FAILS,
		.compress_type = WG_COMPRESS_NONE,
	};
}

wg_channel_state_t wg_channel_on_dtls_up(wg_channel_ctx_t *ctx)
{
	ctx->state = WG_CHANNEL_DTLS_PRIMARY;
	ctx->dtls_active = true;
	ctx->dtls_fail_count = 0;
	return ctx->state;
}

wg_channel_state_t wg_channel_on_dtls_down(wg_channel_ctx_t *ctx)
{
	ctx->dtls_fail_count++;
	if (ctx->dtls_fail_count >= ctx->dtls_max_fails) {
		ctx->state = WG_CHANNEL_CSTP_ONLY;
		ctx->dtls_active = false;
	} else {
		ctx->state = WG_CHANNEL_DTLS_FALLBACK;
		ctx->dtls_active = false;
	}
	return ctx->state;
}

wg_channel_state_t wg_channel_on_dtls_recovery(wg_channel_ctx_t *ctx)
{
	ctx->state = WG_CHANNEL_DTLS_PRIMARY;
	ctx->dtls_active = true;
	ctx->dtls_fail_count = 0;
	return ctx->state;
}

bool wg_channel_use_dtls(const wg_channel_ctx_t *ctx)
{
	return ctx->dtls_active && ctx->state == WG_CHANNEL_DTLS_PRIMARY;
}

const char *wg_channel_state_str(const wg_channel_ctx_t *ctx)
{
	return wg_channel_state_name(ctx->state);
}
