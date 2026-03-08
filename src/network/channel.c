#include "network/channel.h"

void rw_channel_init(rw_channel_ctx_t *ctx)
{
	*ctx = (rw_channel_ctx_t){
		.state = RW_CHANNEL_CSTP_ONLY,
		.cstp_active = true,
		.dtls_active = false,
		.dtls_fail_count = 0,
		.dtls_max_fails = RW_CHANNEL_DEFAULT_MAX_FAILS,
		.compress_type = RW_COMPRESS_NONE,
	};
}

rw_channel_state_t rw_channel_on_dtls_up(rw_channel_ctx_t *ctx)
{
	ctx->state = RW_CHANNEL_DTLS_PRIMARY;
	ctx->dtls_active = true;
	ctx->dtls_fail_count = 0;
	return ctx->state;
}

rw_channel_state_t rw_channel_on_dtls_down(rw_channel_ctx_t *ctx)
{
	ctx->dtls_fail_count++;
	if (ctx->dtls_fail_count >= ctx->dtls_max_fails) {
		ctx->state = RW_CHANNEL_CSTP_ONLY;
		ctx->dtls_active = false;
	} else {
		ctx->state = RW_CHANNEL_DTLS_FALLBACK;
		ctx->dtls_active = false;
	}
	return ctx->state;
}

rw_channel_state_t rw_channel_on_dtls_recovery(rw_channel_ctx_t *ctx)
{
	ctx->state = RW_CHANNEL_DTLS_PRIMARY;
	ctx->dtls_active = true;
	ctx->dtls_fail_count = 0;
	return ctx->state;
}

bool rw_channel_use_dtls(const rw_channel_ctx_t *ctx)
{
	return ctx->dtls_active && ctx->state == RW_CHANNEL_DTLS_PRIMARY;
}

const char *rw_channel_state_str(const rw_channel_ctx_t *ctx)
{
	return rw_channel_state_name(ctx->state);
}
