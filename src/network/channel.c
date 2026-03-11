#include "network/channel.h"

void iog_channel_init(iog_channel_ctx_t *ctx)
{
    *ctx = (iog_channel_ctx_t){
        .state = IOG_CHANNEL_CSTP_ONLY,
        .cstp_active = true,
        .dtls_active = false,
        .dtls_fail_count = 0,
        .dtls_max_fails = IOG_CHANNEL_DEFAULT_MAX_FAILS,
        .compress_type = IOG_COMPRESS_NONE,
    };
}

iog_channel_state_t iog_channel_on_dtls_up(iog_channel_ctx_t *ctx)
{
    ctx->state = IOG_CHANNEL_DTLS_PRIMARY;
    ctx->dtls_active = true;
    ctx->dtls_fail_count = 0;
    return ctx->state;
}

iog_channel_state_t iog_channel_on_dtls_down(iog_channel_ctx_t *ctx)
{
    ctx->dtls_fail_count++;
    if (ctx->dtls_fail_count >= ctx->dtls_max_fails) {
        ctx->state = IOG_CHANNEL_CSTP_ONLY;
        ctx->dtls_active = false;
    } else {
        ctx->state = IOG_CHANNEL_DTLS_FALLBACK;
        ctx->dtls_active = false;
    }
    return ctx->state;
}

iog_channel_state_t iog_channel_on_dtls_recovery(iog_channel_ctx_t *ctx)
{
    ctx->state = IOG_CHANNEL_DTLS_PRIMARY;
    ctx->dtls_active = true;
    ctx->dtls_fail_count = 0;
    return ctx->state;
}

bool iog_channel_use_dtls(const iog_channel_ctx_t *ctx)
{
    return ctx->dtls_active && ctx->state == IOG_CHANNEL_DTLS_PRIMARY;
}

const char *iog_channel_state_str(const iog_channel_ctx_t *ctx)
{
    return iog_channel_state_name(ctx->state);
}
