#include "network/dpd.h"

#include <string.h>

void iog_dpd_init(iog_dpd_ctx_t *ctx, uint32_t interval_s, uint32_t max_retries)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = IOG_DPD_IDLE;
    ctx->channel = IOG_CHANNEL_CSTP_ONLY;
    ctx->interval_s = (interval_s > 0) ? interval_s : IOG_DPD_DEFAULT_INTERVAL_S;
    ctx->max_retries = (max_retries > 0) ? max_retries : IOG_DPD_DEFAULT_MAX_RETRIES;
}

void iog_dpd_reset(iog_dpd_ctx_t *ctx)
{
    ctx->state = IOG_DPD_IDLE;
    ctx->retry_count = 0;
    ctx->need_send_request = false;
    ctx->need_send_response = false;
}

iog_dpd_state_t iog_dpd_on_timeout(iog_dpd_ctx_t *ctx)
{
    switch (ctx->state) {
    case IOG_DPD_IDLE:
        ctx->state = IOG_DPD_PENDING;
        ctx->retry_count = 1;
        ctx->need_send_request = true;
        ctx->sequence++;
        break;
    case IOG_DPD_PENDING:
        ctx->retry_count++;
        if (ctx->retry_count > ctx->max_retries) {
            ctx->state = IOG_DPD_DEAD;
        } else {
            ctx->need_send_request = true;
        }
        break;
    case IOG_DPD_DEAD:
        break;
    }
    return ctx->state;
}

iog_dpd_state_t iog_dpd_on_response(iog_dpd_ctx_t *ctx, uint16_t sequence)
{
    (void)sequence;
    if (ctx->state == IOG_DPD_PENDING) {
        ctx->state = IOG_DPD_IDLE;
        ctx->retry_count = 0;
        ctx->last_recv = time(nullptr);
    }
    return ctx->state;
}

iog_dpd_state_t iog_dpd_on_request(iog_dpd_ctx_t *ctx, uint16_t sequence)
{
    (void)sequence;
    ctx->need_send_response = true;
    ctx->last_recv = time(nullptr);
    return ctx->state;
}

bool iog_dpd_should_probe(const iog_dpd_ctx_t *ctx, time_t now)
{
    return (now - ctx->last_send) >= (time_t)ctx->interval_s;
}

const char *iog_dpd_state_name(iog_dpd_state_t state)
{
    switch (state) {
    case IOG_DPD_IDLE:
        return "IDLE";
    case IOG_DPD_PENDING:
        return "PENDING";
    case IOG_DPD_DEAD:
        return "DEAD";
    default:
        return "UNKNOWN";
    }
}

const char *iog_channel_state_name(iog_channel_state_t state)
{
    switch (state) {
    case IOG_CHANNEL_CSTP_ONLY:
        return "CSTP_ONLY";
    case IOG_CHANNEL_DTLS_PRIMARY:
        return "DTLS_PRIMARY";
    case IOG_CHANNEL_DTLS_FALLBACK:
        return "DTLS_FALLBACK";
    default:
        return "UNKNOWN";
    }
}
