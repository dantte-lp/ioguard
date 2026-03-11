/**
 * @file wolfsentry.c
 * @brief wolfSentry IDPS integration — connection checking, JSON config, ban/unban.
 */

#include "security/wolfsentry.h"
#include <wolfsentry/wolfsentry_json.h>
#include <wolfsentry/wolfsentry_util.h>

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

/** Convert address family to address length in bits. */
static int addr_bits_for_af(int af)
{
    switch (af) {
    case AF_INET:
        return 32;
    case AF_INET6:
        return 128;
    default:
        return -1;
    }
}

/** Convert address family to byte length. */
static int addr_bytes_for_af(int af)
{
    switch (af) {
    case AF_INET:
        return 4;
    case AF_INET6:
        return 16;
    default:
        return -1;
    }
}

int iog_wolfsentry_init(iog_wolfsentry_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -EINVAL;
    }

    ctx->ws_ctx = nullptr;

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return -ENOMEM;
    }

    struct wolfsentry_eventconfig default_config = {
        .route_private_data_size = 0,
        .route_private_data_alignment = 0,
        .max_connection_count = 0,
        .derogatory_threshold_for_penaltybox = 0,
        .penaltybox_duration = 0,
        .route_idle_time_for_purge = 0,
        .flags = WOLFSENTRY_EVENTCONFIG_FLAG_NONE,
    };

    wolfsentry_errcode_t ret = wolfsentry_init(wolfsentry_build_settings,
                                               WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(nullptr, thread),
                                               &default_config, &ctx->ws_ctx);

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);

    if (ret < 0) {
        return -ENOMEM;
    }

    return 0;
}

void iog_wolfsentry_close(iog_wolfsentry_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->ws_ctx == nullptr) {
        return;
    }

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return;
    }

    wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&ctx->ws_ctx, thread));

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);
}

int iog_wolfsentry_load_json(iog_wolfsentry_ctx_t *ctx, const char *json, size_t json_len)
{
    if (ctx == nullptr || ctx->ws_ctx == nullptr) {
        return -EINVAL;
    }
    if (json == nullptr || json_len == 0) {
        return -EINVAL;
    }

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return -ENOMEM;
    }

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));
    wolfsentry_errcode_t ret = wolfsentry_config_json_oneshot(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx->ws_ctx, thread), (const unsigned char *)json, json_len,
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE, err_buf, sizeof(err_buf));

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);

    if (ret < 0) {
        return -EINVAL;
    }

    return 0;
}

iog_ws_result_t iog_wolfsentry_check_connection(iog_wolfsentry_ctx_t *ctx, int af,
                                              const void *remote_addr, uint16_t remote_port,
                                              const void *local_addr, uint16_t local_port,
                                              int protocol)
{
    if (ctx == nullptr || ctx->ws_ctx == nullptr) {
        return IOG_WS_ERROR;
    }

    int addr_bits = addr_bits_for_af(af);
    int addr_bytes = addr_bytes_for_af(af);
    if (addr_bits < 0) {
        return IOG_WS_ERROR;
    }

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return IOG_WS_ERROR;
    }

    WOLFSENTRY_SOCKADDR(128) remote_sa;
    WOLFSENTRY_SOCKADDR(128) local_sa;

    memset(&remote_sa, 0, sizeof(remote_sa));
    memset(&local_sa, 0, sizeof(local_sa));

    remote_sa.sa_family = (wolfsentry_addr_family_t)af;
    remote_sa.sa_proto = (wolfsentry_proto_t)protocol;
    remote_sa.sa_port = remote_port;
    remote_sa.addr_len = (wolfsentry_addr_bits_t)addr_bits;
    memcpy(remote_sa.addr, remote_addr, (size_t)addr_bytes);

    local_sa.sa_family = (wolfsentry_addr_family_t)af;
    local_sa.sa_proto = (wolfsentry_proto_t)protocol;
    local_sa.sa_port = local_port;
    local_sa.addr_len = (wolfsentry_addr_bits_t)addr_bits;
    memcpy(local_sa.addr, local_addr, (size_t)addr_bytes);

    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    wolfsentry_ent_id_t id = 0;
    wolfsentry_route_flags_t inexact_matches = WOLFSENTRY_ROUTE_FLAG_NONE;

    wolfsentry_errcode_t ret =
        wolfsentry_route_event_dispatch(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx->ws_ctx, thread),
                                        (const struct wolfsentry_sockaddr *)&remote_sa,
                                        (const struct wolfsentry_sockaddr *)&local_sa,
                                        WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN, nullptr, /* event_label
                                                                                      */
                                        0,       /* event_label_len */
                                        nullptr, /* caller_arg */
                                        &id, &inexact_matches, &action_results);

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);

    if (ret < 0) {
        /*
         * If dispatch fails because no route matched AND no default
         * policy is set, we get an error. Treat as ACCEPT (permissive
         * default).
         */
        return IOG_WS_ACCEPT;
    }

    if (WOLFSENTRY_MASKIN_BITS(action_results, WOLFSENTRY_ACTION_RES_REJECT)) {
        return IOG_WS_REJECT;
    }

    return IOG_WS_ACCEPT;
}

int iog_wolfsentry_ban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr)
{
    if (ctx == nullptr || ctx->ws_ctx == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    int addr_bits = addr_bits_for_af(af);
    int addr_bytes = addr_bytes_for_af(af);
    if (addr_bits < 0) {
        return -EINVAL;
    }

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return -ENOMEM;
    }

    WOLFSENTRY_SOCKADDR(128) remote_sa;
    WOLFSENTRY_SOCKADDR(128) local_sa;

    memset(&remote_sa, 0, sizeof(remote_sa));
    memset(&local_sa, 0, sizeof(local_sa));

    remote_sa.sa_family = (wolfsentry_addr_family_t)af;
    remote_sa.sa_proto = 0;
    remote_sa.sa_port = 0;
    remote_sa.addr_len = (wolfsentry_addr_bits_t)addr_bits;
    memcpy(remote_sa.addr, addr, (size_t)addr_bytes);

    local_sa.sa_family = (wolfsentry_addr_family_t)af;
    local_sa.sa_proto = 0;
    local_sa.sa_port = 0;
    local_sa.addr_len = 0;
    local_sa.interface = 0;

    wolfsentry_route_flags_t flags =
        WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED |
        WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;

    wolfsentry_ent_id_t id = 0;
    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;

    wolfsentry_errcode_t ret = wolfsentry_route_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx->ws_ctx, thread), nullptr, /* caller_arg
                                                                        */
        (const struct wolfsentry_sockaddr *)&remote_sa,
        (const struct wolfsentry_sockaddr *)&local_sa, flags, nullptr, /* event_label
                                                                        */
        0,                                                             /* event_label_len */
        &id, &action_results);

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);

    if (ret < 0) {
        return -EEXIST;
    }

    return 0;
}

int iog_wolfsentry_unban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr)
{
    if (ctx == nullptr || ctx->ws_ctx == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    int addr_bits = addr_bits_for_af(af);
    int addr_bytes = addr_bytes_for_af(af);
    if (addr_bits < 0) {
        return -EINVAL;
    }

    WOLFSENTRY_THREAD_HEADER(WOLFSENTRY_THREAD_FLAG_NONE);
    if (_thread_context_ret < 0) {
        return -ENOMEM;
    }

    WOLFSENTRY_SOCKADDR(128) remote_sa;
    WOLFSENTRY_SOCKADDR(128) local_sa;

    memset(&remote_sa, 0, sizeof(remote_sa));
    memset(&local_sa, 0, sizeof(local_sa));

    remote_sa.sa_family = (wolfsentry_addr_family_t)af;
    remote_sa.sa_proto = 0;
    remote_sa.sa_port = 0;
    remote_sa.addr_len = (wolfsentry_addr_bits_t)addr_bits;
    memcpy(remote_sa.addr, addr, (size_t)addr_bytes);

    local_sa.sa_family = (wolfsentry_addr_family_t)af;
    local_sa.sa_proto = 0;
    local_sa.sa_port = 0;
    local_sa.addr_len = 0;
    local_sa.interface = 0;

    wolfsentry_route_flags_t flags =
        WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN | WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED |
        WOLFSENTRY_ROUTE_FLAG_SA_PROTO_WILDCARD | WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_PORT_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_PORT_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_REMOTE_INTERFACE_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_LOCAL_INTERFACE_WILDCARD |
        WOLFSENTRY_ROUTE_FLAG_PARENT_EVENT_WILDCARD;

    wolfsentry_action_res_t action_results = WOLFSENTRY_ACTION_RES_NONE;
    int n_deleted = 0;

    wolfsentry_errcode_t ret = wolfsentry_route_delete(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(ctx->ws_ctx, thread), nullptr, /* caller_arg
                                                                        */
        (const struct wolfsentry_sockaddr *)&remote_sa,
        (const struct wolfsentry_sockaddr *)&local_sa, flags, nullptr, /* trigger_label
                                                                        */
        0,                                                             /* trigger_label_len */
        &action_results, &n_deleted);

    WOLFSENTRY_THREAD_TAILER(WOLFSENTRY_THREAD_FLAG_NONE);

    if (ret < 0) {
        return -ENOENT;
    }

    return 0;
}
