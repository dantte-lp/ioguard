#ifndef RINGWALL_CORE_CONN_TIMER_H
#define RINGWALL_CORE_CONN_TIMER_H

#include "core/conn_data.h"
#include "network/dpd.h"

#include <stdint.h>
#include <time.h>

/**
 * @brief Callback invoked when DPD declares peer dead.
 *
 * @param conn_id  Connection identifier.
 * @param user_data  Caller-supplied context.
 */
typedef void (*rw_conn_dead_cb)(uint64_t conn_id, void *user_data);

/**
 * @brief Per-connection timer state for DPD, keepalive, and idle timeout.
 *
 * Drives the DPD state machine via periodic ticks, sends keepalives,
 * and detects idle connections. Designed for testability: tick handlers
 * are public so tests can invoke them without io_uring.
 */
typedef struct {
    rw_dpd_ctx_t *dpd;
    iog_conn_data_t *data;
    uint64_t conn_id;
    uint32_t dpd_interval_ms;
    uint32_t keepalive_interval_ms;
    uint32_t idle_timeout_ms;
    rw_conn_dead_cb on_dead;
    void *on_dead_user_data;
    time_t last_activity;
    bool active;
} iog_conn_timer_t;

/**
 * @brief Configuration for timer initialization.
 */
typedef struct {
    rw_dpd_ctx_t *dpd;
    iog_conn_data_t *data;
    uint64_t conn_id;
    uint32_t dpd_interval_s;
    uint32_t keepalive_interval_s;
    uint32_t idle_timeout_s;
    rw_conn_dead_cb on_dead;
    void *on_dead_user_data;
} iog_conn_timer_config_t;

/**
 * @brief Initialize timer state.
 *
 * @param timer  Timer context (caller-owned).
 * @param cfg    Configuration with intervals and callbacks.
 * @return 0 on success, -EINVAL on bad params.
 */
[[nodiscard]] int iog_conn_timer_init(iog_conn_timer_t *timer, const iog_conn_timer_config_t *cfg);

/**
 * @brief Handle DPD timer tick.
 *
 * Drives the DPD state machine: IDLE → send probe, PENDING → retry or DEAD.
 * If DEAD, invokes the on_dead callback.
 *
 * @param timer  Timer context.
 * @return 0 on success, 1 if peer declared dead, negative errno on error.
 */
[[nodiscard]] int iog_conn_timer_handle_dpd(iog_conn_timer_t *timer);

/**
 * @brief Handle keepalive timer tick.
 *
 * Sends a CSTP keepalive via the data path.
 *
 * @param timer  Timer context.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_conn_timer_handle_keepalive(iog_conn_timer_t *timer);

/**
 * @brief Check if connection has exceeded idle timeout.
 *
 * @param timer  Timer context.
 * @param now    Current time.
 * @return true if idle timeout exceeded.
 */
[[nodiscard]] bool iog_conn_timer_is_idle(const iog_conn_timer_t *timer, time_t now);

/**
 * @brief Record activity on the connection (data received/sent).
 *
 * Resets the idle timeout and DPD last_recv timestamp.
 *
 * @param timer  Timer context.
 */
void iog_conn_timer_on_activity(iog_conn_timer_t *timer);

/**
 * @brief Deactivate timers.
 *
 * @param timer  Timer context.
 */
void iog_conn_timer_stop(iog_conn_timer_t *timer);

#endif /* RINGWALL_CORE_CONN_TIMER_H */
