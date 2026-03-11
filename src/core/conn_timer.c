#include "core/conn_timer.h"

#include "network/cstp.h"

#include <errno.h>
#include <time.h>

int iog_conn_timer_init(iog_conn_timer_t *timer, const iog_conn_timer_config_t *cfg)
{
    if (timer == nullptr || cfg == nullptr) {
        return -EINVAL;
    }
    if (cfg->dpd == nullptr || cfg->data == nullptr) {
        return -EINVAL;
    }

    timer->dpd = cfg->dpd;
    timer->data = cfg->data;
    timer->conn_id = cfg->conn_id;
    timer->dpd_interval_ms = cfg->dpd_interval_s * 1000;
    timer->keepalive_interval_ms = cfg->keepalive_interval_s * 1000;
    timer->idle_timeout_ms = cfg->idle_timeout_s * 1000;
    timer->on_dead = cfg->on_dead;
    timer->on_dead_user_data = cfg->on_dead_user_data;
    timer->last_activity = time(nullptr);
    timer->active = true;

    return 0;
}

int iog_conn_timer_handle_dpd(iog_conn_timer_t *timer)
{
    if (timer == nullptr || !timer->active) {
        return -EINVAL;
    }

    iog_dpd_state_t state = iog_dpd_on_timeout(timer->dpd);

    if (state == IOG_DPD_DEAD) {
        if (timer->on_dead != nullptr) {
            timer->on_dead(timer->conn_id, timer->on_dead_user_data);
        }
        timer->active = false;
        return 1; /* peer dead */
    }

    /* DPD state machine sets need_send_request on timeout.
     * Send directly via conn_data keepalive-style path — do NOT use
     * iog_conn_data_send_dpd_req() which redundantly calls iog_dpd_on_timeout(). */
    if (timer->dpd->need_send_request) {
        uint8_t buf[IOG_CSTP_HEADER_SIZE];
        int encoded = iog_cstp_encode(buf, sizeof(buf), IOG_CSTP_DPD_REQ, nullptr, 0);
        if (encoded > 0) {
            (void)timer->data->tls_write(timer->data->tls_ctx, buf, (size_t)encoded);
        }
        timer->dpd->need_send_request = false;
    }

    return 0;
}

int iog_conn_timer_handle_keepalive(iog_conn_timer_t *timer)
{
    if (timer == nullptr || !timer->active) {
        return -EINVAL;
    }

    return iog_conn_data_send_keepalive(timer->data);
}

bool iog_conn_timer_is_idle(const iog_conn_timer_t *timer, time_t now)
{
    if (timer == nullptr || timer->idle_timeout_ms == 0) {
        return false;
    }

    double elapsed_ms = difftime(now, timer->last_activity) * 1000.0;
    return elapsed_ms >= (double)timer->idle_timeout_ms;
}

void iog_conn_timer_on_activity(iog_conn_timer_t *timer)
{
    if (timer == nullptr) {
        return;
    }

    timer->last_activity = time(nullptr);

    /* Reset DPD state on activity — peer is alive */
    if (timer->dpd != nullptr && timer->dpd->state == IOG_DPD_PENDING) {
        (void)iog_dpd_on_response(timer->dpd, timer->dpd->sequence);
    }
}

void iog_conn_timer_stop(iog_conn_timer_t *timer)
{
    if (timer == nullptr) {
        return;
    }
    timer->active = false;
}
