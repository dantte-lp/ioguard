#include "core/conn_data.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/* Decompress data payload if using compressed CSTP type, write to TUN */
static int handle_data_packet(iog_conn_data_t *data, const iog_cstp_packet_t *pkt)
{
    const uint8_t *payload = pkt->payload;
    size_t payload_len = pkt->payload_len;

    /* Decompress if COMPRESSED type and compressor available */
    uint8_t decomp_buf[IOG_CSTP_MAX_PAYLOAD];
    if (pkt->type == IOG_CSTP_COMPRESSED && data->compress != nullptr) {
        int dlen =
            iog_decompress(data->compress, payload, payload_len, decomp_buf, sizeof(decomp_buf));
        if (dlen < 0) {
            return dlen;
        }
        payload = decomp_buf;
        payload_len = (size_t)dlen;
    }

    /* Write to TUN device */
    ssize_t written = write(data->tun_fd, payload, payload_len);
    if (written < 0) {
        return -errno;
    }

    return 0;
}

/* Send a CSTP control packet (no payload or small payload) via TLS */
static int send_cstp_packet(iog_conn_data_t *data, iog_cstp_type_t type, const uint8_t *payload,
                            size_t payload_len)
{
    int encoded =
        iog_cstp_encode(data->send_buf, sizeof(data->send_buf), type, payload, payload_len);
    if (encoded < 0) {
        return encoded;
    }

    ssize_t written = data->tls_write(data->tls_ctx, data->send_buf, (size_t)encoded);
    if (written < 0) {
        return (int)written;
    }

    return 0;
}

/* Send DPD response */
static int send_dpd_response(iog_conn_data_t *data)
{
    return send_cstp_packet(data, IOG_CSTP_DPD_RESP, nullptr, 0);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int iog_conn_data_init(iog_conn_data_t *data, const iog_conn_data_config_t *cfg)
{
    if (data == nullptr || cfg == nullptr) {
        return -EINVAL;
    }
    if (cfg->tls_read == nullptr || cfg->tls_write == nullptr) {
        return -EINVAL;
    }

    memset(data, 0, sizeof(*data));
    data->tls_read = cfg->tls_read;
    data->tls_write = cfg->tls_write;
    data->tls_ctx = cfg->tls_ctx;
    data->tun_fd = cfg->tun_fd;
    data->dpd = cfg->dpd;
    data->compress = cfg->compress;
    data->disconnected = false;

    return 0;
}

int iog_conn_data_process_tls(iog_conn_data_t *data)
{
    if (data == nullptr) {
        return -EINVAL;
    }

    /* Read from TLS into recv_buf */
    size_t space = sizeof(data->recv_buf) - data->recv_len;
    if (space == 0) {
        return -ENOSPC;
    }

    ssize_t n = data->tls_read(data->tls_ctx, data->recv_buf + data->recv_len, space);
    if (n < 0) {
        return (int)n; /* -EAGAIN or error */
    }
    if (n == 0) {
        return -ECONNRESET; /* EOF */
    }
    data->recv_len += (size_t)n;

    /* Decode CSTP packets (may be multiple in buffer) */
    while (data->recv_len >= IOG_CSTP_HEADER_SIZE) {
        iog_cstp_packet_t pkt;
        int consumed = iog_cstp_decode(data->recv_buf, data->recv_len, &pkt);
        if (consumed == -EAGAIN) {
            break; /* incomplete frame, need more data */
        }
        if (consumed < 0) {
            return consumed;
        }

        /* Route by packet type */
        int rc = 0;
        switch (pkt.type) {
        case IOG_CSTP_DATA:
        case IOG_CSTP_COMPRESSED:
            rc = handle_data_packet(data, &pkt);
            break;
        case IOG_CSTP_DPD_REQ:
            if (data->dpd != nullptr) {
                (void)iog_dpd_on_request(data->dpd, 0);
            }
            rc = send_dpd_response(data);
            break;
        case IOG_CSTP_DPD_RESP:
            if (data->dpd != nullptr) {
                (void)iog_dpd_on_response(data->dpd, 0);
            }
            break;
        case IOG_CSTP_KEEPALIVE:
            break; /* no-op */
        case IOG_CSTP_DISCONNECT:
            data->disconnected = true;
            return -ECONNRESET;
        default:
            break;
        }
        if (rc < 0) {
            return rc;
        }

        /* Shift buffer */
        size_t remaining = data->recv_len - (size_t)consumed;
        if (remaining > 0) {
            memmove(data->recv_buf, data->recv_buf + consumed, remaining);
        }
        data->recv_len = remaining;
    }

    return 0;
}

int iog_conn_data_process_tun(iog_conn_data_t *data, const uint8_t *pkt, size_t pkt_len)
{
    if (data == nullptr || pkt == nullptr || pkt_len == 0) {
        return -EINVAL;
    }
    if (pkt_len > IOG_CSTP_MAX_PAYLOAD) {
        return -EMSGSIZE;
    }

    /* Compress if compressor available and not NONE */
    iog_cstp_type_t type = IOG_CSTP_DATA;
    const uint8_t *payload = pkt;
    size_t payload_len = pkt_len;
    uint8_t comp_buf[IOG_CSTP_MAX_PAYLOAD];

    if (data->compress != nullptr && data->compress->type != IOG_COMPRESS_NONE) {
        int clen = iog_compress(data->compress, pkt, pkt_len, comp_buf, sizeof(comp_buf));
        if (clen > 0 && (size_t)clen < pkt_len) {
            /* Only use compressed version if it's actually smaller */
            payload = comp_buf;
            payload_len = (size_t)clen;
            type = IOG_CSTP_COMPRESSED;
        }
    }

    /* CSTP encode */
    int encoded =
        iog_cstp_encode(data->send_buf, sizeof(data->send_buf), type, payload, payload_len);
    if (encoded < 0) {
        return encoded;
    }

    /* Write to TLS */
    ssize_t written = data->tls_write(data->tls_ctx, data->send_buf, (size_t)encoded);
    if (written < 0) {
        return (int)written;
    }

    return (int)written;
}

int iog_conn_data_send_dpd_req(iog_conn_data_t *data)
{
    if (data == nullptr) {
        return -EINVAL;
    }
    if (data->dpd != nullptr) {
        (void)iog_dpd_on_timeout(data->dpd);
    }
    return send_cstp_packet(data, IOG_CSTP_DPD_REQ, nullptr, 0);
}

int iog_conn_data_send_keepalive(iog_conn_data_t *data)
{
    if (data == nullptr) {
        return -EINVAL;
    }
    return send_cstp_packet(data, IOG_CSTP_KEEPALIVE, nullptr, 0);
}
