#ifndef IOGUARD_CORE_CONN_DATA_H
#define IOGUARD_CORE_CONN_DATA_H

#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief I/O function types for data path abstraction.
 *
 * Decouples conn_data from the TLS layer so unit tests can inject
 * socketpair-based plaintext I/O without requiring real wolfSSL.
 */
typedef ssize_t (*iog_conn_data_read_fn)(void *ctx, void *buf, size_t len);
typedef ssize_t (*iog_conn_data_write_fn)(void *ctx, const void *buf, size_t len);

/**
 * @brief Per-connection data path state.
 *
 * Drives the TLS <-> CSTP <-> TUN pipeline for one VPN client.
 * Owned by the worker event loop, one instance per active connection.
 */
typedef struct {
    /* I/O callbacks (TLS read/write or mock for tests) */
    iog_conn_data_read_fn tls_read;
    iog_conn_data_write_fn tls_write;
    void *tls_ctx;

    int tun_fd;
    iog_dpd_ctx_t *dpd;
    iog_compress_ctx_t *compress;

    /* Receive buffer (accumulates partial CSTP frames from TLS) */
    uint8_t recv_buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
    size_t recv_len;

    /* Send buffer (CSTP-encoded frame for TLS write) */
    uint8_t send_buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];

    /* State */
    bool disconnected;
} iog_conn_data_t;

/**
 * @brief Configuration for data path initialization.
 */
typedef struct {
    iog_conn_data_read_fn tls_read;
    iog_conn_data_write_fn tls_write;
    void *tls_ctx;
    int tun_fd;
    iog_dpd_ctx_t *dpd;
    iog_compress_ctx_t *compress;
} iog_conn_data_config_t;

/**
 * @brief Initialize data path for a connection.
 *
 * @param data  Data path context (caller-owned).
 * @param cfg   Configuration with I/O callbacks and sub-modules.
 * @return 0 on success, -EINVAL on bad params.
 */
[[nodiscard]] int iog_conn_data_init(iog_conn_data_t *data, const iog_conn_data_config_t *cfg);

/**
 * @brief Process data received from TLS.
 *
 * Reads from TLS, decodes CSTP, routes by packet type:
 * - DATA -> decompress -> write to tun_fd
 * - DPD_REQ -> send DPD_RESP via TLS
 * - KEEPALIVE -> ignore
 * - DISCONNECT -> return -ECONNRESET
 *
 * @param data  Data path context.
 * @return 0 on success, -EAGAIN if incomplete, negative errno on error.
 */
[[nodiscard]] int iog_conn_data_process_tls(iog_conn_data_t *data);

/**
 * @brief Process data received from TUN.
 *
 * Compresses payload, CSTP-encodes, sends via TLS.
 *
 * @param data     Data path context.
 * @param pkt      Raw IP packet from TUN.
 * @param pkt_len  Packet length.
 * @return Bytes sent via TLS, or negative errno.
 */
[[nodiscard]] int iog_conn_data_process_tun(iog_conn_data_t *data, const uint8_t *pkt,
                                            size_t pkt_len);

/**
 * @brief Send a DPD request via TLS.
 *
 * @param data  Data path context.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_conn_data_send_dpd_req(iog_conn_data_t *data);

/**
 * @brief Send a keepalive via TLS.
 *
 * @param data  Data path context.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_conn_data_send_keepalive(iog_conn_data_t *data);

#endif /* IOGUARD_CORE_CONN_DATA_H */
