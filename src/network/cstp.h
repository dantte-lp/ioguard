/**
 * @file cstp.h
 * @brief CSTP (Cisco SSL Tunnel Protocol) packet framing for OpenConnect VPN.
 *
 * Wire format: 1-byte type + 3-byte big-endian payload length + payload data.
 * Decode is zero-copy: the returned payload pointer references the input buffer.
 */

#ifndef RINGWALL_NETWORK_CSTP_H
#define RINGWALL_NETWORK_CSTP_H

#include <stddef.h>
#include <stdint.h>

/** CSTP frame header size in bytes. */
constexpr size_t RW_CSTP_HEADER_SIZE = 4;

/** Maximum CSTP payload size. */
constexpr size_t RW_CSTP_MAX_PAYLOAD = 16384;

/** CSTP packet types per OpenConnect protocol. */
typedef enum : uint8_t {
    RW_CSTP_DATA = 0x00,
    RW_CSTP_DPD_REQ = 0x03,
    RW_CSTP_DPD_RESP = 0x04,
    RW_CSTP_DISCONNECT = 0x05,
    RW_CSTP_KEEPALIVE = 0x07,
    RW_CSTP_COMPRESSED = 0x08,
} rw_cstp_type_t;

/** Decoded CSTP packet (zero-copy: payload points into decode buffer). */
typedef struct {
    rw_cstp_type_t type;
    uint32_t payload_len;
    const uint8_t *payload;
} rw_cstp_packet_t;

/**
 * @brief Encode a CSTP packet into buf.
 * @param buf Output buffer.
 * @param buf_size Size of output buffer.
 * @param type Packet type.
 * @param payload Payload data (may be nullptr if payload_len is 0).
 * @param payload_len Length of payload.
 * @return Bytes written (>= 4) on success, -ENOSPC if buffer too small,
 *         -EINVAL if payload too large.
 */
[[nodiscard]] int rw_cstp_encode(uint8_t *buf, size_t buf_size, rw_cstp_type_t type,
                                 const uint8_t *payload, size_t payload_len);

/**
 * @brief Decode a CSTP packet from buf (zero-copy).
 * @param buf Input buffer.
 * @param buf_len Length of data in buffer.
 * @param pkt Output packet (pkt->payload points into buf).
 * @return Bytes consumed on success, -EAGAIN if incomplete, -EINVAL if invalid.
 */
[[nodiscard]] int rw_cstp_decode(const uint8_t *buf, size_t buf_len, rw_cstp_packet_t *pkt);

/**
 * @brief Get human-readable name for a CSTP packet type.
 * @param type Packet type value.
 * @return Static string with the type name, or "UNKNOWN".
 */
const char *rw_cstp_type_name(rw_cstp_type_t type);

#endif /* RINGWALL_NETWORK_CSTP_H */
