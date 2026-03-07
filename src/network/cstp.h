/**
 * @file cstp.h
 * @brief CSTP (Cisco SSL Tunnel Protocol) packet framing for OpenConnect VPN.
 *
 * Wire format: 1-byte type + 3-byte big-endian payload length + payload data.
 * Decode is zero-copy: the returned payload pointer references the input buffer.
 */

#ifndef WOLFGUARD_NETWORK_CSTP_H
#define WOLFGUARD_NETWORK_CSTP_H

#include <stddef.h>
#include <stdint.h>

/** CSTP frame header size in bytes. */
constexpr size_t WG_CSTP_HEADER_SIZE = 4;

/** Maximum CSTP payload size. */
constexpr size_t WG_CSTP_MAX_PAYLOAD = 16384;

/** CSTP packet types per OpenConnect protocol. */
typedef enum : uint8_t {
	WG_CSTP_DATA       = 0x00,
	WG_CSTP_DPD_REQ    = 0x03,
	WG_CSTP_DPD_RESP   = 0x04,
	WG_CSTP_DISCONNECT = 0x05,
	WG_CSTP_KEEPALIVE  = 0x07,
	WG_CSTP_COMPRESSED = 0x08,
} wg_cstp_type_t;

/** Decoded CSTP packet (zero-copy: payload points into decode buffer). */
typedef struct {
	wg_cstp_type_t type;
	uint32_t payload_len;
	const uint8_t *payload;
} wg_cstp_packet_t;

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
[[nodiscard]] int wg_cstp_encode(uint8_t *buf, size_t buf_size,
                                 wg_cstp_type_t type,
                                 const uint8_t *payload, size_t payload_len);

/**
 * @brief Decode a CSTP packet from buf (zero-copy).
 * @param buf Input buffer.
 * @param buf_len Length of data in buffer.
 * @param pkt Output packet (pkt->payload points into buf).
 * @return Bytes consumed on success, -EAGAIN if incomplete, -EINVAL if invalid.
 */
[[nodiscard]] int wg_cstp_decode(const uint8_t *buf, size_t buf_len,
                                 wg_cstp_packet_t *pkt);

/**
 * @brief Get human-readable name for a CSTP packet type.
 * @param type Packet type value.
 * @return Static string with the type name, or "UNKNOWN".
 */
const char *wg_cstp_type_name(wg_cstp_type_t type);

#endif /* WOLFGUARD_NETWORK_CSTP_H */
