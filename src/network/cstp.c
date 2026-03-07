#include "network/cstp.h"

#include <errno.h>
#include <string.h>

int wg_cstp_encode(uint8_t *buf, size_t buf_size,
                   wg_cstp_type_t type,
                   const uint8_t *payload, size_t payload_len)
{
	if (payload_len > WG_CSTP_MAX_PAYLOAD)
		return -EINVAL;

	size_t total = WG_CSTP_HEADER_SIZE + payload_len;
	if (buf_size < total)
		return -ENOSPC;

	buf[0] = (uint8_t)type;
	buf[1] = (uint8_t)((payload_len >> 16) & 0xFF);
	buf[2] = (uint8_t)((payload_len >> 8) & 0xFF);
	buf[3] = (uint8_t)(payload_len & 0xFF);

	if (payload_len > 0 && payload != nullptr)
		memcpy(buf + WG_CSTP_HEADER_SIZE, payload, payload_len);

	return (int)total;
}

int wg_cstp_decode(const uint8_t *buf, size_t buf_len,
                   wg_cstp_packet_t *pkt)
{
	if (buf_len < WG_CSTP_HEADER_SIZE)
		return -EAGAIN;

	uint32_t payload_len = ((uint32_t)buf[1] << 16) |
	                       ((uint32_t)buf[2] << 8) |
	                       (uint32_t)buf[3];

	if (payload_len > WG_CSTP_MAX_PAYLOAD)
		return -EINVAL;

	size_t total = WG_CSTP_HEADER_SIZE + payload_len;
	if (buf_len < total)
		return -EAGAIN;

	pkt->type = (wg_cstp_type_t)buf[0];
	pkt->payload_len = payload_len;
	pkt->payload = (payload_len > 0) ? buf + WG_CSTP_HEADER_SIZE : nullptr;

	return (int)total;
}

const char *wg_cstp_type_name(wg_cstp_type_t type)
{
	switch (type) {
	case WG_CSTP_DATA:       return "DATA";
	case WG_CSTP_DPD_REQ:    return "DPD-REQ";
	case WG_CSTP_DPD_RESP:   return "DPD-RESP";
	case WG_CSTP_DISCONNECT: return "DISCONNECT";
	case WG_CSTP_KEEPALIVE:  return "KEEPALIVE";
	case WG_CSTP_COMPRESSED: return "COMPRESSED";
	default:                 return "UNKNOWN";
	}
}
