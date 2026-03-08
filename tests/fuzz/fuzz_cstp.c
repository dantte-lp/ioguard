/**
 * @file fuzz_cstp.c
 * @brief LibFuzzer target for CSTP packet decoding.
 *
 * Feeds arbitrary bytes to rw_cstp_decode() to find crashes or UB.
 */

#include <network/cstp.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	rw_cstp_packet_t pkt = {0};
	(void)rw_cstp_decode(data, size, &pkt);
	return 0;
}
