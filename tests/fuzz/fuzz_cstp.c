/**
 * @file fuzz_cstp.c
 * @brief LibFuzzer target for CSTP packet decoding.
 *
 * Feeds arbitrary bytes to iog_cstp_decode() to find crashes or UB.
 */

#include <network/cstp.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    iog_cstp_packet_t pkt = {0};
    (void)iog_cstp_decode(data, size, &pkt);
    return 0;
}
