/**
 * @file bench_cstp.c
 * @brief CSTP encode/decode throughput benchmark.
 */
#include "bench_common.h"

#include <string.h>

#include "network/cstp.h"

constexpr int BENCH_ITERS = 100000;
constexpr size_t PAYLOAD_SIZE = 1400;

static uint8_t encode_buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
static uint8_t payload[IOG_CSTP_MAX_PAYLOAD];

static void bench_encode(void *arg)
{
    (void)arg;
    (void)iog_cstp_encode(encode_buf, sizeof(encode_buf), IOG_CSTP_DATA, payload, PAYLOAD_SIZE);
}

static void bench_decode(void *arg)
{
    (void)arg;
    iog_cstp_packet_t pkt;
    (void)iog_cstp_decode(encode_buf, IOG_CSTP_HEADER_SIZE + PAYLOAD_SIZE, &pkt);
}

int main(void)
{
    memset(payload, 0xAB, sizeof(payload));

    (void)iog_cstp_encode(encode_buf, sizeof(encode_buf), IOG_CSTP_DATA, payload, PAYLOAD_SIZE);

    printf("=== CSTP Benchmark (%d iterations) ===\n", BENCH_ITERS);

    double ns = bench_ns_per_iter(bench_encode, nullptr, BENCH_ITERS);
    bench_report("cstp_encode (1400B payload)", ns, BENCH_ITERS);

    ns = bench_ns_per_iter(bench_decode, nullptr, BENCH_ITERS);
    bench_report("cstp_decode (1400B payload)", ns, BENCH_ITERS);

    return 0;
}
