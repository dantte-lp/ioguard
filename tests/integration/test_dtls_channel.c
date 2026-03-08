#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unity/unity.h>
#include <string.h>

#include "network/channel.h"
#include "network/compress.h"
#include "network/cstp.h"
#include "network/dtls_headers.h"
#include "network/dtls_keying.h"
#include "core/worker.h"

void setUp(void) {}
void tearDown(void) {}

/**
 * Channel state machine full lifecycle:
 * CSTP_ONLY → DTLS_PRIMARY → DTLS_FALLBACK → recovery → CSTP_ONLY
 */
void test_channel_lifecycle(void)
{
	rw_channel_ctx_t ch;
	rw_channel_init(&ch);

	/* Start CSTP_ONLY */
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_CSTP_ONLY, ch.state);
	TEST_ASSERT_FALSE(rw_channel_use_dtls(&ch));

	/* DTLS comes up */
	(void)rw_channel_on_dtls_up(&ch);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_PRIMARY, ch.state);
	TEST_ASSERT_TRUE(rw_channel_use_dtls(&ch));

	/* DTLS fails → fallback */
	(void)rw_channel_on_dtls_down(&ch);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_FALLBACK, ch.state);
	TEST_ASSERT_FALSE(rw_channel_use_dtls(&ch));

	/* Recovery */
	(void)rw_channel_on_dtls_recovery(&ch);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_PRIMARY, ch.state);
	TEST_ASSERT_TRUE(rw_channel_use_dtls(&ch));

	/* Multiple failures → CSTP_ONLY */
	(void)rw_channel_on_dtls_down(&ch);
	(void)rw_channel_on_dtls_down(&ch);
	(void)rw_channel_on_dtls_down(&ch);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_CSTP_ONLY, ch.state);
	TEST_ASSERT_FALSE(rw_channel_use_dtls(&ch));
}

/**
 * Compression negotiation + LZS roundtrip through CSTP framing.
 */
void test_compress_lzs_cstp_integration(void)
{
	/* Negotiate LZS */
	rw_compress_type_t ct = rw_compress_negotiate("lzs,deflate");
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, ct);

	/* Init compressor */
	rw_compress_ctx_t comp;
	int ret = rw_compress_init(&comp, ct);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Compress payload */
	const uint8_t data[] = "AAAAAAAABBBBBBBBCCCCCCCC";
	uint8_t compressed[128];
	int clen = rw_compress(&comp, data, sizeof(data) - 1,
	                        compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);

	/* Wrap in CSTP COMPRESSED frame */
	uint8_t frame[RW_CSTP_HEADER_SIZE + 128];
	int flen = rw_cstp_encode(frame, sizeof(frame), RW_CSTP_COMPRESSED,
	                           compressed, (size_t)clen);
	TEST_ASSERT_GREATER_THAN(0, flen);

	/* Decode CSTP */
	rw_cstp_packet_t pkt;
	int consumed = rw_cstp_decode(frame, (size_t)flen, &pkt);
	TEST_ASSERT_EQUAL_INT(flen, consumed);
	TEST_ASSERT_EQUAL_UINT8(RW_CSTP_COMPRESSED, pkt.type);

	/* Decompress with fresh context */
	rw_compress_ctx_t decomp;
	ret = rw_compress_init(&decomp, RW_COMPRESS_LZS);
	TEST_ASSERT_EQUAL_INT(0, ret);

	uint8_t decompressed[64];
	int dlen = rw_decompress(&decomp, pkt.payload, pkt.payload_len,
	                          decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)(sizeof(data) - 1), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data) - 1);

	rw_compress_destroy(&comp);
	rw_compress_destroy(&decomp);
}

/**
 * DTLS master secret hex roundtrip.
 */
void test_master_secret_hex_roundtrip(void)
{
	uint8_t secret[RW_DTLS_MASTER_SECRET_LEN];
	for (size_t i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)(i * 5 + 3);

	char hex[RW_DTLS_MASTER_SECRET_HEX_LEN + 1];
	int ret = rw_dtls_hex_encode(secret, sizeof(secret), hex, sizeof(hex));
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_size_t(RW_DTLS_MASTER_SECRET_HEX_LEN, strlen(hex));

	uint8_t decoded[RW_DTLS_MASTER_SECRET_LEN];
	ret = rw_dtls_hex_decode(hex, strlen(hex), decoded, sizeof(decoded));
	TEST_ASSERT_EQUAL_INT((int)sizeof(secret), ret);
	TEST_ASSERT_EQUAL_MEMORY(secret, decoded, sizeof(secret));
}

/**
 * DTLS headers build + parse roundtrip.
 */
void test_dtls_headers_roundtrip(void)
{
	char headers[512];
	int ret = rw_dtls_build_headers(headers, sizeof(headers),
		"aabbccdd11223344", "DHE-RSA-AES256-SHA", "lzs");
	TEST_ASSERT_GREATER_THAN(0, ret);

	/* Verify key headers present */
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-Master-Secret: aabbccdd11223344"));
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-CipherSuite: DHE-RSA-AES256-SHA"));
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-Accept-Encoding: lzs"));

	/* Parse encoding back */
	rw_compress_type_t ct = rw_dtls_parse_accept_encoding("lzs");
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, ct);
}

/**
 * Worker connection with compression context lifecycle.
 */
void test_worker_compress_lifecycle(void)
{
	rw_worker_config_t cfg;
	rw_worker_config_init(&cfg);
	cfg.max_connections = 4;

	rw_worker_t *w = rw_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	/* Add connection — gets NONE compress by default */
	int64_t cid = rw_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(0, cid);

	rw_connection_t *conn = rw_worker_find_connection(w, (uint64_t)cid);
	TEST_ASSERT_NOT_NULL(conn);
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, conn->compress.type);

	/* Switch to LZS */
	rw_compress_destroy(&conn->compress);
	int ret = rw_compress_init(&conn->compress, RW_COMPRESS_LZS);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, conn->compress.type);

	/* Remove — should clean up compress context */
	(void)rw_worker_remove_connection(w, (uint64_t)cid);
	TEST_ASSERT_EQUAL_UINT32(0, rw_worker_connection_count(w));

	rw_worker_destroy(w);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_channel_lifecycle);
	RUN_TEST(test_compress_lzs_cstp_integration);
	RUN_TEST(test_master_secret_hex_roundtrip);
	RUN_TEST(test_dtls_headers_roundtrip);
	RUN_TEST(test_worker_compress_lifecycle);
	return UNITY_END();
}
