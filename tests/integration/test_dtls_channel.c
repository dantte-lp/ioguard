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
	wg_channel_ctx_t ch;
	wg_channel_init(&ch);

	/* Start CSTP_ONLY */
	TEST_ASSERT_EQUAL_UINT8(WG_CHANNEL_CSTP_ONLY, ch.state);
	TEST_ASSERT_FALSE(wg_channel_use_dtls(&ch));

	/* DTLS comes up */
	(void)wg_channel_on_dtls_up(&ch);
	TEST_ASSERT_EQUAL_UINT8(WG_CHANNEL_DTLS_PRIMARY, ch.state);
	TEST_ASSERT_TRUE(wg_channel_use_dtls(&ch));

	/* DTLS fails → fallback */
	(void)wg_channel_on_dtls_down(&ch);
	TEST_ASSERT_EQUAL_UINT8(WG_CHANNEL_DTLS_FALLBACK, ch.state);
	TEST_ASSERT_FALSE(wg_channel_use_dtls(&ch));

	/* Recovery */
	(void)wg_channel_on_dtls_recovery(&ch);
	TEST_ASSERT_EQUAL_UINT8(WG_CHANNEL_DTLS_PRIMARY, ch.state);
	TEST_ASSERT_TRUE(wg_channel_use_dtls(&ch));

	/* Multiple failures → CSTP_ONLY */
	(void)wg_channel_on_dtls_down(&ch);
	(void)wg_channel_on_dtls_down(&ch);
	(void)wg_channel_on_dtls_down(&ch);
	TEST_ASSERT_EQUAL_UINT8(WG_CHANNEL_CSTP_ONLY, ch.state);
	TEST_ASSERT_FALSE(wg_channel_use_dtls(&ch));
}

/**
 * Compression negotiation + LZS roundtrip through CSTP framing.
 */
void test_compress_lzs_cstp_integration(void)
{
	/* Negotiate LZS */
	wg_compress_type_t ct = wg_compress_negotiate("lzs,deflate");
	TEST_ASSERT_EQUAL_UINT8(WG_COMPRESS_LZS, ct);

	/* Init compressor */
	wg_compress_ctx_t comp;
	int ret = wg_compress_init(&comp, ct);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Compress payload */
	const uint8_t data[] = "AAAAAAAABBBBBBBBCCCCCCCC";
	uint8_t compressed[128];
	int clen = wg_compress(&comp, data, sizeof(data) - 1,
	                        compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);

	/* Wrap in CSTP COMPRESSED frame */
	uint8_t frame[WG_CSTP_HEADER_SIZE + 128];
	int flen = wg_cstp_encode(frame, sizeof(frame), WG_CSTP_COMPRESSED,
	                           compressed, (size_t)clen);
	TEST_ASSERT_GREATER_THAN(0, flen);

	/* Decode CSTP */
	wg_cstp_packet_t pkt;
	int consumed = wg_cstp_decode(frame, (size_t)flen, &pkt);
	TEST_ASSERT_EQUAL_INT(flen, consumed);
	TEST_ASSERT_EQUAL_UINT8(WG_CSTP_COMPRESSED, pkt.type);

	/* Decompress with fresh context */
	wg_compress_ctx_t decomp;
	ret = wg_compress_init(&decomp, WG_COMPRESS_LZS);
	TEST_ASSERT_EQUAL_INT(0, ret);

	uint8_t decompressed[64];
	int dlen = wg_decompress(&decomp, pkt.payload, pkt.payload_len,
	                          decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)(sizeof(data) - 1), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data) - 1);

	wg_compress_destroy(&comp);
	wg_compress_destroy(&decomp);
}

/**
 * DTLS master secret hex roundtrip.
 */
void test_master_secret_hex_roundtrip(void)
{
	uint8_t secret[WG_DTLS_MASTER_SECRET_LEN];
	for (size_t i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)(i * 5 + 3);

	char hex[WG_DTLS_MASTER_SECRET_HEX_LEN + 1];
	int ret = wg_dtls_hex_encode(secret, sizeof(secret), hex, sizeof(hex));
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_size_t(WG_DTLS_MASTER_SECRET_HEX_LEN, strlen(hex));

	uint8_t decoded[WG_DTLS_MASTER_SECRET_LEN];
	ret = wg_dtls_hex_decode(hex, strlen(hex), decoded, sizeof(decoded));
	TEST_ASSERT_EQUAL_INT((int)sizeof(secret), ret);
	TEST_ASSERT_EQUAL_MEMORY(secret, decoded, sizeof(secret));
}

/**
 * DTLS headers build + parse roundtrip.
 */
void test_dtls_headers_roundtrip(void)
{
	char headers[512];
	int ret = wg_dtls_build_headers(headers, sizeof(headers),
		"aabbccdd11223344", "DHE-RSA-AES256-SHA", "lzs");
	TEST_ASSERT_GREATER_THAN(0, ret);

	/* Verify key headers present */
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-Master-Secret: aabbccdd11223344"));
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-CipherSuite: DHE-RSA-AES256-SHA"));
	TEST_ASSERT_NOT_NULL(strstr(headers, "X-DTLS-Accept-Encoding: lzs"));

	/* Parse encoding back */
	wg_compress_type_t ct = wg_dtls_parse_accept_encoding("lzs");
	TEST_ASSERT_EQUAL_UINT8(WG_COMPRESS_LZS, ct);
}

/**
 * Worker connection with compression context lifecycle.
 */
void test_worker_compress_lifecycle(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	/* Add connection — gets NONE compress by default */
	int64_t cid = wg_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(0, cid);

	wg_connection_t *conn = wg_worker_find_connection(w, (uint64_t)cid);
	TEST_ASSERT_NOT_NULL(conn);
	TEST_ASSERT_EQUAL_UINT8(WG_COMPRESS_NONE, conn->compress.type);

	/* Switch to LZS */
	wg_compress_destroy(&conn->compress);
	int ret = wg_compress_init(&conn->compress, WG_COMPRESS_LZS);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_UINT8(WG_COMPRESS_LZS, conn->compress.type);

	/* Remove — should clean up compress context */
	(void)wg_worker_remove_connection(w, (uint64_t)cid);
	TEST_ASSERT_EQUAL_UINT32(0, wg_worker_connection_count(w));

	wg_worker_destroy(w);
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
