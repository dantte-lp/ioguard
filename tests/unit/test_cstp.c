#include <unity/unity.h>
#include "network/cstp.h"
#include <errno.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_cstp_header_size_constant(void)
{
	TEST_ASSERT_EQUAL_UINT(4, RW_CSTP_HEADER_SIZE);
}

void test_cstp_encode_data_packet(void)
{
	uint8_t buf[64];
	const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DATA,
	                         payload, sizeof(payload));
	TEST_ASSERT_EQUAL_INT(9, ret); /* 4 header + 5 payload */

	/* verify header */
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[0]); /* type = DATA */
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[1]); /* length high */
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[2]); /* length mid */
	TEST_ASSERT_EQUAL_UINT8(0x05, buf[3]); /* length low */

	/* verify payload copied */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, buf + 4, sizeof(payload));
}

void test_cstp_encode_dpd_request(void)
{
	uint8_t buf[16];

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DPD_REQ,
	                         nullptr, 0);
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_UINT8(0x03, buf[0]);
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[1]);
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[2]);
	TEST_ASSERT_EQUAL_UINT8(0x00, buf[3]);
}

void test_cstp_encode_dpd_response(void)
{
	uint8_t buf[16];

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DPD_RESP,
	                         nullptr, 0);
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_UINT8(0x04, buf[0]);
}

void test_cstp_encode_keepalive(void)
{
	uint8_t buf[16];

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_KEEPALIVE,
	                         nullptr, 0);
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_UINT8(0x07, buf[0]);
}

void test_cstp_encode_disconnect(void)
{
	uint8_t buf[16];

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DISCONNECT,
	                         nullptr, 0);
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_UINT8(0x05, buf[0]);
}

void test_cstp_decode_data_packet(void)
{
	/* build a valid DATA frame: type=0x00, len=3, payload={0xAA, 0xBB, 0xCC} */
	uint8_t wire[] = { 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC };
	rw_cstp_packet_t pkt;

	int ret = rw_cstp_decode(wire, sizeof(wire), &pkt);
	TEST_ASSERT_EQUAL_INT(7, ret);
	TEST_ASSERT_EQUAL_UINT8(RW_CSTP_DATA, pkt.type);
	TEST_ASSERT_EQUAL_UINT32(3, pkt.payload_len);
	TEST_ASSERT_NOT_NULL(pkt.payload);

	/* zero-copy: payload must point into the wire buffer */
	TEST_ASSERT_EQUAL_PTR(wire + 4, pkt.payload);
	TEST_ASSERT_EQUAL_UINT8(0xAA, pkt.payload[0]);
	TEST_ASSERT_EQUAL_UINT8(0xBB, pkt.payload[1]);
	TEST_ASSERT_EQUAL_UINT8(0xCC, pkt.payload[2]);
}

void test_cstp_decode_incomplete_header(void)
{
	uint8_t wire[] = { 0x00, 0x00 }; /* only 2 bytes, need 4 */
	rw_cstp_packet_t pkt;

	int ret = rw_cstp_decode(wire, sizeof(wire), &pkt);
	TEST_ASSERT_EQUAL_INT(-EAGAIN, ret);
}

void test_cstp_decode_incomplete_payload(void)
{
	/* header says 10 bytes payload, but only 2 bytes of payload present */
	uint8_t wire[] = { 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02 };
	rw_cstp_packet_t pkt;

	int ret = rw_cstp_decode(wire, sizeof(wire), &pkt);
	TEST_ASSERT_EQUAL_INT(-EAGAIN, ret);
}

void test_cstp_encode_buffer_too_small(void)
{
	uint8_t buf[2]; /* way too small for even a header-only packet */
	const uint8_t payload[] = { 0x01 };

	int ret = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DATA,
	                         payload, sizeof(payload));
	TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_cstp_header_size_constant);
	RUN_TEST(test_cstp_encode_data_packet);
	RUN_TEST(test_cstp_encode_dpd_request);
	RUN_TEST(test_cstp_encode_dpd_response);
	RUN_TEST(test_cstp_encode_keepalive);
	RUN_TEST(test_cstp_encode_disconnect);
	RUN_TEST(test_cstp_decode_data_packet);
	RUN_TEST(test_cstp_decode_incomplete_header);
	RUN_TEST(test_cstp_decode_incomplete_payload);
	RUN_TEST(test_cstp_encode_buffer_too_small);
	return UNITY_END();
}
