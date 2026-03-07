#include <unity/unity.h>
#include <string.h>
#include "network/http.h"

static wg_http_parser_t parser;

void setUp(void)
{
	int ret = wg_http_parser_init(&parser);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

void tearDown(void)
{
}

void test_http_parse_post_auth(void)
{
	const char *req =
		"POST /auth HTTP/1.1\r\n"
		"Host: vpn.example.com\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: 44\r\n"
		"Cookie: webvpn=abc123\r\n"
		"\r\n"
		"<config-auth><auth>user:pass</auth></config>";

	int ret = wg_http_parse(&parser, req, strlen(req));
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_TRUE(parser.request.message_complete);
	TEST_ASSERT_TRUE(parser.request.headers_complete);
	TEST_ASSERT_FALSE(parser.request.is_upgrade);
	TEST_ASSERT_EQUAL_UINT8(HTTP_POST, parser.request.method);
	TEST_ASSERT_EQUAL_STRING("/auth", parser.request.url);
	TEST_ASSERT_EQUAL_size_t(5, parser.request.url_len);
	TEST_ASSERT_EQUAL_size_t(44, parser.request.body_len);
	TEST_ASSERT_EQUAL_STRING(
		"<config-auth><auth>user:pass</auth></config>",
		parser.request.body);
}

void test_http_parse_connect_tunnel(void)
{
	const char *req =
		"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
		"Host: vpn.example.com\r\n"
		"X-CSTP-Hostname: client01\r\n"
		"X-CSTP-MTU: 1399\r\n"
		"X-DTLS-CipherSuite: AES256-GCM-SHA384\r\n"
		"Cookie: webvpn=tok456\r\n"
		"\r\n";

	int ret = wg_http_parse(&parser, req, strlen(req));
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_TRUE(parser.request.is_upgrade);
	TEST_ASSERT_TRUE(parser.request.headers_complete);
	TEST_ASSERT_EQUAL_UINT8(HTTP_CONNECT, parser.request.method);
	TEST_ASSERT_EQUAL_STRING("/CSCOSSLC/tunnel", parser.request.url);
}

void test_http_get_header(void)
{
	const char *req =
		"POST /auth HTTP/1.1\r\n"
		"Host: vpn.example.com\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: 5\r\n"
		"Cookie: webvpn=abc123\r\n"
		"X-CSTP-Hostname: workstation42\r\n"
		"\r\n"
		"hello";

	int ret = wg_http_parse(&parser, req, strlen(req));
	TEST_ASSERT_EQUAL_INT(0, ret);

	const char *cookie = wg_http_get_header(&parser.request, "Cookie");
	TEST_ASSERT_NOT_NULL(cookie);
	TEST_ASSERT_EQUAL_STRING("webvpn=abc123", cookie);

	const char *hostname = wg_http_get_header(&parser.request, "X-CSTP-Hostname");
	TEST_ASSERT_NOT_NULL(hostname);
	TEST_ASSERT_EQUAL_STRING("workstation42", hostname);

	const char *ctype = wg_http_get_header(&parser.request, "content-type");
	TEST_ASSERT_NOT_NULL(ctype);
	TEST_ASSERT_EQUAL_STRING("application/xml", ctype);

	/* Non-existent header */
	const char *missing = wg_http_get_header(&parser.request, "X-Nonexistent");
	TEST_ASSERT_NULL(missing);
}

void test_http_format_response(void)
{
	char buf[1024];
	wg_http_header_t hdrs[2];

	snprintf(hdrs[0].name, sizeof(hdrs[0].name), "Content-Type");
	snprintf(hdrs[0].value, sizeof(hdrs[0].value), "text/plain");
	snprintf(hdrs[1].name, sizeof(hdrs[1].name), "X-Custom");
	snprintf(hdrs[1].value, sizeof(hdrs[1].value), "value1");

	const char *body = "OK\n";
	int ret = wg_http_format_response(buf, sizeof(buf), 200, hdrs, 2,
					  body, strlen(body));
	TEST_ASSERT_GREATER_THAN(0, ret);

	/* Verify status line */
	TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200 OK\r\n"));
	/* Verify headers */
	TEST_ASSERT_NOT_NULL(strstr(buf, "Content-Type: text/plain\r\n"));
	TEST_ASSERT_NOT_NULL(strstr(buf, "X-Custom: value1\r\n"));
	/* Verify separator and body */
	TEST_ASSERT_NOT_NULL(strstr(buf, "\r\n\r\nOK\n"));
}

void test_http_max_body_limit(void)
{
	/* Build a request with body larger than WG_HTTP_MAX_BODY */
	char req[WG_HTTP_MAX_BODY + 4096];
	size_t oversized_body_len = WG_HTTP_MAX_BODY + 1024;
	int hdr_len = snprintf(req, sizeof(req),
			       "POST /data HTTP/1.1\r\n"
			       "Content-Length: %zu\r\n"
			       "\r\n",
			       oversized_body_len);
	TEST_ASSERT_GREATER_THAN(0, hdr_len);

	/* Fill body with 'A' characters */
	size_t fill = oversized_body_len;
	if ((size_t)hdr_len + fill > sizeof(req))
		fill = sizeof(req) - (size_t)hdr_len;
	memset(req + hdr_len, 'A', fill);

	int ret = wg_http_parse(&parser, req, (size_t)hdr_len + fill);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Body should be truncated to WG_HTTP_MAX_BODY */
	TEST_ASSERT_EQUAL_size_t(WG_HTTP_MAX_BODY, parser.request.body_len);
}

void test_http_incremental_parse(void)
{
	const char *req =
		"POST /auth HTTP/1.1\r\n"
		"Host: vpn.example.com\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: 11\r\n"
		"\r\n"
		"hello world";

	size_t total = strlen(req);

	/* Parse full request for reference */
	wg_http_parser_t full;
	int ret = wg_http_parser_init(&full);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = wg_http_parse(&full, req, total);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Parse same request in small chunks */
	wg_http_parser_t chunked;
	ret = wg_http_parser_init(&chunked);
	TEST_ASSERT_EQUAL_INT(0, ret);

	constexpr size_t chunk_size = 7;
	size_t offset = 0;
	while (offset < total) {
		size_t n = chunk_size;
		if (offset + n > total)
			n = total - offset;
		ret = wg_http_parse(&chunked, req + offset, n);
		TEST_ASSERT_EQUAL_INT(0, ret);
		offset += n;
	}

	TEST_ASSERT_TRUE(chunked.request.message_complete);
	TEST_ASSERT_EQUAL_UINT8(full.request.method, chunked.request.method);
	TEST_ASSERT_EQUAL_STRING(full.request.url, chunked.request.url);
	TEST_ASSERT_EQUAL_size_t(full.request.body_len, chunked.request.body_len);
	TEST_ASSERT_EQUAL_STRING(full.request.body, chunked.request.body);
	TEST_ASSERT_EQUAL_UINT32(full.request.header_count,
				 chunked.request.header_count);
}

void test_http_invalid_request(void)
{
	const char *garbage = "XYZZY not-http garbage\r\n\r\n";

	int ret = wg_http_parse(&parser, garbage, strlen(garbage));
	TEST_ASSERT_LESS_THAN(0, ret);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_http_parse_post_auth);
	RUN_TEST(test_http_parse_connect_tunnel);
	RUN_TEST(test_http_get_header);
	RUN_TEST(test_http_format_response);
	RUN_TEST(test_http_max_body_limit);
	RUN_TEST(test_http_incremental_parse);
	RUN_TEST(test_http_invalid_request);
	return UNITY_END();
}
