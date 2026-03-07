/**
 * @file http.h
 * @brief HTTP request parser wrapper around llhttp for OpenConnect protocol.
 *
 * Parses POST /auth (authentication) and CONNECT /CSCOSSLC/tunnel (tunnel
 * establishment) requests from Cisco AnyConnect / OpenConnect clients.
 */

#ifndef WOLFGUARD_NETWORK_HTTP_H
#define WOLFGUARD_NETWORK_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <llhttp.h>

constexpr uint32_t WG_HTTP_MAX_HEADERS = 32;
constexpr size_t WG_HTTP_MAX_URL = 512;
constexpr size_t WG_HTTP_MAX_HEADER_NAME = 128;
constexpr size_t WG_HTTP_MAX_HEADER_VALUE = 1024;
constexpr size_t WG_HTTP_MAX_BODY = 8192;

typedef struct {
	char name[WG_HTTP_MAX_HEADER_NAME];
	char value[WG_HTTP_MAX_HEADER_VALUE];
} wg_http_header_t;

typedef struct {
	uint8_t method;          /* llhttp_method_t */
	char url[WG_HTTP_MAX_URL];
	size_t url_len;
	wg_http_header_t headers[WG_HTTP_MAX_HEADERS];
	uint32_t header_count;
	char body[WG_HTTP_MAX_BODY];
	size_t body_len;
	bool headers_complete;
	bool message_complete;
	bool is_upgrade;
	/* internal parsing state */
	char _cur_header_field[WG_HTTP_MAX_HEADER_NAME];
	size_t _cur_field_len;
	char _cur_header_value[WG_HTTP_MAX_HEADER_VALUE];
	size_t _cur_value_len;
	bool _parsing_value;
} wg_http_request_t;

typedef struct {
	llhttp_t parser;
	llhttp_settings_t settings;
	wg_http_request_t request;
} wg_http_parser_t;

/**
 * @brief Initialize an HTTP parser for request parsing.
 * @param p Parser instance to initialize.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int wg_http_parser_init(wg_http_parser_t *p);

/**
 * @brief Reset the parser for a new request (reuses allocated memory).
 * @param p Parser instance to reset.
 */
void wg_http_parser_reset(wg_http_parser_t *p);

/**
 * @brief Parse HTTP data (may be called incrementally).
 * @param p Parser instance.
 * @param data Raw HTTP bytes.
 * @param len Length of data.
 * @return 0 on success, negative errno on parse error.
 */
[[nodiscard]] int wg_http_parse(wg_http_parser_t *p, const char *data, size_t len);

/**
 * @brief Look up a header value by name (case-insensitive).
 * @param req Parsed request.
 * @param name Header name to search for.
 * @return Pointer to the header value string, or nullptr if not found.
 */
const char *wg_http_get_header(const wg_http_request_t *req, const char *name);

/**
 * @brief Format an HTTP response into a buffer.
 * @param buf Output buffer.
 * @param buf_size Size of output buffer.
 * @param status_code HTTP status code (e.g. 200).
 * @param headers Array of response headers.
 * @param header_count Number of headers.
 * @param body Response body (may be nullptr).
 * @param body_len Length of body.
 * @return Number of bytes written on success, negative errno on failure.
 */
[[nodiscard]] int wg_http_format_response(char *buf, size_t buf_size,
                                          int status_code,
                                          const wg_http_header_t *headers,
                                          uint32_t header_count,
                                          const char *body, size_t body_len);

#endif /* WOLFGUARD_NETWORK_HTTP_H */
