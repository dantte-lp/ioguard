/**
 * @file http.h
 * @brief HTTP request parser wrapper around iohttpparser for OpenConnect protocol.
 *
 * Parses POST /auth (authentication) and CONNECT /CSCOSSLC/tunnel (tunnel
 * establishment) requests from Cisco AnyConnect / OpenConnect clients.
 */

#ifndef IOGUARD_NETWORK_HTTP_H
#define IOGUARD_NETWORK_HTTP_H

#include <iohttpparser/ihtp_body.h>
#include <iohttpparser/ihtp_parser.h>
#include <stddef.h>
#include <stdint.h>

constexpr uint32_t IOG_HTTP_MAX_HEADERS = 32;
constexpr size_t IOG_HTTP_MAX_URL = 512;
constexpr size_t IOG_HTTP_MAX_HEADER_NAME = 128;
constexpr size_t IOG_HTTP_MAX_HEADER_VALUE = 1024;
constexpr size_t IOG_HTTP_MAX_BODY = 8192;

/* Accumulation buffer: headers + max body + margin */
constexpr size_t IOG_HTTP_BUF_SIZE = 32768;

typedef struct {
    char name[IOG_HTTP_MAX_HEADER_NAME];
    char value[IOG_HTTP_MAX_HEADER_VALUE];
} iog_http_header_t;

typedef struct {
    uint8_t method; /* ihtp_method_t */
    char url[IOG_HTTP_MAX_URL];
    size_t url_len;
    iog_http_header_t headers[IOG_HTTP_MAX_HEADERS];
    uint32_t header_count;
    char body[IOG_HTTP_MAX_BODY];
    size_t body_len;
    bool headers_complete;
    bool message_complete;
    bool is_upgrade;
} iog_http_request_t;

typedef struct {
    char buf[IOG_HTTP_BUF_SIZE];
    size_t buf_len;
    iog_http_request_t request;
    bool headers_parsed;
    size_t header_bytes;     /* bytes consumed by header section */
    uint64_t content_length; /* expected body length (0 = no body) */
} iog_http_parser_t;

/**
 * @brief Initialize an HTTP parser for request parsing.
 * @param p Parser instance to initialize.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_http_parser_init(iog_http_parser_t *p);

/**
 * @brief Reset the parser for a new request (reuses allocated memory).
 * @param p Parser instance to reset.
 */
void iog_http_parser_reset(iog_http_parser_t *p);

/**
 * @brief Parse HTTP data (may be called incrementally).
 * @param p Parser instance.
 * @param data Raw HTTP bytes.
 * @param len Length of data.
 * @return 0 on success, negative errno on parse error.
 */
[[nodiscard]] int iog_http_parse(iog_http_parser_t *p, const char *data, size_t len);

/**
 * @brief Look up a header value by name (case-insensitive).
 * @param req Parsed request.
 * @param name Header name to search for.
 * @return Pointer to the header value string, or nullptr if not found.
 */
const char *iog_http_get_header(const iog_http_request_t *req, const char *name);

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
[[nodiscard]] int iog_http_format_response(char *buf, size_t buf_size, int status_code,
                                          const iog_http_header_t *headers, uint32_t header_count,
                                          const char *body, size_t body_len);

#endif /* IOGUARD_NETWORK_HTTP_H */
