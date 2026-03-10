/**
 * @file dtls_headers.h
 * @brief Build and parse X-DTLS-* HTTP headers for Cisco compatibility.
 */

#ifndef RINGWALL_NETWORK_DTLS_HEADERS_H
#define RINGWALL_NETWORK_DTLS_HEADERS_H

#include <stddef.h>
#include "network/compress.h"

/**
 * Build X-DTLS-* response headers for CSTP CONNECT response.
 * Writes multiple header lines (X-DTLS-Master-Secret, X-DTLS-CipherSuite, etc.)
 * Returns bytes written or negative errno.
 */
[[nodiscard]] int rw_dtls_build_headers(char *buf, size_t buf_size, const char *master_secret_hex,
                                        const char *cipher_suite, const char *accept_encoding);

/**
 * Parse X-CSTP-Accept-Encoding header value.
 * Returns best compression type or IOG_COMPRESS_NONE.
 */
[[nodiscard]] rw_compress_type_t rw_dtls_parse_accept_encoding(const char *header);

#endif /* RINGWALL_NETWORK_DTLS_HEADERS_H */
