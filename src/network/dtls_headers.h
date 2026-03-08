/**
 * @file dtls_headers.h
 * @brief Build and parse X-DTLS-* HTTP headers for Cisco compatibility.
 */

#ifndef WOLFGUARD_NETWORK_DTLS_HEADERS_H
#define WOLFGUARD_NETWORK_DTLS_HEADERS_H

#include "network/compress.h"
#include <stddef.h>

/**
 * Build X-DTLS-* response headers for CSTP CONNECT response.
 * Writes multiple header lines (X-DTLS-Master-Secret, X-DTLS-CipherSuite, etc.)
 * Returns bytes written or negative errno.
 */
[[nodiscard]] int wg_dtls_build_headers(char *buf, size_t buf_size,
                                         const char *master_secret_hex,
                                         const char *cipher_suite,
                                         const char *accept_encoding);

/**
 * Parse X-CSTP-Accept-Encoding header value.
 * Returns best compression type or WG_COMPRESS_NONE.
 */
[[nodiscard]] wg_compress_type_t wg_dtls_parse_accept_encoding(
	const char *header);

#endif /* WOLFGUARD_NETWORK_DTLS_HEADERS_H */
