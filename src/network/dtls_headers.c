#include "network/dtls_headers.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int rw_dtls_build_headers(char *buf, size_t buf_size, const char *master_secret_hex,
                          const char *cipher_suite, const char *accept_encoding)
{
    if (!buf || !master_secret_hex || !cipher_suite) {
        return -EINVAL;
    }

    int n = snprintf(buf, buf_size,
                     "X-DTLS-Master-Secret: %s\r\n"
                     "X-DTLS-CipherSuite: %s\r\n"
                     "X-DTLS12-CipherSuite: %s\r\n",
                     master_secret_hex, cipher_suite, cipher_suite);

    if (n < 0) {
        return -EIO;
    }
    if ((size_t)n >= buf_size) {
        return -ENOSPC;
    }

    /* Append compression if negotiated */
    if (accept_encoding && strlen(accept_encoding) > 0) {
        rw_compress_type_t ct = rw_compress_negotiate(accept_encoding);
        if (ct != RW_COMPRESS_NONE) {
            int extra = snprintf(buf + n, buf_size - (size_t)n, "X-DTLS-Accept-Encoding: %s\r\n",
                                 rw_compress_type_name(ct));
            if (extra < 0) {
                return -EIO;
            }
            if ((size_t)(n + extra) >= buf_size) {
                return -ENOSPC;
            }
            n += extra;
        }
    }

    return n;
}

rw_compress_type_t rw_dtls_parse_accept_encoding(const char *header)
{
    return rw_compress_negotiate(header);
}
