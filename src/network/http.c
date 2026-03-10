#include "network/http.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *status_phrase(int code)
{
    switch (code) {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 500:
        return "Internal Server Error";
    case 503:
        return "Service Unavailable";
    default:
        return "Unknown";
    }
}

/**
 * Copy up to (dst_size - 1) bytes from src (not NUL-terminated, length src_len)
 * into dst and NUL-terminate.
 */
static void copy_str(char *dst, size_t dst_size, const char *src, size_t src_len)
{
    size_t copy = src_len < dst_size - 1 ? src_len : dst_size - 1;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
}

/**
 * Extract parsed headers from ihtp_request_t into rw_http_request_t.
 * Copies pointer+length pairs into NUL-terminated fixed buffers.
 */
static void extract_headers(rw_http_request_t *dst, const ihtp_request_t *src)
{
    uint32_t count = src->num_headers < RW_HTTP_MAX_HEADERS
                         ? (uint32_t)src->num_headers
                         : RW_HTTP_MAX_HEADERS;

    for (uint32_t i = 0; i < count; i++) {
        copy_str(dst->headers[i].name, RW_HTTP_MAX_HEADER_NAME,
                 src->headers[i].name, src->headers[i].name_len);
        copy_str(dst->headers[i].value, RW_HTTP_MAX_HEADER_VALUE,
                 src->headers[i].value, src->headers[i].value_len);
    }
    dst->header_count = count;
}

int rw_http_parser_init(rw_http_parser_t *p)
{
    if (p == nullptr) {
        return -EINVAL;
    }

    memset(p, 0, sizeof(*p));
    return 0;
}

void rw_http_parser_reset(rw_http_parser_t *p)
{
    if (p == nullptr) {
        return;
    }

    memset(p, 0, sizeof(*p));
}

int rw_http_parse(rw_http_parser_t *p, const char *data, size_t len)
{
    if (p == nullptr || data == nullptr) {
        return -EINVAL;
    }

    /* If message already complete, nothing to do */
    if (p->request.message_complete) {
        return 0;
    }

    /* Accumulate incoming data into the internal buffer */
    size_t avail = RW_HTTP_BUF_SIZE - p->buf_len;
    size_t copy = len < avail ? len : avail;
    if (copy > 0) {
        memcpy(p->buf + p->buf_len, data, copy);
        p->buf_len += copy;
    }

    /* Phase 1: parse headers if not yet done */
    if (!p->headers_parsed) {
        ihtp_request_t req;
        memset(&req, 0, sizeof(req));
        size_t consumed = 0;
        ihtp_policy_t policy = IHTP_POLICY_STRICT;

        ihtp_status_t st =
            ihtp_parse_request(p->buf, p->buf_len, &req, &policy, &consumed);

        if (st == IHTP_INCOMPLETE) {
            return 0; /* need more data */
        }

        if (st != IHTP_OK) {
            return -EPROTO;
        }

        /* Headers parsed successfully — extract results */
        p->headers_parsed = true;
        p->header_bytes = consumed;
        p->request.headers_complete = true;
        p->request.method = (uint8_t)req.method;

        /* Copy URL (path) — NUL-terminate */
        copy_str(p->request.url, RW_HTTP_MAX_URL, req.path, req.path_len);
        p->request.url_len = req.path_len < RW_HTTP_MAX_URL - 1
                                 ? req.path_len
                                 : RW_HTTP_MAX_URL - 1;

        extract_headers(&p->request, &req);

        /* Determine body expectations */
        if (req.method == IHTP_METHOD_CONNECT) {
            p->request.is_upgrade = true;
            p->request.message_complete = true;
            p->content_length = 0;
            return 0;
        }

        if (req.body_mode == IHTP_BODY_FIXED && req.content_length > 0) {
            p->content_length = req.content_length;
        } else {
            /* No body expected */
            p->content_length = 0;
            p->request.message_complete = true;
            return 0;
        }
    }

    /* Phase 2: accumulate body bytes */
    size_t body_in_buf = p->buf_len - p->header_bytes;
    size_t body_want = (uint64_t)RW_HTTP_MAX_BODY < p->content_length
                           ? RW_HTTP_MAX_BODY
                           : (size_t)p->content_length;
    size_t body_copy = body_in_buf < body_want ? body_in_buf : body_want;

    if (body_copy > 0) {
        memcpy(p->request.body, p->buf + p->header_bytes, body_copy);
        p->request.body_len = body_copy;
    }

    /* Check if we have received the full body (or truncated to max) */
    if (body_in_buf >= p->content_length || body_in_buf >= RW_HTTP_MAX_BODY) {
        p->request.message_complete = true;
    }

    return 0;
}

const char *rw_http_get_header(const rw_http_request_t *req, const char *name)
{
    if (req == nullptr || name == nullptr) {
        return nullptr;
    }

    for (uint32_t i = 0; i < req->header_count; i++) {
        if (strncasecmp(req->headers[i].name, name, RW_HTTP_MAX_HEADER_NAME) == 0) {
            return req->headers[i].value;
        }
    }

    return nullptr;
}

int rw_http_format_response(char *buf, size_t buf_size, int status_code,
                            const rw_http_header_t *headers, uint32_t header_count,
                            const char *body, size_t body_len)
{
    if (buf == nullptr || buf_size == 0) {
        return -EINVAL;
    }

    int written =
        snprintf(buf, buf_size, "HTTP/1.1 %d %s\r\n", status_code, status_phrase(status_code));
    if (written < 0 || (size_t)written >= buf_size) {
        return -ENOBUFS;
    }

    size_t pos = (size_t)written;

    for (uint32_t i = 0; i < header_count; i++) {
        written =
            snprintf(buf + pos, buf_size - pos, "%s: %s\r\n", headers[i].name, headers[i].value);
        if (written < 0 || (size_t)written >= buf_size - pos) {
            return -ENOBUFS;
        }
        pos += (size_t)written;
    }

    /* Empty line separating headers from body */
    written = snprintf(buf + pos, buf_size - pos, "\r\n");
    if (written < 0 || (size_t)written >= buf_size - pos) {
        return -ENOBUFS;
    }
    pos += (size_t)written;

    if (body != nullptr && body_len > 0) {
        if (pos + body_len >= buf_size) {
            return -ENOBUFS;
        }
        memcpy(buf + pos, body, body_len);
        pos += body_len;
        buf[pos] = '\0';
    }

    return (int)pos;
}
