#include "network/http.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Forward declarations for llhttp callbacks */
static int on_url(llhttp_t *parser, const char *at, size_t length);
static int on_header_field(llhttp_t *parser, const char *at, size_t length);
static int on_header_value(llhttp_t *parser, const char *at, size_t length);
static int on_header_value_complete(llhttp_t *parser);
static int on_body(llhttp_t *parser, const char *at, size_t length);
static int on_headers_complete(llhttp_t *parser);
static int on_message_complete(llhttp_t *parser);

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

int rw_http_parser_init(rw_http_parser_t *p)
{
    if (p == nullptr) {
        return -EINVAL;
    }

    memset(p, 0, sizeof(*p));

    llhttp_settings_init(&p->settings);
    p->settings.on_url = on_url;
    p->settings.on_header_field = on_header_field;
    p->settings.on_header_value = on_header_value;
    p->settings.on_header_value_complete = on_header_value_complete;
    p->settings.on_body = on_body;
    p->settings.on_headers_complete = on_headers_complete;
    p->settings.on_message_complete = on_message_complete;

    llhttp_init(&p->parser, HTTP_REQUEST, &p->settings);
    p->parser.data = p;

    return 0;
}

void rw_http_parser_reset(rw_http_parser_t *p)
{
    if (p == nullptr) {
        return;
    }

    memset(&p->request, 0, sizeof(p->request));
    llhttp_reset(&p->parser);
    llhttp_init(&p->parser, HTTP_REQUEST, &p->settings);
    p->parser.data = p;
}

int rw_http_parse(rw_http_parser_t *p, const char *data, size_t len)
{
    if (p == nullptr || data == nullptr) {
        return -EINVAL;
    }

    llhttp_errno_t err = llhttp_execute(&p->parser, data, len);

    if (err == HPE_OK) {
        return 0;
    }

    if (err == HPE_PAUSED_UPGRADE) {
        p->request.is_upgrade = true;
        return 0;
    }

    return -EPROTO;
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

/* ---- llhttp callbacks ---- */

static int on_url(llhttp_t *parser, const char *at, size_t length)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    size_t avail = RW_HTTP_MAX_URL - 1 - req->url_len;
    size_t copy = length < avail ? length : avail;

    memcpy(req->url + req->url_len, at, copy);
    req->url_len += copy;
    req->url[req->url_len] = '\0';

    return 0;
}

static int on_header_field(llhttp_t *parser, const char *at, size_t length)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    /* If we were accumulating a value, we've moved to a new field */
    if (req->_parsing_value) {
        req->_cur_field_len = 0;
        req->_cur_value_len = 0;
        req->_parsing_value = false;
    }

    size_t avail = RW_HTTP_MAX_HEADER_NAME - 1 - req->_cur_field_len;
    size_t copy = length < avail ? length : avail;

    memcpy(req->_cur_header_field + req->_cur_field_len, at, copy);
    req->_cur_field_len += copy;
    req->_cur_header_field[req->_cur_field_len] = '\0';

    return 0;
}

static int on_header_value(llhttp_t *parser, const char *at, size_t length)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    req->_parsing_value = true;

    size_t avail = RW_HTTP_MAX_HEADER_VALUE - 1 - req->_cur_value_len;
    size_t copy = length < avail ? length : avail;

    memcpy(req->_cur_header_value + req->_cur_value_len, at, copy);
    req->_cur_value_len += copy;
    req->_cur_header_value[req->_cur_value_len] = '\0';

    return 0;
}

static int on_header_value_complete(llhttp_t *parser)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    if (req->header_count >= RW_HTTP_MAX_HEADERS) {
        return 0;
    }

    snprintf(req->headers[req->header_count].name, RW_HTTP_MAX_HEADER_NAME, "%s",
             req->_cur_header_field);
    snprintf(req->headers[req->header_count].value, RW_HTTP_MAX_HEADER_VALUE, "%s",
             req->_cur_header_value);

    req->header_count++;
    req->_cur_field_len = 0;
    req->_cur_value_len = 0;
    req->_parsing_value = false;

    return 0;
}

static int on_body(llhttp_t *parser, const char *at, size_t length)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    size_t avail = RW_HTTP_MAX_BODY - req->body_len;
    size_t copy = length < avail ? length : avail;

    if (copy > 0) {
        memcpy(req->body + req->body_len, at, copy);
        req->body_len += copy;
    }

    return 0;
}

static int on_headers_complete(llhttp_t *parser)
{
    rw_http_parser_t *p = parser->data;
    rw_http_request_t *req = &p->request;

    req->headers_complete = true;
    req->method = llhttp_get_method(parser);

    /* For CONNECT requests, signal upgrade so llhttp returns HPE_PAUSED_UPGRADE */
    if (req->method == HTTP_CONNECT) {
        return 2;
    }

    return 0;
}

static int on_message_complete(llhttp_t *parser)
{
    rw_http_parser_t *p = parser->data;
    p->request.message_complete = true;
    return 0;
}
