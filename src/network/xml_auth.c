#define _GNU_SOURCE
#include "network/xml_auth.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/**
 * Decode XML character entities in-place from src to dst.
 * Handles: &amp; &lt; &gt; &quot; &apos;
 */
static void xml_entity_decode(const char *src, char *dst, size_t dst_size)
{
	if (dst_size == 0)
		return;

	size_t j = 0;
	size_t max = dst_size - 1;

	for (size_t i = 0; src[i] != '\0' && j < max; ) {
		if (src[i] == '&') {
			if (strncmp(&src[i], "&amp;", 5) == 0) {
				dst[j++] = '&';
				i += 5;
			} else if (strncmp(&src[i], "&lt;", 4) == 0) {
				dst[j++] = '<';
				i += 4;
			} else if (strncmp(&src[i], "&gt;", 4) == 0) {
				dst[j++] = '>';
				i += 4;
			} else if (strncmp(&src[i], "&quot;", 6) == 0) {
				dst[j++] = '"';
				i += 6;
			} else if (strncmp(&src[i], "&apos;", 6) == 0) {
				dst[j++] = '\'';
				i += 6;
			} else {
				dst[j++] = src[i++];
			}
		} else {
			dst[j++] = src[i++];
		}
	}
	dst[j] = '\0';
}

/**
 * Escape special XML characters: < > & "
 * Returns 0 on success, -ENOSPC if buffer too small.
 */
static int xml_escape(const char *src, char *dst, size_t dst_size)
{
	if (dst_size == 0)
		return -ENOSPC;

	size_t j = 0;
	size_t max = dst_size - 1;

	for (size_t i = 0; src[i] != '\0'; i++) {
		const char *esc = nullptr;
		size_t esc_len = 0;

		switch (src[i]) {
		case '&':
			esc = "&amp;";
			esc_len = 5;
			break;
		case '<':
			esc = "&lt;";
			esc_len = 4;
			break;
		case '>':
			esc = "&gt;";
			esc_len = 4;
			break;
		case '"':
			esc = "&quot;";
			esc_len = 6;
			break;
		default:
			if (j >= max)
				return -ENOSPC;
			dst[j++] = src[i];
			continue;
		}

		if (j + esc_len > max)
			return -ENOSPC;
		memcpy(&dst[j], esc, esc_len);
		j += esc_len;
	}
	dst[j] = '\0';
	return 0;
}

/**
 * Find the start of <tag or <tag> in xml.
 * Returns pointer to '<' or nullptr if not found.
 */
static const char *find_tag_start(const char *xml, const char *tag)
{
	size_t tag_len = strlen(tag);

	for (const char *p = xml; *p != '\0'; p++) {
		if (*p != '<')
			continue;
		const char *t = p + 1;
		if (strncmp(t, tag, tag_len) == 0) {
			char next = t[tag_len];
			if (next == '>' || next == ' ' || next == '/'
			    || next == '\t' || next == '\n' || next == '\r')
				return p;
		}
	}
	return nullptr;
}

/**
 * Find the closing </tag> in xml.
 * Returns pointer to '<' of </tag> or nullptr.
 */
static const char *find_tag_end(const char *xml, const char *tag)
{
	size_t tag_len = strlen(tag);
	char pattern[128];
	int n = snprintf(pattern, sizeof(pattern), "</%s>", tag);
	if (n < 0 || (size_t)n >= sizeof(pattern))
		return nullptr;

	const char *p = strstr(xml, pattern);
	(void)tag_len;
	return p;
}

/**
 * Extract text between <tag> and </tag>, entity-decode it.
 * Returns 0 on success, -ENOENT if tag not found.
 */
static int extract_tag_content(const char *xml, const char *tag,
			       char *out, size_t out_size)
{
	const char *start = find_tag_start(xml, tag);
	if (start == nullptr)
		return -ENOENT;

	/* Skip past the '>' of the opening tag */
	const char *gt = strchr(start, '>');
	if (gt == nullptr)
		return -EINVAL;
	/* Check for self-closing tag */
	if (gt > start && *(gt - 1) == '/') {
		out[0] = '\0';
		return 0;
	}
	const char *content_start = gt + 1;

	const char *end = find_tag_end(content_start, tag);
	if (end == nullptr)
		return -ENOENT;

	size_t content_len = (size_t)(end - content_start);

	/* Copy raw content to temporary buffer */
	char tmp[1024];
	size_t copy_len = content_len;
	if (copy_len >= sizeof(tmp))
		copy_len = sizeof(tmp) - 1;
	memcpy(tmp, content_start, copy_len);
	tmp[copy_len] = '\0';

	xml_entity_decode(tmp, out, out_size);
	return 0;
}

/**
 * Extract an attribute value from a tag string.
 * tag_start points to '<'. Searches for attr="value".
 * Returns 0 on success, -ENOENT if not found.
 */
static int extract_attribute(const char *tag_start, const char *attr,
			     char *out, size_t out_size)
{
	/* Find end of opening tag */
	const char *gt = strchr(tag_start, '>');
	if (gt == nullptr)
		return -EINVAL;

	size_t attr_len = strlen(attr);

	for (const char *p = tag_start; p < gt; p++) {
		if (strncmp(p, attr, attr_len) != 0)
			continue;
		if (p[attr_len] != '=')
			continue;
		char quote = p[attr_len + 1];
		if (quote != '"' && quote != '\'')
			continue;

		const char *val_start = p + attr_len + 2;
		const char *val_end = strchr(val_start, quote);
		if (val_end == nullptr || val_end > gt)
			return -EINVAL;

		size_t val_len = (size_t)(val_end - val_start);
		if (val_len >= out_size)
			val_len = out_size - 1;
		memcpy(out, val_start, val_len);
		out[val_len] = '\0';
		return 0;
	}
	return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* append helper for builder                                           */
/* ------------------------------------------------------------------ */

struct xml_buf {
	char *buf;
	size_t size;
	size_t pos;
	bool overflow;
};

static void xb_append(struct xml_buf *xb, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void xb_append(struct xml_buf *xb, const char *fmt, ...)
{
	if (xb->overflow)
		return;

	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(xb->buf + xb->pos, xb->size - xb->pos, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= xb->size - xb->pos) {
		xb->overflow = true;
		return;
	}
	xb->pos += (size_t)n;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int wg_xml_parse_auth_request(const char *xml, size_t len,
			      wg_xml_auth_request_t *out)
{
	if (xml == nullptr || out == nullptr || len == 0)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	/* Verify this looks like XML */
	const char *ca = find_tag_start(xml, "config-auth");
	if (ca == nullptr)
		return -EINVAL;

	/* Extract type attribute from <config-auth> */
	extract_attribute(ca, "type", out->auth_type, sizeof(out->auth_type));

	/* Top-level fields */
	extract_tag_content(xml, "device-id", out->device_id,
			    sizeof(out->device_id));
	extract_tag_content(xml, "group-select", out->group_select,
			    sizeof(out->group_select));
	extract_tag_content(xml, "session-token", out->session_token,
			    sizeof(out->session_token));
	if (out->session_token[0] != '\0')
		out->has_session_token = true;

	/* <version who="vpn"> content -> client_version */
	const char *ver_tag = find_tag_start(xml, "version");
	if (ver_tag != nullptr) {
		extract_tag_content(xml, "version", out->client_version,
				    sizeof(out->client_version));
		extract_attribute(ver_tag, "who", out->platform_version,
				  sizeof(out->platform_version));
	}

	/* <auth> block: username, password, otp */
	const char *auth_start = find_tag_start(xml, "auth");
	if (auth_start != nullptr) {
		const char *auth_end = find_tag_end(auth_start, "auth");
		if (auth_end != nullptr) {
			/* Work within the auth block */
			size_t auth_len = (size_t)(auth_end - auth_start);
			char auth_block[2048];
			size_t copy_len = auth_len;
			if (copy_len >= sizeof(auth_block))
				copy_len = sizeof(auth_block) - 1;
			memcpy(auth_block, auth_start, copy_len);
			auth_block[copy_len] = '\0';

			if (extract_tag_content(auth_block, "username",
						out->username,
						sizeof(out->username)) == 0) {
				if (out->username[0] != '\0')
					out->has_username = true;
			}

			if (extract_tag_content(auth_block, "password",
						out->password,
						sizeof(out->password)) == 0) {
				if (out->password[0] != '\0')
					out->has_password = true;
			}

			if (extract_tag_content(auth_block, "otp",
						out->otp,
						sizeof(out->otp)) == 0) {
				if (out->otp[0] != '\0')
					out->has_otp = true;
			}
		}
	}

	return 0;
}

int wg_xml_build_auth_response(const wg_xml_auth_response_t *resp,
			       char *buf, size_t buf_size, size_t *out_len)
{
	if (resp == nullptr || buf == nullptr || buf_size == 0
	    || out_len == nullptr)
		return -EINVAL;

	struct xml_buf xb = {
		.buf = buf,
		.size = buf_size,
		.pos = 0,
		.overflow = false,
	};

	xb_append(&xb,
		   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

	switch (resp->type) {
	case WG_XML_RESP_CHALLENGE:
		xb_append(&xb,
			   "<config-auth client=\"vpn\""
			   " type=\"auth-request\">\n");

		if (resp->banner[0] != '\0') {
			char esc[1024];
			xml_escape(resp->banner, esc, sizeof(esc));
			xb_append(&xb,
				   "<banner>%s</banner>\n", esc);
		}

		xb_append(&xb,
			   "<opaque is-for=\"sg\">\n"
			   "<tunnel-group>default</tunnel-group>\n"
			   "</opaque>\n");

		xb_append(&xb,
			   "<auth id=\"main\">\n"
			   "<title>Login</title>\n"
			   "<message>Please enter your credentials"
			   "</message>\n"
			   "<form method=\"post\" action=\"/auth\">\n");

		/* Group select if groups are provided */
		if (resp->group_count > 0) {
			xb_append(&xb,
				   "<select name=\"group_list\" "
				   "label=\"GROUP:\">\n");
			for (uint32_t i = 0; i < resp->group_count
			     && i < WG_XML_MAX_GROUPS; i++) {
				char esc_name[128];
				char esc_label[256];
				xml_escape(resp->groups[i].name,
					   esc_name, sizeof(esc_name));
				xml_escape(resp->groups[i].label,
					   esc_label, sizeof(esc_label));
				xb_append(&xb,
					   "<option value=\"%s\">%s"
					   "</option>\n",
					   esc_name, esc_label);
			}
			xb_append(&xb, "</select>\n");
		}

		xb_append(&xb,
			   "<input type=\"text\" name=\"username\""
			   " label=\"Username:\"/>\n"
			   "<input type=\"password\" name=\"password\""
			   " label=\"Password:\"/>\n"
			   "</form>\n"
			   "</auth>\n"
			   "</config-auth>\n");
		break;

	case WG_XML_RESP_MFA_CHALLENGE:
		xb_append(&xb,
			   "<config-auth client=\"vpn\""
			   " type=\"auth-request\">\n");

		xb_append(&xb,
			   "<auth id=\"main\">\n"
			   "<title>Two-Factor Authentication</title>\n");

		if (resp->mfa_message[0] != '\0') {
			char esc[512];
			xml_escape(resp->mfa_message, esc, sizeof(esc));
			xb_append(&xb,
				   "<message>%s</message>\n", esc);
		} else {
			xb_append(&xb,
				   "<message>Enter verification code"
				   "</message>\n");
		}

		xb_append(&xb,
			   "<form method=\"post\" action=\"/auth\">\n"
			   "<input type=\"text\" name=\"otp\""
			   " label=\"Verification Code:\"/>\n"
			   "</form>\n"
			   "</auth>\n"
			   "</config-auth>\n");
		break;

	case WG_XML_RESP_SUCCESS:
		xb_append(&xb,
			   "<config-auth client=\"vpn\""
			   " type=\"complete\">\n");

		if (resp->session_token[0] != '\0') {
			char esc[512];
			xml_escape(resp->session_token, esc, sizeof(esc));
			xb_append(&xb,
				   "<session-token>%s</session-token>\n",
				   esc);
		}

		xb_append(&xb,
			   "<config>\n"
			   "<vpn-base-config>\n"
			   "<server-cert-hash/>\n"
			   "</vpn-base-config>\n"
			   "</config>\n"
			   "</config-auth>\n");
		break;

	case WG_XML_RESP_FAILURE:
		xb_append(&xb,
			   "<config-auth client=\"vpn\""
			   " type=\"auth-failed\">\n");

		if (resp->error_message[0] != '\0') {
			char esc[512];
			xml_escape(resp->error_message, esc, sizeof(esc));
			xb_append(&xb,
				   "<error>%s</error>\n", esc);
		}

		if (resp->max_retries > 0) {
			xb_append(&xb,
				   "<retry-count>%u</retry-count>\n"
				   "<max-retries>%u</max-retries>\n",
				   resp->retry_count, resp->max_retries);
		}

		xb_append(&xb, "</config-auth>\n");
		break;
	}

	if (xb.overflow)
		return -ENOSPC;

	*out_len = xb.pos;
	return 0;
}

void wg_xml_auth_request_zero(wg_xml_auth_request_t *req)
{
	if (req == nullptr)
		return;

	explicit_bzero(req->password, sizeof(req->password));
	explicit_bzero(req->otp, sizeof(req->otp));
	explicit_bzero(req->session_token, sizeof(req->session_token));
}
