#ifndef WOLFGUARD_NETWORK_XML_AUTH_H
#define WOLFGUARD_NETWORK_XML_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

constexpr size_t WG_XML_MAX_STR = 256;
constexpr uint32_t WG_XML_MAX_GROUPS = 16;

typedef struct {
	char username[WG_XML_MAX_STR];
	char password[WG_XML_MAX_STR];
	char group_select[WG_XML_MAX_STR];
	char device_id[WG_XML_MAX_STR];
	char platform_version[WG_XML_MAX_STR];
	char session_token[WG_XML_MAX_STR];
	char otp[64];
	char client_version[WG_XML_MAX_STR];
	char auth_type[64]; /* "auth-request", "init", etc. */
	bool has_username;
	bool has_password;
	bool has_otp;
	bool has_session_token;
} wg_xml_auth_request_t;

typedef enum {
	WG_XML_RESP_CHALLENGE,
	WG_XML_RESP_MFA_CHALLENGE,
	WG_XML_RESP_SUCCESS,
	WG_XML_RESP_FAILURE,
} wg_xml_response_type_t;

typedef struct {
	char name[64];
	char label[128];
} wg_xml_group_t;

typedef struct {
	wg_xml_response_type_t type;
	wg_xml_group_t groups[WG_XML_MAX_GROUPS];
	uint32_t group_count;
	char banner[512];
	char session_token[WG_XML_MAX_STR];
	char error_message[WG_XML_MAX_STR];
	uint32_t retry_count;
	uint32_t max_retries;
	char mfa_message[WG_XML_MAX_STR];
} wg_xml_auth_response_t;

/**
 * @brief Parse an AggAuth XML request from client.
 * @param xml   Raw XML string
 * @param len   Length of xml
 * @param out   Parsed result (caller-allocated)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int wg_xml_parse_auth_request(const char *xml, size_t len,
					    wg_xml_auth_request_t *out);

/**
 * @brief Build an AggAuth XML response to send to client.
 * @param resp     Response description
 * @param buf      Output buffer
 * @param buf_size Size of output buffer
 * @param out_len  Bytes written (excluding NUL)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int wg_xml_build_auth_response(
	const wg_xml_auth_response_t *resp, char *buf, size_t buf_size,
	size_t *out_len);

/**
 * @brief Securely zero sensitive fields in an auth request.
 * @param req  Request to zero
 */
void wg_xml_auth_request_zero(wg_xml_auth_request_t *req);

#endif /* WOLFGUARD_NETWORK_XML_AUTH_H */
