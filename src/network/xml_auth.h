#ifndef RINGWALL_NETWORK_XML_AUTH_H
#define RINGWALL_NETWORK_XML_AUTH_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t IOG_XML_MAX_STR = 256;
constexpr uint32_t IOG_XML_MAX_GROUPS = 16;

typedef struct {
    char username[IOG_XML_MAX_STR];
    char password[IOG_XML_MAX_STR];
    char group_select[IOG_XML_MAX_STR];
    char device_id[IOG_XML_MAX_STR];
    char platform_version[IOG_XML_MAX_STR];
    char session_token[IOG_XML_MAX_STR];
    char otp[64];
    char client_version[IOG_XML_MAX_STR];
    char auth_type[64]; /* "auth-request", "init", etc. */
    bool has_username;
    bool has_password;
    bool has_otp;
    bool has_session_token;
} iog_xml_auth_request_t;

typedef enum {
    IOG_XML_RESP_CHALLENGE,
    IOG_XML_RESP_MFA_CHALLENGE,
    IOG_XML_RESP_SUCCESS,
    IOG_XML_RESP_FAILURE,
} iog_xml_response_type_t;

typedef struct {
    char name[64];
    char label[128];
} iog_xml_group_t;

typedef struct {
    iog_xml_response_type_t type;
    iog_xml_group_t groups[IOG_XML_MAX_GROUPS];
    uint32_t group_count;
    char banner[512];
    char session_token[IOG_XML_MAX_STR];
    char error_message[IOG_XML_MAX_STR];
    uint32_t retry_count;
    uint32_t max_retries;
    char mfa_message[IOG_XML_MAX_STR];
} iog_xml_auth_response_t;

/**
 * @brief Parse an AggAuth XML request from client.
 * @param xml   Raw XML string
 * @param len   Length of xml
 * @param out   Parsed result (caller-allocated)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int iog_xml_parse_auth_request(const char *xml, size_t len,
                                            iog_xml_auth_request_t *out);

/**
 * @brief Build an AggAuth XML response to send to client.
 * @param resp     Response description
 * @param buf      Output buffer
 * @param buf_size Size of output buffer
 * @param out_len  Bytes written (excluding NUL)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int iog_xml_build_auth_response(const iog_xml_auth_response_t *resp, char *buf,
                                             size_t buf_size, size_t *out_len);

/**
 * @brief Securely zero sensitive fields in an auth request.
 * @param req  Request to zero
 */
void iog_xml_auth_request_zero(iog_xml_auth_request_t *req);

#endif /* RINGWALL_NETWORK_XML_AUTH_H */
