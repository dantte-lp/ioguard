#ifndef RINGWALL_NETWORK_XML_AUTH_H
#define RINGWALL_NETWORK_XML_AUTH_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_XML_MAX_STR = 256;
constexpr uint32_t RW_XML_MAX_GROUPS = 16;

typedef struct {
    char username[RW_XML_MAX_STR];
    char password[RW_XML_MAX_STR];
    char group_select[RW_XML_MAX_STR];
    char device_id[RW_XML_MAX_STR];
    char platform_version[RW_XML_MAX_STR];
    char session_token[RW_XML_MAX_STR];
    char otp[64];
    char client_version[RW_XML_MAX_STR];
    char auth_type[64]; /* "auth-request", "init", etc. */
    bool has_username;
    bool has_password;
    bool has_otp;
    bool has_session_token;
} rw_xml_auth_request_t;

typedef enum {
    RW_XML_RESP_CHALLENGE,
    RW_XML_RESP_MFA_CHALLENGE,
    RW_XML_RESP_SUCCESS,
    RW_XML_RESP_FAILURE,
} rw_xml_response_type_t;

typedef struct {
    char name[64];
    char label[128];
} rw_xml_group_t;

typedef struct {
    rw_xml_response_type_t type;
    rw_xml_group_t groups[RW_XML_MAX_GROUPS];
    uint32_t group_count;
    char banner[512];
    char session_token[RW_XML_MAX_STR];
    char error_message[RW_XML_MAX_STR];
    uint32_t retry_count;
    uint32_t max_retries;
    char mfa_message[RW_XML_MAX_STR];
} rw_xml_auth_response_t;

/**
 * @brief Parse an AggAuth XML request from client.
 * @param xml   Raw XML string
 * @param len   Length of xml
 * @param out   Parsed result (caller-allocated)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int rw_xml_parse_auth_request(const char *xml, size_t len,
                                            rw_xml_auth_request_t *out);

/**
 * @brief Build an AggAuth XML response to send to client.
 * @param resp     Response description
 * @param buf      Output buffer
 * @param buf_size Size of output buffer
 * @param out_len  Bytes written (excluding NUL)
 * @return 0 on success, negative errno on failure
 */
[[nodiscard]] int rw_xml_build_auth_response(const rw_xml_auth_response_t *resp, char *buf,
                                             size_t buf_size, size_t *out_len);

/**
 * @brief Securely zero sensitive fields in an auth request.
 * @param req  Request to zero
 */
void rw_xml_auth_request_zero(rw_xml_auth_request_t *req);

#endif /* RINGWALL_NETWORK_XML_AUTH_H */
