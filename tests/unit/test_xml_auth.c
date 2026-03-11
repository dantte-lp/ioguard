#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/xml_auth.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_xml_parse_init_request(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"init\""
                      " aggregate-auth-version=\"2\">"
                      "<version who=\"vpn\">5.0</version>"
                      "<device-id>linux-64</device-id>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("init", req.auth_type);
    TEST_ASSERT_EQUAL_STRING("linux-64", req.device_id);
    TEST_ASSERT_EQUAL_STRING("5.0", req.client_version);
    TEST_ASSERT_EQUAL_STRING("vpn", req.platform_version);
}

void test_xml_parse_auth_credentials(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"auth-request\""
                      " aggregate-auth-version=\"2\">"
                      "<version who=\"vpn\">5.0</version>"
                      "<device-id>linux-64</device-id>"
                      "<auth>"
                      "<username>testuser</username>"
                      "<password>s3cret!</password>"
                      "</auth>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("auth-request", req.auth_type);
    TEST_ASSERT_TRUE(req.has_username);
    TEST_ASSERT_TRUE(req.has_password);
    TEST_ASSERT_EQUAL_STRING("testuser", req.username);
    TEST_ASSERT_EQUAL_STRING("s3cret!", req.password);
}

void test_xml_parse_group_select(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"auth-request\">"
                      "<group-select>engineering</group-select>"
                      "<auth>"
                      "<username>alice</username>"
                      "<password>pw</password>"
                      "</auth>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("engineering", req.group_select);
}

void test_xml_parse_otp(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"auth-request\">"
                      "<auth>"
                      "<otp>123456</otp>"
                      "</auth>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(req.has_otp);
    TEST_ASSERT_EQUAL_STRING("123456", req.otp);
}

void test_xml_parse_session_token(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"auth-request\">"
                      "<session-token>tok_abc123def456</session-token>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(req.has_session_token);
    TEST_ASSERT_EQUAL_STRING("tok_abc123def456", req.session_token);
}

void test_xml_build_challenge_form(void)
{
    iog_xml_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = IOG_XML_RESP_CHALLENGE;

    char buf[4096];
    size_t out_len = 0;
    int ret = iog_xml_build_auth_response(&resp, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_THAN(0, out_len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "<?xml version="));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<config-auth"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "type=\"auth-request\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<input type=\"text\" name=\"username\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<input type=\"password\" name=\"password\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "</config-auth>"));
}

void test_xml_build_mfa_challenge(void)
{
    iog_xml_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = IOG_XML_RESP_MFA_CHALLENGE;
    snprintf(resp.mfa_message, sizeof(resp.mfa_message), "Enter your OTP code");

    char buf[4096];
    size_t out_len = 0;
    int ret = iog_xml_build_auth_response(&resp, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_THAN(0, out_len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "Two-Factor Authentication"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "Enter your OTP code"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "name=\"otp\""));
}

void test_xml_build_success_response(void)
{
    iog_xml_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = IOG_XML_RESP_SUCCESS;
    snprintf(resp.session_token, sizeof(resp.session_token), "session_xyz789");

    char buf[4096];
    size_t out_len = 0;
    int ret = iog_xml_build_auth_response(&resp, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_THAN(0, out_len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "type=\"complete\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<session-token>session_xyz789</session-token>"));
}

void test_xml_build_failure_response(void)
{
    iog_xml_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = IOG_XML_RESP_FAILURE;
    snprintf(resp.error_message, sizeof(resp.error_message), "Invalid credentials");
    resp.retry_count = 1;
    resp.max_retries = 3;

    char buf[4096];
    size_t out_len = 0;
    int ret = iog_xml_build_auth_response(&resp, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_THAN(0, out_len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "type=\"auth-failed\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "Invalid credentials"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<retry-count>1</retry-count>"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<max-retries>3</max-retries>"));
}

void test_xml_build_group_select(void)
{
    iog_xml_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = IOG_XML_RESP_CHALLENGE;
    resp.group_count = 2;
    snprintf(resp.groups[0].name, sizeof(resp.groups[0].name), "engineering");
    snprintf(resp.groups[0].label, sizeof(resp.groups[0].label), "Engineering VPN");
    snprintf(resp.groups[1].name, sizeof(resp.groups[1].name), "sales");
    snprintf(resp.groups[1].label, sizeof(resp.groups[1].label), "Sales VPN");

    char buf[4096];
    size_t out_len = 0;
    int ret = iog_xml_build_auth_response(&resp, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_NOT_NULL(strstr(buf, "<select"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<option value=\"engineering\">Engineering VPN</option>"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "<option value=\"sales\">Sales VPN</option>"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "</select>"));
}

void test_xml_parse_entity_decode(void)
{
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                      "<config-auth client=\"vpn\" type=\"auth-request\">"
                      "<auth>"
                      "<username>user&amp;name</username>"
                      "<password>p&lt;s&gt;s&quot;w</password>"
                      "</auth>"
                      "</config-auth>";

    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(xml, strlen(xml), &req);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("user&name", req.username);
    TEST_ASSERT_EQUAL_STRING("p<s>s\"w", req.password);
}

void test_xml_password_zeroed(void)
{
    iog_xml_auth_request_t req;
    memset(&req, 0, sizeof(req));
    snprintf(req.password, sizeof(req.password), "supersecret");
    snprintf(req.otp, sizeof(req.otp), "123456");
    snprintf(req.session_token, sizeof(req.session_token), "tok_abc");

    /* Verify fields are set */
    TEST_ASSERT_EQUAL_STRING("supersecret", req.password);
    TEST_ASSERT_EQUAL_STRING("123456", req.otp);
    TEST_ASSERT_EQUAL_STRING("tok_abc", req.session_token);

    iog_xml_auth_request_zero(&req);

    /* All sensitive fields should be zeroed */
    for (size_t i = 0; i < sizeof(req.password); i++) {
        TEST_ASSERT_EQUAL_UINT8(0, (uint8_t)req.password[i]);
    }
    for (size_t i = 0; i < sizeof(req.otp); i++) {
        TEST_ASSERT_EQUAL_UINT8(0, (uint8_t)req.otp[i]);
    }
    for (size_t i = 0; i < sizeof(req.session_token); i++) {
        TEST_ASSERT_EQUAL_UINT8(0, (uint8_t)req.session_token[i]);
    }
}

void test_xml_malformed_xml(void)
{
    /* No config-auth tag at all */
    const char *garbage = "this is not xml at all";
    iog_xml_auth_request_t req;
    int ret = iog_xml_parse_auth_request(garbage, strlen(garbage), &req);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* nullptr input */
    ret = iog_xml_parse_auth_request(nullptr, 0, &req);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* Empty input */
    ret = iog_xml_parse_auth_request("", 0, &req);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_xml_parse_init_request);
    RUN_TEST(test_xml_parse_auth_credentials);
    RUN_TEST(test_xml_parse_group_select);
    RUN_TEST(test_xml_parse_otp);
    RUN_TEST(test_xml_parse_session_token);
    RUN_TEST(test_xml_build_challenge_form);
    RUN_TEST(test_xml_build_mfa_challenge);
    RUN_TEST(test_xml_build_success_response);
    RUN_TEST(test_xml_build_failure_response);
    RUN_TEST(test_xml_build_group_select);
    RUN_TEST(test_xml_parse_entity_decode);
    RUN_TEST(test_xml_password_zeroed);
    RUN_TEST(test_xml_malformed_xml);
    return UNITY_END();
}
