#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "network/dns.h"

static rw_dns_config_t cfg;

void setUp(void)
{
    rw_dns_config_init(&cfg);
}

void tearDown(void)
{
}

/* ============================================================================
 * DNS config initialization
 * ============================================================================ */

void test_dns_config_init_defaults(void)
{
    TEST_ASSERT_EQUAL_INT(RW_DNS_STANDARD, cfg.mode);
    TEST_ASSERT_EQUAL_UINT(0, cfg.server_count);
    TEST_ASSERT_EQUAL_UINT(0, cfg.split_domain_count);
    TEST_ASSERT_EQUAL_CHAR('\0', cfg.default_domain[0]);
}

void test_dns_config_add_server(void)
{
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_server(&cfg, "8.8.8.8"));
    TEST_ASSERT_EQUAL_UINT(1, cfg.server_count);
    TEST_ASSERT_EQUAL_STRING("8.8.8.8", cfg.servers[0]);
}

void test_dns_config_add_server_ipv6(void)
{
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_server(&cfg, "2001:4860:4860::8888"));
    TEST_ASSERT_EQUAL_UINT(1, cfg.server_count);
    TEST_ASSERT_EQUAL_STRING("2001:4860:4860::8888", cfg.servers[0]);
}

void test_dns_config_add_server_max(void)
{
    for (size_t i = 0; i < RW_DNS_MAX_SERVERS; i++) {
        char addr[16];
        snprintf(addr, sizeof(addr), "10.0.0.%zu", i + 1);
        TEST_ASSERT_EQUAL_INT(0, rw_dns_add_server(&cfg, addr));
    }
    /* One more should fail */
    TEST_ASSERT_EQUAL_INT(-ENOSPC, rw_dns_add_server(&cfg, "10.0.0.99"));
}

void test_dns_config_set_domain(void)
{
    rw_dns_set_default_domain(&cfg, "corp.example.com");
    TEST_ASSERT_EQUAL_STRING("corp.example.com", cfg.default_domain);
}

/* ============================================================================
 * Split DNS domain matching
 * ============================================================================ */

void test_dns_domain_match_exact(void)
{
    TEST_ASSERT_TRUE(rw_dns_domain_matches("corp.example.com", "corp.example.com"));
}

void test_dns_domain_match_subdomain(void)
{
    TEST_ASSERT_TRUE(rw_dns_domain_matches("mail.corp.example.com", "corp.example.com"));
}

void test_dns_domain_no_match(void)
{
    TEST_ASSERT_FALSE(rw_dns_domain_matches("example.org", "corp.example.com"));
}

void test_dns_domain_no_partial_match(void)
{
    /* "notcorp.example.com" must NOT match "corp.example.com" */
    TEST_ASSERT_FALSE(rw_dns_domain_matches("notcorp.example.com", "corp.example.com"));
}

void test_dns_domain_case_insensitive(void)
{
    TEST_ASSERT_TRUE(rw_dns_domain_matches("CORP.EXAMPLE.COM", "corp.example.com"));
    TEST_ASSERT_TRUE(rw_dns_domain_matches("Mail.Corp.Example.COM", "corp.example.com"));
}

/* ============================================================================
 * Split DNS domain list
 * ============================================================================ */

void test_dns_add_split_domain(void)
{
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_split_domain(&cfg, "corp.example.com"));
    TEST_ASSERT_EQUAL_UINT(1, cfg.split_domain_count);
}

void test_dns_add_split_domain_max(void)
{
    for (size_t i = 0; i < RW_DNS_MAX_DOMAINS; i++) {
        char domain[64];
        snprintf(domain, sizeof(domain), "d%zu.example.com", i);
        TEST_ASSERT_EQUAL_INT(0, rw_dns_add_split_domain(&cfg, domain));
    }
    TEST_ASSERT_EQUAL_INT(-ENOSPC, rw_dns_add_split_domain(&cfg, "overflow.com"));
}

void test_dns_is_split_domain(void)
{
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_split_domain(&cfg, "corp.example.com"));
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_split_domain(&cfg, "internal.net"));

    TEST_ASSERT_TRUE(rw_dns_is_split_domain(&cfg, "corp.example.com"));
    TEST_ASSERT_TRUE(rw_dns_is_split_domain(&cfg, "mail.corp.example.com"));
    TEST_ASSERT_TRUE(rw_dns_is_split_domain(&cfg, "internal.net"));
}

void test_dns_is_not_split_domain(void)
{
    TEST_ASSERT_EQUAL_INT(0, rw_dns_add_split_domain(&cfg, "corp.example.com"));

    TEST_ASSERT_FALSE(rw_dns_is_split_domain(&cfg, "example.org"));
    TEST_ASSERT_FALSE(rw_dns_is_split_domain(&cfg, "notcorp.example.com"));
}

/* ============================================================================
 * Mode validation
 * ============================================================================ */

void test_dns_mode_split(void)
{
    rw_dns_set_mode(&cfg, RW_DNS_SPLIT);
    TEST_ASSERT_EQUAL_INT(RW_DNS_SPLIT, cfg.mode);
}

void test_dns_mode_tunnel_all(void)
{
    rw_dns_set_mode(&cfg, RW_DNS_TUNNEL_ALL);
    TEST_ASSERT_EQUAL_INT(RW_DNS_TUNNEL_ALL, cfg.mode);
}

void test_dns_mode_standard(void)
{
    rw_dns_set_mode(&cfg, RW_DNS_STANDARD);
    TEST_ASSERT_EQUAL_INT(RW_DNS_STANDARD, cfg.mode);
}

int main(void)
{
    UNITY_BEGIN();
    /* Config init */
    RUN_TEST(test_dns_config_init_defaults);
    RUN_TEST(test_dns_config_add_server);
    RUN_TEST(test_dns_config_add_server_ipv6);
    RUN_TEST(test_dns_config_add_server_max);
    RUN_TEST(test_dns_config_set_domain);
    /* Domain matching */
    RUN_TEST(test_dns_domain_match_exact);
    RUN_TEST(test_dns_domain_match_subdomain);
    RUN_TEST(test_dns_domain_no_match);
    RUN_TEST(test_dns_domain_no_partial_match);
    RUN_TEST(test_dns_domain_case_insensitive);
    /* Split domain list */
    RUN_TEST(test_dns_add_split_domain);
    RUN_TEST(test_dns_add_split_domain_max);
    RUN_TEST(test_dns_is_split_domain);
    RUN_TEST(test_dns_is_not_split_domain);
    /* Mode */
    RUN_TEST(test_dns_mode_split);
    RUN_TEST(test_dns_mode_tunnel_all);
    RUN_TEST(test_dns_mode_standard);
    return UNITY_END();
}
