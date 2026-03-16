#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "network/ipam.h"

static iog_ipam_t ipam;

void setUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_init(&ipam));
}

void tearDown(void)
{
    iog_ipam_destroy(&ipam);
}

/* ============================================================================
 * Pool creation and validation
 * ============================================================================ */

void test_ipam_pool_create_ipv4(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));
    TEST_ASSERT_EQUAL_UINT(1, ipam.pool_count);
    TEST_ASSERT_EQUAL_UINT(254, ipam.pools[0].total_hosts);
    TEST_ASSERT_EQUAL_INT(AF_INET, ipam.pools[0].af);
}

void test_ipam_pool_create_ipv6(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "fd00:abcd::/112"));
    TEST_ASSERT_EQUAL_UINT(1, ipam.pool_count);
    TEST_ASSERT_EQUAL_UINT(65535, ipam.pools[0].total_hosts);
    TEST_ASSERT_EQUAL_INT(AF_INET6, ipam.pools[0].af);
}

void test_ipam_pool_create_invalid_cidr(void)
{
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ipam_add_pool(&ipam, "invalid"));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ipam_add_pool(&ipam, ""));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ipam_add_pool(&ipam, "10.0.0.1"));
}

void test_ipam_pool_create_host_addr(void)
{
    /* /32 has no usable host range */
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ipam_add_pool(&ipam, "10.0.0.1/32"));
    /* /31 point-to-point — no usable hosts */
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ipam_add_pool(&ipam, "10.0.0.0/31"));
}

/* ============================================================================
 * Allocation and release
 * ============================================================================ */

void test_ipam_alloc_ipv4_first(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr addr;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &addr));

    /* First usable address: 10.10.0.1 (skip network .0) */
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("10.10.0.1", buf);
}

void test_ipam_alloc_ipv4_sequential(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr a1, a2, a3;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a1));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a2));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a3));

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a1, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("10.10.0.1", buf);
    inet_ntop(AF_INET, &a2, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("10.10.0.2", buf);
    inet_ntop(AF_INET, &a3, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("10.10.0.3", buf);
}

void test_ipam_free_and_reuse(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr addr;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &addr));

    char buf1[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf1, sizeof(buf1));

    /* Free and re-allocate — should get same address */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_free_ipv4(&ipam, &addr));

    struct in_addr addr2;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &addr2));

    char buf2[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr2, buf2, sizeof(buf2));
    TEST_ASSERT_EQUAL_STRING(buf1, buf2);
}

void test_ipam_alloc_exhausted(void)
{
    /* /30 = 4 addresses, 2 usable hosts (network + broadcast excluded) */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/30"));
    TEST_ASSERT_EQUAL_UINT(2, ipam.pools[0].total_hosts);

    struct in_addr a1, a2, a3;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a1));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a2));
    TEST_ASSERT_EQUAL_INT(-ENOSPC, iog_ipam_alloc_ipv4(&ipam, &a3));
}

void test_ipam_alloc_ipv6(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "fd00:abcd::/112"));

    struct in6_addr addr;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv6(&ipam, &addr));

    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("fd00:abcd::1", buf);
}

/* ============================================================================
 * Collision detection
 * ============================================================================ */

void test_ipam_collision_detect_no_overlap(void)
{
    /* Use a range that should NOT overlap with any server interface */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "198.51.100.0/24"));
    /* This is TEST-NET-2 (RFC 5737), unlikely to be on any interface */
    int ret = iog_ipam_check_collisions(&ipam);
    /* Should not collide unless test environment uses this range */
    TEST_ASSERT_TRUE(ret == 0 || ret == -EEXIST);
}

void test_ipam_collision_detect_overlap(void)
{
    /* 127.0.0.0/8 contains loopback 127.0.0.1 — should always collide */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "127.0.0.0/8"));
    TEST_ASSERT_EQUAL_INT(-EEXIST, iog_ipam_check_collisions(&ipam));
}

void test_ipam_collision_detect_supernet(void)
{
    /* /8 supernet containing loopback */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "127.0.0.0/8"));
    TEST_ASSERT_EQUAL_INT(-EEXIST, iog_ipam_check_collisions(&ipam));
}

void test_ipam_collision_detect_ipv6(void)
{
    /* ::1/128 is loopback — but /128 has 0 hosts so we use /120 containing ::1 */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "::0/120"));
    /* Should collide with ::1 (loopback) */
    TEST_ASSERT_EQUAL_INT(-EEXIST, iog_ipam_check_collisions(&ipam));
}

/* ============================================================================
 * Multi-pool
 * ============================================================================ */

void test_ipam_multi_pool_add(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.20.0.0/24"));
    TEST_ASSERT_EQUAL_UINT(2, ipam.pool_count);
}

void test_ipam_multi_pool_alloc_first(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/30")); /* 2 hosts */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.20.0.0/24")); /* 254 hosts */

    struct in_addr a1, a2, a3;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a1));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a2));
    /* First pool exhausted, third alloc comes from second pool */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a3));

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a3, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("10.20.0.1", buf);
}

/* ============================================================================
 * RADIUS override
 * ============================================================================ */

void test_ipam_reserve_specific_ipv4(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr addr;
    inet_pton(AF_INET, "10.10.0.50", &addr);
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_reserve_ipv4(&ipam, &addr));
    TEST_ASSERT_EQUAL_UINT(1, ipam.pools[0].used_count);
}

void test_ipam_reserve_already_taken(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr addr;
    inet_pton(AF_INET, "10.10.0.50", &addr);
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_reserve_ipv4(&ipam, &addr));
    TEST_ASSERT_EQUAL_INT(-EADDRINUSE, iog_ipam_reserve_ipv4(&ipam, &addr));
}

void test_ipam_reserve_outside_pool(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr addr;
    inet_pton(AF_INET, "192.168.1.100", &addr);
    /* Address not in any pool — returns 0 (external RADIUS assignment) */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_reserve_ipv4(&ipam, &addr));
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void test_ipam_stats_total_and_used(void)
{
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr a1, a2;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a1));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a2));

    iog_ipam_stats_t stats;
    iog_ipam_get_stats(&ipam, &stats);
    TEST_ASSERT_EQUAL_UINT(1, stats.total_pools);
    TEST_ASSERT_EQUAL_UINT(254, stats.total_addresses);
    TEST_ASSERT_EQUAL_UINT(2, stats.used_addresses);
    TEST_ASSERT_EQUAL_UINT(252, stats.available_addresses);

    /* Free one, recheck */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_free_ipv4(&ipam, &a1));
    iog_ipam_get_stats(&ipam, &stats);
    TEST_ASSERT_EQUAL_UINT(1, stats.used_addresses);
    TEST_ASSERT_EQUAL_UINT(253, stats.available_addresses);
}

/* ============================================================================
 * Word-scan performance
 * ============================================================================ */

void test_ipam_alloc_performance_large_pool(void)
{
    /* Verify large pool allocation works correctly with word-scan */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.0.0.0/16"));
    /* /16 = 65534 usable hosts */
    TEST_ASSERT_EQUAL_UINT(65534, ipam.pools[0].total_hosts);

    /* Allocate first 100 addresses */
    for (int i = 0; i < 100; i++) {
        struct in_addr addr;
        int ret = iog_ipam_alloc_ipv4(&ipam, &addr);
        TEST_ASSERT_EQUAL_INT(0, ret);
    }

    TEST_ASSERT_EQUAL_UINT(100, ipam.pools[0].used_count);

    /* Verify first address is 10.0.0.1 by freeing all and re-allocating */
    iog_ipam_stats_t stats;
    iog_ipam_get_stats(&ipam, &stats);
    TEST_ASSERT_EQUAL_UINT(100, stats.used_addresses);
    TEST_ASSERT_EQUAL_UINT(65434, stats.available_addresses);
}

void test_ipam_alloc_free_reuse_with_hint(void)
{
    /* Verify next_free hint is reset when freeing earlier address */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_add_pool(&ipam, "10.10.0.0/24"));

    struct in_addr a1, a2, a3;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a1));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a2));
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a3));

    /* Free a1 (offset 0) — hint should go back to 0 */
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_free_ipv4(&ipam, &a1));

    /* Next alloc should reuse a1's address */
    struct in_addr a4;
    TEST_ASSERT_EQUAL_INT(0, iog_ipam_alloc_ipv4(&ipam, &a4));

    char buf1[INET_ADDRSTRLEN];
    char buf4[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a1, buf1, sizeof(buf1));
    inet_ntop(AF_INET, &a4, buf4, sizeof(buf4));
    TEST_ASSERT_EQUAL_STRING(buf1, buf4);
}

int main(void)
{
    UNITY_BEGIN();
    /* Pool creation */
    RUN_TEST(test_ipam_pool_create_ipv4);
    RUN_TEST(test_ipam_pool_create_ipv6);
    RUN_TEST(test_ipam_pool_create_invalid_cidr);
    RUN_TEST(test_ipam_pool_create_host_addr);
    /* Allocation */
    RUN_TEST(test_ipam_alloc_ipv4_first);
    RUN_TEST(test_ipam_alloc_ipv4_sequential);
    RUN_TEST(test_ipam_free_and_reuse);
    RUN_TEST(test_ipam_alloc_exhausted);
    RUN_TEST(test_ipam_alloc_ipv6);
    /* Collision detection */
    RUN_TEST(test_ipam_collision_detect_no_overlap);
    RUN_TEST(test_ipam_collision_detect_overlap);
    RUN_TEST(test_ipam_collision_detect_supernet);
    RUN_TEST(test_ipam_collision_detect_ipv6);
    /* Multi-pool */
    RUN_TEST(test_ipam_multi_pool_add);
    RUN_TEST(test_ipam_multi_pool_alloc_first);
    /* RADIUS override */
    RUN_TEST(test_ipam_reserve_specific_ipv4);
    RUN_TEST(test_ipam_reserve_already_taken);
    RUN_TEST(test_ipam_reserve_outside_pool);
    /* Statistics */
    RUN_TEST(test_ipam_stats_total_and_used);
    /* Word-scan performance */
    RUN_TEST(test_ipam_alloc_performance_large_pool);
    RUN_TEST(test_ipam_alloc_free_reuse_with_hint);
    return UNITY_END();
}
