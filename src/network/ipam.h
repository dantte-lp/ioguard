#ifndef RINGWALL_NETWORK_IPAM_H
#define RINGWALL_NETWORK_IPAM_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum number of address pools. */
constexpr size_t IOG_IPAM_MAX_POOLS = 16;

/**
 * @brief Single IP address pool with bitmap allocation.
 */
typedef struct {
    int af; /* AF_INET or AF_INET6 */
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } network;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } netmask;
    uint32_t prefix_len;
    uint32_t total_hosts; /* usable host count (excluding network/broadcast for v4) */
    uint32_t used_count;
    uint8_t *bitmap; /* 1 bit per host address */
} iog_ipam_pool_t;

/**
 * @brief IPAM context managing multiple address pools.
 */
typedef struct {
    iog_ipam_pool_t pools[IOG_IPAM_MAX_POOLS];
    uint32_t pool_count;
} iog_ipam_t;

/**
 * @brief IPAM statistics.
 */
typedef struct {
    uint32_t total_pools;
    uint32_t total_addresses;
    uint32_t used_addresses;
    uint32_t available_addresses;
} iog_ipam_stats_t;

/**
 * @brief Initialize IPAM context.
 * @param ipam  IPAM context (caller-owned).
 * @return 0 on success, -EINVAL on nullptr.
 */
[[nodiscard]] int iog_ipam_init(iog_ipam_t *ipam);

/**
 * @brief Destroy IPAM context and free all pool bitmaps.
 * @param ipam  IPAM context.
 */
void iog_ipam_destroy(iog_ipam_t *ipam);

/**
 * @brief Add an address pool from a CIDR string.
 *
 * Parses "10.10.0.0/24" or "fd00:vpn::/112" and allocates a bitmap.
 * For IPv4: network and broadcast addresses are excluded.
 *
 * @param ipam  IPAM context.
 * @param cidr  CIDR notation string (e.g., "10.10.0.0/24").
 * @return 0 on success, -EINVAL on parse error, -ENOSPC if max pools reached.
 */
[[nodiscard]] int iog_ipam_add_pool(iog_ipam_t *ipam, const char *cidr);

/**
 * @brief Check for collisions with server network interfaces.
 *
 * Enumerates interfaces via getifaddrs(). Returns -EEXIST if any
 * pool overlaps an existing server network.
 *
 * @param ipam  IPAM context.
 * @return 0 if no collisions, -EEXIST on overlap.
 */
[[nodiscard]] int iog_ipam_check_collisions(const iog_ipam_t *ipam);

/**
 * @brief Allocate the next available IPv4 address.
 * @param ipam  IPAM context.
 * @param out   Output address.
 * @return 0 on success, -ENOSPC if all pools exhausted.
 */
[[nodiscard]] int iog_ipam_alloc_ipv4(iog_ipam_t *ipam, struct in_addr *out);

/**
 * @brief Allocate the next available IPv6 address.
 * @param ipam  IPAM context.
 * @param out   Output address.
 * @return 0 on success, -ENOSPC if all pools exhausted.
 */
[[nodiscard]] int iog_ipam_alloc_ipv6(iog_ipam_t *ipam, struct in6_addr *out);

/**
 * @brief Release a previously allocated IPv4 address.
 * @param ipam  IPAM context.
 * @param addr  Address to release.
 * @return 0 on success, -ENOENT if not found in any pool.
 */
[[nodiscard]] int iog_ipam_free_ipv4(iog_ipam_t *ipam, const struct in_addr *addr);

/**
 * @brief Release a previously allocated IPv6 address.
 * @param ipam  IPAM context.
 * @param addr  Address to release.
 * @return 0 on success, -ENOENT if not found in any pool.
 */
[[nodiscard]] int iog_ipam_free_ipv6(iog_ipam_t *ipam, const struct in6_addr *addr);

/**
 * @brief Reserve a specific IPv4 address (e.g., RADIUS override).
 *
 * If the address falls within a pool, marks it as used.
 * If not in any pool, returns 0 (external assignment).
 *
 * @param ipam  IPAM context.
 * @param addr  Address to reserve.
 * @return 0 on success, -EADDRINUSE if already taken.
 */
[[nodiscard]] int iog_ipam_reserve_ipv4(iog_ipam_t *ipam, const struct in_addr *addr);

/**
 * @brief Reserve a specific IPv6 address (e.g., RADIUS override).
 * @param ipam  IPAM context.
 * @param addr  Address to reserve.
 * @return 0 on success, -EADDRINUSE if already taken.
 */
[[nodiscard]] int iog_ipam_reserve_ipv6(iog_ipam_t *ipam, const struct in6_addr *addr);

/**
 * @brief Get IPAM statistics.
 * @param ipam   IPAM context.
 * @param stats  Output statistics.
 */
void iog_ipam_get_stats(const iog_ipam_t *ipam, iog_ipam_stats_t *stats);

#endif /* RINGWALL_NETWORK_IPAM_H */
