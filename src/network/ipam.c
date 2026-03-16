#include "network/ipam.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Bitmap helpers
 * ============================================================================ */

static bool bitmap_get(const uint8_t *bitmap, uint32_t idx)
{
    return (bitmap[idx / 8] & (1u << (idx % 8))) != 0;
}

static void bitmap_set(uint8_t *bitmap, uint32_t idx)
{
    bitmap[idx / 8] |= (uint8_t)(1u << (idx % 8));
}

static void bitmap_clear(uint8_t *bitmap, uint32_t idx)
{
    bitmap[idx / 8] &= (uint8_t)~(1u << (idx % 8));
}

/* ============================================================================
 * CIDR parsing
 * ============================================================================ */

static int parse_cidr(const char *cidr, int *af, void *network, uint32_t *prefix_len)
{
    char buf[128];
    size_t len = strnlen(cidr, sizeof(buf));
    if (len >= sizeof(buf)) {
        return -EINVAL;
    }
    memcpy(buf, cidr, len + 1);

    char *slash = strchr(buf, '/');
    if (slash == nullptr) {
        return -EINVAL;
    }
    *slash = '\0';
    const char *prefix_str = slash + 1;

    char *end = nullptr;
    long plen = strtol(prefix_str, &end, 10);
    if (end == prefix_str || *end != '\0' || plen < 0) {
        return -EINVAL;
    }

    /* Try IPv4 first, then IPv6 */
    struct in_addr v4;
    struct in6_addr v6;

    if (inet_pton(AF_INET, buf, &v4) == 1) {
        if (plen > 32 || plen < 1) {
            return -EINVAL;
        }
        *af = AF_INET;
        *prefix_len = (uint32_t)plen;
        memcpy(network, &v4, sizeof(v4));
        return 0;
    }

    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        if (plen > 128 || plen < 1) {
            return -EINVAL;
        }
        *af = AF_INET6;
        *prefix_len = (uint32_t)plen;
        memcpy(network, &v6, sizeof(v6));
        return 0;
    }

    return -EINVAL;
}

static uint32_t calc_host_count(int af, uint32_t prefix_len)
{
    if (af == AF_INET) {
        uint32_t host_bits = 32 - prefix_len;
        if (host_bits == 0) {
            return 0; /* /32 — single host, no range */
        }
        if (host_bits == 1) {
            return 0; /* /31 — point-to-point, no usable hosts */
        }
        uint32_t total = (1u << host_bits);
        return total - 2; /* exclude network and broadcast */
    }

    /* IPv6: cap at 2^20 hosts to avoid huge bitmaps */
    uint32_t host_bits = 128 - prefix_len;
    if (host_bits == 0) {
        return 0;
    }
    if (host_bits > 20) {
        host_bits = 20; /* cap to ~1M hosts */
    }
    uint32_t total = (1u << host_bits);
    return total - 1; /* exclude subnet-router anycast (::0) */
}

static void build_netmask_v4(struct in_addr *mask, uint32_t prefix_len)
{
    if (prefix_len == 0) {
        mask->s_addr = 0;
    } else {
        mask->s_addr = htonl(~((1u << (32 - prefix_len)) - 1));
    }
}

static void build_netmask_v6(struct in6_addr *mask, uint32_t prefix_len)
{
    memset(mask, 0, sizeof(*mask));
    uint32_t full_bytes = prefix_len / 8;
    uint32_t remaining_bits = prefix_len % 8;
    memset(mask->s6_addr, 0xFF, full_bytes);
    if (remaining_bits > 0 && full_bytes < 16) {
        mask->s6_addr[full_bytes] = (uint8_t)(0xFF << (8 - remaining_bits));
    }
}

/* Compute host address from network + offset for IPv4 */
static struct in_addr host_addr_v4(const struct in_addr *network, uint32_t offset)
{
    /* offset 0 = first host (network + 1 for IPv4) */
    uint32_t net_host = ntohl(network->s_addr);
    uint32_t host = net_host + offset + 1; /* +1 to skip network address */
    struct in_addr result;
    result.s_addr = htonl(host);
    return result;
}

/* Compute host address from network + offset for IPv6 */
static struct in6_addr host_addr_v6(const struct in6_addr *network, uint32_t offset)
{
    struct in6_addr result;
    memcpy(&result, network, sizeof(result));

    /* Add offset+1 to skip ::0 (subnet-router anycast) */
    uint32_t add = offset + 1;

    /* Add to the last 4 bytes (big-endian) */
    for (int i = 15; i >= 0 && add > 0; i--) {
        uint32_t sum = (uint32_t)result.s6_addr[i] + (add & 0xFF);
        result.s6_addr[i] = (uint8_t)(sum & 0xFF);
        add = (add >> 8) + (sum >> 8);
    }

    return result;
}

/* Find the offset of an address within a pool, or -1 */
static int32_t find_offset_v4(const iog_ipam_pool_t *pool, const struct in_addr *addr)
{
    uint32_t net = ntohl(pool->network.v4.s_addr);
    uint32_t a = ntohl(addr->s_addr);
    if (a <= net) {
        return -1;
    }
    uint32_t offset = a - net - 1; /* -1 because offset 0 = network+1 */
    if (offset >= pool->total_hosts) {
        return -1;
    }
    return (int32_t)offset;
}

static int32_t find_offset_v6(const iog_ipam_pool_t *pool, const struct in6_addr *addr)
{
    /* Compute addr - network, check it's within range */
    const uint8_t *net = pool->network.v6.s6_addr;
    const uint8_t *a = addr->s6_addr;

    /* Simple subtraction of last 4 bytes (sufficient for pools up to 2^20) */
    int64_t diff = 0;
    for (int i = 12; i < 16; i++) {
        diff = (diff << 8) + (int64_t)a[i] - (int64_t)net[i];
    }

    /* Check upper bytes match */
    for (int i = 0; i < 12; i++) {
        if (a[i] != net[i]) {
            return -1;
        }
    }

    diff -= 1; /* -1 because offset 0 = network+1 */
    if (diff < 0 || (uint32_t)diff >= pool->total_hosts) {
        return -1;
    }
    return (int32_t)diff;
}

/* Check if an IPv4 address falls within a pool's CIDR range */
static bool addr_in_pool_v4(const iog_ipam_pool_t *pool, const struct in_addr *addr)
{
    return (addr->s_addr & pool->netmask.v4.s_addr) ==
           (pool->network.v4.s_addr & pool->netmask.v4.s_addr);
}

static bool addr_in_pool_v6(const iog_ipam_pool_t *pool, const struct in6_addr *addr)
{
    for (int i = 0; i < 16; i++) {
        if ((addr->s6_addr[i] & pool->netmask.v6.s6_addr[i]) !=
            (pool->network.v6.s6_addr[i] & pool->netmask.v6.s6_addr[i])) {
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * Word-level bitmap scan
 * ============================================================================ */

/**
 * Scan bitmap by 64-bit words to find the first free bit.
 * Returns the bit offset, or -1 if no free bit exists.
 * Updates pool->next_free hint on success.
 */
static int32_t bitmap_find_free(iog_ipam_pool_t *pool)
{
    const uint64_t *words = (const uint64_t *)pool->bitmap;
    size_t nwords = (pool->total_hosts + 63) / 64;
    size_t start_word = pool->next_free / 64;

    for (size_t w = 0; w < nwords; w++) {
        size_t idx = (start_word + w) % nwords;
        if (words[idx] != UINT64_MAX) {
            uint32_t bit = (uint32_t)__builtin_ctzll(~words[idx]);
            uint32_t offset = (uint32_t)(idx * 64 + bit);
            if (offset < pool->total_hosts) {
                bitmap_set(pool->bitmap, offset);
                pool->next_free = offset + 1;
                pool->used_count++;
                return (int32_t)offset;
            }
        }
    }

    return -1;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int iog_ipam_init(iog_ipam_t *ipam)
{
    if (ipam == nullptr) {
        return -EINVAL;
    }
    memset(ipam, 0, sizeof(*ipam));
    return 0;
}

void iog_ipam_destroy(iog_ipam_t *ipam)
{
    if (ipam == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        free(ipam->pools[i].bitmap);
        ipam->pools[i].bitmap = nullptr;
    }
    ipam->pool_count = 0;
}

int iog_ipam_add_pool(iog_ipam_t *ipam, const char *cidr)
{
    if (ipam == nullptr || cidr == nullptr) {
        return -EINVAL;
    }
    if (ipam->pool_count >= IOG_IPAM_MAX_POOLS) {
        return -ENOSPC;
    }

    int af = 0;
    uint32_t prefix_len = 0;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } network;

    int ret = parse_cidr(cidr, &af, &network, &prefix_len);
    if (ret < 0) {
        return ret;
    }

    uint32_t hosts = calc_host_count(af, prefix_len);
    if (hosts == 0) {
        return -EINVAL; /* no usable hosts (e.g., /32, /31) */
    }

    /* Round up to 8-byte alignment for safe uint64_t word-level scan */
    size_t bitmap_size = ((hosts + 63) / 64) * 8;
    uint8_t *bitmap = aligned_alloc(8, bitmap_size);
    if (bitmap == nullptr) {
        return -ENOMEM;
    }
    memset(bitmap, 0, bitmap_size);

    iog_ipam_pool_t *pool = &ipam->pools[ipam->pool_count];
    pool->af = af;
    pool->prefix_len = prefix_len;
    pool->total_hosts = hosts;
    pool->used_count = 0;
    pool->next_free = 0;
    pool->bitmap = bitmap;

    if (af == AF_INET) {
        pool->network.v4 = network.v4;
        build_netmask_v4(&pool->netmask.v4, prefix_len);
    } else {
        pool->network.v6 = network.v6;
        build_netmask_v6(&pool->netmask.v6, prefix_len);
    }

    ipam->pool_count++;
    return 0;
}

int iog_ipam_check_collisions(const iog_ipam_t *ipam)
{
    if (ipam == nullptr) {
        return -EINVAL;
    }

    struct ifaddrs *ifap = nullptr;
    if (getifaddrs(&ifap) < 0) {
        return -errno;
    }

    int result = 0;
    for (struct ifaddrs *ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        for (uint32_t i = 0; i < ipam->pool_count; i++) {
            const iog_ipam_pool_t *pool = &ipam->pools[i];
            if (ifa->ifa_addr->sa_family != pool->af) {
                continue;
            }

            if (pool->af == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (addr_in_pool_v4(pool, &sin->sin_addr)) {
                    result = -EEXIST;
                    goto done;
                }
            } else if (pool->af == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (addr_in_pool_v6(pool, &sin6->sin6_addr)) {
                    result = -EEXIST;
                    goto done;
                }
            }
        }
    }

done:
    freeifaddrs(ifap);
    return result;
}

int iog_ipam_alloc_ipv4(iog_ipam_t *ipam, struct in_addr *out)
{
    if (ipam == nullptr || out == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET || pool->used_count >= pool->total_hosts) {
            continue;
        }

        int32_t offset = bitmap_find_free(pool);
        if (offset >= 0) {
            *out = host_addr_v4(&pool->network.v4, (uint32_t)offset);
            return 0;
        }
    }

    return -ENOSPC;
}

int iog_ipam_alloc_ipv6(iog_ipam_t *ipam, struct in6_addr *out)
{
    if (ipam == nullptr || out == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET6 || pool->used_count >= pool->total_hosts) {
            continue;
        }

        int32_t offset = bitmap_find_free(pool);
        if (offset >= 0) {
            *out = host_addr_v6(&pool->network.v6, (uint32_t)offset);
            return 0;
        }
    }

    return -ENOSPC;
}

int iog_ipam_free_ipv4(iog_ipam_t *ipam, const struct in_addr *addr)
{
    if (ipam == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET) {
            continue;
        }
        int32_t offset = find_offset_v4(pool, addr);
        if (offset >= 0) {
            uint32_t idx = (uint32_t)offset;
            if (bitmap_get(pool->bitmap, idx)) {
                bitmap_clear(pool->bitmap, idx);
                pool->used_count--;
                if (idx < pool->next_free) {
                    pool->next_free = idx;
                }
                return 0;
            }
        }
    }

    return -ENOENT;
}

int iog_ipam_free_ipv6(iog_ipam_t *ipam, const struct in6_addr *addr)
{
    if (ipam == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET6) {
            continue;
        }
        int32_t offset = find_offset_v6(pool, addr);
        if (offset >= 0) {
            uint32_t idx = (uint32_t)offset;
            if (bitmap_get(pool->bitmap, idx)) {
                bitmap_clear(pool->bitmap, idx);
                pool->used_count--;
                if (idx < pool->next_free) {
                    pool->next_free = idx;
                }
                return 0;
            }
        }
    }

    return -ENOENT;
}

int iog_ipam_reserve_ipv4(iog_ipam_t *ipam, const struct in_addr *addr)
{
    if (ipam == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET) {
            continue;
        }
        int32_t offset = find_offset_v4(pool, addr);
        if (offset >= 0) {
            uint32_t idx = (uint32_t)offset;
            if (bitmap_get(pool->bitmap, idx)) {
                return -EADDRINUSE;
            }
            bitmap_set(pool->bitmap, idx);
            pool->used_count++;
            return 0;
        }
    }

    return 0; /* not in any pool — external RADIUS assignment, OK */
}

int iog_ipam_reserve_ipv6(iog_ipam_t *ipam, const struct in6_addr *addr)
{
    if (ipam == nullptr || addr == nullptr) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        iog_ipam_pool_t *pool = &ipam->pools[i];
        if (pool->af != AF_INET6) {
            continue;
        }
        int32_t offset = find_offset_v6(pool, addr);
        if (offset >= 0) {
            uint32_t idx = (uint32_t)offset;
            if (bitmap_get(pool->bitmap, idx)) {
                return -EADDRINUSE;
            }
            bitmap_set(pool->bitmap, idx);
            pool->used_count++;
            return 0;
        }
    }

    return 0; /* not in any pool — external assignment */
}

void iog_ipam_get_stats(const iog_ipam_t *ipam, iog_ipam_stats_t *stats)
{
    if (ipam == nullptr || stats == nullptr) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
    stats->total_pools = ipam->pool_count;

    for (uint32_t i = 0; i < ipam->pool_count; i++) {
        stats->total_addresses += ipam->pools[i].total_hosts;
        stats->used_addresses += ipam->pools[i].used_count;
    }
    stats->available_addresses = stats->total_addresses - stats->used_addresses;
}
