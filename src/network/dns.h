#ifndef IOGUARD_NETWORK_DNS_H
#define IOGUARD_NETWORK_DNS_H

#include <stddef.h>
#include <stdint.h>

/** Maximum number of DNS servers per config. */
constexpr size_t IOG_DNS_MAX_SERVERS = 4;

/** Maximum number of split DNS domains. */
constexpr size_t IOG_DNS_MAX_DOMAINS = 32;

/** Maximum DNS name length. */
constexpr size_t IOG_DNS_MAX_NAME = 256;

/**
 * @brief DNS routing mode for VPN clients.
 */
typedef enum : uint8_t {
    IOG_DNS_STANDARD = 0,   /* client uses its own DNS */
    IOG_DNS_TUNNEL_ALL = 1, /* all DNS forced through tunnel */
    IOG_DNS_SPLIT = 2,      /* domain-based split routing */
} iog_dns_mode_t;

/**
 * @brief DNS configuration for a VPN group/session.
 */
typedef struct {
    iog_dns_mode_t mode;
    char servers[IOG_DNS_MAX_SERVERS][46]; /* INET6_ADDRSTRLEN */
    uint32_t server_count;
    char default_domain[IOG_DNS_MAX_NAME];
    char split_domains[IOG_DNS_MAX_DOMAINS][IOG_DNS_MAX_NAME];
    uint32_t split_domain_count;
} iog_dns_config_t;

/**
 * @brief Initialize DNS config with defaults (mode=STANDARD, empty).
 * @param cfg  Config to initialize.
 */
void iog_dns_config_init(iog_dns_config_t *cfg);

/**
 * @brief Add a DNS server address.
 * @param cfg   Config.
 * @param addr  Server address (IPv4 or IPv6 string).
 * @return 0 on success, -ENOSPC if max servers reached, -EINVAL on bad addr.
 */
[[nodiscard]] int iog_dns_add_server(iog_dns_config_t *cfg, const char *addr);

/**
 * @brief Set the default DNS domain.
 * @param cfg     Config.
 * @param domain  Domain name (e.g., "corp.example.com").
 */
void iog_dns_set_default_domain(iog_dns_config_t *cfg, const char *domain);

/**
 * @brief Set the DNS routing mode.
 * @param cfg   Config.
 * @param mode  DNS mode.
 */
void iog_dns_set_mode(iog_dns_config_t *cfg, iog_dns_mode_t mode);

/**
 * @brief Add a split DNS domain for domain-based routing.
 * @param cfg     Config.
 * @param domain  Domain to tunnel (e.g., "corp.example.com").
 * @return 0 on success, -ENOSPC if max domains reached.
 */
[[nodiscard]] int iog_dns_add_split_domain(iog_dns_config_t *cfg, const char *domain);

/**
 * @brief Check if a query matches any split DNS domain.
 *
 * Uses suffix match with '.' boundary:
 * - "mail.corp.example.com" matches "corp.example.com"
 * - "notcorp.example.com" does NOT match "corp.example.com"
 *
 * @param cfg    Config.
 * @param query  DNS query name.
 * @return true if query matches a split domain.
 */
[[nodiscard]] bool iog_dns_is_split_domain(const iog_dns_config_t *cfg, const char *query);

/**
 * @brief Check if a single query matches a single domain (suffix match).
 *
 * Exported for direct testing.
 *
 * @param query   DNS query name.
 * @param domain  Domain to match against.
 * @return true if query matches domain.
 */
[[nodiscard]] bool iog_dns_domain_matches(const char *query, const char *domain);

#endif /* IOGUARD_NETWORK_DNS_H */
