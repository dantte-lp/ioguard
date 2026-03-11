#include "network/dns.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

void iog_dns_config_init(iog_dns_config_t *cfg)
{
    if (cfg == nullptr) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = IOG_DNS_STANDARD;
}

int iog_dns_add_server(iog_dns_config_t *cfg, const char *addr)
{
    if (cfg == nullptr || addr == nullptr) {
        return -EINVAL;
    }
    if (cfg->server_count >= IOG_DNS_MAX_SERVERS) {
        return -ENOSPC;
    }

    /* Validate address format */
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, addr, &v4) != 1 && inet_pton(AF_INET6, addr, &v6) != 1) {
        return -EINVAL;
    }

    snprintf(cfg->servers[cfg->server_count], sizeof(cfg->servers[0]), "%s", addr);
    cfg->server_count++;
    return 0;
}

void iog_dns_set_default_domain(iog_dns_config_t *cfg, const char *domain)
{
    if (cfg == nullptr || domain == nullptr) {
        return;
    }
    snprintf(cfg->default_domain, sizeof(cfg->default_domain), "%s", domain);
}

void iog_dns_set_mode(iog_dns_config_t *cfg, iog_dns_mode_t mode)
{
    if (cfg == nullptr) {
        return;
    }
    cfg->mode = mode;
}

int iog_dns_add_split_domain(iog_dns_config_t *cfg, const char *domain)
{
    if (cfg == nullptr || domain == nullptr) {
        return -EINVAL;
    }
    if (cfg->split_domain_count >= IOG_DNS_MAX_DOMAINS) {
        return -ENOSPC;
    }

    snprintf(cfg->split_domains[cfg->split_domain_count], sizeof(cfg->split_domains[0]), "%s",
             domain);
    cfg->split_domain_count++;
    return 0;
}

bool iog_dns_domain_matches(const char *query, const char *domain)
{
    if (query == nullptr || domain == nullptr) {
        return false;
    }

    size_t qlen = strlen(query);
    size_t dlen = strlen(domain);

    if (qlen == 0 || dlen == 0) {
        return false;
    }

    /* Exact match (case-insensitive) */
    if (qlen == dlen) {
        return strncasecmp(query, domain, qlen) == 0;
    }

    /* Query must be longer and end with ".domain" */
    if (qlen <= dlen) {
        return false;
    }

    /* Check boundary: character before domain suffix must be '.' */
    size_t offset = qlen - dlen;
    if (query[offset - 1] != '.') {
        return false;
    }

    /* Compare suffix (case-insensitive) */
    return strncasecmp(query + offset, domain, dlen) == 0;
}

bool iog_dns_is_split_domain(const iog_dns_config_t *cfg, const char *query)
{
    if (cfg == nullptr || query == nullptr) {
        return false;
    }

    for (uint32_t i = 0; i < cfg->split_domain_count; i++) {
        if (iog_dns_domain_matches(query, cfg->split_domains[i])) {
            return true;
        }
    }
    return false;
}
