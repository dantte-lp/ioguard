/**
 * @file firewall.h
 * @brief nftables per-user firewall chains via libmnl + libnftnl.
 *
 * Creates and destroys per-session nftables chains in the "ioguard" table
 * to enforce source-IP filtering for VPN users.  Requires CAP_NET_ADMIN.
 */

#ifndef IOGUARD_SECURITY_FIREWALL_H
#define IOGUARD_SECURITY_FIREWALL_H

#include <netinet/in.h>
#include <stdint.h>

constexpr size_t IOG_FW_CHAIN_NAME_MAX = 64;
constexpr char IOG_FW_TABLE_NAME[] = "ioguard";

/** Batch buffer size for netlink messages (page-aligned). */
constexpr size_t IOG_FW_BATCH_BUF_SIZE = 16384;

typedef struct {
    char chain_name[IOG_FW_CHAIN_NAME_MAX];
    int af;                 /**< AF_INET or AF_INET6 */
    uint32_t assigned_ipv4; /**< network byte order */
    struct in6_addr assigned_ipv6;
    char username[256];
} iog_fw_session_t;

/**
 * @brief Format a chain name for the given session.
 * @param session  Session with username and assigned IP.
 * @param out      Output buffer for the chain name.
 * @param out_size Size of @p out buffer.
 * @return 0 on success, negative errno on failure.
 *
 * Format: "iog_<username>_<iphex>" truncated to IOG_FW_CHAIN_NAME_MAX-1.
 */
[[nodiscard]] int iog_fw_chain_name(const iog_fw_session_t *session, char *out, size_t out_size);

/**
 * @brief Build a netlink batch to create the per-user chain and rule.
 * @param session   Session describing the user.
 * @param batch_buf Receives a malloc'd batch buffer (caller must free).
 * @param batch_len Receives the length of the batch in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_fw_build_create_batch(const iog_fw_session_t *session, void **batch_buf,
                                            size_t *batch_len);

/**
 * @brief Build a netlink batch to destroy the per-user chain.
 * @param session   Session describing the user.
 * @param batch_buf Receives a malloc'd batch buffer (caller must free).
 * @param batch_len Receives the length of the batch in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_fw_build_destroy_batch(const iog_fw_session_t *session, void **batch_buf,
                                             size_t *batch_len);

/**
 * @brief Create a per-user nftables chain and accept rule.
 * @param session Session with username and assigned IP.
 * @return 0 on success, negative errno on failure (-EPERM if not root).
 */
[[nodiscard]] int iog_fw_session_create(const iog_fw_session_t *session);

/**
 * @brief Destroy the per-user nftables chain (flush rules first).
 * @param session Session with username and assigned IP.
 * @return 0 on success, negative errno on failure (-EPERM if not root).
 */
[[nodiscard]] int iog_fw_session_destroy(const iog_fw_session_t *session);

#endif /* IOGUARD_SECURITY_FIREWALL_H */
