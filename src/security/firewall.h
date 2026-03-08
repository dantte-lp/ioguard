/**
 * @file firewall.h
 * @brief nftables per-user firewall chains via libmnl + libnftnl.
 *
 * Creates and destroys per-session nftables chains in the "ringwall" table
 * to enforce source-IP filtering for VPN users.  Requires CAP_NET_ADMIN.
 */

#ifndef RINGWALL_SECURITY_FIREWALL_H
#define RINGWALL_SECURITY_FIREWALL_H

#include <stdint.h>
#include <netinet/in.h>

constexpr size_t RW_FW_CHAIN_NAME_MAX = 64;
constexpr char RW_FW_TABLE_NAME[] = "ringwall";

/** Batch buffer size for netlink messages (page-aligned). */
constexpr size_t RW_FW_BATCH_BUF_SIZE = 16384;

typedef struct {
	char     chain_name[RW_FW_CHAIN_NAME_MAX];
	int      af;                    /**< AF_INET or AF_INET6 */
	uint32_t assigned_ipv4;         /**< network byte order */
	struct in6_addr assigned_ipv6;
	char     username[256];
} rw_fw_session_t;

/**
 * @brief Format a chain name for the given session.
 * @param session  Session with username and assigned IP.
 * @param out      Output buffer for the chain name.
 * @param out_size Size of @p out buffer.
 * @return 0 on success, negative errno on failure.
 *
 * Format: "rw_<username>_<iphex>" truncated to RW_FW_CHAIN_NAME_MAX-1.
 */
[[nodiscard]] int rw_fw_chain_name(const rw_fw_session_t *session,
				   char *out, size_t out_size);

/**
 * @brief Build a netlink batch to create the per-user chain and rule.
 * @param session   Session describing the user.
 * @param batch_buf Receives a malloc'd batch buffer (caller must free).
 * @param batch_len Receives the length of the batch in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_fw_build_create_batch(const rw_fw_session_t *session,
					   void **batch_buf,
					   size_t *batch_len);

/**
 * @brief Build a netlink batch to destroy the per-user chain.
 * @param session   Session describing the user.
 * @param batch_buf Receives a malloc'd batch buffer (caller must free).
 * @param batch_len Receives the length of the batch in bytes.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_fw_build_destroy_batch(const rw_fw_session_t *session,
					    void **batch_buf,
					    size_t *batch_len);

/**
 * @brief Create a per-user nftables chain and accept rule.
 * @param session Session with username and assigned IP.
 * @return 0 on success, negative errno on failure (-EPERM if not root).
 */
[[nodiscard]] int rw_fw_session_create(const rw_fw_session_t *session);

/**
 * @brief Destroy the per-user nftables chain (flush rules first).
 * @param session Session with username and assigned IP.
 * @return 0 on success, negative errno on failure (-EPERM if not root).
 */
[[nodiscard]] int rw_fw_session_destroy(const rw_fw_session_t *session);

#endif /* RINGWALL_SECURITY_FIREWALL_H */
