/**
 * @file firewall.c
 * @brief nftables per-user firewall chains via libmnl + libnftnl.
 */

#include "security/firewall.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/common.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/table.h>

/* ---- Internal helpers ---- */

/**
 * Build the chain name into @p out.
 * Format: rw_<username>_<hex-ip>
 */
int rw_fw_chain_name(const rw_fw_session_t *session,
		     char *out, size_t out_size)
{
	if (session == nullptr || out == nullptr || out_size == 0)
		return -EINVAL;

	int ret;

	if (session->af == AF_INET) {
		const uint8_t *a = (const uint8_t *)&session->assigned_ipv4;
		ret = snprintf(out, out_size, "rw_%.48s_%02x%02x%02x%02x",
			       session->username,
			       a[0], a[1], a[2], a[3]);
	} else if (session->af == AF_INET6) {
		const uint8_t *b = session->assigned_ipv6.s6_addr;
		ret = snprintf(out, out_size, "rw_%.24s_"
			       "%02x%02x%02x%02x%02x%02x%02x%02x"
			       "%02x%02x%02x%02x%02x%02x%02x%02x",
			       session->username,
			       b[0], b[1], b[2], b[3],
			       b[4], b[5], b[6], b[7],
			       b[8], b[9], b[10], b[11],
			       b[12], b[13], b[14], b[15]);
	} else {
		return -EAFNOSUPPORT;
	}

	if (ret < 0 || (size_t)ret >= out_size)
		return -ENAMETOOLONG;

	return 0;
}

/**
 * Add nft expressions to a rule for source IP matching + accept verdict.
 *
 * Equivalent to:  ip saddr <assigned_ipv4> accept
 *            or:  ip6 saddr <assigned_ipv6> accept
 */
static int rule_add_src_match(struct nftnl_rule *rule,
			      const rw_fw_session_t *session)
{
	/*
	 * Expression 1: payload — load source address from network header.
	 *   IPv4: offset 12 (src in IPv4 header), length 4
	 *   IPv6: offset 8  (src in IPv6 header), length 16
	 */
	struct nftnl_expr *payload = nftnl_expr_alloc("payload");
	if (payload == nullptr)
		return -ENOMEM;

	nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
	nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_BASE,
			   NFT_PAYLOAD_NETWORK_HEADER);

	if (session->af == AF_INET) {
		nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_OFFSET, 12);
		nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_LEN, 4);
	} else {
		nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_OFFSET, 8);
		nftnl_expr_set_u32(payload, NFTNL_EXPR_PAYLOAD_LEN, 16);
	}

	nftnl_rule_add_expr(rule, payload);

	/*
	 * Expression 2: cmp — compare loaded value against assigned IP.
	 */
	struct nftnl_expr *cmp = nftnl_expr_alloc("cmp");
	if (cmp == nullptr)
		return -ENOMEM;

	nftnl_expr_set_u32(cmp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(cmp, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);

	if (session->af == AF_INET) {
		nftnl_expr_set(cmp, NFTNL_EXPR_CMP_DATA,
			       &session->assigned_ipv4, sizeof(uint32_t));
	} else {
		nftnl_expr_set(cmp, NFTNL_EXPR_CMP_DATA,
			       &session->assigned_ipv6,
			       sizeof(struct in6_addr));
	}

	nftnl_rule_add_expr(rule, cmp);

	/*
	 * Expression 3: immediate — verdict NF_ACCEPT.
	 */
	struct nftnl_expr *imm = nftnl_expr_alloc("immediate");
	if (imm == nullptr)
		return -ENOMEM;

	nftnl_expr_set_u32(imm, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(imm, NFTNL_EXPR_IMM_VERDICT, NF_ACCEPT);

	nftnl_rule_add_expr(rule, imm);

	return 0;
}

/**
 * Build a nftnl_rule struct for source IP accept.
 * Caller must free with nftnl_rule_free().
 */
static struct nftnl_rule *build_accept_rule(const rw_fw_session_t *session,
					    const char *chain_name)
{
	uint32_t family = (session->af == AF_INET) ? NFPROTO_IPV4
						   : NFPROTO_IPV6;

	struct nftnl_rule *rule = nftnl_rule_alloc();
	if (rule == nullptr)
		return nullptr;

	nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, RW_FW_TABLE_NAME);
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

	int ret = rule_add_src_match(rule, session);
	if (ret < 0) {
		nftnl_rule_free(rule);
		return nullptr;
	}

	return rule;
}

/**
 * Build a nftnl_chain struct for the per-user chain.
 * Caller must free with nftnl_chain_free().
 */
static struct nftnl_chain *build_chain(const rw_fw_session_t *session,
				       const char *chain_name)
{
	uint32_t family = (session->af == AF_INET) ? NFPROTO_IPV4
						   : NFPROTO_IPV6;

	struct nftnl_chain *chain = nftnl_chain_alloc();
	if (chain == nullptr)
		return nullptr;

	nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, RW_FW_TABLE_NAME);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name);

	return chain;
}

/** Monotonically increasing sequence number for netlink batches. */
static uint32_t seq_next(void)
{
	static _Atomic uint32_t seq = 0;
	return ++seq;
}

/* ---- Public batch builders ---- */

int rw_fw_build_create_batch(const rw_fw_session_t *session,
			     void **batch_buf, size_t *batch_len)
{
	if (session == nullptr || batch_buf == nullptr || batch_len == nullptr)
		return -EINVAL;

	char chain_name[RW_FW_CHAIN_NAME_MAX];
	int ret = rw_fw_chain_name(session, chain_name, sizeof(chain_name));
	if (ret < 0)
		return ret;

	char *buf = calloc(1, RW_FW_BATCH_BUF_SIZE);
	if (buf == nullptr)
		return -ENOMEM;

	struct mnl_nlmsg_batch *batch =
		mnl_nlmsg_batch_start(buf, RW_FW_BATCH_BUF_SIZE);
	if (batch == nullptr) {
		free(buf);
		return -ENOMEM;
	}

	uint32_t family = (session->af == AF_INET) ? NFPROTO_IPV4
						   : NFPROTO_IPV6;

	/* Begin batch. */
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq_next());
	mnl_nlmsg_batch_next(batch);

	/* NFT_MSG_NEWCHAIN — create the per-user chain. */
	struct nftnl_chain *chain = build_chain(session, chain_name);
	if (chain == nullptr) {
		mnl_nlmsg_batch_stop(batch);
		free(buf);
		return -ENOMEM;
	}

	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(
		mnl_nlmsg_batch_current(batch),
		(uint16_t)(NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWCHAIN),
		(uint16_t)family,
		NLM_F_CREATE | NLM_F_ACK,
		seq_next());
	nftnl_chain_nlmsg_build_payload(nlh, chain);
	nftnl_chain_free(chain);
	mnl_nlmsg_batch_next(batch);

	/* NFT_MSG_NEWRULE — add accept rule for source IP. */
	struct nftnl_rule *rule = build_accept_rule(session, chain_name);
	if (rule == nullptr) {
		mnl_nlmsg_batch_stop(batch);
		free(buf);
		return -ENOMEM;
	}

	nlh = nftnl_nlmsg_build_hdr(
		mnl_nlmsg_batch_current(batch),
		(uint16_t)(NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWRULE),
		(uint16_t)family,
		NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK,
		seq_next());
	nftnl_rule_nlmsg_build_payload(nlh, rule);
	nftnl_rule_free(rule);
	mnl_nlmsg_batch_next(batch);

	/* End batch. */
	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq_next());
	mnl_nlmsg_batch_next(batch);

	*batch_len = mnl_nlmsg_batch_size(batch);
	mnl_nlmsg_batch_stop(batch);

	/* Shrink buffer to actual size. */
	*batch_buf = buf;
	return 0;
}

int rw_fw_build_destroy_batch(const rw_fw_session_t *session,
			      void **batch_buf, size_t *batch_len)
{
	if (session == nullptr || batch_buf == nullptr || batch_len == nullptr)
		return -EINVAL;

	char chain_name[RW_FW_CHAIN_NAME_MAX];
	int ret = rw_fw_chain_name(session, chain_name, sizeof(chain_name));
	if (ret < 0)
		return ret;

	char *buf = calloc(1, RW_FW_BATCH_BUF_SIZE);
	if (buf == nullptr)
		return -ENOMEM;

	struct mnl_nlmsg_batch *batch =
		mnl_nlmsg_batch_start(buf, RW_FW_BATCH_BUF_SIZE);
	if (batch == nullptr) {
		free(buf);
		return -ENOMEM;
	}

	uint32_t family = (session->af == AF_INET) ? NFPROTO_IPV4
						   : NFPROTO_IPV6;

	/* Begin batch. */
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq_next());
	mnl_nlmsg_batch_next(batch);

	/* Flush rules from the chain first. */
	struct nftnl_rule *rule = nftnl_rule_alloc();
	if (rule == nullptr) {
		mnl_nlmsg_batch_stop(batch);
		free(buf);
		return -ENOMEM;
	}

	nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, RW_FW_TABLE_NAME);
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(
		mnl_nlmsg_batch_current(batch),
		(uint16_t)(NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELRULE),
		(uint16_t)family,
		NLM_F_ACK,
		seq_next());
	nftnl_rule_nlmsg_build_payload(nlh, rule);
	nftnl_rule_free(rule);
	mnl_nlmsg_batch_next(batch);

	/* Delete the chain. */
	struct nftnl_chain *chain = build_chain(session, chain_name);
	if (chain == nullptr) {
		mnl_nlmsg_batch_stop(batch);
		free(buf);
		return -ENOMEM;
	}

	nlh = nftnl_nlmsg_build_hdr(
		mnl_nlmsg_batch_current(batch),
		(uint16_t)(NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELCHAIN),
		(uint16_t)family,
		NLM_F_ACK,
		seq_next());
	nftnl_chain_nlmsg_build_payload(nlh, chain);
	nftnl_chain_free(chain);
	mnl_nlmsg_batch_next(batch);

	/* End batch. */
	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq_next());
	mnl_nlmsg_batch_next(batch);

	*batch_len = mnl_nlmsg_batch_size(batch);
	mnl_nlmsg_batch_stop(batch);

	*batch_buf = buf;
	return 0;
}

/* ---- Netlink send helper ---- */

static int send_batch(const void *buf, size_t len)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == nullptr)
		return -errno;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		int err = errno;
		mnl_socket_close(nl);
		return -err;
	}

	ssize_t sent = mnl_socket_sendto(nl, buf, len);
	if (sent < 0) {
		int err = errno;
		mnl_socket_close(nl);
		return -err;
	}

	mnl_socket_close(nl);
	return 0;
}

/* ---- Public API ---- */

int rw_fw_session_create(const rw_fw_session_t *session)
{
	if (geteuid() != 0)
		return -EPERM;

	void *buf = nullptr;
	size_t len = 0;

	int ret = rw_fw_build_create_batch(session, &buf, &len);
	if (ret < 0)
		return ret;

	ret = send_batch(buf, len);
	free(buf);
	return ret;
}

int rw_fw_session_destroy(const rw_fw_session_t *session)
{
	if (geteuid() != 0)
		return -EPERM;

	void *buf = nullptr;
	size_t len = 0;

	int ret = rw_fw_build_destroy_batch(session, &buf, &len);
	if (ret < 0)
		return ret;

	ret = send_batch(buf, len);
	free(buf);
	return ret;
}
