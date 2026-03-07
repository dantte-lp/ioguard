/**
 * @file tun.h
 * @brief TUN device allocation and MTU calculation for VPN tunneling.
 *
 * Provides TUN device creation via /dev/net/tun, MTU configuration,
 * and VPN MTU calculation accounting for IP/TCP/TLS/CSTP overhead.
 */

#ifndef WOLFGUARD_NETWORK_TUN_H
#define WOLFGUARD_NETWORK_TUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum TUN device name length (IFNAMSIZ). */
constexpr size_t WG_TUN_NAME_MAX = 16;

/** Default VPN MTU (conservative for TLS overhead). */
constexpr uint32_t WG_TUN_DEFAULT_MTU = 1406;

/** Minimum allowed MTU (RFC 791 minimum). */
constexpr uint32_t WG_TUN_MIN_MTU = 68;

/** Maximum allowed MTU. */
constexpr uint32_t WG_TUN_MAX_MTU = 65535;

/** TUN device configuration. */
typedef struct {
	char dev_name[WG_TUN_NAME_MAX];
	uint32_t mtu;
	bool set_nonblock;
} wg_tun_config_t;

/** Allocated TUN device state. */
typedef struct {
	int fd;
	char dev_name[WG_TUN_NAME_MAX];
	uint32_t mtu;
} wg_tun_t;

/**
 * @brief Initialize config with defaults (MTU=1406, nonblock=true, empty name).
 * @param cfg Config to initialize.
 */
void wg_tun_config_init(wg_tun_config_t *cfg);

/**
 * @brief Validate config.
 * @param cfg Config to validate.
 * @return 0 on success, -EINVAL on invalid parameters.
 */
[[nodiscard]] int wg_tun_config_validate(const wg_tun_config_t *cfg);

/**
 * @brief Allocate and configure a TUN device. Requires CAP_NET_ADMIN.
 * @param cfg Configuration.
 * @param tun Output: allocated device state (tun->fd is valid on success).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int wg_tun_alloc(const wg_tun_config_t *cfg, wg_tun_t *tun);

/**
 * @brief Close TUN device and release resources.
 * @param tun Device to close (tun->fd set to -1 after close).
 */
void wg_tun_close(wg_tun_t *tun);

/**
 * @brief Calculate effective VPN MTU from base network MTU.
 *
 * Subtracts IP(20) + TCP(20) + TLS(37) + CSTP(4) = 81 bytes overhead.
 * @param base_mtu Base network MTU (e.g., 1500).
 * @return Effective VPN MTU, clamped to WG_TUN_MIN_MTU minimum.
 */
[[nodiscard]] uint32_t wg_tun_calc_mtu(uint32_t base_mtu);

#endif /* WOLFGUARD_NETWORK_TUN_H */
