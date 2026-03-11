#include "network/tun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

void iog_tun_config_init(iog_tun_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->mtu = IOG_TUN_DEFAULT_MTU;
    cfg->set_nonblock = true;
}

int iog_tun_config_validate(const iog_tun_config_t *cfg)
{
    if (cfg->mtu < IOG_TUN_MIN_MTU || cfg->mtu > IOG_TUN_MAX_MTU) {
        return -EINVAL;
    }
    return 0;
}

int iog_tun_alloc(const iog_tun_config_t *cfg, iog_tun_t *tun)
{
    int ret = iog_tun_config_validate(cfg);
    if (ret < 0) {
        return ret;
    }

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (cfg->dev_name[0] != '\0') {
        strncpy(ifr.ifr_name, cfg->dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    if (cfg->set_nonblock) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            ret = -errno;
            close(fd);
            return ret;
        }
    }

    /* Set MTU via socket ioctl */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq mtu_ifr;
        memset(&mtu_ifr, 0, sizeof(mtu_ifr));
        strncpy(mtu_ifr.ifr_name, ifr.ifr_name, IFNAMSIZ - 1);
        mtu_ifr.ifr_mtu = (int)cfg->mtu;
        ioctl(sock, SIOCSIFMTU, &mtu_ifr); /* best-effort */
        close(sock);
    }

    tun->fd = fd;
    strncpy(tun->dev_name, ifr.ifr_name, IOG_TUN_NAME_MAX - 1);
    tun->dev_name[IOG_TUN_NAME_MAX - 1] = '\0';
    tun->mtu = cfg->mtu;

    return 0;
}

void iog_tun_close(iog_tun_t *tun)
{
    if (tun->fd >= 0) {
        close(tun->fd);
        tun->fd = -1;
    }
}

uint32_t iog_tun_calc_mtu(uint32_t base_mtu, int af)
{
    /* IP header: 20 (IPv4) or 40 (IPv6) */
    uint32_t ip_overhead = (af == AF_INET6) ? 40 : 20;
    /* TCP: 20, TLS record: 37, CSTP header: 4 */
    uint32_t total_overhead = ip_overhead + 20 + 37 + 4;

    if (base_mtu <= total_overhead + IOG_TUN_MIN_MTU) {
        return IOG_TUN_MIN_MTU;
    }
    return base_mtu - total_overhead;
}
