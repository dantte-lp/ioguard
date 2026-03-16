#include "ipc/fdpass.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int iog_fdpass_send(int sock_fd, const int *fds, size_t nfds, const void *data, size_t data_len)
{
    if (sock_fd < 0) {
        return -EBADF;
    }
    if (fds == nullptr || nfds == 0 || nfds > IOG_FDPASS_MAX_FDS) {
        return -EINVAL;
    }

    /* Validate all fds are non-negative */
    for (size_t i = 0; i < nfds; i++) {
        if (fds[i] < 0) {
            return -EBADF;
        }
    }

    /* Some kernels require at least 1 byte of payload for ancillary data */
    uint8_t dummy = 0;
    struct iovec iov = {
        .iov_base = (data != nullptr && data_len > 0) ? (void *)(uintptr_t)data : &dummy,
        .iov_len = (data != nullptr && data_len > 0) ? data_len : 1,
    };

    /* Build control message for SCM_RIGHTS */
    size_t cmsg_len = CMSG_SPACE(nfds * sizeof(int));
    union {
        char buf[CMSG_SPACE(IOG_FDPASS_MAX_FDS * sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = cmsg_len,
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(int));

    ssize_t n = sendmsg(sock_fd, &msg, MSG_NOSIGNAL);
    if (n < 0) {
        return -errno;
    }

    return 0;
}

int iog_fdpass_recv(int sock_fd, int *fds_out, size_t max_fds, size_t *nfds_out, void *data,
                    size_t *data_len)
{
    if (sock_fd < 0) {
        return -EBADF;
    }
    if (fds_out == nullptr || nfds_out == nullptr || max_fds == 0) {
        return -EINVAL;
    }

    /* Initialize outputs */
    *nfds_out = 0;
    for (size_t i = 0; i < max_fds; i++) {
        fds_out[i] = -1;
    }

    /* Receive buffer: use caller's data buf, or a small dummy */
    uint8_t dummy = 0;
    struct iovec iov = {
        .iov_base = (data != nullptr && data_len != nullptr && *data_len > 0) ? data : &dummy,
        .iov_len = (data != nullptr && data_len != nullptr && *data_len > 0) ? *data_len : 1,
    };

    /* Control message buffer */
    union {
        char buf[CMSG_SPACE(IOG_FDPASS_MAX_FDS * sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = sizeof(cmsg_buf.buf),
    };

    ssize_t n = recvmsg(sock_fd, &msg, 0);
    if (n < 0) {
        return -errno;
    }
    if (n == 0) {
        return -ECONNRESET;
    }

    /* Update data_len with actual received bytes */
    if (data_len != nullptr) {
        *data_len = (size_t)n;
    }

    /* Extract fds from control message */
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t payload_len = cmsg->cmsg_len - CMSG_LEN(0);
            size_t nfds = payload_len / sizeof(int);
            if (nfds > max_fds) {
                /* Close excess fds to prevent leaking */
                int *all_fds = (int *)CMSG_DATA(cmsg);
                for (size_t i = max_fds; i < nfds; i++) {
                    close(all_fds[i]);
                }
                nfds = max_fds;
            }
            memcpy(fds_out, CMSG_DATA(cmsg), nfds * sizeof(int));
            *nfds_out = nfds;

            /* Set CLOEXEC on all received fds to prevent leak on fork+exec */
            for (size_t j = 0; j < nfds; j++) {
                (void)fcntl(fds_out[j], F_SETFD, FD_CLOEXEC);
            }
            break;
        }
    }

    return 0;
}
