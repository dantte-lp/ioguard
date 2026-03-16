#define _GNU_SOURCE
#include "ipc/transport.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int iog_ipc_create_pair(iog_ipc_channel_t *ch)
{
    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    if (ret < 0) {
        return -errno;
    }
    ch->parent_fd = sv[0];
    ch->child_fd = sv[1];
    return 0;
}

void iog_ipc_close(iog_ipc_channel_t *ch)
{
    if (ch->parent_fd >= 0) {
        close(ch->parent_fd);
        ch->parent_fd = -1;
    }
    if (ch->child_fd >= 0) {
        close(ch->child_fd);
        ch->child_fd = -1;
    }
}

int iog_ipc_send(int fd, const uint8_t *data, size_t len)
{
    if (data == nullptr || len == 0) {
        return -EINVAL;
    }
    if (len > IOG_IPC_MAX_MSG_SIZE) {
        return -EMSGSIZE;
    }

    ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
    if (n < 0) {
        return -errno;
    }
    /* SOCK_SEQPACKET sends atomically, but verify completeness */
    if ((size_t)n != len) {
        return -EIO;
    }
    return 0;
}

ssize_t iog_ipc_recv(int fd, uint8_t *buf, size_t buf_size)
{
    ssize_t n = recv(fd, buf, buf_size, 0);
    if (n < 0) {
        return -errno;
    }
    return n;
}

int iog_ipc_send_fd(int socket_fd, int fd_to_send)
{
    struct msghdr msg = {0};
    struct iovec iov;
    uint8_t dummy = 0;

    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    ssize_t n = sendmsg(socket_fd, &msg, MSG_NOSIGNAL);
    if (n < 0) {
        return -errno;
    }
    return 0;
}

int iog_ipc_recv_fd(int socket_fd)
{
    struct msghdr msg = {0};
    struct iovec iov;
    uint8_t dummy;

    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    ssize_t n = recvmsg(socket_fd, &msg, 0);
    if (n < 0) {
        return -errno;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return -EPROTO;
    }

    int received_fd;
    memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

    /* Prevent fd leak to child processes on fork+exec */
    (void)fcntl(received_fd, F_SETFD, FD_CLOEXEC);

    return received_fd;
}
