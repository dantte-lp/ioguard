#ifndef RINGWALL_IPC_TRANSPORT_H
#define RINGWALL_IPC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* IPC channel: a SOCK_SEQPACKET socketpair */
typedef struct {
    int parent_fd; /* used by parent process (Main) */
    int child_fd;  /* used by child process (worker/sec-mod) */
} rw_ipc_channel_t;

/* Maximum IPC message size (must fit in provided buffers) */
constexpr size_t RW_IPC_MAX_MSG_SIZE = 4096;

/* Create a SOCK_SEQPACKET socketpair for IPC */
[[nodiscard]] int rw_ipc_create_pair(rw_ipc_channel_t *ch);

/* Close both ends of the channel */
void rw_ipc_close(rw_ipc_channel_t *ch);

/* Send raw bytes. Returns 0 on success, -errno on error. */
[[nodiscard]] int rw_ipc_send(int fd, const uint8_t *data, size_t len);

/* Receive raw bytes. Returns message length, or negative errno. */
[[nodiscard]] ssize_t rw_ipc_recv(int fd, uint8_t *buf, size_t buf_size);

/* Send a file descriptor via SCM_RIGHTS. Returns 0 on success. */
[[nodiscard]] int rw_ipc_send_fd(int socket_fd, int fd_to_send);

/* Receive a file descriptor via SCM_RIGHTS. Returns fd or negative errno. */
[[nodiscard]] int rw_ipc_recv_fd(int socket_fd);

#endif /* RINGWALL_IPC_TRANSPORT_H */
