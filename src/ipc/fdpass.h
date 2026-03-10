#ifndef RINGWALL_IPC_FDPASS_H
#define RINGWALL_IPC_FDPASS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_FDPASS_MAX_FDS = 4;

/**
 * @brief Send file descriptor(s) over a unix socket via SCM_RIGHTS.
 *
 * @param sock_fd  Unix socket (SOCK_SEQPACKET or SOCK_STREAM).
 * @param fds      Array of fds to send.
 * @param nfds     Number of fds (1..RW_FDPASS_MAX_FDS).
 * @param data     Optional payload (may be nullptr if data_len == 0).
 * @param data_len Payload length.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_fdpass_send(int sock_fd, const int *fds, size_t nfds, const void *data,
                                 size_t data_len);

/**
 * @brief Receive file descriptor(s) from a unix socket.
 *
 * @param sock_fd   Unix socket.
 * @param fds_out   Array to receive fds (set to -1 if no fds in message).
 * @param max_fds   Capacity of fds_out array.
 * @param nfds_out  Number of fds actually received.
 * @param data      Buffer for payload.
 * @param data_len  [in] buffer size, [out] bytes received.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_fdpass_recv(int sock_fd, int *fds_out, size_t max_fds, size_t *nfds_out,
                                 void *data, size_t *data_len);

#endif /* RINGWALL_IPC_FDPASS_H */
