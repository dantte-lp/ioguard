#ifndef RINGWALL_IPC_MESSAGES_H
#define RINGWALL_IPC_MESSAGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    RW_IPC_MSG_UNKNOWN = 0,
    RW_IPC_MSG_AUTH_REQUEST = 1,
    RW_IPC_MSG_AUTH_RESPONSE = 2,
    RW_IPC_MSG_SESSION_OPEN = 3,
    RW_IPC_MSG_SESSION_CLOSE = 4,
    RW_IPC_MSG_WORKER_STATUS = 5,
    RW_IPC_MSG_CONFIG_RELOAD = 6,
    RW_IPC_MSG_SHUTDOWN = 7,
    RW_IPC_MSG_SESSION_VALIDATE = 8,
} rw_ipc_msg_type_t;

typedef struct {
    rw_ipc_msg_type_t type;
    uint32_t seq;
} rw_ipc_msg_t;

void rw_ipc_msg_init(rw_ipc_msg_t *msg, rw_ipc_msg_type_t type);

typedef struct {
    const char *username;
    const char *group;
    const uint8_t *cookie;
    size_t cookie_len;
    const char *source_ip;
    const char *password;
    const char *otp;
} rw_ipc_auth_request_t;

[[nodiscard]] ssize_t rw_ipc_pack_auth_request(const rw_ipc_auth_request_t *req,
                                                uint8_t *buf, size_t buf_size);
[[nodiscard]] int rw_ipc_unpack_auth_request(const uint8_t *data, size_t len,
                                              rw_ipc_auth_request_t *out);
void rw_ipc_free_auth_request(rw_ipc_auth_request_t *req);

typedef struct {
    bool success;
    const char *error_msg;
    const uint8_t *session_cookie;
    size_t session_cookie_len;
    uint32_t session_ttl;
    const char *assigned_ip;
    const char *dns_server;
    const char *default_domain;
    const char **routes;
    uint32_t route_count;
} rw_ipc_auth_response_t;

[[nodiscard]] ssize_t rw_ipc_pack_auth_response(const rw_ipc_auth_response_t *resp,
                                                  uint8_t *buf, size_t buf_size);
[[nodiscard]] int rw_ipc_unpack_auth_response(const uint8_t *data, size_t len,
                                                rw_ipc_auth_response_t *out);
void rw_ipc_free_auth_response(rw_ipc_auth_response_t *resp);

typedef struct {
    const uint8_t *cookie;
    size_t cookie_len;
} rw_ipc_session_validate_t;

[[nodiscard]] ssize_t rw_ipc_pack_session_validate(const rw_ipc_session_validate_t *req,
                                                    uint8_t *buf, size_t buf_size);
[[nodiscard]] int rw_ipc_unpack_session_validate(const uint8_t *data, size_t len,
                                                  rw_ipc_session_validate_t *out);
void rw_ipc_free_session_validate(rw_ipc_session_validate_t *req);

typedef struct {
    uint32_t active_connections;
    uint64_t bytes_rx;
    uint64_t bytes_tx;
    uint32_t pid;
} rw_ipc_worker_status_t;

[[nodiscard]] ssize_t rw_ipc_pack_worker_status(const rw_ipc_worker_status_t *status,
                                                  uint8_t *buf, size_t buf_size);
[[nodiscard]] int rw_ipc_unpack_worker_status(const uint8_t *data, size_t len,
                                                rw_ipc_worker_status_t *out);

#endif /* RINGWALL_IPC_MESSAGES_H */
