#include "ipc/messages.h"
#include "wg_ipc.pb-c.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>

void wg_ipc_msg_init(wg_ipc_msg_t *msg, wg_ipc_msg_type_t type)
{
    msg->type = type;
    msg->seq = 0;
}

ssize_t wg_ipc_pack_auth_request(const wg_ipc_auth_request_t *req,
                                  uint8_t *buf, size_t buf_size)
{
    WgIpc__AuthRequest pb = WG_IPC__AUTH_REQUEST__INIT;
    WgIpc__IpcHeader hdr = WG_IPC__IPC_HEADER__INIT;
    hdr.type = WG_IPC__MSG_TYPE__MSG_TYPE_AUTH_REQUEST;

    pb.header = &hdr;
    pb.username = (char *)req->username;
    pb.group = (char *)req->group;
    pb.source_ip = (char *)req->source_ip;
    if (req->cookie != nullptr && req->cookie_len > 0) {
        pb.cookie.data = (uint8_t *)req->cookie;
        pb.cookie.len = req->cookie_len;
    }

    size_t packed_size = wg_ipc__auth_request__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)wg_ipc__auth_request__pack(&pb, buf);
}

int wg_ipc_unpack_auth_request(const uint8_t *data, size_t len,
                                wg_ipc_auth_request_t *out)
{
    WgIpc__AuthRequest *pb = wg_ipc__auth_request__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->username = pb->username ? strdup(pb->username) : nullptr;
    out->group = pb->group ? strdup(pb->group) : nullptr;
    out->source_ip = pb->source_ip ? strdup(pb->source_ip) : nullptr;
    out->cookie = nullptr;
    out->cookie_len = 0;
    if (pb->cookie.len > 0 && pb->cookie.data != nullptr) {
        out->cookie = malloc(pb->cookie.len);
        if (out->cookie != nullptr) {
            memcpy((void *)out->cookie, pb->cookie.data, pb->cookie.len);
            out->cookie_len = pb->cookie.len;
        }
    }
    wg_ipc__auth_request__free_unpacked(pb, nullptr);
    return 0;
}

void wg_ipc_free_auth_request(wg_ipc_auth_request_t *req)
{
    free((void *)req->username);
    free((void *)req->group);
    free((void *)req->source_ip);
    free((void *)req->cookie);
    memset(req, 0, sizeof(*req));
}

ssize_t wg_ipc_pack_auth_response(const wg_ipc_auth_response_t *resp,
                                    uint8_t *buf, size_t buf_size)
{
    WgIpc__AuthResponse pb = WG_IPC__AUTH_RESPONSE__INIT;
    WgIpc__IpcHeader hdr = WG_IPC__IPC_HEADER__INIT;
    hdr.type = WG_IPC__MSG_TYPE__MSG_TYPE_AUTH_RESPONSE;

    pb.header = &hdr;
    pb.success = resp->success;
    pb.error_msg = (char *)resp->error_msg;
    pb.session_ttl = resp->session_ttl;
    pb.assigned_ip = (char *)resp->assigned_ip;
    pb.dns_server = (char *)resp->dns_server;
    if (resp->session_cookie != nullptr && resp->session_cookie_len > 0) {
        pb.session_cookie.data = (uint8_t *)resp->session_cookie;
        pb.session_cookie.len = resp->session_cookie_len;
    }

    size_t packed_size = wg_ipc__auth_response__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)wg_ipc__auth_response__pack(&pb, buf);
}

int wg_ipc_unpack_auth_response(const uint8_t *data, size_t len,
                                  wg_ipc_auth_response_t *out)
{
    WgIpc__AuthResponse *pb = wg_ipc__auth_response__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->success = pb->success;
    out->error_msg = pb->error_msg ? strdup(pb->error_msg) : nullptr;
    out->session_ttl = pb->session_ttl;
    out->assigned_ip = pb->assigned_ip ? strdup(pb->assigned_ip) : nullptr;
    out->dns_server = pb->dns_server ? strdup(pb->dns_server) : nullptr;
    out->session_cookie = nullptr;
    out->session_cookie_len = 0;
    if (pb->session_cookie.len > 0 && pb->session_cookie.data != nullptr) {
        out->session_cookie = malloc(pb->session_cookie.len);
        if (out->session_cookie != nullptr) {
            memcpy((void *)out->session_cookie, pb->session_cookie.data,
                   pb->session_cookie.len);
            out->session_cookie_len = pb->session_cookie.len;
        }
    }
    wg_ipc__auth_response__free_unpacked(pb, nullptr);
    return 0;
}

void wg_ipc_free_auth_response(wg_ipc_auth_response_t *resp)
{
    free((void *)resp->error_msg);
    free((void *)resp->assigned_ip);
    free((void *)resp->dns_server);
    free((void *)resp->session_cookie);
    memset(resp, 0, sizeof(*resp));
}

ssize_t wg_ipc_pack_worker_status(const wg_ipc_worker_status_t *status,
                                    uint8_t *buf, size_t buf_size)
{
    WgIpc__WorkerStatus pb = WG_IPC__WORKER_STATUS__INIT;
    WgIpc__IpcHeader hdr = WG_IPC__IPC_HEADER__INIT;
    hdr.type = WG_IPC__MSG_TYPE__MSG_TYPE_WORKER_STATUS;

    pb.header = &hdr;
    pb.active_connections = status->active_connections;
    pb.bytes_rx = status->bytes_rx;
    pb.bytes_tx = status->bytes_tx;
    pb.pid = status->pid;

    size_t packed_size = wg_ipc__worker_status__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)wg_ipc__worker_status__pack(&pb, buf);
}

int wg_ipc_unpack_worker_status(const uint8_t *data, size_t len,
                                  wg_ipc_worker_status_t *out)
{
    WgIpc__WorkerStatus *pb = wg_ipc__worker_status__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->active_connections = pb->active_connections;
    out->bytes_rx = pb->bytes_rx;
    out->bytes_tx = pb->bytes_tx;
    out->pid = pb->pid;
    wg_ipc__worker_status__free_unpacked(pb, nullptr);
    return 0;
}
