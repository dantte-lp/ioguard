#define _GNU_SOURCE
#include "ipc/messages.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "iog_ipc.pb-c.h"

void iog_ipc_msg_init(iog_ipc_msg_t *msg, iog_ipc_msg_type_t type)
{
    msg->type = type;
    msg->seq = 0;
}

ssize_t iog_ipc_pack_auth_request(const iog_ipc_auth_request_t *req, uint8_t *buf, size_t buf_size)
{
    IogIpc__AuthRequest pb = IOG_IPC__AUTH_REQUEST__INIT;
    IogIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_AUTH_REQUEST;

    pb.header = &hdr;
    pb.username = (char *)req->username;
    pb.group = (char *)req->group;
    pb.source_ip = (char *)req->source_ip;
    pb.password = (char *)req->password;
    pb.otp = (char *)req->otp;
    if (req->cookie != nullptr && req->cookie_len > 0) {
        pb.cookie.data = (uint8_t *)req->cookie;
        pb.cookie.len = req->cookie_len;
    }

    size_t packed_size = iog_ipc__auth_request__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)iog_ipc__auth_request__pack(&pb, buf);
}

int iog_ipc_unpack_auth_request(const uint8_t *data, size_t len, iog_ipc_auth_request_t *out)
{
    IogIpc__AuthRequest *pb = iog_ipc__auth_request__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->username = pb->username ? strdup(pb->username) : nullptr;
    out->group = pb->group ? strdup(pb->group) : nullptr;
    out->source_ip = pb->source_ip ? strdup(pb->source_ip) : nullptr;
    out->password = pb->password ? strdup(pb->password) : nullptr;
    out->otp = pb->otp ? strdup(pb->otp) : nullptr;
    out->cookie = nullptr;
    out->cookie_len = 0;
    if (pb->cookie.len > 0 && pb->cookie.data != nullptr) {
        out->cookie = malloc(pb->cookie.len);
        if (out->cookie != nullptr) {
            memcpy((void *)out->cookie, pb->cookie.data, pb->cookie.len);
            out->cookie_len = pb->cookie.len;
        }
    }
    iog_ipc__auth_request__free_unpacked(pb, nullptr);
    return 0;
}

void iog_ipc_free_auth_request(iog_ipc_auth_request_t *req)
{
    free((void *)req->username);
    free((void *)req->group);
    free((void *)req->source_ip);
    if (req->password != nullptr) {
        explicit_bzero((void *)req->password, strlen(req->password));
        free((void *)req->password);
    }
    if (req->otp != nullptr) {
        explicit_bzero((void *)req->otp, strlen(req->otp));
        free((void *)req->otp);
    }
    free((void *)req->cookie);
    memset(req, 0, sizeof(*req));
}

ssize_t iog_ipc_pack_auth_response(const iog_ipc_auth_response_t *resp, uint8_t *buf, size_t buf_size)
{
    IogIpc__AuthResponse pb = IOG_IPC__AUTH_RESPONSE__INIT;
    IogIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_AUTH_RESPONSE;

    pb.header = &hdr;
    pb.success = resp->success;
    pb.error_msg = (char *)resp->error_msg;
    pb.session_ttl = resp->session_ttl;
    pb.assigned_ip = (char *)resp->assigned_ip;
    pb.dns_server = (char *)resp->dns_server;
    pb.default_domain = (char *)resp->default_domain;
    pb.n_routes = resp->route_count;
    pb.routes = (char **)resp->routes;
    if (resp->session_cookie != nullptr && resp->session_cookie_len > 0) {
        pb.session_cookie.data = (uint8_t *)resp->session_cookie;
        pb.session_cookie.len = resp->session_cookie_len;
    }
    pb.requires_totp = resp->requires_totp;

    size_t packed_size = iog_ipc__auth_response__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)iog_ipc__auth_response__pack(&pb, buf);
}

int iog_ipc_unpack_auth_response(const uint8_t *data, size_t len, iog_ipc_auth_response_t *out)
{
    IogIpc__AuthResponse *pb = iog_ipc__auth_response__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->success = pb->success;
    out->error_msg = pb->error_msg ? strdup(pb->error_msg) : nullptr;
    out->session_ttl = pb->session_ttl;
    out->assigned_ip = pb->assigned_ip ? strdup(pb->assigned_ip) : nullptr;
    out->dns_server = pb->dns_server ? strdup(pb->dns_server) : nullptr;
    out->default_domain = pb->default_domain ? strdup(pb->default_domain) : nullptr;
    out->routes = nullptr;
    out->route_count = 0;
    if (pb->n_routes > 0 && pb->routes != nullptr) {
        out->routes = malloc(pb->n_routes * sizeof(*out->routes));
        if (out->routes != nullptr) {
            for (size_t i = 0; i < pb->n_routes; i++) {
                out->routes[i] = strdup(pb->routes[i]);
            }
            out->route_count = (uint32_t)pb->n_routes;
        }
    }
    out->session_cookie = nullptr;
    out->session_cookie_len = 0;
    if (pb->session_cookie.len > 0 && pb->session_cookie.data != nullptr) {
        out->session_cookie = malloc(pb->session_cookie.len);
        if (out->session_cookie != nullptr) {
            memcpy((void *)out->session_cookie, pb->session_cookie.data, pb->session_cookie.len);
            out->session_cookie_len = pb->session_cookie.len;
        }
    }
    out->requires_totp = pb->requires_totp;
    iog_ipc__auth_response__free_unpacked(pb, nullptr);
    return 0;
}

void iog_ipc_free_auth_response(iog_ipc_auth_response_t *resp)
{
    free((void *)resp->error_msg);
    free((void *)resp->assigned_ip);
    free((void *)resp->dns_server);
    free((void *)resp->default_domain);
    for (uint32_t i = 0; i < resp->route_count; i++) {
        free((void *)resp->routes[i]);
    }
    free((void *)resp->routes);
    if (resp->session_cookie != nullptr) {
        explicit_bzero((void *)resp->session_cookie, resp->session_cookie_len);
        free((void *)resp->session_cookie);
    }
    memset(resp, 0, sizeof(*resp));
}

ssize_t iog_ipc_pack_session_validate(const iog_ipc_session_validate_t *req, uint8_t *buf,
                                     size_t buf_size)
{
    IogIpc__SessionValidate pb = IOG_IPC__SESSION_VALIDATE__INIT;
    IogIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_SESSION_VALIDATE;

    pb.header = &hdr;
    if (req->cookie != nullptr && req->cookie_len > 0) {
        pb.cookie.data = (uint8_t *)req->cookie;
        pb.cookie.len = req->cookie_len;
    }

    size_t packed_size = iog_ipc__session_validate__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)iog_ipc__session_validate__pack(&pb, buf);
}

int iog_ipc_unpack_session_validate(const uint8_t *data, size_t len, iog_ipc_session_validate_t *out)
{
    IogIpc__SessionValidate *pb = iog_ipc__session_validate__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->cookie = nullptr;
    out->cookie_len = 0;
    if (pb->cookie.len > 0 && pb->cookie.data != nullptr) {
        out->cookie = malloc(pb->cookie.len);
        if (out->cookie != nullptr) {
            memcpy((void *)out->cookie, pb->cookie.data, pb->cookie.len);
            out->cookie_len = pb->cookie.len;
        }
    }
    iog_ipc__session_validate__free_unpacked(pb, nullptr);
    return 0;
}

void iog_ipc_free_session_validate(iog_ipc_session_validate_t *req)
{
    free((void *)req->cookie);
    memset(req, 0, sizeof(*req));
}

ssize_t iog_ipc_pack_worker_status(const iog_ipc_worker_status_t *status, uint8_t *buf,
                                  size_t buf_size)
{
    IogIpc__WorkerStatus pb = IOG_IPC__WORKER_STATUS__INIT;
    IogIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_WORKER_STATUS;

    pb.header = &hdr;
    pb.active_connections = status->active_connections;
    pb.bytes_rx = status->bytes_rx;
    pb.bytes_tx = status->bytes_tx;
    pb.pid = status->pid;

    size_t packed_size = iog_ipc__worker_status__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -ENOBUFS;
    }
    return (ssize_t)iog_ipc__worker_status__pack(&pb, buf);
}

int iog_ipc_unpack_worker_status(const uint8_t *data, size_t len, iog_ipc_worker_status_t *out)
{
    IogIpc__WorkerStatus *pb = iog_ipc__worker_status__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -EINVAL;
    }
    out->active_connections = pb->active_connections;
    out->bytes_rx = pb->bytes_rx;
    out->bytes_tx = pb->bytes_tx;
    out->pid = pb->pid;
    iog_ipc__worker_status__free_unpacked(pb, nullptr);
    return 0;
}
