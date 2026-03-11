---
name: wolfsentry-idps
description: Use when implementing firewall rules, rate limiting, connection tracking, DDoS mitigation, IP blocking, geographic filtering, or integrating wolfSentry IDPS into ioguard. Also use for per-user/per-group firewall and nftables integration.
---

# wolfSentry IDPS Integration for ioguard

## Context7 Reference
Always fetch latest docs: library ID `/wolfssl/wolfsentry`

## Full Documentation
See `/opt/projects/repositories/ioguard-docs/docs/ioguard/architecture/wolfsentry-integration.md`

## Overview

wolfSentry 1.6.3 — embedded IDPS/firewall engine from wolfSSL. Pure C, GPLv2, 64KB code + 32KB RAM.

### Capabilities
- Dynamic firewall rules (IP/port/protocol)
- CIDR-based prefix matching
- Connection tracking and rate limiting
- Event-action framework
- JSON-based runtime reconfiguration
- Transactional policy updates (atomic, no downtime)
- Native wolfSSL TLS/DTLS integration

## Architecture: wolfSentry in ioguard

```
Client → libuv → wolfSentry → wolfSSL → Worker → TUN → Kernel
                    ↓ REJECT
                  (logged)
```

wolfSentry checks EVERY incoming connection BEFORE TLS handshake:
1. Check source IP against rules (allow/deny/rate-limit)
2. Check rate limits (per-IP, per-subnet)
3. Check connection tracking state
4. Return ACCEPT or REJECT

## Initialization

```c
#include <wolfsentry/wolfsentry.h>

static struct wolfsentry_context *ws_ctx = nullptr;

[[nodiscard]]
static int iog_wolfsentry_init(const char *config_path) {
    struct wolfsentry_eventconfig default_config = {
        .route_private_data_size = sizeof(iog_route_data_t),
        .max_connection_count = 10000,
        .penalty_box_duration = 300,  // 5 minutes
    };

    int ret = wolfsentry_init(
        wolfsentry_build_settings,
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(nullptr, nullptr),
        &default_config,
        &ws_ctx
    );
    if (ret < 0) return ret;

    // Load JSON configuration
    if (config_path != nullptr) {
        ret = wolfsentry_config_json_file(ws_ctx, config_path, 0);
    }

    return ret;
}
```

## Connection Checking (libuv callback)

```c
static void on_new_connection(uv_stream_t *server, int status) {
    struct sockaddr_in client_addr;
    // ... accept connection ...

    // Check wolfSentry BEFORE TLS handshake
    wolfsentry_action_res_t action_res;
    struct wolfsentry_sockaddr sa = {
        .sa_family = AF_INET,
        .addr_len = 32,
    };
    memcpy(sa.addr, &client_addr.sin_addr, 4);
    sa.sa_port = ntohs(client_addr.sin_port);

    int ret = wolfsentry_route_event_dispatch(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX(ws_ctx),
        &sa,      // remote
        &local_sa, // local
        WOLFSENTRY_ROUTE_FLAG_DIRECTION_IN,
        "connect",  // event name
        strlen("connect"),
        nullptr,
        nullptr,
        &action_res
    );

    if (WOLFSENTRY_CHECK_BITS(action_res, WOLFSENTRY_ACTION_RES_REJECT)) {
        // Connection denied — close immediately
        uv_close((uv_handle_t *)client, on_close);
        return;
    }

    // Connection allowed — proceed with TLS handshake
    iog_start_tls_handshake(client);
}
```

## wolfSSL Native Integration

wolfSentry integrates directly into wolfSSL's accept callback:

```c
// Set wolfSentry callback on wolfSSL context
wolfSSL_CTX_set_AcceptFilter(ctx, wolfsentry_accept_filter_callback, ws_ctx);

// wolfSentry automatically checks each connection during SSL_accept()
```

## JSON Configuration

```json
{
  "wolfsentry-config-version": 1,
  "default-policies": {
    "default-policy-static": "reject",
    "default-policy-dynamic": "reject",
    "default-event-label": "default"
  },
  "events": [
    {
      "label": "connect",
      "config": {
        "max_connection_count": 100,
        "penalty_box_duration": "5m"
      }
    }
  ],
  "static-routes-insert": [
    {
      "parent-event": "connect",
      "direction": "in",
      "family": 2,
      "remote": { "address": "10.0.0.0/8" },
      "flags": ["SA_FAMILY_WILDCARD", "SA_PROTO_WILDCARD"],
      "action": "accept"
    },
    {
      "parent-event": "connect",
      "direction": "in",
      "remote": { "address": "0.0.0.0/0" },
      "flags": ["SA_FAMILY_WILDCARD", "SA_PROTO_WILDCARD"],
      "action": "reject"
    }
  ]
}
```

## Rate Limiting

```c
// Per-IP rate limiting: max 10 connections per minute
struct wolfsentry_eventconfig rate_config = {
    .max_connection_count = 10,
    .derog_thresh_for_penalty_boxing = 5,  // 5 violations → penalty box
    .penalty_box_duration = 300,            // 5 minutes in penalty box
};
```

## Per-User/Per-Group Firewall (nftables integration)

wolfSentry handles pre-authentication firewall. For authenticated per-user rules, use nftables via libmnl + libnftnl:

```c
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>

// Create per-user nftables chain after authentication
[[nodiscard]]
static int iog_create_user_chain(const char *username, uint32_t client_ip) {
    // 1. Create named chain: ioguard_user_<username>
    // 2. Add rules based on user's group policy
    // 3. Jump from main chain to user chain for this IP
    // 4. Cleanup on disconnect
}
```

## DDoS Mitigation

wolfSentry + XDP for layered defense:
1. **XDP** (physical NIC): Drop known-bad IPs at line rate
2. **wolfSentry** (userspace): Dynamic rate limiting, penalty boxing
3. **nftables** (per-user): Post-auth access control

## Monitoring

```c
// Get wolfSentry statistics
struct wolfsentry_route_table_stats stats;
wolfsentry_route_table_stats_get(ws_ctx, &stats);
// stats.n_routes, stats.n_route_lookups, stats.n_route_hits, etc.
```

## Checklist

- [ ] Initialize wolfSentry before accepting connections
- [ ] Check EVERY connection before TLS handshake
- [ ] Configure rate limiting per event type
- [ ] Set penalty box duration for repeat offenders
- [ ] Load rules from JSON config (atomic reload supported)
- [ ] Log all REJECT actions with source IP and reason
- [ ] Integrate with wolfSSL AcceptFilter for native filtering
- [ ] Zero wolfSentry context on shutdown
