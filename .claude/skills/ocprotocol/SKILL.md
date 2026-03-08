---
name: ocprotocol
description: Use when implementing OpenConnect protocol features — DTLS/TCP tunneling, XML configuration exchange, cookie-based authentication, Cisco Secure Client compatibility, CSTP/DTLS headers, DPD timers, split DNS, NVM telemetry
---

# OpenConnect Protocol for ringwall

## Full Documentation
See `/opt/projects/repositories/ringwall-docs/docs/openconnect-protocol/` for complete specs.

## Protocol Overview

ringwall implements OpenConnect VPN Protocol v1.2, compatible with Cisco Secure Client 5.x+.

### Connection Flow

```
Client                              Server (ringwall)
  |                                    |
  |--- TLS Handshake (port 443) ------>|
  |<-- TLS Handshake Complete ---------|
  |                                    |
  |--- HTTP POST /auth (XML) -------->|  Cookie-based auth (AggAuth)
  |<-- HTTP 200 + session cookie ------|
  |                                    |
  |--- HTTP CONNECT /CSCOSSLC/tunnel ->|  CSTP tunnel setup
  |<-- HTTP 200 + VPN headers ---------|
  |                                    |
  |=== CSTP Data Channel (TLS) =======>|  TCP data tunnel (SSL-Tunnel)
  |                                    |
  |--- DTLS ClientHello (port 443) --->|  UDP data channel
  |<-- DTLS ServerHello ---------------|
  |=== DTLS Data Channel =============>|  Preferred data path (DTLS-Tunnel)
```

### Three Tunnel Types (CRITICAL)

1. **Parent-Tunnel**: Session token container, no encryption, persists for reconnection
2. **SSL-Tunnel (TLS/TCP)**: Control + fallback data, established first
3. **DTLS-Tunnel (UDP)**: Primary data channel, preferred when available

Parent-Tunnel MUST persist even when SSL/DTLS tunnels drop — client enters "Waiting to Resume" state.

### Key Headers (CSTP)

```http
X-CSTP-Version: 1
X-CSTP-Hostname: client-hostname
X-CSTP-Address: 10.0.0.2           # Assigned IP
X-CSTP-Netmask: 255.255.255.0
X-CSTP-DNS: 8.8.8.8                # DNS servers (multiple allowed)
X-CSTP-Split-Include: 10.0.0.0/8   # Split tunnel routes
X-CSTP-Split-Exclude: 192.168.0.0/16
X-CSTP-Split-DNS: corp.example.com  # Split DNS domains
X-CSTP-MTU: 1406
X-CSTP-DPD: 30                     # DPD interval (seconds)
X-CSTP-Keepalive: 20               # Keepalive interval
X-CSTP-Base-MTU: 1500
X-CSTP-Banner: "Welcome to VPN"    # Banner message
X-DTLS-Session-ID: <hex>           # DTLS bootstrap params
X-DTLS-Master-Secret: <hex>
X-DTLS-CipherSuite: AES256-GCM-SHA384
```

### DTLS Session Bootstrap

DTLS uses session parameters from CSTP headers — NO separate TLS handshake:

```c
typedef struct {
    uint8_t session_id[32];
    uint8_t master_secret[48];   // MUST be zeroed after DTLS setup
    char cipher_suite[64];
} rw_dtls_params_t;
```

## Authentication (AggAuth Protocol)

### XML Authentication Exchange

Cisco uses Aggregate Authentication (AggAuth) XML protocol. Content-Type MUST be `text/xml`.

```xml
<!-- Client auth request -->
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <version who="vpn">5.0</version>
  <device-id>linux-64</device-id>
  <group-select>default</group-select>
  <auth>
    <username>user</username>
    <password>pass</password>
  </auth>
</config-auth>

<!-- Server success response -->
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
  <session-token>COOKIE_VALUE</session-token>
  <auth id="success" message="Login successful"/>
</config-auth>
```

### Multi-Factor Authentication (MFA/TOTP)

Server can challenge with secondary password (TOTP code):

```xml
<!-- Server challenge for TOTP -->
<config-auth client="vpn" type="auth-request">
  <auth id="main">
    <message>Enter verification code:</message>
    <form method="post">
      <input type="text" name="secondary_password" label="Verification Code:"/>
    </form>
  </auth>
</config-auth>
```

### Authentication Methods (ringwall)

| Method | Library | Config |
|--------|---------|--------|
| Local password | built-in | `auth = plain[passwd=/etc/ringwall/passwd]` |
| PAM | libpam | `auth = pam` |
| RADIUS | radcli | `auth = radius[config=/etc/ringwall/radius.conf]` |
| LDAP | libldap | `auth = ldap[config=/etc/ringwall/ldap.conf]` |
| TOTP/HOTP | liboath | Secondary password, RFC 6238/4226 |
| Certificate | wolfSSL | `auth = certificate` |

### RADIUS IP Assignment

RADIUS can assign static IPs via Framed-IP-Address (attribute 8):

```c
#define RADIUS_FRAMED_IP_ADDRESS    8
#define RADIUS_FRAMED_IP_NETMASK    9
// Access-Accept with attribute 8 → server assigns that IP to client
```

## DPD (Dead Peer Detection)

### DPD Behavior

- **Default interval**: 30 seconds, bidirectional
- **During establishment**: 3 missed retries → failover to backup server
- **Post-establishment**: Client enters "Waiting to Resume" (tunnels drop, Parent-Tunnel persists)
- **Keepalive**: 20 seconds (MANDATORY for stateful failover)

### DPD Packet Format

```c
typedef struct {
    uint8_t type;           // 0x03 = DPD-REQ, 0x04 = DPD-RESP
    uint8_t reserved;
    uint16_t sequence;      // Incremental sequence number
    uint32_t timestamp;     // Milliseconds since connection
} cstp_dpd_header_t;
```

### Timer State Machine

```
CONNECTED → [DPD timeout] → WAITING_TO_RESUME → [reconnect] → CONNECTED
                                                → [disconnect timeout] → DISCONNECTED
```

## Split DNS

### Three DNS Modes

1. **Split DNS**: Domain-based routing (matching → tunnel DNS, else → local)
2. **Tunnel-All-DNS**: All DNS through tunnel
3. **Standard**: Tunnel DNS as primary

### Decision Algorithm

```c
for each DNS query:
  if (config->tunnel_all) → route to tunnel DNS
  else if (domain matches split-dns list) → route to tunnel DNS
  else → route to local DNS (or refuse)
```

## Crypto: Cipher Suite Priority (from Cisco binary analysis)

### TLS 1.3
```
TLS_AES_256_GCM_SHA384 > TLS_AES_128_GCM_SHA256 > TLS_CHACHA20_POLY1305_SHA256
```

### TLS 1.2 (Cisco exact order)
```
ECDHE-RSA-AES256-GCM-SHA384 > ECDHE-ECDSA-AES256-GCM-SHA384 >
ECDHE-RSA-AES128-GCM-SHA256 > ECDHE-ECDSA-AES128-GCM-SHA256 >
DHE-RSA-AES256-GCM-SHA384 > AES256-GCM-SHA384 > AES128-GCM-SHA256
```

### DTLS 1.2 (more conservative, no ECDHE)
```
DHE-RSA-AES256-GCM-SHA384 > DHE-RSA-AES128-GCM-SHA256 >
AES256-SHA > AES128-SHA
```

### Signature Algorithms
```
ECDSA+SHA256 > ECDSA+SHA384 > RSA-PSS+SHA256 > RSA-PSS+SHA384 > RSA+SHA256
```

### Elliptic Curves (priority)
```
X25519 > secp256r1 (P-256) > secp384r1 (P-384) > secp521r1 (P-521)
```

## Packet Format

### CSTP Packet (over TLS)

```
+-------+-------+-------+-------+
| Type  |  Len (24-bit)         |
+-------+-------+-------+-------+
|           Payload             |
+-------------------------------+
```

| Type | Value | Description |
|------|-------|-------------|
| DATA | 0x00 | VPN data (IP packet) |
| DPD-REQ | 0x03 | Dead Peer Detection request |
| DPD-RESP | 0x04 | Dead Peer Detection response |
| DISCONNECT | 0x05 | Disconnect notification |
| KEEPALIVE | 0x07 | Keepalive packet |
| COMPRESSED | 0x08 | LZ4-compressed data |

### DTLS Packet
Raw VPN data (IP packets) without additional framing.
MTU: `link_MTU - IP_hdr(20/40) - UDP_hdr(8) - DTLS_overhead(~29-37)`

## Cisco Compatibility Checklist

- [ ] TLS 1.2+ on port 443 (TLS 1.3 preferred)
- [ ] DTLS 1.2 for data channel (Cisco doesn't support DTLS 1.3)
- [ ] Content-Type: `text/xml` (NOT `application/xml`)
- [ ] AggAuth XML protocol for authentication
- [ ] Cookie-based session management (URL-safe base64)
- [ ] X-CSTP-* and X-DTLS-* headers (exact names)
- [ ] DPD support (bidirectional, 30s default)
- [ ] Keepalive support (20s recommended)
- [ ] Session reconnection via Parent-Tunnel cookie
- [ ] Banner message support
- [ ] Split tunnel/DNS configuration via headers
- [ ] Accept and ignore CSD (posture assessment) headers
- [ ] Accept `X-Aggregate-Auth: 1` header
- [ ] MTU discovery via DPD probing
- [ ] NVM telemetry support (IPFIX on port 2055, optional)
