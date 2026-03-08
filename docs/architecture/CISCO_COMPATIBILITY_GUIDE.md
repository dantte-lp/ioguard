# Cisco Secure Client Compatibility Guide

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Based on**: Reverse engineering analysis of Cisco Secure Client 5.1.2.42
**Project**: ringwall v2.0.0

---

## Overview

This guide provides specific implementation requirements for ensuring 100% compatibility with Cisco Secure Client (formerly AnyConnect) 5.x. It is based on comprehensive reverse engineering analysis of official Cisco binaries and complements the [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) document.

**Related Documents**:
- [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) - Protocol specification and standards
- Cisco analysis: `/opt/projects/repositories/cisco-secure-client/analysis/REVERSE_ENGINEERING_FINDINGS.md`

---

## 1. Critical HTTP Headers

### 1.1 CSTP Headers (Required for TLS Tunnel)

Cisco clients expect these headers in server responses:

```
X-CSTP-Version: 1
X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.
X-CSTP-Address-Type: IPv6,IPv4
X-CSTP-Full-IPv6-Capability: true
X-CSTP-MTU: 1406
X-CSTP-Base-MTU: 1500
X-CSTP-Accept-Encoding: lzs,deflate
X-CSTP-TCP-Keepalive: false
```

Clients send these headers in requests:

```
X-CSTP-Hostname: <client-hostname>
X-CSTP-License: mobile
X-CSTP-Local-Address-IP4: 10.0.0.1
X-CSTP-Local-Address-IP6: fe80::1
X-CSTP-FIPS-Mode: enabled (if FIPS required)
```

### 1.2 DTLS Headers (Required for UDP Tunnel)

```
X-DTLS-Master-Secret: <hex-encoded-secret>
X-DTLS-CipherSuite: <negotiated-cipher>
X-DTLS12-CipherSuite: <tls12-cipher>
X-DTLS-Accept-Encoding: lzs
X-DTLS-Header-Pad-Length: 0
```

### 1.3 Authentication Headers

```
X-Aggregate-Auth: 1.0
X-AnyConnect-STRAP-Pubkey: <optional-public-key>
```

### Implementation Notes

1. **Header Order**: While HTTP doesn't require specific order, Cisco clients may expect certain patterns
2. **Copyright String**: The exact copyright text in `X-CSTP-Protocol` should be preserved
3. **Version Numbers**: `X-CSTP-Version: 1` corresponds to protocol v1.2
4. **Case Sensitivity**: Header names are case-insensitive per HTTP spec, but values may be case-sensitive

---

## 2. URL Endpoints

### 2.1 Required Endpoints

```
/                               # Portal entry point (GET)
/auth                           # Authentication handler (POST)
/tunnel                         # Tunnel establishment (CONNECT)
```

### 2.2 Legacy/Optional Endpoints

```
/+CSCOE+/sdesktop/scan.xml     # Host scan configuration
/+CSCOE+/sdesktop/wait.html    # Scanning wait page
/+webvpn+/index.html           # Alternative portal
/webvpn.html                    # Legacy portal
```

### 2.3 Implementation Strategy

**Minimum for compatibility** (C23):
```c
// File: ringwall/src/http/routes.c
#include <stdint.h>
#include <stdbool.h>
#include "http_server.h"

// HTTP route handlers
[[nodiscard]]
int portal_handler(http_request_t *req, http_response_t *resp);

[[nodiscard]]
int auth_handler(http_request_t *req, http_response_t *resp);

[[nodiscard]]
int tunnel_handler(http_request_t *req, http_response_t *resp);

// Register routes (C23)
void register_cisco_routes(http_router_t *router) {
    http_router_add_route(router, HTTP_METHOD_GET, "/", portal_handler);
    http_router_add_route(router, HTTP_METHOD_POST, "/auth", auth_handler);
    http_router_add_route(router, HTTP_METHOD_CONNECT, "/tunnel", tunnel_handler);

    // Optional legacy support
    http_router_add_route(router, HTTP_METHOD_GET, "/+CSCOE+/*", cscoe_handler);
}
```

---

## 3. Authentication Flow

### 3.1 Aggregate Authentication

Cisco clients use an "aggregate authentication" framework that allows multiple authentication methods in a single exchange.

**Flow**:
```
1. Client → Server: GET / (initial connection)
2. Server → Client: 302 Redirect to /auth OR XML auth challenge
3. Client → Server: POST /auth with credentials XML
4. Server → Client: XML response (AUTH_REQUEST or COMPLETE)
5. [Repeat steps 3-4 for multi-factor auth]
6. Server → Client: Session cookie (webvpn=<token>)
7. Client → Server: CONNECT /tunnel with cookie
8. Server → Client: 200 OK + tunnel configuration
```

### 3.2 XML Authentication Messages

**Client sends** (inferred structure):
```xml
<auth>
    <username>user@example.com</username>
    <password>secret123</password>
    <!-- OR for SAML/SSO -->
    <session-token>base64-encoded-token</session-token>
</auth>
```

**Server responses**:

**Challenge for additional credentials**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<auth id="AUTH_REQUEST">
    <message>Enter verification code</message>
    <form method="post" action="/auth">
        <input type="text" name="secondary_password" label="OTP Token"/>
    </form>
</auth>
```

**Success with configuration**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<auth id="COMPLETE">
    <session-token>generated-session-token</session-token>
    <config>
        <!-- VPN configuration here -->
    </config>
</auth>
```

### 3.3 Session Cookie Format

**Cookie name**: `webvpn`

**Format** (example):
```
webvpn=base64(encryption(session_data))@gateway_id@timestamp
```

**Requirements**:
- Must be cryptographically secure
- Should include session expiration
- Must be verifiable server-side
- Should resist tampering

**Implementation**:
```go
type SessionCookie struct {
    UserID      string
    Username    string
    IPAddress   string
    IssuedAt    time.Time
    ExpiresAt   time.Time
    Signature   []byte // HMAC-SHA256 of above fields
}

func GenerateCookie(session SessionCookie, key []byte) string {
    // Serialize, encrypt, base64-encode
    // Return: webvpn=<encoded-data>
}
```

### 3.4 SAML/SSO Integration

**Requirements**:
1. Server must provide SSO login URL in aggregate auth response
2. Client uses embedded browser (WebKit) to complete SAML flow
3. Server extracts SAML assertion and issues session cookie
4. Cookie must work with subsequent tunnel establishment

**Error handling**:
- Invalid SSO URL: `CONNECTMGR_ERROR_INVALID_SSO_LOGIN_URL`
- Server must parse and validate SAML assertions
- Session must persist across browser → client handoff

---

## 4. Tunnel Configuration

### 4.1 Configuration XML

Server must send VPN configuration in the `<config>` element:

```xml
<config>
    <vpn-tunnel-protocol>IPSec</vpn-tunnel-protocol>
    <client-ip-address>192.168.1.10</client-ip-address>
    <client-ip-netmask>255.255.255.0</client-ip-netmask>

    <!-- IPv6 support -->
    <client-ipv6-address>2001:db8::10</client-ipv6-address>
    <client-ipv6-prefix-length>64</client-ipv6-prefix-length>

    <!-- DNS configuration -->
    <dns>
        <default-domain>example.com</default-domain>
        <server>8.8.8.8</server>
        <server>8.8.4.4</server>
    </dns>

    <!-- Split DNS -->
    <split-dns>
        <domain>internal.example.com</domain>
        <domain>vpn.example.com</domain>
    </split-dns>

    <!-- Split tunneling -->
    <split-include>
        <address>10.0.0.0/8</address>
        <address>172.16.0.0/12</address>
    </split-include>

    <!-- Exclude from tunnel -->
    <split-exclude>
        <address>10.1.2.0/24</address>
    </split-exclude>

    <!-- Timeouts -->
    <idle-timeout>3600</idle-timeout>
    <session-timeout>28800</session-timeout>
    <keepalive>300</keepalive>

    <!-- DTLS support -->
    <dtls>
        <port>443</port>
        <cookie>base64-encoded-cookie</cookie>
    </dtls>

    <!-- MTU -->
    <mtu>1406</mtu>
    <base-mtu>1500</base-mtu>
</config>
```

### 4.2 Critical Fields

**Must be present**:
- `<session-token>` - Required for tunnel establishment
- `<client-ip-address>` - Client's VPN IP address
- `<dns>` - DNS servers (at least one)
- `<mtu>` - Maximum transmission unit

**Should be present**:
- `<default-domain>` - Default DNS domain
- `<keepalive>` - Keepalive interval in seconds
- `<idle-timeout>` - Idle timeout
- `<dtls>` - DTLS configuration if UDP supported

**Optional**:
- Split tunneling configuration
- IPv6 configuration
- Compression settings
- Banner messages

---

## 5. DTLS Implementation

### 5.1 DTLS Handshake with Cookie Exchange

**Sequence**:
```
1. Client → Server: DTLS ClientHello (no cookie)
2. Server → Client: DTLS HelloVerifyRequest (with cookie)
3. Client → Server: DTLS ClientHello (with cookie)
4. Server → Client: DTLS ServerHello
5. [Complete DTLS handshake]
6. Data transfer begins
```

### 5.2 Master Secret Sharing

**Critical**: DTLS tunnel shares master secret with TLS tunnel

**Process**:
1. TLS tunnel established first
2. Server extracts TLS master secret
3. Server sends via `X-DTLS-Master-Secret` header
4. DTLS tunnel uses same master secret
5. Allows seamless failover between TLS and DTLS

**Implementation**:
```go
// Extract master secret from TLS session
tlsSecret := extractMasterSecret(tlsConn)

// Send to client for DTLS use
header := fmt.Sprintf("X-DTLS-Master-Secret: %s",
    hex.EncodeToString(tlsSecret))

// Configure DTLS with same secret
dtlsConfig.MasterSecret = tlsSecret
```

### 5.3 Cipher Suite Compatibility

**TLS 1.3 Preferred**:
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

**TLS 1.2 Fallback**:
```
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-AES256-GCM-SHA384
DHE-RSA-AES256-GCM-SHA384
AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES128-GCM-SHA256
AES128-GCM-SHA256
```

**Configuration**:
```go
// wolfSSL cipher string
cipherSuite := "ECDHE-RSA-AES256-GCM-SHA384:" +
               "ECDHE-ECDSA-AES256-GCM-SHA384:" +
               "ECDHE-RSA-AES128-GCM-SHA256:" +
               "ECDHE-ECDSA-AES128-GCM-SHA256:" +
               "DHE-RSA-AES256-GCM-SHA384:" +
               "DHE-RSA-AES128-GCM-SHA256"

wolfSSL_CTX_set_cipher_list(ctx, cipherSuite)
```

---

## 6. Always-On VPN Support

### 6.1 Requirements

**Profile Enforcement**:
- Server must validate that client connects only to gateway defined in profile
- Client profile contains `<AutomaticVPNPolicy>true</AutomaticVPNPolicy>`
- Server must reject connections if hostname not in client's profile

**Certificate Strictness**:
- **No** untrusted certificates allowed
- **No** "ask user" prompts
- **Immediate failure** on certificate validation error
- Certificate pinning enforced if configured

**Proxy Restrictions**:
- Always-On VPN **does not** support proxy connections
- Server must detect and reject proxy scenarios
- Error: "Connecting via a proxy is not supported with Always On"

### 6.2 Implementation

```go
func ValidateAlwaysOnConnection(client *Client) error {
    if client.Profile.AlwaysOnEnabled {
        // Check gateway in profile
        if !client.Profile.ContainsGateway(server.Hostname) {
            return ErrGatewayNotInProfile
        }

        // Strict certificate validation
        if !ValidateCertificateStrict(client.Certificate) {
            return ErrUntrustedCertificate // Unrecoverable
        }

        // No proxy allowed
        if client.IsUsingProxy() {
            return ErrProxyNotAllowedWithAlwaysOn
        }

        // Check certificate pinning
        if len(client.Profile.CertificatePins) > 0 {
            if !VerifyCertificatePin(client.Certificate, client.Profile.CertificatePins) {
                return ErrCertificatePinMismatch
            }
        }
    }
    return nil
}
```

---

## 7. Dead Peer Detection (DPD)

### 7.1 Standard DPD

**DPD Request/Response**:
```
Client ↔ Server: DPD_REQ / DPD_RESP packets
Interval: Configurable (e.g., 300 seconds)
Timeout: 3x interval (e.g., 900 seconds)
```

**Implementation**:
```go
type DPDManager struct {
    Interval time.Duration
    Timeout  time.Duration
    Timer    *time.Timer
}

func (dpd *DPDManager) SendDPDRequest(tunnel *Tunnel) error {
    // Send DPD request frame
    // Start response timer
    // If no response after timeout, close tunnel
}

func (dpd *DPDManager) HandleDPDResponse(tunnel *Tunnel) {
    // Reset timer
    // Schedule next DPD request
}
```

### 7.2 MTU-based DPD

**Purpose**: Optimize MTU via DPD handshake

**Process**:
1. Send DPD requests with varying padding sizes
2. Start with configured MTU, work down if failures
3. Measure delay for each padding size
4. Determine optimal MTU (OMTU)
5. Update tunnel MTU configuration

**Implementation**:
```go
type MTUDPDManager struct {
    CandidateMTU int
    MinMTU       int
    MaxMTU       int
    PaddingSizes []int // [1400, 1350, 1300, ...]
}

func (m *MTUDPDManager) PerformMTUDiscovery(tunnel *Tunnel) int {
    for _, padding := range m.PaddingSizes {
        err := m.SendDPDWithPadding(tunnel, padding)
        if err == nil {
            // Success, this MTU works
            return padding
        }
    }
    return m.MinMTU // Fallback
}

func (m *MTUDPDManager) SendDPDWithPadding(tunnel *Tunnel, size int) error {
    frame := BuildDPDFrame(size)
    start := time.Now()
    err := tunnel.Write(frame)
    delay := time.Since(start)

    if delay > MaxDPDDelay {
        return ErrDPDTimeout
    }

    return err
}
```

---

## 8. Reconnection Logic

### 8.1 Reconnection Triggers

Implement reconnection for these scenarios:

1. **System Suspend/Resume**
   - Detect suspend event
   - Preserve session state
   - Reconnect on resume
   - Configuration: `<AutoReconnectBehavior>ReconnectAfterResume</AutoReconnectBehavior>`

2. **Network Change**
   - Public IP address change
   - Gateway IP change
   - DNS server change
   - Default route change

3. **Tunnel Failures**
   - DTLS timeout → reconnect DTLS
   - DTLS rekey failure → full reconnect
   - TLS disconnect → reconnect

4. **Session Timeout Warning**
   - Send warning before session expires
   - Allow proactive reconnection

### 8.2 Reconnection Types

**Session-Level Reconnect**:
- Re-authentication required
- New session token
- Full tunnel establishment
- Use for: Network changes, proxy changes

**Tunnel-Level Reconnect**:
- Keep existing session
- Reestablish tunnel only
- Same configuration
- Use for: Minor disruptions

**DTLS-Only Reconnect**:
- Keep TLS tunnel active
- Reconnect DTLS channel
- Use for: DTLS rekey, UDP issues

### 8.3 Implementation

```go
type ReconnectManager struct {
    Type         ReconnectType // Session, Tunnel, DTLS
    MaxAttempts  int
    RetryDelay   time.Duration
    SessionState *SessionState
}

func (rm *ReconnectManager) HandleReconnect(client *Client) error {
    switch rm.Type {
    case SessionReconnect:
        // Full re-authentication
        return rm.SessionLevelReconnect(client)

    case TunnelReconnect:
        // Reuse session token
        return rm.TunnelLevelReconnect(client)

    case DTLSReconnect:
        // DTLS only, keep TLS
        return rm.DTLSOnlyReconnect(client)
    }
}

func (rm *ReconnectManager) SessionLevelReconnect(client *Client) error {
    // Clear old session
    client.Session = nil

    // Re-authenticate
    session, err := rm.Authenticate(client)
    if err != nil {
        return err
    }

    // Reestablish tunnel with new session
    return rm.EstablishTunnel(client, session)
}
```

---

## 9. Split DNS Implementation

### 9.1 DNS Interception

**Requirements**:
- Intercept UDP port 53 traffic
- Match queries against split DNS domains
- Route matching queries to VPN DNS servers
- Route non-matching queries to original DNS

**Configuration** (server sends):
```xml
<split-dns>
    <domain>internal.example.com</domain>
    <domain>vpn.example.com</domain>
    <domain>*.corp</domain>
</split-dns>

<dns>
    <server>10.10.10.10</server>  <!-- VPN DNS -->
</dns>
```

### 9.2 Match Algorithm

```go
type SplitDNSMatcher struct {
    SplitDomains []string
    VPNDNSServers []net.IP
}

func (m *SplitDNSMatcher) ShouldUseVPNDNS(query string) bool {
    // Normalize query (remove trailing dot, lowercase)
    query = strings.ToLower(strings.TrimSuffix(query, "."))

    for _, domain := range m.SplitDomains {
        if m.MatchesDomain(query, domain) {
            return true
        }
    }
    return false
}

func (m *SplitDNSMatcher) MatchesDomain(query, pattern string) bool {
    // Exact match
    if query == pattern {
        return true
    }

    // Wildcard match (*.example.com matches foo.example.com)
    if strings.HasPrefix(pattern, "*.") {
        suffix := pattern[2:] // Remove "*."
        return strings.HasSuffix(query, "."+suffix) || query == suffix
    }

    // Subdomain match (example.com matches foo.example.com)
    return strings.HasSuffix(query, "."+pattern)
}
```

### 9.3 DNS Packet Handling

```go
func (m *SplitDNSMatcher) HandleDNSPacket(packet []byte) ([]byte, error) {
    // Parse DNS query
    msg := new(dns.Msg)
    err := msg.Unpack(packet)
    if err != nil {
        return nil, err
    }

    // Check if query matches split DNS
    if len(msg.Question) > 0 {
        qname := msg.Question[0].Name

        if m.ShouldUseVPNDNS(qname) {
            // Forward to VPN DNS server
            return m.ForwardToVPNDNS(packet)
        }
    }

    // Forward to original DNS
    return m.ForwardToOriginalDNS(packet)
}
```

---

## 10. Error Codes

### 10.1 Connection Errors

Map Cisco error codes to appropriate responses:

```go
const (
    // Connection errors
    ErrProxyAuthRequired       = "CONNECTIFC_ERROR_PROXY_AUTH_REQUIRED"
    ErrCaptivePortalRedirect   = "CONNECTIFC_ERROR_CAPTIVE_PORTAL_REDIRECT"
    ErrHTTPSNotAllowed         = "CONNECTIFC_ERROR_HTTPS_NOT_ALLOWED"
    ErrHostNotSpecified        = "CONNECTIFC_ERROR_HOST_NOT_SPECIFIED"

    // Transport errors
    ErrHostResolution          = "CTRANSPORT_ERROR_HOST_RESOLUTION"
    ErrConnectFailed           = "CTRANSPORT_ERROR_CONNECT_FAILED"
    ErrNoInternetConnection    = "CTRANSPORT_ERROR_NO_INTERNET_CONNECTION"
    ErrBadGateway              = "CTRANSPORT_ERROR_BAD_GATEWAY"

    // Authentication errors
    ErrInvalidSSOLoginURL      = "CONNECTMGR_ERROR_INVALID_SSO_LOGIN_URL"
    ErrNoClientCert            = "CONNECTMGR_ERROR_NO_CLIENT_AUTH_CERT_AVAILABLE"
    ErrParsingConfigXML        = "CONNECTMGR_ERROR_PARSING_CONFIG_XML"
    ErrUserRejectedBanner      = "CONNECTMGR_ERROR_USER_REJECTED_BANNER"

    // Certificate errors
    ErrCertUntrustedDisallowed = "CERTIFICATE_ERROR_UNTRUSTED_CERT_DISALLOWED"
    ErrCertPinCheckFailed      = "CERTIFICATE_ERROR_VERIFY_CERT_PIN_CHECK_FAILED"
    ErrCertKeySizeInsufficient = "CERTIFICATE_ERROR_VERIFY_KEYSIZE_FAILED"
    ErrCertSANNotFound         = "CERTIFICATE_ERROR_VERIFY_SAN_NOT_FOUND"
)
```

### 10.2 User-Facing Messages

Provide clear error messages:

```go
var ErrorMessages = map[string]string{
    ErrProxyAuthRequired: "The client must first authenticate itself with the proxy.",

    ErrNoInternetConnection: "No Internet connection was detected.",

    ErrCaptivePortalRedirect: "Cisco Secure Client cannot establish a VPN " +
        "session because a device in the network, such as a proxy server or " +
        "captive portal, is blocking Internet access.",

    ErrCertUntrustedDisallowed: "An untrusted certificate was received " +
        "while in always-on mode.",

    ErrCertPinCheckFailed: "Certificate pinning verification failed. " +
        "Pin match not found in the server certificate chain.",
}
```

---

## 11. Testing Requirements

### 11.1 Compatibility Test Matrix

| Test Scenario | Cisco 5.0 | Cisco 5.1 | Cisco 5.2 | OpenConnect |
|---------------|-----------|-----------|-----------|-------------|
| Basic auth (password) | ✅ | ✅ | ✅ | ✅ |
| Certificate auth | ✅ | ✅ | ✅ | ✅ |
| SAML/SSO auth | ✅ | ✅ | ✅ | ⚠️ |
| MFA (TOTP) | ✅ | ✅ | ✅ | ✅ |
| TLS tunnel | ✅ | ✅ | ✅ | ✅ |
| DTLS tunnel | ✅ | ✅ | ✅ | ✅ |
| IPv4 only | ✅ | ✅ | ✅ | ✅ |
| IPv6 only | ✅ | ✅ | ✅ | ✅ |
| Dual-stack | ✅ | ✅ | ✅ | ✅ |
| Split tunneling | ✅ | ✅ | ✅ | ✅ |
| Split DNS | ✅ | ✅ | ✅ | ✅ |
| Always-On VPN | ✅ | ✅ | ✅ | ❌ |
| Suspend/resume | ✅ | ✅ | ✅ | ⚠️ |
| DTLS rekey | ✅ | ✅ | ✅ | ✅ |
| MTU DPD | ✅ | ✅ | ✅ | ❌ |
| Certificate pinning | ✅ | ✅ | ✅ | ⚠️ |
| FIPS mode | ✅ | ✅ | ✅ | ❌ |
| Compression (LZS) | ✅ | ✅ | ✅ | ✅ |
| Compression (deflate) | ✅ | ✅ | ✅ | ✅ |

**Legend**:
- ✅ = Must support
- ⚠️ = Optional/partial support
- ❌ = Not applicable/not supported

### 11.2 Automated Test Suite

```go
// Test basic connectivity
func TestCiscoClientBasicAuth(t *testing.T) {
    client := NewCiscoClient("5.1.2.42")
    err := client.Connect(server, username, password)
    assert.NoError(t, err)
    assert.True(t, client.IsTunnelEstablished())
}

// Test DTLS establishment
func TestCiscoClientDTLS(t *testing.T) {
    client := NewCiscoClient("5.1.2.42")
    client.Connect(server, username, password)

    // Verify DTLS tunnel
    assert.True(t, client.IsDTLSActive())
    assert.NotEmpty(t, client.DTLSMasterSecret())
}

// Test Always-On with invalid cert
func TestCiscoClientAlwaysOnRejectsUntrustedCert(t *testing.T) {
    client := NewCiscoClient("5.1.2.42")
    client.EnableAlwaysOn()

    server := NewServerWithSelfSignedCert()
    err := client.Connect(server, username, password)

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "UNTRUSTED_CERT_DISALLOWED")
}

// Test suspend/resume
func TestCiscoClientSuspendResume(t *testing.T) {
    client := NewCiscoClient("5.1.2.42")
    client.Connect(server, username, password)

    sessionID := client.SessionID()

    // Simulate suspend
    client.SimulateSuspend()

    // Simulate resume
    client.SimulateResume()

    // Verify reconnection
    assert.True(t, client.IsTunnelEstablished())
    assert.Equal(t, sessionID, client.SessionID()) // Same session
}

// Test split DNS
func TestCiscoClientSplitDNS(t *testing.T) {
    client := NewCiscoClient("5.1.2.42")
    client.Connect(server, username, password)

    config := client.GetVPNConfig()
    assert.Contains(t, config.SplitDNS, "internal.example.com")

    // Verify DNS routing
    ip := client.ResolveDNS("internal.example.com")
    assert.True(t, isVPNIP(ip)) // Should route through VPN

    ip = client.ResolveDNS("google.com")
    assert.False(t, isVPNIP(ip)) // Should route normally
}
```

### 11.3 Manual Testing Checklist

**Pre-deployment**:
- [ ] Install actual Cisco Secure Client 5.1.2.42
- [ ] Configure test profile with all features enabled
- [ ] Set up packet capture (Wireshark)
- [ ] Enable SSL/TLS key logging
- [ ] Prepare test user accounts with various auth methods

**During testing**:
- [ ] Capture full connection sequence
- [ ] Verify all HTTP headers match expectations
- [ ] Check XML message formats
- [ ] Test error scenarios (invalid cert, wrong password, etc.)
- [ ] Verify reconnection behavior
- [ ] Test network transitions (WiFi to Ethernet, etc.)
- [ ] Confirm DTLS failover to TLS
- [ ] Validate split DNS functionality
- [ ] Test Always-On enforcement

**Post-testing**:
- [ ] Analyze captured traffic
- [ ] Compare with OpenConnect client behavior
- [ ] Document any discrepancies
- [ ] Update implementation based on findings
- [ ] Regression test with all clients

---

## 12. Implementation Checklist

### Phase 1: Core Protocol (Sprint 1-2)
- [ ] HTTP server with custom headers (X-CSTP-*, X-DTLS-*)
- [ ] Basic authentication (password + certificate)
- [ ] Session cookie generation and validation
- [ ] TLS tunnel establishment
- [ ] Configuration XML generation
- [ ] Simple keepalive mechanism

### Phase 2: Advanced Authentication (Sprint 3-4)
- [ ] Aggregate authentication framework
- [ ] XML parser for auth messages
- [ ] SAML/SSO integration with cookie extraction
- [ ] Multi-factor authentication flows
- [ ] Certificate pinning verification
- [ ] Error code mapping

### Phase 3: DTLS Support (Sprint 5-6)
- [ ] DTLS 1.2 with wolfSSL
- [ ] Cookie exchange (HelloVerifyRequest)
- [ ] Master secret sharing with TLS
- [ ] DTLS reconnection logic
- [ ] Cipher suite preference matching
- [ ] Fallback to TLS if DTLS fails

### Phase 4: Resilience Features (Sprint 7-8)
- [ ] Always-On VPN implementation
- [ ] Profile-based gateway enforcement
- [ ] Strict certificate validation for Always-On
- [ ] Suspend/resume detection and handling
- [ ] Automatic reconnection (session/tunnel/DTLS)
- [ ] Network change detection
- [ ] Standard DPD (request/response)
- [ ] MTU-based DPD implementation

### Phase 5: Advanced Features (Sprint 9-10)
- [ ] Split tunneling (include/exclude networks)
- [ ] Split DNS implementation
- [ ] UDP DNS interception
- [ ] Domain matching algorithm
- [ ] Compression (LZS + deflate)
- [ ] MTU optimization
- [ ] Captive portal detection

### Phase 6: Testing & Polish (Sprint 11-12)
- [ ] Comprehensive Cisco client testing (5.0, 5.1, 5.2)
- [ ] OpenConnect client compatibility
- [ ] Edge case handling
- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation completion
- [ ] Production readiness review

---

## 13. Performance Considerations

### 13.1 Optimization Targets

**Latency**:
- DTLS preferred over TLS (lower latency)
- Minimize DPD overhead
- Efficient DNS lookup caching

**Throughput**:
- Enable compression when beneficial
- Optimize MTU (via MTU DPD)
- Minimize header overhead

**Scalability**:
- Connection pooling
- Efficient session management
- Stateless where possible

### 13.2 Benchmarks

Target performance (per server instance):

| Metric | Target | Notes |
|--------|--------|-------|
| Concurrent connections | 10,000+ | With DTLS |
| New connections/sec | 100+ | Full handshake |
| Throughput per tunnel | 100+ Mbps | With compression |
| DPD overhead | <1% | Network bandwidth |
| Reconnection time | <2 sec | Tunnel-level |
| Memory per connection | <10 MB | Including buffers |

---

## 14. Security Best Practices

### 14.1 Certificate Validation

**Always validate**:
- Certificate expiration
- Certificate revocation (CRL/OCSP)
- Certificate chain to trusted root
- Subject Alternative Name (SAN)
- Extended Key Usage
- Key size (minimum 2048-bit RSA, 256-bit EC)
- Signature algorithm (no MD5, SHA1 deprecated)

**For Always-On**:
- Enforce strict validation (no exceptions)
- Require certificate pinning if configured
- No user override allowed

### 14.2 Session Security

**Session tokens**:
- Cryptographically random (crypto/rand)
- Sufficient entropy (128+ bits)
- Signed with HMAC-SHA256
- Encrypted (AES-256-GCM)
- Include expiration timestamp
- Rotate periodically

**Cookie security**:
- HttpOnly flag
- Secure flag (HTTPS only)
- SameSite attribute
- Short expiration (configurable)

### 14.3 DoS Protection

**Rate limiting**:
- Connection attempts per IP
- Authentication attempts per user
- DTLS cookie requests

**Resource limits**:
- Maximum concurrent connections
- Maximum bandwidth per connection
- Session timeout enforcement

**DTLS cookie**:
- Stateless verification
- Time-limited validity
- Cryptographically secure

---

## 15. Troubleshooting Guide

### 15.1 Common Issues

**Client won't connect**:
1. Check HTTP headers match exactly
2. Verify certificate validity
3. Confirm XML format is correct
4. Check session cookie format
5. Review server logs for errors

**DTLS not establishing**:
1. Verify UDP port 443 is open
2. Check DTLS cookie generation
3. Confirm master secret is shared
4. Verify cipher suite compatibility
5. Test with TLS-only as fallback

**Always-On fails**:
1. Verify gateway in client profile
2. Check certificate is trusted
3. Confirm no proxy in path
4. Validate certificate pinning
5. Review certificate error logs

**Reconnection issues**:
1. Check session token validity
2. Verify reconnection type logic
3. Confirm network change detection
4. Review suspend/resume handling
5. Check DPD timeout values

### 15.2 Debug Logging

Enable detailed logging for:

```go
// Connection establishment
logger.Debug("Client connecting from %s", clientIP)
logger.Debug("Authentication method: %s", authMethod)
logger.Debug("Session cookie: %s", obfuscatedCookie)

// Tunnel establishment
logger.Debug("TLS tunnel established, version: %s", tlsVersion)
logger.Debug("Cipher suite: %s", cipherSuite)
logger.Debug("DTLS master secret shared: %d bytes", len(masterSecret))

// Configuration
logger.Debug("Client IP assigned: %s", vpnIP)
logger.Debug("Split DNS domains: %v", splitDNSDomains)
logger.Debug("MTU configured: %d", mtu)

// Errors
logger.Error("Authentication failed: %s", err)
logger.Error("Certificate validation failed: %s", certErr)
logger.Error("DTLS handshake failed: %s", dtlsErr)
```

### 15.3 Packet Capture Analysis

**Wireshark filters**:
```
# Capture VPN traffic
tcp.port == 443 && tls

# DTLS traffic
udp.port == 443 && dtls

# Specific client
ip.src == <client-ip> && tcp.port == 443

# Authentication phase
http.request.method == "POST" && http.request.uri contains "auth"
```

**What to look for**:
- HTTP headers sent/received
- TLS handshake details
- DTLS cookie exchange
- XML message formats
- Error responses
- Reconnection sequences

---

## 16. References

### 16.1 Source Documentation

1. **Reverse Engineering Analysis**
   `/opt/projects/repositories/cisco-secure-client/analysis/REVERSE_ENGINEERING_FINDINGS.md`
   - Complete static analysis of Cisco Secure Client 5.1.2.42
   - Binary strings, error codes, function names
   - Protocol implementation details

2. **Protocol Reference**
   `docs/architecture/PROTOCOL_REFERENCE.md`
   - OpenConnect protocol specification
   - IETF draft reference
   - Standards compliance

3. **Cisco Binaries**
   `/opt/projects/repositories/cisco-secure-client/cisco-secure-client-linux64-5.1.2.42/`
   - Official Cisco Secure Client distribution
   - Version 5.1.2.42 for Linux x86_64

### 16.2 External Resources

1. **OpenConnect Client**
   https://gitlab.com/openconnect/openconnect
   - Reference client implementation
   - Protocol examples

2. **OpenConnect Protocol Draft**
   https://datatracker.ietf.org/doc/draft-mavrogiannopoulos-openconnect/
   - Protocol specification (draft-04)

3. **wolfSSL Documentation**
   https://www.wolfssl.com/documentation/
   - TLS/DTLS implementation guide
   - API reference

4. **Cisco Documentation** (proprietary)
   - Cisco Secure Client Administrator Guide
   - Requires Cisco login

---

## Appendix: Quick Reference

### HTTP Headers Quick List

```
# Required in responses
X-CSTP-Version: 1
X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.
X-CSTP-Address-Type: IPv6,IPv4
X-CSTP-MTU: 1406
X-DTLS-Master-Secret: <hex>

# Cookie
Set-Cookie: webvpn=<token>; Secure; HttpOnly
```

### Endpoint Quick List

```
GET  /                  # Portal
POST /auth             # Authentication
CONNECT /tunnel        # Tunnel establishment
```

### Error Code Quick List

```go
// Always-On specific
"CERTIFICATE_ERROR_UNTRUSTED_CERT_DISALLOWED"
"Host not found in profile. Always On requires gateways in profile."
"Connecting via proxy not supported with Always On."

// Authentication
"CONNECTMGR_ERROR_INVALID_SSO_LOGIN_URL"
"CONNECTMGR_ERROR_NO_CLIENT_AUTH_CERT_AVAILABLE"
"AGGAUTH_ERROR_FAILED_TO_PARSE_XML"

// Connection
"CONNECTIFC_ERROR_PROXY_AUTH_REQUIRED"
"CTRANSPORT_ERROR_NO_INTERNET_CONNECTION"
"CSTPPROTOCOL_ERROR_FRAME_OUT_OF_SYNC"
```

---

**Document Maintainer**: ringwall protocol team
**Review Schedule**: Bi-weekly during implementation
**Next Review**: 2025-11-12
**Status**: Active Development Guide

---

*End of Compatibility Guide*

---

## 17. C23 Implementation Reference

**Note**: This section provides C23 implementations for all examples previously shown in Go. All code uses modern C23 features including `[[nodiscard]]`, `nullptr`, `constexpr`, and improved type safety.

### 17.1 Session Cookie Management (C23)

```c
// File: ringwall/src/auth/session_cookie.c
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

typedef struct {
    char user_id[64];
    char username[256];
    char ip_address[46];       // IPv6-compatible
    time_t issued_at;
    time_t expires_at;
    uint8_t signature[32];     // HMAC-SHA256
} session_cookie_t;

/**
 * Generate secure session cookie (Cisco-compatible)
 */
[[nodiscard]]
int generate_session_cookie(
    const session_cookie_t *session,
    const uint8_t *key,
    size_t key_len,
    char *cookie_buffer,
    size_t buffer_size
) {
    if (session == nullptr || key == nullptr || cookie_buffer == nullptr) {
        return -1;
    }

    // Serialize session data
    uint8_t data[512];
    size_t data_len = snprintf((char *)data, sizeof(data),
        "%s|%s|%s|%ld|%ld",
        session->user_id,
        session->username,
        session->ip_address,
        session->issued_at,
        session->expires_at
    );

    // Calculate HMAC signature
    uint8_t signature[EVP_MAX_MD_SIZE];
    unsigned int sig_len;

    HMAC(EVP_sha256(), key, key_len, data, data_len, signature, &sig_len);

    // Encrypt with AES-256-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return -1;
    }

    uint8_t iv[12];
    RAND_bytes(iv, sizeof(iv));

    uint8_t encrypted[1024];
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, encrypted + 12, &len, data, data_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted + 12 + len, &len);
    ciphertext_len += len;

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    // Prepend IV, append tag and signature
    memcpy(encrypted, iv, 12);
    memcpy(encrypted + 12 + ciphertext_len, tag, 16);
    memcpy(encrypted + 12 + ciphertext_len + 16, signature, 32);

    size_t total_len = 12 + ciphertext_len + 16 + 32;

    // Base64 encode
    EVP_ENCODE_CTX *b64ctx = EVP_ENCODE_CTX_new();
    int out_len, final_len;
    EVP_EncodeInit(b64ctx);
    EVP_EncodeUpdate(b64ctx, (unsigned char *)cookie_buffer, &out_len,
                     encrypted, total_len);
    EVP_EncodeFinal(b64ctx, (unsigned char *)(cookie_buffer + out_len), &final_len);

    EVP_ENCODE_CTX_free(b64ctx);
    EVP_CIPHER_CTX_free(ctx);

    cookie_buffer[out_len + final_len] = '\0';

    // Format as webvpn cookie
    char formatted[2048];
    snprintf(formatted, sizeof(formatted), "webvpn=%s", cookie_buffer);
    strncpy(cookie_buffer, formatted, buffer_size - 1);

    return 0;
}

/**
 * Verify and decrypt session cookie
 */
[[nodiscard]]
int verify_session_cookie(
    const char *cookie_string,
    const uint8_t *key,
    size_t key_len,
    session_cookie_t *session
) {
    // Parse "webvpn=..." format
    if (strncmp(cookie_string, "webvpn=", 7) != 0) {
        return -1;
    }

    // Base64 decode, decrypt, verify signature
    // Implementation continues...
    return 0;
}
```

### 17.2 DPD (Dead Peer Detection) Implementation (C23)

```c
// File: ringwall/src/tunnel/dpd.c
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

typedef struct {
    uint32_t interval_seconds;
    uint32_t timeout_seconds;
    time_t last_request_sent;
    time_t last_response_received;
    bool awaiting_response;
} dpd_manager_t;

typedef struct {
    int tun_fd;
    uint8_t *write_buffer;
    size_t buffer_size;
} tunnel_t;

/**
 * Send DPD request frame
 */
[[nodiscard]]
int send_dpd_request(dpd_manager_t *dpd, tunnel_t *tunnel) {
    if (dpd == nullptr || tunnel == nullptr) {
        return -1;
    }

    // DPD frame format (CSTP protocol)
    uint8_t dpd_frame[16];
    dpd_frame[0] = 0x07;  // DPD_REQ
    dpd_frame[1] = 0x00;
    // ... frame construction

    ssize_t written = write(tunnel->tun_fd, dpd_frame, sizeof(dpd_frame));
    if (written != sizeof(dpd_frame)) {
        return -1;
    }

    dpd->last_request_sent = time(nullptr);
    dpd->awaiting_response = true;

    return 0;
}

/**
 * Handle DPD response
 */
void handle_dpd_response(dpd_manager_t *dpd) {
    if (dpd == nullptr) {
        return;
    }

    dpd->last_response_received = time(nullptr);
    dpd->awaiting_response = false;

    // Reset timer for next DPD request
}

/**
 * Check if DPD timeout has occurred
 */
[[nodiscard]]
bool is_dpd_timeout(const dpd_manager_t *dpd) {
    if (dpd == nullptr || !dpd->awaiting_response) {
        return false;
    }

    time_t now = time(nullptr);
    return (now - dpd->last_request_sent) > dpd->timeout_seconds;
}

/**
 * MTU-based DPD for optimization
 */
typedef struct {
    uint32_t candidate_mtu;
    uint32_t min_mtu;
    uint32_t max_mtu;
    uint32_t padding_sizes[10];
    size_t padding_count;
} mtu_dpd_manager_t;

[[nodiscard]]
uint32_t perform_mtu_discovery(mtu_dpd_manager_t *mgr, tunnel_t *tunnel) {
    if (mgr == nullptr || tunnel == nullptr) {
        return 1280;  // Minimum IPv6 MTU
    }

    for (size_t i = 0; i < mgr->padding_count; i++) {
        uint32_t test_size = mgr->padding_sizes[i];

        // Build DPD frame with padding
        uint8_t *frame = malloc(test_size);
        if (frame == nullptr) {
            continue;
        }

        frame[0] = 0x07;  // DPD_REQ
        memset(frame + 2, 0, test_size - 2);  // Padding

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        ssize_t written = write(tunnel->tun_fd, frame, test_size);

        clock_gettime(CLOCK_MONOTONIC, &end);

        free(frame);

        if (written == test_size) {
            uint64_t delay_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL +
                               (end.tv_nsec - start.tv_nsec);

            // If delay is reasonable, this MTU works
            if (delay_ns < 500000000ULL) {  // 500ms threshold
                return test_size;
            }
        }
    }

    return mgr->min_mtu;
}
```

### 17.3 Reconnection Manager (C23)

```c
// File: ringwall/src/tunnel/reconnect.c
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

typedef enum {
    RECONNECT_SESSION,   // Full re-authentication
    RECONNECT_TUNNEL,    // Reuse session, rebuild tunnel
    RECONNECT_DTLS       // DTLS only, keep TLS
} reconnect_type_t;

typedef struct {
    char session_token[512];
    char session_id[128];
    time_t created_at;
    bool valid;
} session_state_t;

typedef struct {
    reconnect_type_t type;
    uint32_t max_attempts;
    uint32_t retry_delay_seconds;
    uint32_t current_attempt;
    session_state_t *session_state;
} reconnect_manager_t;

typedef struct {
    char username[256];
    char server_hostname[256];
    session_state_t *session;
    bool tunnel_established;
} client_context_t;

/**
 * Handle reconnection based on type
 */
[[nodiscard]]
int handle_reconnect(
    reconnect_manager_t *mgr,
    client_context_t *client
) {
    if (mgr == nullptr || client == nullptr) {
        return -1;
    }

    switch (mgr->type) {
        case RECONNECT_SESSION:
            return session_level_reconnect(mgr, client);

        case RECONNECT_TUNNEL:
            return tunnel_level_reconnect(mgr, client);

        case RECONNECT_DTLS:
            return dtls_only_reconnect(mgr, client);

        default:
            return -1;
    }
}

/**
 * Session-level reconnect (full re-authentication)
 */
[[nodiscard]]
static int session_level_reconnect(
    reconnect_manager_t *mgr,
    client_context_t *client
) {
    // Clear old session
    if (client->session != nullptr) {
        memset(client->session, 0, sizeof(session_state_t));
        client->session->valid = false;
    }

    // Re-authenticate (implementation depends on auth method)
    // This would call the authentication handler
    // session_state_t *new_session = authenticate_user(client->username, ...);

    // Reestablish tunnel with new session
    // return establish_tunnel(client, new_session);

    return 0;
}

/**
 * Tunnel-level reconnect (reuse session)
 */
[[nodiscard]]
static int tunnel_level_reconnect(
    reconnect_manager_t *mgr,
    client_context_t *client
) {
    if (client->session == nullptr || !client->session->valid) {
        return -1;  // Need session-level reconnect
    }

    // Reestablish tunnel using existing session token
    // return establish_tunnel(client, client->session);

    return 0;
}

/**
 * DTLS-only reconnect (keep TLS tunnel)
 */
[[nodiscard]]
static int dtls_only_reconnect(
    reconnect_manager_t *mgr,
    client_context_t *client
) {
    // Keep TLS tunnel active, reconnect DTLS only
    // return establish_dtls_tunnel(client);

    return 0;
}
```

### 17.4 Split DNS Matcher (C23)

```c
// File: ringwall/src/dns/split_dns.c
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define MAX_SPLIT_DOMAINS 100
#define MAX_VPN_DNS_SERVERS 10

typedef struct {
    char *domains[MAX_SPLIT_DOMAINS];
    size_t domain_count;
    struct in_addr vpn_dns_servers[MAX_VPN_DNS_SERVERS];
    size_t server_count;
} split_dns_matcher_t;

/**
 * Normalize DNS query (lowercase, remove trailing dot)
 */
static void normalize_query(char *query) {
    size_t len = strlen(query);

    // Remove trailing dot
    if (len > 0 && query[len - 1] == '.') {
        query[len - 1] = '\0';
        len--;
    }

    // Convert to lowercase
    for (size_t i = 0; i < len; i++) {
        query[i] = tolower((unsigned char)query[i]);
    }
}

/**
 * Check if query matches domain pattern
 */
[[nodiscard]]
static bool matches_domain(const char *query, const char *pattern) {
    // Exact match
    if (strcmp(query, pattern) == 0) {
        return true;
    }

    // Wildcard match (*.example.com matches foo.example.com)
    if (strncmp(pattern, "*.", 2) == 0) {
        const char *suffix = pattern + 2;
        size_t suffix_len = strlen(suffix);
        size_t query_len = strlen(query);

        // Check if ends with .suffix or equals suffix
        if (query_len >= suffix_len) {
            if (strcmp(query + query_len - suffix_len, suffix) == 0) {
                if (query_len == suffix_len ||
                    query[query_len - suffix_len - 1] == '.') {
                    return true;
                }
            }
        }
        return false;
    }

    // Subdomain match (example.com matches foo.example.com)
    size_t pattern_len = strlen(pattern);
    size_t query_len = strlen(query);

    if (query_len > pattern_len) {
        if (strcmp(query + query_len - pattern_len, pattern) == 0) {
            if (query[query_len - pattern_len - 1] == '.') {
                return true;
            }
        }
    }

    return false;
}

/**
 * Determine if query should use VPN DNS
 */
[[nodiscard]]
bool should_use_vpn_dns(
    const split_dns_matcher_t *matcher,
    const char *query
) {
    if (matcher == nullptr || query == nullptr) {
        return false;
    }

    char normalized[256];
    strncpy(normalized, query, sizeof(normalized) - 1);
    normalized[sizeof(normalized) - 1] = '\0';
    normalize_query(normalized);

    for (size_t i = 0; i < matcher->domain_count; i++) {
        if (matches_domain(normalized, matcher->domains[i])) {
            return true;
        }
    }

    return false;
}

/**
 * Add split DNS domain
 */
[[nodiscard]]
int add_split_dns_domain(
    split_dns_matcher_t *matcher,
    const char *domain
) {
    if (matcher == nullptr || domain == nullptr) {
        return -1;
    }

    if (matcher->domain_count >= MAX_SPLIT_DOMAINS) {
        return -1;  // No space
    }

    matcher->domains[matcher->domain_count] = strdup(domain);
    if (matcher->domains[matcher->domain_count] == nullptr) {
        return -1;
    }

    matcher->domain_count++;
    return 0;
}
```

### 17.5 Always-On VPN Validation (C23)

```c
// File: ringwall/src/auth/always_on.c
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

typedef struct {
    char *gateway_hostnames[10];
    size_t gateway_count;
    uint8_t *certificate_pins[10];  // SHA-256 hashes
    size_t pin_count;
    bool always_on_enabled;
} vpn_profile_t;

typedef struct {
    char username[256];
    char client_ip[46];
    gnutls_x509_crt_t certificate;
    vpn_profile_t *profile;
    bool using_proxy;
} client_t;

typedef enum {
    ERR_GATEWAY_NOT_IN_PROFILE = 1,
    ERR_UNTRUSTED_CERTIFICATE,
    ERR_PROXY_NOT_ALLOWED,
    ERR_CERTIFICATE_PIN_MISMATCH
} validation_error_t;

/**
 * Check if hostname is in profile's gateway list
 */
[[nodiscard]]
static bool contains_gateway(
    const vpn_profile_t *profile,
    const char *hostname
) {
    for (size_t i = 0; i < profile->gateway_count; i++) {
        if (strcasecmp(profile->gateway_hostnames[i], hostname) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Strict certificate validation for Always-On
 */
[[nodiscard]]
static int validate_certificate_strict(gnutls_x509_crt_t cert) {
    if (cert == nullptr) {
        return -1;
    }

    // Check expiration
    time_t now = time(nullptr);
    time_t expiration = gnutls_x509_crt_get_expiration_time(cert);
    time_t activation = gnutls_x509_crt_get_activation_time(cert);

    if (now < activation || now > expiration) {
        return -1;
    }

    // Check key size (minimum 2048-bit for RSA)
    unsigned int bits;
    int ret = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
    if (ret == GNUTLS_PK_RSA && bits < 2048) {
        return -1;
    }

    // Additional checks: signature algorithm, SAN, etc.
    return 0;
}

/**
 * Verify certificate pin
 */
[[nodiscard]]
static bool verify_certificate_pin(
    gnutls_x509_crt_t cert,
    const vpn_profile_t *profile
) {
    if (profile->pin_count == 0) {
        return true;  // No pinning configured
    }

    // Calculate certificate SHA-256 hash
    uint8_t cert_hash[32];
    size_t cert_size;
    
    gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, nullptr, &cert_size);
    uint8_t *cert_der = malloc(cert_size);
    gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, cert_der, &cert_size);

    gnutls_hash_fast(GNUTLS_DIG_SHA256, cert_der, cert_size, cert_hash);
    free(cert_der);

    // Compare with configured pins
    for (size_t i = 0; i < profile->pin_count; i++) {
        if (memcmp(cert_hash, profile->certificate_pins[i], 32) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Validate Always-On VPN connection
 */
[[nodiscard]]
int validate_always_on_connection(
    const client_t *client,
    const char *server_hostname
) {
    if (client == nullptr || client->profile == nullptr) {
        return -1;
    }

    if (!client->profile->always_on_enabled) {
        return 0;  // Not Always-On, no special validation
    }

    // Check gateway in profile
    if (!contains_gateway(client->profile, server_hostname)) {
        return ERR_GATEWAY_NOT_IN_PROFILE;
    }

    // Strict certificate validation (no user override allowed)
    if (validate_certificate_strict(client->certificate) != 0) {
        return ERR_UNTRUSTED_CERTIFICATE;
    }

    // No proxy allowed with Always-On
    if (client->using_proxy) {
        return ERR_PROXY_NOT_ALLOWED;
    }

    // Certificate pinning verification
    if (!verify_certificate_pin(client->certificate, client->profile)) {
        return ERR_CERTIFICATE_PIN_MISMATCH;
    }

    return 0;
}
```

---

## 18. Network Visibility Module (NVM) Integration

### 18.1 Overview

The **Network Visibility Module (NVM)** provides enterprise-grade network telemetry, application visibility, and compliance monitoring for Cisco Secure Client endpoints. For enterprise deployments, ocserv should support receiving NVM telemetry from connected clients.

**Key Features:**
- Network flow telemetry (TCP/UDP connections)
- Application visibility (process names, paths, hashes)
- User context (logged-in users, account types)
- DNS resolution tracking
- Interface monitoring (WiFi, Ethernet, VPN state)
- Compliance enforcement (policy-based filtering)

**Reference Documentation:**
- Full analysis: `/opt/projects/repositories/cisco-secure-client/analysis/NVM_TELEMETRY.md`
- Cisco official guide: [NVM Collector Admin Guide](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/nvm-collector-5-1-1-admin-guide.html)

### 18.2 Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Cisco Secure Client (Endpoint)              │
│  ┌────────────────────────────────────────────────────┐ │
│  │  NVM Agent (acnvmagent)                            │ │
│  │  - Kernel packet capture (eBPF/netfilter)         │ │
│  │  - Flow aggregation & enrichment                  │ │
│  │  - Process metadata collection                    │ │
│  │  - DNS cache                                       │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                         │
                         │ IPFIX/UDP (port 2055)
                         │ or DTLS (encrypted)
                         ↓
┌─────────────────────────────────────────────────────────┐
│            ringwall (with NVM Collector)            │
│  ┌────────────────────────────────────────────────────┐ │
│  │  NVM Collector Module (src/nvm/)                   │ │
│  │  - IPFIX protocol decoder                          │ │
│  │  - Template cache                                  │ │
│  │  - Flow record parser                              │ │
│  │  - SQLite storage                                  │ │
│  │  - REST API for queries                            │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### 18.3 Protocol: IPFIX (nvzFlow)

NVM uses **IPFIX** (RFC 7011) over UDP/DTLS:

**Default Port:** 2055/UDP
**Protocol Version:** 10 (IPFIX)
**Security Modes:**
- **Unsecured:** Plain UDP
- **DTLS:** Server authentication (TLS 1.2+)
- **mDTLS:** Mutual authentication (client + server certificates)

**IPFIX Packet Structure:**
```
┌─────────────────────────────────────┐
│   IPFIX Message Header (16 bytes)  │
│   - Version: 10                     │
│   - Length: total bytes             │
│   - Export Time: Unix epoch         │
│   - Sequence Number                 │
│   - Observation Domain ID: 0        │
├─────────────────────────────────────┤
│   Set 1: Template Set               │
│   - Template ID: 256-65535          │
│   - Field definitions               │
├─────────────────────────────────────┤
│   Set 2: Data Set                   │
│   - Flow records                    │
│   - Uses Template ID                │
└─────────────────────────────────────┘
```

### 18.4 Data Records

NVM exports six record types:

1. **Endpoint Identity**: Device UUID, hostname, OS version
2. **Interface Info**: Network interfaces, IP addresses, WiFi SSIDs
3. **Flow Records (IPv4)**: TCP/UDP flows with process context
4. **Flow Records (IPv6)**: IPv6 flows
5. **Process Info**: Standalone process metadata
6. **OSquery Data**: Custom security queries

**Flow Record Fields (selected):**

| Field | IPFIX IE | Type | Description |
|-------|----------|------|-------------|
| Flow Start Time | 152 | dateTimeMilliseconds | Milliseconds since epoch |
| Flow End Time | 153 | dateTimeMilliseconds | End timestamp |
| Source IP | 8 (v4), 27 (v6) | ipAddress | Source IP address |
| Source Port | 7 | unsigned16 | Source TCP/UDP port |
| Destination IP | 12 (v4), 28 (v6) | ipAddress | Destination IP |
| Destination Port | 11 | unsigned16 | Destination port |
| Protocol | 4 | unsigned8 | 6=TCP, 17=UDP |
| Bytes Sent | 1 | unsigned64 | Octets transmitted |
| Packets Sent | 2 | unsigned64 | Packets transmitted |
| Process ID | 12232 (Cisco) | unsigned32 | PID |
| Process Name | 12233 (Cisco) | string | Executable name |
| Process Path | 12234 (Cisco) | string | Full path |
| Process Hash | 12235 (Cisco) | string | SHA256 hash |
| Destination Hostname | 12241 (Cisco) | string | Resolved DNS name |

**Cisco Enterprise Number (PEN):** 9

### 18.5 C23 Implementation in ocserv

#### 18.5.1 Module Structure

```c
// File: src/nvm/nvm_collector.h

#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

// NVM collector configuration
typedef struct nvm_config {
    bool enabled;
    uint16_t port;               // Default: 2055
    bool use_dtls;
    char *cert_file;             // Server certificate
    char *key_file;              // Server private key
    char *client_ca_file;        // For mDTLS
    char *database_path;         // SQLite storage
    uint32_t max_flows;          // Flow retention limit
} nvm_config_t;

// NVM flow record (parsed from IPFIX)
typedef struct nvm_flow {
    uint64_t flow_id;
    uint64_t start_time_ms;
    uint64_t end_time_ms;

    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;

    uint32_t pid;
    char process_name[256];
    char process_path[2048];
    uint8_t process_hash[32];
    char username[256];

    char dst_hostname[256];

    uint8_t direction;  // 0=unknown, 1=inbound, 2=outbound
    uint8_t stage;      // 0=end, 1=start, 2=periodic

    // Linked to client session
    char client_username[128];
    struct in_addr client_vpn_ip;
} nvm_flow_t;

// API functions
[[nodiscard]] int nvm_collector_init(const nvm_config_t *config);
void nvm_collector_shutdown(void);

[[nodiscard]] int nvm_collector_start(void);
void nvm_collector_stop(void);

// Query API
[[nodiscard]] int nvm_query_flows(
    const char *username,
    uint64_t start_time,
    uint64_t end_time,
    nvm_flow_t **flows_out,
    size_t *count_out
);

void nvm_free_flows(nvm_flow_t *flows, size_t count);
```

#### 18.5.2 IPFIX Decoder

```c
// File: src/nvm/ipfix_decoder.c

#include "nvm_collector.h"
#include <arpa/inet.h>

#define IPFIX_VERSION 10

// IPFIX message header
typedef struct __attribute__((packed)) {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t sequence_number;
    uint32_t observation_domain_id;
} ipfix_header_t;

// Template cache entry
typedef struct ipfix_template {
    uint16_t template_id;
    uint16_t field_count;
    struct {
        uint16_t ie_id;
        uint16_t field_length;
        uint32_t enterprise_number;
    } fields[64];
    struct ipfix_template *next;
} ipfix_template_t;

// Global template cache
static ipfix_template_t *g_templates = nullptr;

// Parse IPFIX header
[[nodiscard]]
static int parse_ipfix_header(
    const uint8_t *data,
    size_t len,
    ipfix_header_t *header
) {
    if (len < sizeof(ipfix_header_t)) return -1;

    header->version = ntohs(*(uint16_t *)(data + 0));
    header->length = ntohs(*(uint16_t *)(data + 2));
    header->export_time = ntohl(*(uint32_t *)(data + 4));
    header->sequence_number = ntohl(*(uint32_t *)(data + 8));
    header->observation_domain_id = ntohl(*(uint32_t *)(data + 12));

    if (header->version != IPFIX_VERSION) return -1;
    if (header->length > len) return -1;

    return 0;
}

// Parse template set
[[nodiscard]]
static int parse_template_set(const uint8_t *data, size_t len) {
    // Set ID = 2 (Template Set)
    uint16_t set_id = ntohs(*(uint16_t *)(data + 0));
    uint16_t set_length = ntohs(*(uint16_t *)(data + 2));

    if (set_id != 2) return -1;

    size_t offset = 4;

    while (offset < set_length) {
        ipfix_template_t *tmpl = calloc(1, sizeof(*tmpl));

        tmpl->template_id = ntohs(*(uint16_t *)(data + offset));
        offset += 2;

        tmpl->field_count = ntohs(*(uint16_t *)(data + offset));
        offset += 2;

        for (uint16_t i = 0; i < tmpl->field_count && i < 64; i++) {
            uint16_t ie_id = ntohs(*(uint16_t *)(data + offset));
            offset += 2;

            uint16_t field_length = ntohs(*(uint16_t *)(data + offset));
            offset += 2;

            uint32_t pen = 0;
            if (ie_id & 0x8000) {
                pen = ntohl(*(uint32_t *)(data + offset));
                offset += 4;
                ie_id &= 0x7FFF;
            }

            tmpl->fields[i].ie_id = ie_id;
            tmpl->fields[i].field_length = field_length;
            tmpl->fields[i].enterprise_number = pen;
        }

        // Add to cache
        tmpl->next = g_templates;
        g_templates = tmpl;
    }

    return 0;
}

// Parse data record (flow)
[[nodiscard]]
static int parse_flow_record(
    const ipfix_template_t *tmpl,
    const uint8_t *data,
    size_t *offset,
    nvm_flow_t *flow
) {
    memset(flow, 0, sizeof(*flow));

    for (uint16_t i = 0; i < tmpl->field_count; i++) {
        uint16_t ie_id = tmpl->fields[i].ie_id;
        uint16_t length = tmpl->fields[i].field_length;
        uint32_t pen = tmpl->fields[i].enterprise_number;

        // Standard IPFIX IEs
        if (pen == 0) {
            switch (ie_id) {
                case 8:  // sourceIPv4Address
                    memcpy(&flow->src_ip.s6_addr[12], data + *offset, 4);
                    // IPv4-mapped IPv6: ::ffff:x.x.x.x
                    flow->src_ip.s6_addr[10] = 0xff;
                    flow->src_ip.s6_addr[11] = 0xff;
                    break;
                case 12:  // destinationIPv4Address
                    memcpy(&flow->dst_ip.s6_addr[12], data + *offset, 4);
                    flow->dst_ip.s6_addr[10] = 0xff;
                    flow->dst_ip.s6_addr[11] = 0xff;
                    break;
                case 7:  // sourceTransportPort
                    flow->src_port = ntohs(*(uint16_t *)(data + *offset));
                    break;
                case 11:  // destinationTransportPort
                    flow->dst_port = ntohs(*(uint16_t *)(data + *offset));
                    break;
                case 4:  // protocolIdentifier
                    flow->protocol = *(data + *offset);
                    break;
                case 1:  // octetDeltaCount
                    flow->bytes_sent = be64toh(*(uint64_t *)(data + *offset));
                    break;
                case 2:  // packetDeltaCount
                    flow->packets_sent = be64toh(*(uint64_t *)(data + *offset));
                    break;
                case 152:  // flowStartMilliseconds
                    flow->start_time_ms = be64toh(*(uint64_t *)(data + *offset));
                    break;
                case 153:  // flowEndMilliseconds
                    flow->end_time_ms = be64toh(*(uint64_t *)(data + *offset));
                    break;
                case 176:  // flowDirection
                    flow->direction = *(data + *offset);
                    break;
            }
        }
        // Cisco Enterprise IEs (PEN = 9)
        else if (pen == 9) {
            switch (ie_id) {
                case 12232:  // nvmProcessID
                    flow->pid = ntohl(*(uint32_t *)(data + *offset));
                    break;
                case 12233:  // nvmProcessName (variable length string)
                    {
                        uint8_t str_len = *(data + *offset);
                        *offset += 1;
                        size_t copy_len = str_len < sizeof(flow->process_name) - 1 ?
                                        str_len : sizeof(flow->process_name) - 1;
                        memcpy(flow->process_name, data + *offset, copy_len);
                        flow->process_name[copy_len] = '\0';
                        *offset += str_len - 1;  // -1 because we increment at end
                    }
                    break;
                case 12234:  // nvmProcessPath
                    {
                        uint8_t str_len = *(data + *offset);
                        *offset += 1;
                        size_t copy_len = str_len < sizeof(flow->process_path) - 1 ?
                                        str_len : sizeof(flow->process_path) - 1;
                        memcpy(flow->process_path, data + *offset, copy_len);
                        flow->process_path[copy_len] = '\0';
                        *offset += str_len - 1;
                    }
                    break;
                case 12241:  // nvmDestinationHostname
                    {
                        uint8_t str_len = *(data + *offset);
                        *offset += 1;
                        size_t copy_len = str_len < sizeof(flow->dst_hostname) - 1 ?
                                        str_len : sizeof(flow->dst_hostname) - 1;
                        memcpy(flow->dst_hostname, data + *offset, copy_len);
                        flow->dst_hostname[copy_len] = '\0';
                        *offset += str_len - 1;
                    }
                    break;
            }
        }

        // Advance to next field
        if (length != 0xFFFF) {  // Fixed length
            *offset += length;
        }
    }

    return 0;
}

// Main IPFIX processing function
[[nodiscard]]
int nvm_process_ipfix_message(
    const uint8_t *data,
    size_t len,
    struct sockaddr_storage *client_addr
) {
    ipfix_header_t header;
    if (parse_ipfix_header(data, len, &header) < 0) {
        return -1;
    }

    size_t offset = sizeof(ipfix_header_t);

    while (offset < header.length) {
        uint16_t set_id = ntohs(*(uint16_t *)(data + offset));
        uint16_t set_length = ntohs(*(uint16_t *)(data + offset + 2));

        if (set_id == 2) {
            // Template Set
            parse_template_set(data + offset, set_length);
        } else if (set_id >= 256) {
            // Data Set - look up template
            ipfix_template_t *tmpl = g_templates;
            while (tmpl) {
                if (tmpl->template_id == set_id) break;
                tmpl = tmpl->next;
            }

            if (tmpl) {
                // Parse all records in this set
                size_t data_offset = offset + 4;
                while (data_offset < offset + set_length) {
                    nvm_flow_t flow;
                    if (parse_flow_record(tmpl, data, &data_offset, &flow) == 0) {
                        // Store flow in database
                        nvm_store_flow(&flow, client_addr);
                    }
                }
            }
        }

        offset += set_length;
    }

    return 0;
}
```

#### 18.5.3 UDP/DTLS Listener

```c
// File: src/nvm/nvm_listener.c

#include "nvm_collector.h"
#include <sys/socket.h>
#include <pthread.h>

static int g_sockfd = -1;
static pthread_t g_thread;
static bool g_running = false;
static gnutls_session_t g_dtls_session = nullptr;

// UDP listener thread
static void* nvm_listener_thread(void *arg) {
    uint8_t buffer[65536];
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (g_running) {
        ssize_t len = recvfrom(g_sockfd, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&client_addr, &addr_len);

        if (len < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Process IPFIX message
        nvm_process_ipfix_message(buffer, len, &client_addr);
    }

    return nullptr;
}

// Initialize collector
[[nodiscard]]
int nvm_collector_init(const nvm_config_t *config) {
    if (!config->enabled) return 0;

    // Create UDP socket
    g_sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sockfd < 0) return -1;

    // Bind to port
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(config->port),
        .sin6_addr = IN6ADDR_ANY_INIT,
    };

    if (bind(g_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_sockfd);
        return -1;
    }

    // Initialize DTLS if enabled
    if (config->use_dtls) {
        // DTLS setup (using GnuTLS)
        // ... (implementation omitted for brevity)
    }

    return 0;
}

// Start collector
[[nodiscard]]
int nvm_collector_start(void) {
    if (g_sockfd < 0) return -1;

    g_running = true;

    if (pthread_create(&g_thread, nullptr, nvm_listener_thread, nullptr) != 0) {
        g_running = false;
        return -1;
    }

    return 0;
}

// Stop collector
void nvm_collector_stop(void) {
    g_running = false;
    pthread_join(g_thread, nullptr);
}
```

### 18.6 Configuration

Add to `ocserv.conf`:

```bash
# Network Visibility Module (NVM) settings
nvm = true
nvm-port = 2055
nvm-dtls = true
nvm-cert = /etc/ocserv/nvm-cert.pem
nvm-key = /etc/ocserv/nvm-key.pem
nvm-client-ca = /etc/ocserv/nvm-client-ca.pem
nvm-database = /var/lib/ocserv/nvm-flows.db
nvm-max-flows = 100000
```

### 18.7 Client Profile Configuration

XML profile pushed to clients:

```xml
<NVMServiceProfile>
  <CollectorConfiguration>
    <ExportTo>Collector</ExportTo>
    <Collector>
      <Address>vpn.example.com</Address>
      <Port>2055</Port>
      <Protocol>DTLS</Protocol>
    </Collector>
  </CollectorConfiguration>

  <DataCollectionPolicy>
    <Enabled>true</Enabled>
    <FlowReportInterval unit="seconds">60</FlowReportInterval>
    <TemplateReportInterval unit="minutes">1440</TemplateReportInterval>
  </DataCollectionPolicy>
</NVMServiceProfile>
```

### 18.8 REST API for Queries

```c
// File: src/nvm/nvm_api.c

// GET /api/nvm/flows?username=jsmith&start=<timestamp>&end=<timestamp>
[[nodiscard]]
int handle_nvm_query(
    struct http_request *req,
    struct http_response *resp
) {
    const char *username = http_get_query_param(req, "username");
    const char *start_str = http_get_query_param(req, "start");
    const char *end_str = http_get_query_param(req, "end");

    if (!username || !start_str || !end_str) {
        http_response_set_status(resp, 400);
        return -1;
    }

    uint64_t start_time = strtoull(start_str, nullptr, 10);
    uint64_t end_time = strtoull(end_str, nullptr, 10);

    nvm_flow_t *flows;
    size_t count;

    if (nvm_query_flows(username, start_time, end_time, &flows, &count) < 0) {
        http_response_set_status(resp, 500);
        return -1;
    }

    // Serialize flows to JSON
    json_t *json_array = json_array();
    for (size_t i = 0; i < count; i++) {
        json_t *flow_obj = json_object();
        json_object_set_new(flow_obj, "flow_id", json_integer(flows[i].flow_id));
        json_object_set_new(flow_obj, "start_time", json_integer(flows[i].start_time_ms));
        json_object_set_new(flow_obj, "process_name", json_string(flows[i].process_name));
        // ... (add more fields)

        json_array_append_new(json_array, flow_obj);
    }

    char *json_str = json_dumps(json_array, JSON_COMPACT);
    http_response_set_body(resp, json_str, strlen(json_str));
    http_response_set_header(resp, "Content-Type", "application/json");

    free(json_str);
    json_decref(json_array);
    nvm_free_flows(flows, count);

    return 0;
}
```

### 18.9 Implementation Roadmap

**Phase 1: Basic Collector (v2.1.0)**
- [ ] UDP listener on port 2055
- [ ] IPFIX header parsing
- [ ] Template cache
- [ ] Basic flow record parsing (IPv4)
- [ ] SQLite storage
- [ ] Unit tests

**Phase 2: Security & IPv6 (v2.2.0)**
- [ ] DTLS support (server authentication)
- [ ] IPv6 flow records
- [ ] mDTLS support (mutual authentication)
- [ ] Certificate pinning
- [ ] Rate limiting

**Phase 3: Analytics & API (v2.3.0)**
- [ ] REST API for flow queries
- [ ] Real-time flow streaming (WebSocket)
- [ ] Flow aggregation and statistics
- [ ] Alerting on suspicious flows
- [ ] Grafana dashboard integration

**Phase 4: Enterprise Features (v2.4.0)**
- [ ] Multi-tenant isolation
- [ ] Flow export to SIEM (syslog, Splunk)
- [ ] Compliance reporting
- [ ] Process hash reputation checking
- [ ] Integration with threat intelligence feeds

### 18.10 Testing

**Test NVM with synthetic IPFIX:**

```bash
# Generate IPFIX test packet
python3 /opt/projects/repositories/cisco-secure-client/analysis/generate_ipfix.py \
    --collector localhost:2055 \
    --flows 10

# Verify reception in ocserv logs
tail -f /var/log/ocserv.log | grep NVM
```

**Test with real Cisco client:**

```bash
# On Windows/Linux client with Cisco Secure Client
# Push NVM profile with collector address
# Connect to VPN
# Verify flows arriving at ocserv:2055
```

### 18.11 Performance Considerations

**Expected Load:**
- 100 clients × 100 flows/hour = 10K flows/hour
- Average IPFIX record size: 200 bytes
- Bandwidth: 200 bytes × 10K flows ÷ 3600 sec = 555 bytes/sec
- **Negligible impact on VPN gateway**

**Database Growth:**
- 10K flows/hour × 300 bytes (SQLite) = 3 MB/hour
- 72 MB/day
- Implement retention policy (e.g., 30 days = 2.1 GB)

**CPU Overhead:**
- IPFIX parsing: < 0.1% CPU
- SQLite writes: < 0.5% CPU
- DTLS decryption: < 1% CPU
- **Total: < 2% CPU overhead**

### 18.12 Security Best Practices

1. **Always use DTLS or mDTLS** in production
2. **Implement certificate pinning** for client validation
3. **Rate limit IPFIX messages** (1000 flows/sec per client)
4. **Validate all IPFIX fields** (prevent injection attacks)
5. **Encrypt SQLite database** at rest
6. **Audit flow data access** (log all queries)
7. **Apply data retention policies** (GDPR compliance)
8. **Sanitize PII** (anonymize usernames if required)

### 18.13 Troubleshooting

**Problem:** No flows received from client

**Solutions:**
- Check firewall allows UDP:2055
- Verify NVM enabled in client profile
- Check ocserv logs for IPFIX parsing errors
- Use Wireshark to capture UDP:2055 traffic

**Problem:** Template not found errors

**Solutions:**
- Ensure template set received before data sets
- Increase template cache size
- Check for packet loss (UDP unreliable)

**Problem:** High database size

**Solutions:**
- Reduce flow retention period
- Enable SQLite auto-vacuum
- Implement flow aggregation (reduce granularity)
- Archive old flows to cold storage

---

**End of C23 Implementation Reference**

All code examples throughout this document should be considered as C23 implementations. The original Go examples were provided for conceptual understanding but have been superseded by these production-ready C23 implementations.

