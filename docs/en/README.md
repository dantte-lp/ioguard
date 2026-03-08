# WolfGuard Documentation

![Documents](https://img.shields.io/badge/Documents-11-34a853?style=for-the-badge)
![Language](https://img.shields.io/badge/Lang-English-ea4335?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> Technical documentation for **WolfGuard** -- a C23 VPN server implementing the OpenConnect protocol with wolfSSL, io_uring, and Linux-native security.

---

## Documentation Map

```mermaid
graph TD
    IDX["docs/en/README.md<br/>(You are here)"]

    subgraph "Architecture"
        A1["01-architecture.md<br/>Architecture"]
        A2["02-protocol.md<br/>OpenConnect Protocol"]
    end

    subgraph "Crypto & Security"
        B1["04-tls-dtls.md<br/>TLS and DTLS"]
        B2["07-security.md<br/>Security"]
    end

    subgraph "Operations"
        C1["03-configuration.md<br/>Configuration"]
        C2["05-authentication.md<br/>Authentication"]
        C3["06-deployment.md<br/>Deployment"]
    end

    subgraph "Reference"
        D1["08-development.md<br/>Development"]
        D2["09-rfc-compliance.md<br/>RFC Compliance"]
        D3["10-monitoring.md<br/>Monitoring"]
        D4["11-cli-reference.md<br/>CLI Reference"]
    end

    IDX --> A1
    IDX --> B1
    IDX --> C1
    IDX --> D1

    A1 --> A2
    A2 --> B1
    B1 --> B2
    C1 --> C2
    C2 --> C3
    C3 --> D3
    D1 --> D2
    D4 --> D3

    style IDX fill:#1a73e8,color:#fff
```

---

## Table of Contents

### Architecture

| # | Document | Description |
|---|---|---|
| 01 | [**Architecture**](./01-architecture.md) | Three-process model, io_uring I/O, IPC design |
| 02 | [**OpenConnect Protocol**](./02-protocol.md) | CSTP/DTLS tunnel, packet format, handshake flow |

### Crypto & Security

| # | Document | Description |
|---|---|---|
| 04 | [**TLS and DTLS**](./04-tls-dtls.md) | wolfSSL integration, cipher suites, DTLS 1.2 |
| 07 | [**Security**](./07-security.md) | wolfSentry, seccomp, Landlock, nftables hardening |

### Operations

| # | Document | Description |
|---|---|---|
| 03 | [**Configuration**](./03-configuration.md) | TOML config reference, JSON rules, environment |
| 05 | [**Authentication**](./05-authentication.md) | PAM, RADIUS, LDAP, TOTP, sec-mod design |
| 06 | [**Deployment**](./06-deployment.md) | systemd, containers, production setup |

### Reference

| # | Document | Description |
|---|---|---|
| 08 | [**Development**](./08-development.md) | Build system, testing, C23 conventions, toolchain |
| 09 | [**RFC Compliance**](./09-rfc-compliance.md) | RFC compliance matrix, implementation notes |
| 10 | [**Monitoring**](./10-monitoring.md) | Prometheus metrics, structured logging, alerts |
| 11 | [**CLI Reference**](./11-cli-reference.md) | rwctl commands, output formats, REST API |

---

*Last updated: 2026-03-08*
