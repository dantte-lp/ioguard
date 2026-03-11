#!/usr/bin/env python3
"""RFC scraper for the ioguard VPN project.

Searches datatracker.ietf.org API for RFCs and active Internet-Drafts
relevant to TLS, DTLS, QUIC, VPN, authentication, and cryptography.
Outputs a structured Markdown registry.

Usage:
    python3 rfc-scraper.py                          # stdout
    python3 rfc-scraper.py -o ioguard-rfcs.md     # file
    python3 rfc-scraper.py --download docs/rfc/     # download .txt
    python3 rfc-scraper.py --json                   # JSON output
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter, Retry

log = logging.getLogger("rfc-scraper")

# ── Datatracker API ───────────────────────────────────────────────────

DATATRACKER_BASE = "https://datatracker.ietf.org"
DATATRACKER_API = f"{DATATRACKER_BASE}/api/v1"
RFC_EDITOR_BASE = "https://www.rfc-editor.org"
USER_AGENT = "ioguard-rfc-scraper/2.0"
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 0.3

# Full URI references for Tastypie filtered fields
DOCTYPE_RFC = f"{DATATRACKER_API}/name/doctypename/rfc/"
DOCTYPE_DRAFT = f"{DATATRACKER_API}/name/doctypename/draft/"


# ── Data model ────────────────────────────────────────────────────────


@dataclass
class RfcEntry:
    """Metadata for a single RFC."""

    number: int
    title: str
    status: str = ""
    pages: int | None = None
    categories: set[str] = field(default_factory=set)

    @property
    def url(self) -> str:
        return f"{RFC_EDITOR_BASE}/rfc/rfc{self.number}"

    @property
    def txt_url(self) -> str:
        return f"{RFC_EDITOR_BASE}/rfc/rfc{self.number}.txt"


@dataclass
class DraftEntry:
    """Metadata for an active Internet-Draft."""

    name: str
    title: str
    status: str = "ACTIVE DRAFT"
    rev: str = ""
    categories: set[str] = field(default_factory=set)

    @property
    def url(self) -> str:
        return f"{DATATRACKER_BASE}/doc/{self.name}/"


# ── Search categories ────────────────────────────────────────────────

CATEGORIES: dict[str, list[str]] = {
    "TLS/DTLS": [
        "TLS 1.3",
        "DTLS 1.3",
        "DTLS 1.2",
        "TLS 1.2",
        "TLS extensions",
        "TLS certificate",
        "TLS session resumption",
        "TLS encrypted client hello",
        "TLS key share",
        "DTLS connection id",
        "TLS post-quantum",
        "TLS record padding",
        "TLS ALPN",
        "TLS SNI",
        "TLS exported authenticators",
        "TLS keying material",
        "TLS delegated credentials",
        "compact TLS",
    ],
    "QUIC": [
        "QUIC transport",
        "QUIC TLS",
        "QUIC recovery",
        "QUIC datagram",
        "QUIC multipath",
        "QUIC version negotiation",
        "QUIC load balancing",
        "MASQUE",
        "CONNECT-UDP",
        "CONNECT-IP",
        "HTTP/3",
        "HTTP datagrams",
    ],
    "Authentication": [
        "RADIUS",
        "RADIUS TLS",
        "RADIUS DTLS",
        "LDAP",
        "LDAP TLS",
        "TOTP",
        "HOTP",
        "OATH",
        "PKCS",
        "X.509 certificate",
        "OCSP",
        "certificate revocation",
        "certificate transparency",
        "SAML",
        "OAuth 2.0",
        "OpenID Connect",
        "FIDO",
        "WebAuthn",
        "SCRAM authentication",
        "EAP",
    ],
    "IP tunneling": [
        "IP tunneling",
        "IP encapsulation",
        "GRE tunnel",
        "IP-in-IP",
        "IPv6 transition",
        "IPv6 tunnel",
        "Mobile IP",
        "LISP",
        "Segment Routing",
        "SRv6",
        "Network Address Translation",
        "NAT traversal",
        "STUN",
        "TURN",
        "ICE",
    ],
    "VPN protocols": [
        "IPsec",
        "IKEv2",
        "ESP",
        "WireGuard",
        "Noise protocol",
        "OpenConnect",
        "AnyConnect",
        "L2TP",
        "PPTP",
        "SSTP",
        "SSL VPN",
    ],
    "DNS": [
        "DNS over TLS",
        "DNS over HTTPS",
        "DNS over QUIC",
        "DNSSEC",
        "DNS split horizon",
        "DNS service binding",
        "SVCB DNS",
        "Encrypted DNS",
        "Oblivious DNS",
    ],
    "HTTP": [
        "HTTP/1.1 semantics",
        "HTTP/2",
        "HTTP/3",
        "WebSocket",
        "HTTP CONNECT",
        "HTTP proxy",
        "HTTP authentication",
    ],
    "Cryptography": [
        "AES-GCM",
        "ChaCha20-Poly1305",
        "Curve25519",
        "X25519",
        "Ed25519",
        "HKDF",
        "HMAC",
        "Argon2",
        "PBKDF2",
        "post-quantum cryptography",
        "ML-KEM",
        "Kyber",
        "hybrid key exchange",
        "AEAD",
        "nonce",
    ],
    "Compression": [
        "header compression",
        "HPACK",
        "QPACK",
        "IP header compression",
        "ROHC",
        "Zstandard",
        "LZ4",
        "TCP BBR",
        "congestion control",
        "Explicit Congestion Notification",
    ],
    "Network security": [
        "DDoS",
        "BCP38",
        "firewall traversal",
        "traffic analysis",
        "padding",
        "network address translation detection",
        "Encrypted SNI",
        "ECH",
    ],
    "Management": [
        "SNMP",
        "YANG",
        "NETCONF",
        "syslog",
        "structured logging",
        "Prometheus",
        "OpenTelemetry",
        "IPFIX",
        "NetFlow",
    ],
    "Transport": [
        "UDP encapsulation",
        "UDP options",
        "TCP Fast Open",
        "Multipath TCP",
        "SCTP",
        "DCCP",
        "Happy Eyeballs",
        "connection racing",
    ],
    "Encoding": [
        "JSON",
        "CBOR",
        "MessagePack",
        "ASN.1",
        "DER",
        "PEM",
        "Protocol Buffers",
        "TOML",
        "base64",
        "URI",
    ],
    "QoS & Traffic Shaping": [
        "DiffServ",
        "DSCP",
        "Expedited Forwarding",
        "Assured Forwarding",
        "ECN",
        "Explicit Congestion Notification",
        "Active Queue Management",
        "CoDel",
        "CUBIC",
        "BBR",
    ],
    "IPFIX & NetFlow": [
        "IPFIX",
        "NetFlow",
        "flow export",
        "flow aggregation",
        "PSAMP",
        "packet sampling",
    ],
    "Post-Quantum": [
        "ML-KEM",
        "ML-DSA",
        "SLH-DSA",
        "post-quantum TLS",
        "hybrid key exchange",
        "Kyber",
        "Dilithium",
        "SPHINCS",
    ],
    "Certificate Management": [
        "ACME",
        "Let's Encrypt",
        "Certificate Transparency",
        "DANE",
        "TLSA",
        "OCSP stapling",
        "certificate revocation",
        "short-lived certificate",
    ],
    "IPv6 Extended": [
        "IPv6 flow label",
        "IPv6 SLAAC",
        "IPv6 PMTUD",
        "NAT64",
        "DNS64",
        "464XLAT",
        "DHCPv6",
        "ICMPv6",
        "Neighbor Discovery",
    ],
    "MASQUE & Obfuscation": [
        "MASQUE",
        "CONNECT-IP",
        "CONNECT-UDP",
        "Oblivious HTTP",
        "OHTTP",
        "Encrypted Client Hello",
        "ECH",
        "traffic obfuscation",
    ],
}

# Known critical RFCs — manually curated
KNOWN_CRITICAL: dict[int, tuple[str, str]] = {
    # TLS/DTLS
    8446: ("TLS 1.3", "PROPOSED STANDARD"),
    9147: ("DTLS 1.3", "PROPOSED STANDARD"),
    6347: ("DTLS 1.2", "PROPOSED STANDARD"),
    5246: ("TLS 1.2", "PROPOSED STANDARD"),
    9146: ("DTLS Connection ID", "PROPOSED STANDARD"),
    8449: ("TLS Record Size Limit", "PROPOSED STANDARD"),
    7301: ("TLS ALPN", "PROPOSED STANDARD"),
    6066: ("TLS Extensions (SNI etc.)", "PROPOSED STANDARD"),
    5077: ("TLS Session Resumption without Server-Side State", "PROPOSED STANDARD"),
    8879: ("TLS Certificate Compression", "PROPOSED STANDARD"),
    9149: ("TLS Ticket Requests", "PROPOSED STANDARD"),
    7250: ("Raw Public Keys in TLS/DTLS", "PROPOSED STANDARD"),
    7924: ("TLS Cached Information Extension", "PROPOSED STANDARD"),
    9325: ("Recommendations for TLS/DTLS 1.2 and Older", "BCP"),
    7627: ("TLS Session Hash and Extended Master Secret", "PROPOSED STANDARD"),
    8701: ("Applying GREASE to TLS Extensibility", "PROPOSED STANDARD"),
    8996: ("Deprecating TLS 1.0 and TLS 1.1", "BCP"),
    7366: ("Encrypt-then-MAC for TLS and DTLS", "PROPOSED STANDARD"),
    7457: ("Summarizing Known Attacks on TLS and DTLS", "INFORMATIONAL"),
    7905: ("ChaCha20-Poly1305 Cipher Suites for TLS", "PROPOSED STANDARD"),
    8448: ("Example Handshake Traces for TLS 1.3", "INFORMATIONAL"),
    9151: ("CNSA Suite Profile for TLS and DTLS", "INFORMATIONAL"),
    9345: ("Delegated Credentials for TLS and DTLS", "PROPOSED STANDARD"),
    9848: ("Deprecating Obsolete Key Exchange in TLS 1.2", "PROPOSED STANDARD"),
    9849: ("Deprecating Obsolete Cipher Suites in TLS", "PROPOSED STANDARD"),
    9847: ("IANA Registry Updates for TLS and DTLS", "PROPOSED STANDARD"),
    8773: (
        "TLS 1.3 Extension for Certificate-Based Auth with External PSK",
        "PROPOSED STANDARD",
    ),
    # QUIC
    9000: ("QUIC Transport Protocol", "PROPOSED STANDARD"),
    9001: ("Using TLS to Secure QUIC", "PROPOSED STANDARD"),
    9002: ("QUIC Loss Detection and Congestion Control", "PROPOSED STANDARD"),
    9221: ("QUIC Unreliable Datagram Extension", "PROPOSED STANDARD"),
    9369: ("QUIC Version 2", "PROPOSED STANDARD"),
    9443: ("QUIC Demux on Port 443", "PROPOSED STANDARD"),
    9298: ("CONNECT-UDP (MASQUE)", "PROPOSED STANDARD"),
    9484: ("CONNECT-IP (MASQUE)", "PROPOSED STANDARD"),
    9297: ("HTTP Datagrams and CONNECT-UDP Capsules", "PROPOSED STANDARD"),
    8999: ("Version-Independent Properties of QUIC", "PROPOSED STANDARD"),
    9368: ("Compatible Version Negotiation for QUIC", "PROPOSED STANDARD"),
    9287: ("Greasing the QUIC Bit", "PROPOSED STANDARD"),
    8899: ("DPLPMTUD for Datagram Transports", "PROPOSED STANDARD"),
    9204: ("QPACK: Field Compression for HTTP/3", "PROPOSED STANDARD"),
    # HTTP
    9110: ("HTTP Semantics", "INTERNET STANDARD"),
    9112: ("HTTP/1.1", "INTERNET STANDARD"),
    9113: ("HTTP/2", "PROPOSED STANDARD"),
    9114: ("HTTP/3", "PROPOSED STANDARD"),
    6455: ("WebSocket Protocol", "PROPOSED STANDARD"),
    8441: ("WebSocket over HTTP/2", "PROPOSED STANDARD"),
    9220: ("Bootstrapping WebSockets with HTTP/3", "PROPOSED STANDARD"),
    7235: ("HTTP/1.1: Authentication", "PROPOSED STANDARD"),
    7617: ("The 'Basic' HTTP Authentication Scheme", "PROPOSED STANDARD"),
    # Auth
    2865: ("RADIUS", "DRAFT STANDARD"),
    6614: ("RADIUS over TLS", "EXPERIMENTAL"),
    7360: ("RADIUS over DTLS", "EXPERIMENTAL"),
    4511: ("LDAPv3", "PROPOSED STANDARD"),
    4513: ("LDAP Authentication Methods", "PROPOSED STANDARD"),
    6238: ("TOTP: Time-Based One-Time Password", "INFORMATIONAL"),
    4226: ("HOTP: HMAC-Based One-Time Password", "PROPOSED STANDARD"),
    7519: ("JSON Web Token (JWT)", "PROPOSED STANDARD"),
    6749: ("OAuth 2.0", "PROPOSED STANDARD"),
    7636: ("OAuth PKCE", "PROPOSED STANDARD"),
    2866: ("RADIUS Accounting", "INFORMATIONAL"),
    5176: ("Dynamic Authorization Extensions to RADIUS", "INFORMATIONAL"),
    4515: ("LDAP: String Representation of Search Filters", "PROPOSED STANDARD"),
    6750: ("OAuth 2.0 Bearer Token Usage", "PROPOSED STANDARD"),
    7515: ("JSON Web Signature (JWS)", "PROPOSED STANDARD"),
    3748: ("Extensible Authentication Protocol (EAP)", "PROPOSED STANDARD"),
    9190: ("EAP-TLS 1.3", "PROPOSED STANDARD"),
    8705: ("OAuth 2.0 Mutual-TLS", "PROPOSED STANDARD"),
    # Crypto
    5116: ("AEAD Interface", "PROPOSED STANDARD"),
    8439: ("ChaCha20 and Poly1305 for IETF", "INFORMATIONAL"),
    7748: ("Elliptic Curves for Security (X25519/X448)", "INFORMATIONAL"),
    8032: ("Ed25519 and Ed448", "INFORMATIONAL"),
    5869: ("HKDF", "INFORMATIONAL"),
    2104: ("HMAC", "INFORMATIONAL"),
    9180: ("Hybrid Public Key Encryption (HPKE)", "INFORMATIONAL"),
    5288: ("AES-GCM Cipher Suites for TLS", "PROPOSED STANDARD"),
    8017: ("PKCS #1: RSA Cryptography v2.2", "INFORMATIONAL"),
    6979: ("Deterministic Usage of DSA and ECDSA", "INFORMATIONAL"),
    8018: ("PKCS #5: PBKDF2", "INFORMATIONAL"),
    9106: ("Argon2 Memory-Hard Function", "INFORMATIONAL"),
    # Tunneling & NAT
    5764: ("DTLS-SRTP", "PROPOSED STANDARD"),
    8489: ("STUN", "PROPOSED STANDARD"),
    8656: ("TURN", "PROPOSED STANDARD"),
    8445: ("ICE", "PROPOSED STANDARD"),
    6886: ("NAT-PMP", "INFORMATIONAL"),
    7983: ("Multiplexing Scheme Updates for DTLS-SRTP", "PROPOSED STANDARD"),
    # VPN
    4301: ("IPsec Architecture", "PROPOSED STANDARD"),
    7296: ("IKEv2", "INTERNET STANDARD"),
    4303: ("ESP", "PROPOSED STANDARD"),
    # DNS
    7858: ("DNS over TLS (DoT)", "PROPOSED STANDARD"),
    8484: ("DNS over HTTPS (DoH)", "PROPOSED STANDARD"),
    9250: ("DNS over QUIC (DoQ)", "PROPOSED STANDARD"),
    4033: ("DNSSEC Introduction", "PROPOSED STANDARD"),
    9460: ("SVCB and HTTPS DNS Records", "PROPOSED STANDARD"),
    1035: ("Domain Names — Implementation and Specification", "INTERNET STANDARD"),
    4034: ("Resource Records for DNSSEC", "PROPOSED STANDARD"),
    4035: ("Protocol Modifications for DNSSEC", "PROPOSED STANDARD"),
    9461: ("SVCB for DNS (DDR)", "PROPOSED STANDARD"),
    # Compression / Transport
    8878: ("Zstandard Compression", "INFORMATIONAL"),
    1951: ("DEFLATE Compressed Data Format", "INFORMATIONAL"),
    1952: ("GZIP File Format Specification", "INFORMATIONAL"),
    # IP
    791: ("Internet Protocol (IPv4)", "INTERNET STANDARD"),
    8200: ("Internet Protocol, Version 6 (IPv6)", "INTERNET STANDARD"),
    2473: ("IPv6 Tunneling", "PROPOSED STANDARD"),
    4213: ("Transition Mechanisms for IPv6", "PROPOSED STANDARD"),
    4861: ("Neighbor Discovery for IPv6", "DRAFT STANDARD"),
    # Transport
    768: ("User Datagram Protocol (UDP)", "INTERNET STANDARD"),
    9293: ("TCP Specification", "INTERNET STANDARD"),
    8085: ("UDP Usage Guidelines", "BCP"),
    # Misc
    8305: ("Happy Eyeballs v2", "PROPOSED STANDARD"),
    6555: ("Happy Eyeballs v1", "PROPOSED STANDARD"),
    # Security BCP
    7525: ("Recommendations for Secure Use of TLS and DTLS", "BCP"),
    2827: ("Network Ingress Filtering (BCP 38)", "BCP"),
    6797: ("HTTP Strict Transport Security (HSTS)", "PROPOSED STANDARD"),
    9505: ("Survey of Worldwide Censorship Techniques", "INFORMATIONAL"),
    # Logging
    5424: ("Syslog Protocol", "PROPOSED STANDARD"),
    5425: ("TLS Transport Mapping for Syslog", "PROPOSED STANDARD"),
    # Certificates
    5280: ("X.509 PKI Certificate", "PROPOSED STANDARD"),
    6960: ("OCSP", "PROPOSED STANDARD"),
    6961: (
        "TLS Multiple Certificate Status Extension (OCSP Stapling)",
        "PROPOSED STANDARD",
    ),
    6962: ("Certificate Transparency", "EXPERIMENTAL"),
    7292: ("PKCS #12", "INFORMATIONAL"),
    7468: ("PEM Encoding", "PROPOSED STANDARD"),
    5958: ("Asymmetric Key Packages (PKCS #8)", "PROPOSED STANDARD"),
    6818: ("Updates to RFC 5280 (X.509)", "PROPOSED STANDARD"),
    8555: ("ACME (Automatic Certificate Management)", "PROPOSED STANDARD"),
    5652: ("Cryptographic Message Syntax (CMS)", "INTERNET STANDARD"),
    # Encoding
    8259: ("JSON", "INTERNET STANDARD"),
    8949: ("CBOR", "INTERNET STANDARD"),
    4648: ("Base Encodings (Base16, Base32, Base64)", "PROPOSED STANDARD"),
    3986: ("Uniform Resource Identifier (URI)", "INTERNET STANDARD"),
    # Traffic Shaping / QoS
    2474: ("Definition of the DS Field in IPv4 and IPv6 Headers", "PROPOSED STANDARD"),
    2475: ("An Architecture for Differentiated Services", "INFORMATIONAL"),
    2983: ("Differentiated Services and Tunnels", "INFORMATIONAL"),
    3168: ("The Addition of ECN to IP", "PROPOSED STANDARD"),
    2597: ("Assured Forwarding PHB Group", "PROPOSED STANDARD"),
    3246: ("An Expedited Forwarding PHB", "PROPOSED STANDARD"),
    4594: ("Configuration Guidelines for DiffServ Service Classes", "INFORMATIONAL"),
    8622: ("A Lower-Effort Per-Hop Behavior (LE PHB)", "PROPOSED STANDARD"),
    9438: ("CUBIC for Fast Long-Distance Networks", "PROPOSED STANDARD"),
    5681: ("TCP Congestion Control", "DRAFT STANDARD"),
    6298: ("Computing TCP's Retransmission Timer", "PROPOSED STANDARD"),
    9743: ("Specifying New Congestion Control Algorithms (BCP 133)", "BCP"),
    # IPFIX / NetFlow
    7011: ("IPFIX Protocol Specification (STD 77)", "INTERNET STANDARD"),
    7012: ("Information Model for IPFIX", "PROPOSED STANDARD"),
    7015: ("Flow Aggregation for IPFIX", "PROPOSED STANDARD"),
    5103: ("Bidirectional Flow Export Using IPFIX", "PROPOSED STANDARD"),
    # Post-Quantum Cryptography
    9794: ("Terminology for PQ/T Hybrid Schemes", "INFORMATIONAL"),
    # Obfuscation / Anti-Censorship
    9458: ("Oblivious HTTP (OHTTP)", "PROPOSED STANDARD"),
    9540: ("Discovery of Oblivious Services via SVCB", "PROPOSED STANDARD"),
    8744: ("Issues and Requirements for SNI Encryption in TLS", "INFORMATIONAL"),
    7685: ("TLS ClientHello Padding Extension", "PROPOSED STANDARD"),
    # RADIUS modernization
    9765: ("RADIUS/1.1: Removing MD5 via ALPN", "EXPERIMENTAL"),
    6929: ("RADIUS Protocol Extensions", "PROPOSED STANDARD"),
    3579: ("RADIUS Support for EAP", "INFORMATIONAL"),
    # Certificate management
    8737: ("ACME TLS-ALPN Challenge", "PROPOSED STANDARD"),
    9162: ("Certificate Transparency v2", "EXPERIMENTAL"),
    9773: ("ACME Renewal Information (ARI)", "PROPOSED STANDARD"),
    8738: ("ACME IP Identifier Validation", "PROPOSED STANDARD"),
    8739: ("STAR Certificates in ACME", "PROPOSED STANDARD"),
    6698: ("DANE TLSA", "PROPOSED STANDARD"),
    7671: ("DANE Protocol: Updates and Operational Guidance", "PROPOSED STANDARD"),
    # IPv6
    4291: ("IPv6 Addressing Architecture", "DRAFT STANDARD"),
    8201: ("Path MTU Discovery for IPv6", "PROPOSED STANDARD"),
    8981: ("Temporary Address Extensions for SLAAC", "PROPOSED STANDARD"),
    7217: ("Semantically Opaque Interface IDs with SLAAC", "PROPOSED STANDARD"),
    6437: ("IPv6 Flow Label Specification", "PROPOSED STANDARD"),
    6724: ("Default Address Selection for IPv6", "PROPOSED STANDARD"),
    4443: ("ICMPv6", "INTERNET STANDARD"),
    4862: ("IPv6 SLAAC", "DRAFT STANDARD"),
    6146: ("Stateful NAT64", "PROPOSED STANDARD"),
    # Address allocation
    8415: ("DHCPv6 (consolidated)", "PROPOSED STANDARD"),
    2131: ("DHCPv4", "DRAFT STANDARD"),
    # Monitoring
    9232: ("Network Telemetry Framework", "INFORMATIONAL"),
    # Structured logging
    7464: ("JSON Text Sequences", "PROPOSED STANDARD"),
    5426: ("UDP Transport for Syslog", "PROPOSED STANDARD"),
    # Tunneling
    8926: ("Geneve: Generic Network Virtualization Encapsulation", "PROPOSED STANDARD"),
    2784: ("GRE", "PROPOSED STANDARD"),
    2890: ("GRE Key and Sequence Extensions", "PROPOSED STANDARD"),
    # MASQUE extensions
    9614: ("Partitioning as an Architecture for Privacy", "INFORMATIONAL"),
    # WebSocket / WebTransport
    7692: ("Compression Extensions for WebSocket", "PROPOSED STANDARD"),
    # HTTP authentication
    9449: ("OAuth 2.0 DPoP", "PROPOSED STANDARD"),
    9421: ("HTTP Message Signatures", "PROPOSED STANDARD"),
    9440: ("Client-Cert HTTP Header Field", "INFORMATIONAL"),
    # Multipath / SCTP
    8684: ("MPTCP v1", "PROPOSED STANDARD"),
    9260: ("SCTP (revised)", "PROPOSED STANDARD"),
    # QUIC applicability
    9308: ("Applicability of QUIC Transport", "INFORMATIONAL"),
    9312: ("Manageability of QUIC", "INFORMATIONAL"),
    9230: ("Oblivious DNS over HTTPS (ODoH)", "PROPOSED STANDARD"),
}

# Manually curated important drafts
IMPORTANT_DRAFTS: dict[str, str] = {
    "draft-ietf-tls-esni": "Encrypted Client Hello (ECH)",
    "draft-ietf-quic-multipath": "QUIC Multipath",
    "draft-ietf-tls-hybrid-design": "Hybrid Key Exchange in TLS 1.3 (post-quantum)",
    "draft-connolly-tls-mlkem-key-agreement": "ML-KEM Key Agreement for TLS",
    "draft-ietf-radext-radiusv11": "RADIUS v1.1",
    "draft-ietf-dnsop-svcb-https": "SVCB/HTTPS DNS Records",
    "draft-ietf-quic-ack-frequency": "QUIC ACK Frequency",
    "draft-ietf-masque-connect-ethernet": "CONNECT-ETHERNET for MASQUE",
    "draft-ietf-tls-ctls": "Compact TLS 1.3",
    "draft-mavrogiannopoulos-openconnect": "OpenConnect VPN Protocol v1.2",
    "draft-ietf-ipsecme-ikev2-multiple-ke": "IKEv2 Multiple Key Exchange (PQ)",
    "draft-ietf-webtrans-http3": "WebTransport over HTTP/3",
    "draft-ietf-quic-reliable-stream-reset": "QUIC Reliable Stream Reset",
    "draft-ietf-tls-rfc8446bis": "TLS 1.3 (maintenance update)",
    "draft-ietf-quic-qlog-main-schema": "qlog: Main Schema",
    # Post-Quantum Cryptography
    "draft-ietf-tls-ecdhe-mlkem": "Post-quantum hybrid ECDHE-MLKEM for TLS 1.3",
    "draft-ietf-tls-mlkem": "ML-KEM Post-Quantum Key Agreement for TLS 1.3",
    "draft-ietf-tls-mldsa": "ML-DSA for TLS 1.3 Authentication",
    "draft-ietf-lamps-pq-composite-sigs": "Composite ML-DSA for X.509 PKI",
    "draft-ietf-uta-pqc-app": "PQC Recommendations for TLS Applications",
    # Obfuscation / Anti-Censorship
    "draft-ietf-tls-svcb-ech": "Bootstrapping TLS ECH with DNS SVCB",
    # RADIUS modernization
    "draft-ietf-radext-radiusdtls-bis": "RadSec: RADIUS over TLS and DTLS",
    "draft-ietf-radext-deprecating-radius": "Deprecating Insecure RADIUS Practices",
    # Congestion control
    "draft-ietf-ccwg-bbr": "BBR Congestion Control (BBRv3)",
    # MASQUE
    "draft-ietf-masque-quic-proxy": "QUIC-Aware Proxying Using HTTP",
    "draft-ietf-masque-connect-ip-dns": "DNS Config for CONNECT-IP",
    # TLS deprecation
    "draft-ietf-tls-deprecate-obsolete-kex": "Deprecating Obsolete Key Exchange in TLS 1.2",
    # ACME
    "draft-ietf-acme-client": "ACME End User Client Certificates",
}

# Critical RFC groups for the summary section
CRITICAL_GROUPS: dict[str, list[int]] = {
    "TLS/DTLS (core crypto stack)": [
        8446,
        9147,
        6347,
        5246,
        9146,
        7301,
        6066,
        8449,
        5077,
        8879,
        9149,
        9325,
        7627,
        8701,
        8996,
        7366,
        7457,
        7905,
        9848,
        9849,
        9151,
    ],
    "QUIC (future transport)": [
        9000,
        9001,
        9002,
        9221,
        9369,
        9443,
        9298,
        9484,
        9297,
        8999,
        8899,
        9204,
    ],
    "HTTP (control channel)": [
        9110,
        9112,
        9113,
        9114,
        6455,
        8441,
        7235,
        7617,
    ],
    "Authentication": [
        2865,
        2866,
        6614,
        7360,
        4511,
        4513,
        4515,
        6238,
        4226,
        7519,
        7515,
        6749,
        6750,
        7636,
        9190,
    ],
    "Cryptography": [
        5116,
        5288,
        8439,
        7748,
        8032,
        5869,
        2104,
        8017,
        9180,
        9106,
    ],
    "Certificates & PKI": [
        5280,
        6818,
        6960,
        6961,
        6962,
        7292,
        7468,
        5958,
        8555,
    ],
    "NAT Traversal & Connectivity": [
        8489,
        8656,
        8445,
        8305,
        7983,
    ],
    "DNS": [
        1035,
        7858,
        8484,
        9250,
        4033,
        9460,
    ],
    "IP & Transport": [
        791,
        8200,
        768,
        9293,
    ],
    "VPN protocols (reference)": [
        4301,
        7296,
        4303,
    ],
    "Security & Operations": [
        2827,
        6797,
        5424,
        9505,
    ],
    "Traffic Shaping / QoS": [
        2474,
        2475,
        2983,
        3168,
        2597,
        3246,
        9438,
        9743,
    ],
    "IPFIX / NetFlow": [
        7011,
        7012,
        7015,
        5103,
    ],
    "RADIUS (modern)": [
        9765,
        6929,
        3579,
    ],
    "Certificate Management": [
        8737,
        9162,
        9773,
        8738,
        6698,
        7671,
    ],
    "IPv6 (extended)": [
        4291,
        8201,
        8981,
        4443,
        6437,
        6724,
        4862,
    ],
    "Congestion Control": [
        9438,
        9002,
        5681,
        6298,
    ],
    "Obfuscation & Privacy": [
        9458,
        9540,
        8744,
        7685,
        9614,
    ],
    "Address Allocation": [
        8415,
        2131,
        4861,
    ],
    "Multipath / SCTP": [
        8684,
        9260,
    ],
}

# Protocol-to-RFC mapping for the matrix section
PROTOCOL_MATRIX: dict[str, list[str]] = {
    "OpenConnect VPN (control channel)": [
        "RFC 9110 (HTTP Semantics)",
        "RFC 9112 (HTTP/1.1)",
        "RFC 8446 (TLS 1.3)",
        "RFC 6455 (WebSocket)",
        "RFC 7301 (ALPN)",
        "RFC 6066 (SNI)",
        "draft-mavrogiannopoulos-openconnect-04",
    ],
    "DTLS Data Channel": [
        "RFC 9147 (DTLS 1.3)",
        "RFC 6347 (DTLS 1.2)",
        "RFC 9146 (DTLS Connection ID)",
        "RFC 8449 (Record Size Limit)",
        "RFC 9443 (Demux on port 443)",
        "RFC 8899 (DPLPMTUD)",
    ],
    "QUIC Transport (Hysteria 2, TUIC)": [
        "RFC 9000 (QUIC Transport)",
        "RFC 9001 (QUIC + TLS)",
        "RFC 9002 (Loss Detection)",
        "RFC 9221 (Datagrams)",
        "RFC 9369 (QUIC v2)",
        "RFC 9114 (HTTP/3)",
    ],
    "MASQUE (CONNECT-IP/CONNECT-UDP)": [
        "RFC 9298 (CONNECT-UDP)",
        "RFC 9484 (CONNECT-IP)",
        "RFC 9297 (HTTP Datagrams)",
    ],
    "Authentication": [
        "RFC 2865 (RADIUS)",
        "RFC 2866 (RADIUS Accounting)",
        "RFC 6614 (RADIUS/TLS)",
        "RFC 7360 (RADIUS/DTLS)",
        "RFC 4511 (LDAPv3)",
        "RFC 4513 (LDAP Auth)",
        "RFC 6238 (TOTP)",
        "RFC 4226 (HOTP)",
        "RFC 5280 (X.509)",
        "RFC 6960 (OCSP)",
        "RFC 7519 (JWT)",
        "RFC 6749 (OAuth 2.0)",
    ],
    "Cryptography (wolfSSL)": [
        "RFC 8446 S4.2 (Key Exchange)",
        "RFC 8439 (ChaCha20-Poly1305)",
        "RFC 5288 (AES-GCM for TLS)",
        "RFC 7748 (X25519/X448)",
        "RFC 8032 (Ed25519)",
        "RFC 5869 (HKDF)",
        "RFC 5116 (AEAD)",
        "RFC 8017 (RSA)",
        "RFC 9180 (HPKE)",
        "RFC 9106 (Argon2)",
    ],
    "DNS (Split DNS)": [
        "RFC 7858 (DoT)",
        "RFC 8484 (DoH)",
        "RFC 9250 (DoQ)",
        "RFC 9460 (SVCB/HTTPS)",
        "RFC 4033 (DNSSEC)",
    ],
    "NAT Traversal": [
        "RFC 8489 (STUN)",
        "RFC 8656 (TURN)",
        "RFC 8445 (ICE)",
        "RFC 8305 (Happy Eyeballs v2)",
    ],
    "Obfuscation & Anti-DPI": [
        "RFC 8446 S5.4 (TLS Record Padding)",
        "RFC 8701 (GREASE)",
        "RFC 9443 (Demux on port 443)",
        "RFC 9505 (Censorship Techniques Survey)",
        "RFC 7685 (ClientHello Padding)",
        "RFC 9458 (Oblivious HTTP)",
        "draft-ietf-tls-esni (ECH)",
        "draft-ietf-tls-svcb-ech (ECH DNS Bootstrap)",
    ],
    "Traffic Shaping / QoS": [
        "RFC 2474 (DS Field)",
        "RFC 2475 (DiffServ Architecture)",
        "RFC 2983 (DiffServ and Tunnels)",
        "RFC 3168 (ECN)",
        "RFC 9438 (CUBIC)",
        "draft-ietf-ccwg-bbr (BBRv3)",
    ],
    "Post-Quantum Cryptography": [
        "draft-ietf-tls-ecdhe-mlkem (Hybrid PQ for TLS 1.3)",
        "draft-ietf-tls-mlkem (Pure ML-KEM)",
        "draft-ietf-tls-mldsa (ML-DSA Auth)",
        "draft-ietf-lamps-pq-composite-sigs (Composite X.509)",
    ],
    "RADIUS (modern)": [
        "RFC 2865 (RADIUS Core)",
        "RFC 9765 (RADIUS/1.1 without MD5)",
        "RFC 6929 (RADIUS Extensions)",
        "draft-ietf-radext-radiusdtls-bis (RadSec)",
    ],
    "Certificate Automation": [
        "RFC 8555 (ACME Core)",
        "RFC 8737 (ACME TLS-ALPN)",
        "RFC 8738 (ACME IP Validation)",
        "RFC 9773 (ACME ARI)",
        "RFC 9162 (Certificate Transparency v2)",
        "RFC 6698 (DANE TLSA)",
    ],
    "Network Visibility (IPFIX)": [
        "RFC 7011 (IPFIX Protocol)",
        "RFC 7012 (IPFIX Information Model)",
        "RFC 7015 (Flow Aggregation)",
    ],
    "IPv6 & Address Management": [
        "RFC 8200 (IPv6)",
        "RFC 4291 (IPv6 Addressing)",
        "RFC 8201 (IPv6 PMTUD)",
        "RFC 8415 (DHCPv6)",
        "RFC 4861 (Neighbor Discovery)",
        "RFC 4862 (SLAAC)",
    ],
}

# Relevance scoring keywords
HIGH_RELEVANCE_KEYWORDS: list[str] = [
    "tls 1.3",
    "dtls",
    "quic",
    "vpn",
    "tunnel",
    "ipsec",
    "radius",
    "totp",
    "hotp",
    "dns over",
    "websocket",
    "x25519",
    "chacha20",
    "aes-gcm",
    "x.509",
    "ocsp",
    "http/3",
    "http/2",
    "masque",
    "connect-ip",
    "connect-udp",
    "happy eyeballs",
    "nat traversal",
    "stun",
    "turn",
    "ice",
    "certificate",
    "aead",
    "hkdf",
    "hmac",
    "oauth",
    "ldap",
    "sni",
    "alpn",
    "encrypted client hello",
    "connection id",
    "session resumption",
    "wireguard",
    "ml-kem",
    "post-quantum",
    "diffserv",
    "dscp",
    "ipfix",
    "acme",
    "dane",
    "oblivious http",
    "cubic",
    "bbr",
    "radius/1.1",
    "radsec",
    "geneve",
    "dhcpv6",
    "slaac",
    "nat64",
    "dpop",
]

MEDIUM_RELEVANCE_KEYWORDS: list[str] = [
    "congestion",
    "ipv6",
    "tunneling",
    "syslog",
    "json",
    "compression",
    "zstandard",
    "pem",
    "pkcs",
    "cbor",
    "multipath",
    "ecn",
    "padding",
    "firewall",
    "netflow",
    "flow export",
    "certificate transparency",
    "qos",
    "traffic shaping",
    "sctp",
    "neighbor discovery",
    "flow label",
]

DRAFT_RELEVANCE_KEYWORDS: list[str] = [
    "tls",
    "dtls",
    "quic",
    "vpn",
    "tunnel",
    "radius",
    "dns",
    "certificate",
    "encrypt",
    "key exchange",
    "websocket",
    "masque",
    "connect",
    "authentication",
]


# ── API client ────────────────────────────────────────────────────────


def _create_session() -> requests.Session:
    """Create a reusable HTTP session with connection pooling."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        ),
    )
    session.mount("https://", adapter)
    return session


def _parse_rfc_number(name: str) -> int | None:
    """Extract RFC number from a document name like 'rfc8446'."""
    if name.startswith("rfc"):
        try:
            return int(name[3:])
        except ValueError:
            pass
    return None


def search_datatracker_rfcs(
    session: requests.Session,
    query: str,
    *,
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """Search datatracker for RFCs matching a title query."""
    params: dict[str, str | int] = {
        "title__icontains": query,
        "type": DOCTYPE_RFC,
        "limit": max_results,
        "format": "json",
        "order_by": "-rfc_number",
    }
    try:
        resp = session.get(
            f"{DATATRACKER_API}/doc/document/",
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for obj in data.get("objects", []):
            rfc_num = _parse_rfc_number(obj.get("name", ""))
            if rfc_num is not None:
                results.append(
                    {
                        "rfc": rfc_num,
                        "title": obj.get("title", ""),
                        "status": obj.get("std_level", ""),
                        "pages": obj.get("pages"),
                    }
                )
        return results
    except requests.RequestException as exc:
        log.warning("Datatracker RFC search failed for %r: %s", query, exc)
        return []


def search_datatracker_drafts(
    session: requests.Session,
    query: str,
    *,
    max_results: int = 5,
) -> list[dict[str, Any]]:
    """Search datatracker for active Internet-Drafts."""
    params: dict[str, str | int] = {
        "title__icontains": query,
        "type": DOCTYPE_DRAFT,
        "states__slug__in": "active",
        "limit": max_results,
        "format": "json",
        "order_by": "-time",
    }
    try:
        resp = session.get(
            f"{DATATRACKER_API}/doc/document/",
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return [
            {
                "name": obj.get("name", ""),
                "title": obj.get("title", ""),
                "rev": obj.get("rev", ""),
            }
            for obj in data.get("objects", [])
        ]
    except requests.RequestException as exc:
        log.warning("Datatracker draft search failed for %r: %s", query, exc)
        return []


def fetch_rfc_metadata(
    session: requests.Session,
    rfc_numbers: list[int],
    *,
    batch_size: int = 20,
) -> dict[int, dict[str, Any]]:
    """Fetch metadata for multiple RFCs using name__in batches."""
    result: dict[int, dict[str, Any]] = {}
    for i in range(0, len(rfc_numbers), batch_size):
        batch = rfc_numbers[i : i + batch_size]
        names = ",".join(f"rfc{n}" for n in batch)
        try:
            resp = session.get(
                f"{DATATRACKER_API}/doc/document/",
                params={"name__in": names, "format": "json", "limit": batch_size},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            for obj in resp.json().get("objects", []):
                rfc_num = _parse_rfc_number(obj.get("name", ""))
                if rfc_num is not None:
                    result[rfc_num] = {
                        "title": obj.get("title", ""),
                        "status": obj.get("std_level", ""),
                        "pages": obj.get("pages"),
                        "abstract": obj.get("abstract", ""),
                    }
        except requests.RequestException as exc:
            log.warning("Batch metadata fetch failed: %s", exc)
        time.sleep(RATE_LIMIT_DELAY)
    return result


def download_rfc_txt(
    session: requests.Session,
    rfc_num: int,
    dest_dir: Path,
) -> Path | None:
    """Download RFC plain-text to dest_dir/rfcNNNN.txt."""
    dest = dest_dir / f"rfc{rfc_num}.txt"
    if dest.exists():
        log.debug("Already exists: %s", dest)
        return dest
    url = f"{RFC_EDITOR_BASE}/rfc/rfc{rfc_num}.txt"
    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        log.info("Downloaded rfc%d (%d bytes)", rfc_num, len(resp.content))
        return dest
    except requests.RequestException as exc:
        log.warning("Failed to download rfc%d: %s", rfc_num, exc)
        return None


# ── Collection ────────────────────────────────────────────────────────


def collect_rfcs(
    session: requests.Session,
) -> tuple[dict[int, RfcEntry], dict[str, DraftEntry]]:
    """Search all categories and collect RFC + draft entries."""
    rfcs: dict[int, RfcEntry] = {}
    drafts: dict[str, DraftEntry] = {}

    for cat_name, queries in CATEGORIES.items():
        log.info("Category: %s", cat_name)

        for query in queries:
            log.debug("  Search: %s", query)

            for r in search_datatracker_rfcs(session, query):
                num = r["rfc"]
                if num not in rfcs:
                    rfcs[num] = RfcEntry(
                        number=num,
                        title=r["title"],
                        status=r.get("status", ""),
                        pages=r.get("pages"),
                    )
                rfcs[num].categories.add(cat_name)

            for d in search_datatracker_drafts(session, query):
                name = d["name"]
                if name not in drafts:
                    drafts[name] = DraftEntry(
                        name=name,
                        title=d["title"],
                        rev=d.get("rev", ""),
                    )
                drafts[name].categories.add(cat_name)

            time.sleep(RATE_LIMIT_DELAY)

    # Merge known critical RFCs
    for rfc_num, (title, status) in KNOWN_CRITICAL.items():
        if rfc_num not in rfcs:
            rfcs[rfc_num] = RfcEntry(number=rfc_num, title=title, status=status)
        rfcs[rfc_num].categories.add("Curated critical")

    return rfcs, drafts


# ── Scoring ───────────────────────────────────────────────────────────


def relevance_score(entry: RfcEntry) -> int:
    """Score an RFC's relevance to the ioguard project."""
    score = 0
    title_lower = entry.title.lower()

    for kw in HIGH_RELEVANCE_KEYWORDS:
        if kw in title_lower:
            score += 10
    for kw in MEDIUM_RELEVANCE_KEYWORDS:
        if kw in title_lower:
            score += 5

    if entry.number in KNOWN_CRITICAL:
        score += 20

    status_lower = entry.status.lower() if entry.status else ""
    if "standard" in status_lower:
        score += 3
    elif "proposed" in status_lower:
        score += 2

    return score


# ── Markdown generation ──────────────────────────────────────────────


def _status_label(rfc_num: int, entry: RfcEntry) -> str:
    """Resolve display status: prefer curated, fall back to API."""
    if rfc_num in KNOWN_CRITICAL:
        return KNOWN_CRITICAL[rfc_num][1]
    status = entry.status
    if isinstance(status, str) and "/" in status:
        return status.rsplit("/", maxsplit=1)[-1].strip()
    return status or ""


def generate_markdown(rfcs: dict[int, RfcEntry], drafts: dict[str, DraftEntry]) -> str:
    """Generate the full Markdown registry."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    w = lines.append

    w("# ioguard VPN — RFC Registry\n")
    w(f"**Generated**: {now}")
    w(f"**RFCs found**: {len(rfcs)}")
    w(f"**Active Internet-Drafts found**: {len(drafts)}")
    w("")

    # Statistics
    status_counts: dict[str, int] = defaultdict(int)
    for entry in rfcs.values():
        label = (entry.status or "UNKNOWN").upper()
        if "/" in label:
            label = label.rsplit("/", maxsplit=1)[-1].strip()
        status_counts[label] += 1

    w("---\n")
    w("## Statistics\n")
    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        w(f"- **{status}**: {count}")
    w("")

    # Critical RFCs
    w("---\n")
    w("## Critical RFCs (must-implement)\n")

    for group_name, rfc_nums in CRITICAL_GROUPS.items():
        w(f"\n### {group_name}\n")
        w("| RFC | Title | Status | Relevance |")
        w("|-----|-------|--------|-----------|")
        for num in rfc_nums:
            entry = rfcs.get(num)
            title = entry.title if entry else KNOWN_CRITICAL.get(num, ("?",))[0]
            status = (
                _status_label(num, entry)
                if entry
                else KNOWN_CRITICAL.get(num, ("", ""))[1]
            )
            score = relevance_score(entry) if entry else 0
            w(
                f"| [{num}]({RFC_EDITOR_BASE}/rfc/rfc{num}) | {title} | {status} | {score} |"
            )

    # High-relevance non-critical RFCs
    critical_set: set[int] = set()
    for nums in CRITICAL_GROUPS.values():
        critical_set.update(nums)

    scored = sorted(
        ((relevance_score(e), e) for e in rfcs.values()),
        key=lambda x: (-x[0], x[1].number),
    )

    w("\n---\n")
    w("## High-relevance RFCs (not in critical list)\n")
    w("| RFC | Title | Status | Score |")
    w("|-----|-------|--------|-------|")
    count = 0
    for score, entry in scored:
        if entry.number in critical_set or score < 5:
            continue
        status = _status_label(entry.number, entry)
        w(
            f"| [{entry.number}]({entry.url}) | {entry.title[:80]} | {status} | {score} |"
        )
        count += 1
        if count >= 60:
            break

    # Important drafts
    w("\n---\n")
    w("## Active Internet-Drafts\n")
    w("| Draft | Description | Status |")
    w("|-------|-------------|--------|")
    for name, desc in IMPORTANT_DRAFTS.items():
        w(f"| [{name}]({DATATRACKER_BASE}/doc/{name}/) | {desc} | Curated |")

    # Discovered drafts
    seen = set(IMPORTANT_DRAFTS.keys())
    draft_scored: list[tuple[int, DraftEntry]] = []
    for entry in drafts.values():
        base = (
            entry.name.rsplit("-", maxsplit=1)[0]
            if entry.name[-1:].isdigit()
            else entry.name
        )
        if base in seen or entry.name in seen:
            continue
        seen.add(base)
        t_lower = entry.title.lower()
        dscore = sum(10 for kw in DRAFT_RELEVANCE_KEYWORDS if kw in t_lower)
        if dscore >= 10:
            draft_scored.append((dscore, entry))

    if draft_scored:
        draft_scored.sort(key=lambda x: -x[0])
        w("\n### Additional discovered drafts\n")
        w("| Draft | Title | Categories |")
        w("|-------|-------|------------|")
        for _, entry in draft_scored[:30]:
            cats = ", ".join(sorted(entry.categories)) if entry.categories else "-"
            w(f"| [{entry.name}]({entry.url}) | {entry.title[:80]} | {cats} |")

    # Protocol matrix
    w("\n---\n")
    w("## Protocol-to-RFC matrix for ioguard\n")
    for component, rfc_refs in PROTOCOL_MATRIX.items():
        w(f"\n### {component}\n")
        for ref in rfc_refs:
            w(f"- {ref}")

    return "\n".join(lines)


def generate_json(rfcs: dict[int, RfcEntry], drafts: dict[str, DraftEntry]) -> str:
    """Generate JSON output."""
    data = {
        "generated": datetime.now(tz=timezone.utc).isoformat(),
        "rfcs": {
            num: {
                "title": e.title,
                "status": e.status,
                "pages": e.pages,
                "categories": sorted(e.categories),
                "relevance": relevance_score(e),
                "url": e.url,
            }
            for num, e in sorted(rfcs.items())
        },
        "drafts": {
            e.name: {
                "title": e.title,
                "rev": e.rev,
                "categories": sorted(e.categories),
                "url": e.url,
            }
            for e in sorted(drafts.values(), key=lambda x: x.name)
        },
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ── CLI ───────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RFC scraper for the ioguard VPN project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON instead of Markdown",
    )
    parser.add_argument(
        "--download",
        type=Path,
        default=None,
        metavar="DIR",
        help="Download RFC .txt files to DIR (only critical RFCs)",
    )
    parser.add_argument(
        "--download-all",
        type=Path,
        default=None,
        metavar="DIR",
        help="Download ALL discovered RFC .txt files to DIR",
    )
    parser.add_argument(
        "--skip-search",
        action="store_true",
        help="Skip API search, only use curated KNOWN_CRITICAL list",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Configure logging
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)-5s %(message)s",
        stream=sys.stderr,
    )

    session = _create_session()

    # Collect RFCs
    if args.skip_search:
        log.info("Skipping API search, using curated list only")
        rfcs: dict[int, RfcEntry] = {}
        for rfc_num, (title, status) in KNOWN_CRITICAL.items():
            rfcs[rfc_num] = RfcEntry(
                number=rfc_num,
                title=title,
                status=status,
                categories={"Curated critical"},
            )
        drafts: dict[str, DraftEntry] = {}
    else:
        log.info("Scanning datatracker.ietf.org...")
        rfcs, drafts = collect_rfcs(session)

    log.info("Found %d RFCs and %d drafts", len(rfcs), len(drafts))

    # Download RFC text files
    download_dir = args.download_all or args.download
    if download_dir is not None:
        download_dir.mkdir(parents=True, exist_ok=True)
        if args.download_all:
            nums_to_download = sorted(rfcs.keys())
        else:
            nums_to_download = sorted(KNOWN_CRITICAL.keys())
        log.info("Downloading %d RFCs to %s", len(nums_to_download), download_dir)
        ok = 0
        for rfc_num in nums_to_download:
            if download_rfc_txt(session, rfc_num, download_dir):
                ok += 1
            time.sleep(RATE_LIMIT_DELAY)
        log.info("Downloaded %d/%d RFC files", ok, len(nums_to_download))

    # Generate output
    if args.json_output:
        output = generate_json(rfcs, drafts)
    else:
        output = generate_markdown(rfcs, drafts)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        log.info("Written to %s (%d chars)", args.output, len(output))
    else:
        sys.stdout.write(output)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
