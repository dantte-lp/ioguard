# GnuTLS API Audit - ocserv to wolfSSL Migration

**Project**: ringwall v2.0.0-alpha.1
**Date**: 2025-10-29
**Author**: ringwall Architecture Team
**Status**: In Progress

## Executive Summary

This document provides a comprehensive audit of all GnuTLS API usage in the upstream ocserv codebase (https://gitlab.com/openconnect/ocserv), mapping each function to its wolfSSL equivalent and assessing migration complexity.

**Key Statistics**:
- **Total unique GnuTLS functions identified**: 94
- **Primary TLS/DTLS files**: 21 files with gnutls.h includes
- **Total gnutls_ function calls**: 457 occurrences across 25 files
- **Core abstraction layer**: `src/tlslib.c` (142 calls) and `src/tlslib.h` (21 calls)

## Upstream Repository Analysis

**Repository**: https://gitlab.com/openconnect/ocserv.git
**Latest Commit**: 284f2ecd (Merge branch 'tmp-protobuf')
**Recent Updates**:
- Migration to llhttp (21bef68a)
- Linux kernel coding style adoption (78c65b5a)
- Protobuf 1.5.1 update (78658605)

### Directory Structure

```
ocserv-upstream/src/
├── acct/               # Accounting (PAM, RADIUS)
├── auth/               # Authentication modules
├── ccan/               # C utility library
├── common/             # Common utilities (hmac.c uses GnuTLS)
├── inih/               # INI parser
├── llhttp/             # HTTP parser (recently migrated)
├── occtl/              # Control utility
├── ocpasswd/           # Password utility (uses GnuTLS)
├── pcl/                # Process control
├── protobuf/           # Protocol buffers
├── sup-config/         # Config support
├── tlslib.c            # TLS ABSTRACTION LAYER (PRIMARY TARGET)
├── tlslib.h            # TLS abstraction header
├── worker-*.c          # Worker process implementations
├── sec-mod*.c          # Security module
└── main-*.c            # Main process components
```

## GnuTLS Function Inventory

### Category 1: Library Initialization and Global State

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_global_init()` | `wolfSSL_Init()` | LOW | Direct mapping |
| `gnutls_global_deinit()` | `wolfSSL_Cleanup()` | LOW | Direct mapping |
| `gnutls_check_version()` | `wolfSSL_lib_version()` | LOW | String format differs |
| `gnutls_check_version_numeric()` | `LIBWOLFSSL_VERSION_HEX` | LOW | Macro comparison |
| `gnutls_global_set_log_function()` | `wolfSSL_SetLoggingCb()` | LOW | Signature differs slightly |
| `gnutls_global_set_log_level()` | `wolfSSL_Debugging_ON()`/`OFF()` | LOW | Different approach |
| `gnutls_global_set_audit_log_function()` | Custom implementation | MEDIUM | No direct equivalent |

**Migration Strategy**: Replace in initialization code paths. Audit logging requires custom wrapper.

### Category 2: Session Management

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_init()` | `wolfSSL_new()` | MEDIUM | Requires WOLFSSL_CTX first |
| `gnutls_deinit()` | `wolfSSL_free()` | LOW | Direct mapping |
| `gnutls_session_set_ptr()` | `wolfSSL_SetIOWriteCtx()`/`ReadCtx()` | MEDIUM | Split into read/write contexts |
| `gnutls_session_get_ptr()` | `wolfSSL_GetIOWriteCtx()` | LOW | Direct mapping |
| `gnutls_session_get_desc()` | Custom implementation | HIGH | No direct equivalent - need custom |
| `gnutls_session_set_premaster()` | `wolfSSL_set_session()` | HIGH | PSK-specific, complex |

**Migration Strategy**: Refactor session lifecycle management. Context pointers need careful handling.

### Category 3: Certificate and Credential Management

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_certificate_allocate_credentials()` | `wolfSSL_CTX_new()` | MEDIUM | Different abstraction level |
| `gnutls_certificate_free_credentials()` | `wolfSSL_CTX_free()` | LOW | Direct mapping |
| `gnutls_certificate_set_key()` | `wolfSSL_CTX_use_certificate_file()` + `wolfSSL_CTX_use_PrivateKey_file()` | MEDIUM | Split into separate calls |
| `gnutls_certificate_server_set_request()` | `wolfSSL_CTX_set_verify()` | MEDIUM | Different verification model |
| `gnutls_certificate_set_verify_function()` | `wolfSSL_CTX_set_verify()` callback | MEDIUM | Callback signature differs |
| `gnutls_certificate_get_peers()` | `wolfSSL_get_peer_certificate()` | MEDIUM | Return type differs |
| `gnutls_certificate_get_ours()` | `wolfSSL_get_certificate()` | LOW | Direct mapping |
| `gnutls_certificate_get_crt_raw()` | `wolfSSL_get_peer_certificate()` | MEDIUM | DER encoding handling |
| `gnutls_certificate_verification_status_print()` | Custom implementation | MEDIUM | Need custom formatter |
| `gnutls_certificate_type_get()` | `wolfSSL_get_peer_certificate()` + type check | LOW | Extract from cert |
| `gnutls_certificate_set_flags()` | Various `wolfSSL_CTX_*` functions | MEDIUM | Flag-specific mapping |

**Migration Strategy**: Certificate handling is a major refactor area. Need comprehensive wrapper functions.

### Category 4: DH Parameters and Key Exchange

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_dh_params_init()` | `wolfSSL_CTX_SetTmpDH()` | MEDIUM | Different initialization |
| `gnutls_certificate_set_dh_params()` | `wolfSSL_CTX_SetTmpDH_file()` | MEDIUM | File-based or buffer |
| `gnutls_certificate_set_known_dh_params()` | `wolfSSL_CTX_SetMinDhKey_Sz()` | MEDIUM | Different approach |

**Migration Strategy**: DH parameters require careful handling. Consider using ECDHE by default (TLS 1.3).

### Category 5: PSK (Pre-Shared Key) Support

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_psk_allocate_server_credentials()` | `wolfSSL_CTX_new()` + PSK setup | MEDIUM | Integrated into CTX |
| `gnutls_psk_free_server_credentials()` | `wolfSSL_CTX_free()` | LOW | Automatic cleanup |
| `gnutls_psk_set_server_credentials_function()` | `wolfSSL_CTX_set_psk_server_callback()` | MEDIUM | Callback signature differs |

**Migration Strategy**: PSK support is critical for ocserv. Test thoroughly with Cisco clients.

### Category 6: Priority Strings and Cipher Suites

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_priority_init()` | `wolfSSL_CTX_set_cipher_list()` | HIGH | **CRITICAL** - Priority string parser needed |
| `gnutls_priority_set()` | N/A | HIGH | Applied during init |
| `gnutls_priority_set_direct()` | `wolfSSL_set_cipher_list()` | HIGH | Per-session priority |
| `gnutls_priority_deinit()` | N/A | LOW | Automatic cleanup |

**Migration Strategy**: **HIGH PRIORITY** - Need to implement GnuTLS priority string parser or maintain configuration compatibility. This is a major compatibility risk.

**Example GnuTLS Priority String**:
```
NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0
```

**Translation Requirements**:
- Parse priority string syntax
- Map cipher suite names
- Handle version constraints
- Support keyword expansion (NORMAL, SECURE, etc.)

### Category 7: TLS Handshake

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_handshake()` | `wolfSSL_connect()`/`wolfSSL_accept()` | MEDIUM | Client/server split |
| `gnutls_handshake_set_timeout()` | `wolfSSL_set_timeout()` | LOW | Direct mapping |
| `gnutls_handshake_set_hook_function()` | Custom implementation | HIGH | No direct equivalent |
| `gnutls_safe_renegotiation_status()` | `wolfSSL_Rehandshake()` status | MEDIUM | Different API |

**Migration Strategy**: Handshake hooks require custom implementation for debugging/monitoring.

### Category 8: Record Layer I/O

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_record_send()` | `wolfSSL_write()` | LOW | Direct mapping |
| `gnutls_record_recv()` | `wolfSSL_read()` | LOW | Direct mapping |
| `gnutls_record_recv_packet()` | Custom with `wolfSSL_read()` | MEDIUM | Packet-based I/O |
| `gnutls_record_check_pending()` | `wolfSSL_pending()` | LOW | Direct mapping |
| `gnutls_record_cork()` | Custom implementation | MEDIUM | TCP_CORK at socket level |
| `gnutls_record_uncork()` | Custom implementation | MEDIUM | TCP_CORK at socket level |
| `gnutls_packet_get()` | N/A | MEDIUM | GnuTLS-specific |
| `gnutls_packet_deinit()` | N/A | LOW | Cleanup |

**Migration Strategy**: Record layer is straightforward except for packet-based API. Cork/uncork already has socket-level fallback in ocserv.

### Category 9: DTLS Support

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_dtls_set_mtu()` | `wolfSSL_dtls_set_mtu()` | LOW | Direct mapping |
| `gnutls_dtls_get_mtu()` | `wolfSSL_dtls_get_current_mtu()` | LOW | Direct mapping |
| `gnutls_dtls_set_data_mtu()` | `wolfSSL_dtls_set_mtu()` | LOW | Direct mapping |
| `gnutls_dtls_get_data_mtu()` | `wolfSSL_dtls_get_current_mtu()` | LOW | Direct mapping |
| `gnutls_dtls_set_timeouts()` | `wolfSSL_dtls_set_timeout_init()`/`max()` | LOW | Direct mapping |

**Migration Strategy**: DTLS support is well-aligned between libraries. Low risk.

### Category 10: Transport Layer Integration

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_transport_set_ptr()` | `wolfSSL_set_fd()` or custom I/O | MEDIUM | Different approaches |
| `gnutls_transport_set_push_function()` | `wolfSSL_SetIOSend()` | LOW | Direct mapping |
| `gnutls_transport_set_pull_function()` | `wolfSSL_SetIORecv()` | LOW | Direct mapping |
| `gnutls_transport_set_pull_timeout_function()` | Custom implementation | MEDIUM | Timeout handling differs |

**Migration Strategy**: Custom I/O callbacks are well-supported. Need wrapper for timeout behavior.

### Category 11: Session Resumption and Caching

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_db_set_ptr()` | `wolfSSL_CTX_set_session_cache_mode()` | MEDIUM | Different abstraction |
| `gnutls_db_set_store_function()` | `wolfSSL_CTX_sess_set_new_cb()` | MEDIUM | Callback semantics differ |
| `gnutls_db_set_retrieve_function()` | `wolfSSL_CTX_sess_set_get_cb()` | MEDIUM | Callback semantics differ |
| `gnutls_db_set_remove_function()` | `wolfSSL_CTX_sess_set_remove_cb()` | MEDIUM | Callback semantics differ |
| `gnutls_db_check_entry_time()` | `wolfSSL_SESSION_get_time()` | LOW | Time check |
| `gnutls_db_set_cache_expiration()` | `wolfSSL_CTX_set_timeout()` | LOW | Direct mapping |

**Migration Strategy**: Session caching callbacks need careful refactoring. Critical for performance.

### Category 12: Cryptographic Information

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_protocol_get_version()` | `wolfSSL_get_version()` | LOW | Direct mapping |
| `gnutls_cipher_get()` | `wolfSSL_get_current_cipher()` | LOW | Direct mapping |
| `gnutls_cipher_get_name()` | `wolfSSL_get_cipher()` | LOW | Direct mapping |
| `gnutls_mac_get()` | `wolfSSL_get_current_cipher()` + parse | MEDIUM | Extract from cipher info |
| `gnutls_mac_get_name()` | Custom lookup | MEDIUM | Need name mapping |
| `gnutls_est_record_overhead_size()` | `wolfSSL_GetMaxRecordSize()` calc | MEDIUM | Calculate overhead |

**Migration Strategy**: Information retrieval is mostly straightforward with minor parsing needs.

### Category 13: Alerts

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_alert_get()` | `wolfSSL_get_alert_history()` | MEDIUM | Different API structure |
| `gnutls_alert_get_name()` | Custom string table | LOW | Simple lookup |
| `gnutls_alert_send()` | `wolfSSL_SendAlert()` | LOW | Direct mapping |
| `gnutls_bye()` | `wolfSSL_shutdown()` | LOW | Direct mapping |

**Migration Strategy**: Alert handling is straightforward. Need alert name lookup table.

### Category 14: Error Handling

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_strerror()` | `wolfSSL_ERR_error_string()` | MEDIUM | Error code mapping needed |
| `gnutls_error_is_fatal()` | Custom logic | MEDIUM | Different error model |

**Migration Strategy**: Error code translation layer required. Critical for debugging.

### Category 15: Cryptographic Utilities

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_hash_fast()` | `wc_Hash()` | LOW | Direct mapping |
| `gnutls_rnd()` | `wc_RNG_GenerateBlock()` | MEDIUM | Requires RNG init |
| `gnutls_hex_encode()` | `Base16_Encode()` | LOW | Direct mapping |
| `gnutls_prf()` | `wolfSSL_get_keys()` + PRF | HIGH | Complex TLS PRF |

**Migration Strategy**: Crypto utilities need wolfCrypt (wolfSSL's crypto library) integration.

### Category 16: PKCS#11 and Hardware Tokens

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_privkey_init()` | `wolfSSL_CTX_use_PrivateKey()` | MEDIUM | Different abstraction |
| `gnutls_privkey_deinit()` | Automatic cleanup | LOW | Cleanup |
| `gnutls_privkey_import_url()` | Custom PKCS#11 layer | HIGH | wolfSSL PKCS#11 support varies |
| `gnutls_privkey_set_pin_function()` | Custom PKCS#11 layer | HIGH | PIN callback |
| `gnutls_privkey_sign_hash()` | `wc_SignatureGenerate()` | MEDIUM | Different API |
| `gnutls_privkey_decrypt_data()` | `wc_RsaPrivateDecrypt()` | MEDIUM | Algorithm-specific |
| `gnutls_privkey_get_pk_algorithm()` | Extract from key | LOW | Metadata access |
| `gnutls_pubkey_get_pk_algorithm()` | Extract from cert | LOW | Metadata access |
| `gnutls_url_is_supported()` | Custom check | MEDIUM | URL scheme validation |
| `gnutls_sign_supports_pk_algorithm()` | `wolfSSL_CTX_UseSupportedCurve()` | MEDIUM | Algorithm support check |

**Migration Strategy**: **HIGH RISK** - PKCS#11 support is critical for enterprise deployments. wolfSSL's PKCS#11 support may require additional work or alternative approaches.

### Category 17: OCSP (Online Certificate Status Protocol)

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_certificate_set_ocsp_status_request_function()` | `wolfSSL_CTX_EnableOCSP()` + callback | HIGH | Different callback model |

**Migration Strategy**: OCSP support needs careful validation. Critical for certificate revocation.

### Category 18: Miscellaneous

| GnuTLS Function | wolfSSL Equivalent | Complexity | Notes |
|----------------|-------------------|------------|-------|
| `gnutls_malloc()` | `XMALLOC()` | LOW | Memory allocator |
| `gnutls_free()` | `XFREE()` | LOW | Memory deallocator |
| `gnutls_load_file()` | Custom implementation | LOW | File I/O utility |
| `gnutls_idna_map()` | Custom IDNA library | MEDIUM | Internationalized domain names |
| `gnutls_credentials_set()` | Various `wolfSSL_CTX_*` | MEDIUM | Credential type-specific |

**Migration Strategy**: Utility functions are straightforward to replace.

## File-by-File Analysis

### Critical Files with Heavy GnuTLS Usage

#### 1. `src/tlslib.c` (142 calls)
**Purpose**: Primary TLS abstraction layer
**Complexity**: HIGH
**Functions**:
- `tls_global_init()` - Global TLS initialization
- `tls_vhost_init()` - Virtual host TLS setup
- `tls_load_files()` - Certificate/key loading
- `tls_load_prio()` - Priority string parsing
- `cstp_send()`/`cstp_recv()` - CSTP protocol I/O
- `dtls_send()`/`dtls_recv()` - DTLS I/O
- Session caching infrastructure

**Migration Strategy**: This file is the PRIMARY MIGRATION TARGET. Convert to backend-agnostic API.

#### 2. `src/worker-http.c` (62 calls)
**Purpose**: HTTP handling in worker processes
**Complexity**: MEDIUM
**GnuTLS Usage**: Session management, I/O operations

#### 3. `src/sec-mod.c` (24 calls)
**Purpose**: Security module main logic
**Complexity**: MEDIUM
**GnuTLS Usage**: Certificate operations, credential management

#### 4. `src/worker-http-handlers.c` (23 calls)
**Purpose**: HTTP request handlers
**Complexity**: MEDIUM
**GnuTLS Usage**: Session information retrieval

#### 5. `src/worker-auth.c` (17 calls)
**Purpose**: Worker authentication logic
**Complexity**: MEDIUM
**GnuTLS Usage**: Certificate verification, client authentication

## Migration Complexity Assessment

### Low Complexity (35 functions)
Direct API mapping with minimal refactoring:
- Basic I/O operations
- Simple getter/setter functions
- Standard DTLS operations
- Error string lookups

**Estimated Effort**: 1-2 weeks

### Medium Complexity (40 functions)
Requires wrapper functions or moderate refactoring:
- Session management differences
- Certificate handling
- Transport layer integration
- Callback signature changes

**Estimated Effort**: 4-6 weeks

### High Complexity (19 functions)
Significant architectural changes or custom implementation:
- Priority string parsing (**CRITICAL**)
- PKCS#11 integration (**RISK**)
- OCSP callback model
- Session resumption callbacks
- Handshake hooks
- Custom session descriptors

**Estimated Effort**: 8-12 weeks

## Critical Cisco Compatibility Considerations

### 1. Priority String Compatibility
**Risk**: HIGH
**Impact**: Configuration files use GnuTLS priority strings
**Mitigation**: Implement priority string parser or configuration migration tool

### 2. DTLS Behavior
**Risk**: MEDIUM
**Impact**: Cisco clients expect specific DTLS timeout behavior
**Mitigation**: Extensive testing with actual Cisco Secure Client 5.x

### 3. Session Resumption
**Risk**: MEDIUM
**Impact**: Performance and user experience depend on session resumption
**Mitigation**: Validate session caching behavior matches GnuTLS

### 4. Certificate Authentication
**Risk**: HIGH
**Impact**: Enterprise deployments require certificate auth
**Mitigation**: Comprehensive certificate validation testing

### 5. PSK Support
**Risk**: MEDIUM
**Impact**: Some deployments use PSK for performance
**Mitigation**: PSK callback compatibility testing

## Recommended Abstraction Layer Design

### Phase 1: Minimal Abstraction (Sprint 1-2)
Create thin wrapper around most common operations:
```c
// Context management
tls_ctx_t* tls_ctx_new(tls_backend_t backend);
void tls_ctx_free(tls_ctx_t *ctx);

// Session management
tls_session_t* tls_session_new(tls_ctx_t *ctx);
void tls_session_free(tls_session_t *session);

// I/O operations
ssize_t tls_read(tls_session_t *session, void *buf, size_t len);
ssize_t tls_write(tls_session_t *session, const void *buf, size_t len);

// Handshake
int tls_handshake(tls_session_t *session);
```

### Phase 2: Complete Abstraction (Sprint 3-6)
Full feature parity including:
- Priority string parsing
- Certificate verification callbacks
- Session caching
- DTLS support
- PKCS#11 integration

### Phase 3: Advanced Features (Sprint 7+)
wolfSSL-specific optimizations:
- TLS 1.3 native support
- Post-quantum crypto readiness
- Performance tuning

## Dependencies and Prerequisites

### Build System Changes
- Add wolfSSL detection to `configure.ac`
- Add backend selection option (`--with-tls=wolfssl|gnutls`)
- Update pkg-config files

### Testing Requirements
- Unit tests for each abstraction layer function
- Integration tests with Cisco Secure Client
- Performance benchmarks (before/after)
- Compatibility matrix validation

### Documentation Updates
- Configuration migration guide
- API migration guide for plugins/extensions
- Performance tuning guide
- Troubleshooting guide

## Risk Assessment

| Risk Category | Level | Mitigation Strategy |
|--------------|-------|-------------------|
| Configuration Incompatibility | HIGH | Priority string parser or migration tool |
| Cisco Client Compatibility | HIGH | Extensive real-world testing |
| PKCS#11 Support | MEDIUM | Evaluate wolfSSL PKCS#11 status, consider alternatives |
| Performance Regression | MEDIUM | Continuous benchmarking |
| Session Resumption Issues | MEDIUM | Thorough session caching testing |
| Certificate Validation Differences | LOW | Standard validation logic |
| DTLS Interoperability | LOW | Well-specified protocol |

## Success Criteria

### GO Decision Criteria (Sprint 1)
- [ ] PoC demonstrates TLS connection establishment
- [ ] Basic I/O operations work correctly
- [ ] Performance is within 10% of GnuTLS baseline
- [ ] No critical blocking issues identified

### Phase 1 Completion Criteria (Sprint 6)
- [ ] All core TLS operations migrated
- [ ] DTLS support functional
- [ ] Basic Cisco client connectivity verified
- [ ] Unit test coverage >80%

### Phase 2 Completion Criteria (Sprint 12)
- [ ] All advanced features migrated
- [ ] Full Cisco Secure Client compatibility
- [ ] PKCS#11 support (if required)
- [ ] Performance meets or exceeds GnuTLS

### Final Release Criteria (v2.0.0)
- [ ] External security audit passed
- [ ] 100% Cisco compatibility verified
- [ ] Production deployments successful
- [ ] Documentation complete

## Next Steps

1. **Immediate** (Sprint 0 - Current Sprint):
   - [x] Complete this audit document
   - [ ] Design TLS abstraction layer API
   - [ ] Create PoC with basic TLS connection
   - [ ] Establish performance baselines

2. **Short Term** (Sprint 1):
   - [ ] Implement abstraction layer headers
   - [ ] Create GnuTLS backend implementation
   - [ ] Create wolfSSL backend implementation
   - [ ] Benchmark PoC results
   - [ ] GO/NO-GO decision

3. **Medium Term** (Sprint 2-6):
   - [ ] Migrate core TLS operations
   - [ ] Implement session caching
   - [ ] Add DTLS support
   - [ ] Cisco client testing begins

4. **Long Term** (Sprint 7+):
   - [ ] Priority string parser
   - [ ] PKCS#11 integration
   - [ ] Performance optimization
   - [ ] Security audit preparation

## References

- **ocserv upstream**: https://gitlab.com/openconnect/ocserv
- **OpenConnect Protocol**: https://datatracker.ietf.org/doc/draft-mavrogiannopoulos-openconnect/ (v1.2, draft-04)
- **Protocol Reference**: docs/architecture/PROTOCOL_REFERENCE.md
- **GnuTLS Manual**: https://gnutls.org/manual/
- **wolfSSL Manual**: https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
- **wolfSSL Tuning Guide**: https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html
- **wolfSSL Examples**: https://github.com/wolfSSL/wolfssl-examples
- **wolfSSL Ecosystem Guide**: docs/architecture/WOLFSSL_ECOSYSTEM.md
- **RFC 8446**: Transport Layer Security (TLS) 1.3
- **RFC 9147**: DTLS 1.3
- **Cisco AnyConnect Protocol**: (Proprietary - OpenConnect provides compatible implementation)

## Appendix A: Complete Function Mapping Table

[See separate file: `GNUTLS_WOLFSSL_MAPPING.csv`]

## Appendix B: Priority String Grammar

[To be developed in Sprint 1]

## Appendix C: Test Plan

[To be developed in Sprint 1]

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Next Review**: Sprint 1 Retrospective
