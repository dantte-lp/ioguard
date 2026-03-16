# CMakeLists.txt for ioguard
# Modern C23 VPN server with io_uring event loop
# Dual-compiler: Clang 22+ (dev) / GCC 15+ (release)
cmake_minimum_required(VERSION 3.25)

project(ioguard
    VERSION 0.1.0
    DESCRIPTION "Modern C23 VPN server with io_uring event loop"
    LANGUAGES C
)

# Require C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Export compile_commands.json for clangd/clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build options
option(USE_WOLFSSL "Use wolfSSL backend instead of GnuTLS" ON)
option(BUILD_TESTING "Build unit tests" ON)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(BUILD_DOCUMENTATION "Build API documentation with Doxygen" ON)
option(BUILD_FUZZ "Build fuzzing targets (Clang only)" OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# ============================================================================
# Compiler-Specific Configuration (dual-compiler strategy)
# ============================================================================

# Common security hardening flags
add_compile_options(
    -Wall -Wextra -Wpedantic -Werror
    -fstack-protector-strong
    -fstack-clash-protection
    -fPIE
)

# Compiler-specific flags
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Compiler: Clang ${CMAKE_C_COMPILER_VERSION} (primary dev compiler)")
    add_compile_options(
        -Wno-padded
        -Wno-declaration-after-statement
        -Wno-unsafe-buffer-usage
        -Wno-pre-c23-compat
        -fcolor-diagnostics
    )
    # CFI for release builds
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-fsanitize=cfi -fvisibility=hidden)
        add_link_options(-fsanitize=cfi)
    endif()

elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message(STATUS "Compiler: GCC ${CMAKE_C_COMPILER_VERSION} (validation compiler)")
    add_compile_options(
        -Wduplicated-branches
        -Wduplicated-cond
        -Wlogical-op
        -Wformat-overflow=2
        -Wnull-dereference
        -Wjump-misses-init
        -fdiagnostics-color=always
    )
    # -fanalyzer for debug builds (powerful static analysis, C-only)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-fanalyzer)
    endif()
endif()

# Build type flags
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -D_FORTIFY_SOURCE=3")

# Linker flags for security hardening
add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -pie
)

# Sanitizers (prefer CMake presets, but keep option for backwards compat)
if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Code coverage
if(ENABLE_COVERAGE)
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(-lgcov --coverage)
endif()

# ============================================================================
# Dependencies
# ============================================================================

find_package(PkgConfig REQUIRED)

# --- TLS backend detection ---
# Detect both backends; USE_WOLFSSL selects the primary one
pkg_check_modules(WOLFSSL wolfssl)
if(WOLFSSL_FOUND)
    message(STATUS "TLS backend: wolfSSL (found)")
else()
    message(STATUS "wolfSSL not found")
endif()

pkg_check_modules(GNUTLS gnutls>=3.8.0)
if(GNUTLS_FOUND)
    message(STATUS "TLS backend: GnuTLS (found)")
else()
    message(STATUS "GnuTLS not found")
endif()

if(USE_WOLFSSL AND WOLFSSL_FOUND)
    set(TLS_BACKEND "wolfssl")
elseif(GNUTLS_FOUND)
    set(TLS_BACKEND "gnutls")
endif()

# --- Core dependencies ---
pkg_check_modules(PAM REQUIRED pam)
pkg_check_modules(LIBSECCOMP REQUIRED libseccomp)
pkg_check_modules(LZ4 REQUIRED liblz4)
pkg_check_modules(LIBNL3 REQUIRED libnl-3.0)

# --- Network & I/O ---
pkg_check_modules(LIBURING REQUIRED liburing>=2.7)

# --- Data & Configuration ---
# tomlc99
find_path(TOML_INCLUDE_DIR toml.h PATHS /usr/local/include /usr/include)
find_library(TOML_LIBRARY toml PATHS /usr/local/lib /usr/lib /usr/local/lib64 /usr/lib64)
if(TOML_INCLUDE_DIR AND TOML_LIBRARY)
    set(TOML_FOUND TRUE)
    message(STATUS "Found tomlc99: ${TOML_LIBRARY}")
else()
    message(STATUS "tomlc99 not found")
endif()

# yyjson: prefer find, fallback to pkg-config
find_path(YYJSON_INCLUDE_DIR yyjson.h)
find_library(YYJSON_LIBRARY yyjson)
if(YYJSON_INCLUDE_DIR AND YYJSON_LIBRARY)
    set(YYJSON_FOUND TRUE)
    message(STATUS "Found yyjson: ${YYJSON_LIBRARY}")
else()
    message(STATUS "yyjson not found - will use cJSON only")
endif()

# cJSON (fallback / simple config)
pkg_check_modules(CJSON libcjson)
if(NOT CJSON_FOUND)
    find_path(CJSON_INCLUDE_DIRS cJSON.h PATHS /usr/local/include /usr/include)
    find_library(CJSON_LIBRARIES cjson PATHS /usr/local/lib /usr/lib)
endif()

# --- IPC serialization ---
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c>=1.5.0)

# protoc-c code generation
find_program(PROTOC_C protoc-c REQUIRED)
set(PROTO_GEN_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

# --- Authentication ---
pkg_check_modules(RADCLI radcli)
pkg_check_modules(LIBOATH liboath)
pkg_check_modules(LDAP ldap)
pkg_check_modules(KRB5 krb5)

# --- Networking & Firewall ---
pkg_check_modules(LIBMNL libmnl)
pkg_check_modules(LIBNFTNL libnftnl)

# --- Async DNS ---
pkg_check_modules(CARES libcares)

# --- Memory allocator ---
find_path(MIMALLOC_INCLUDE_DIR mimalloc.h
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES mimalloc-3.2 mimalloc-3.1 mimalloc-3.0 mimalloc)
find_library(MIMALLOC_LIBRARY
    NAMES mimalloc-secure mimalloc
    PATHS /usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64)
if(MIMALLOC_INCLUDE_DIR AND MIMALLOC_LIBRARY)
    set(MIMALLOC_FOUND TRUE)
    message(STATUS "Found mimalloc: ${MIMALLOC_LIBRARY}")
endif()

# ============================================================================
# Include directories (minimal base; library-specific on targets)
# ============================================================================

include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

# ============================================================================
# ioguard core libraries
# ============================================================================

add_library(iog_io STATIC src/io/uring.c)
target_link_libraries(iog_io PUBLIC ${LIBURING_LIBRARIES})
target_link_directories(iog_io PUBLIC ${LIBURING_LIBRARY_DIRS})
target_include_directories(iog_io PUBLIC ${CMAKE_SOURCE_DIR}/src ${LIBURING_INCLUDE_DIRS})
target_compile_definitions(iog_io PUBLIC _GNU_SOURCE)

add_library(iog_memory STATIC src/utils/memory.c)
target_include_directories(iog_memory PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(MIMALLOC_FOUND)
    target_link_libraries(iog_memory PUBLIC ${MIMALLOC_LIBRARY})
    target_include_directories(iog_memory PUBLIC ${MIMALLOC_INCLUDE_DIR})
    target_compile_definitions(iog_memory PUBLIC USE_MIMALLOC)
endif()

add_library(iog_config STATIC src/config/config.c)
target_include_directories(iog_config PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(TOML_FOUND)
    target_link_libraries(iog_config PUBLIC ${TOML_LIBRARY})
    target_include_directories(iog_config PUBLIC ${TOML_INCLUDE_DIR})
    target_compile_definitions(iog_config PUBLIC USE_TOML)
endif()

# Generate protobuf-c sources
set(PROTO_SRC ${CMAKE_SOURCE_DIR}/src/ipc/proto/iog_ipc.proto)
if(EXISTS ${PROTO_SRC})
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/iog_ipc.pb-c.h ${PROTO_GEN_DIR}/iog_ipc.pb-c.c
        COMMAND ${PROTOC_C} --c_out=${PROTO_GEN_DIR}
                --proto_path=${CMAKE_SOURCE_DIR}/src/ipc/proto
                ${PROTO_SRC}
        DEPENDS ${PROTO_SRC}
        COMMENT "Generating protobuf-c sources from iog_ipc.proto"
    )
    add_custom_target(proto_gen DEPENDS ${PROTO_GEN_DIR}/iog_ipc.pb-c.h)
    set(PROTO_GEN_SOURCES ${PROTO_GEN_DIR}/iog_ipc.pb-c.c)
else()
    set(PROTO_GEN_SOURCES "")
endif()

add_library(iog_fdpass STATIC src/ipc/fdpass.c)
target_include_directories(iog_fdpass PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(iog_fdpass PUBLIC _GNU_SOURCE)

add_library(iog_ipc STATIC src/ipc/transport.c src/ipc/messages.c ${PROTO_GEN_SOURCES})
if(TARGET proto_gen)
    add_dependencies(iog_ipc proto_gen)
endif()
target_link_libraries(iog_ipc PUBLIC ${PROTOBUF_C_LIBRARIES} iog_memory)
target_link_directories(iog_ipc PUBLIC ${PROTOBUF_C_LIBRARY_DIRS})
target_include_directories(iog_ipc PUBLIC ${CMAKE_SOURCE_DIR}/src ${PROTOBUF_C_INCLUDE_DIRS} ${PROTO_GEN_DIR})

add_library(iog_xml_auth STATIC src/network/xml_auth.c)
target_include_directories(iog_xml_auth PUBLIC ${CMAKE_SOURCE_DIR}/src)

find_path(IOHTTPPARSER_INCLUDE_DIR iohttpparser/ihtp_parser.h
    PATHS /usr/local/include /usr/include)
find_library(IOHTTPPARSER_LIBRARY iohttpparser
    PATHS /usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64)
if(IOHTTPPARSER_INCLUDE_DIR AND IOHTTPPARSER_LIBRARY)
    set(IOHTTPPARSER_FOUND TRUE)
    message(STATUS "Found iohttpparser: ${IOHTTPPARSER_LIBRARY}")
else()
    message(WARNING "iohttpparser not found — HTTP parser will not build")
endif()

add_library(iog_http STATIC src/network/http.c)
target_include_directories(iog_http PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(IOHTTPPARSER_FOUND)
    target_include_directories(iog_http PUBLIC ${IOHTTPPARSER_INCLUDE_DIR})
    target_link_libraries(iog_http PUBLIC ${IOHTTPPARSER_LIBRARY})
else()
    message(WARNING "iog_http: iohttpparser not found — linking will fail")
endif()
target_compile_definitions(iog_http PUBLIC _GNU_SOURCE)

add_library(iog_core STATIC src/core/process.c)
target_include_directories(iog_core PUBLIC ${CMAKE_SOURCE_DIR}/src)

# Main process bootstrap helpers (testable, excludes main() entry point)
add_library(iog_main_helpers STATIC src/core/main.c)
target_include_directories(iog_main_helpers PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(iog_main_helpers PUBLIC _GNU_SOURCE PRIVATE IOG_TESTING)

add_library(iog_session STATIC src/core/session.c)
target_include_directories(iog_session PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(iog_session PUBLIC _GNU_SOURCE)
if(WOLFSSL_FOUND)
    target_compile_definitions(iog_session PRIVATE USE_WOLFSSL)
    target_include_directories(iog_session PRIVATE ${WOLFSSL_INCLUDE_DIRS})
    target_link_libraries(iog_session PRIVATE ${WOLFSSL_LIBRARIES})
    target_link_directories(iog_session PRIVATE ${WOLFSSL_LIBRARY_DIRS})
endif()

# --- Crypto / TLS libraries ---
# wolfSSL backend
if(WOLFSSL_FOUND)
    add_library(iog_crypto STATIC
        src/crypto/tls_wolfssl.c
        src/crypto/tls_abstract.c
        src/crypto/priority_parser.c
        src/crypto/session_cache.c
    )
    target_compile_definitions(iog_crypto PUBLIC _GNU_SOURCE USE_WOLFSSL)
    target_compile_definitions(iog_crypto PRIVATE
        CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    target_include_directories(iog_crypto PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${WOLFSSL_INCLUDE_DIRS}
    )
    target_link_libraries(iog_crypto PUBLIC ${WOLFSSL_LIBRARIES} pthread)
    target_link_directories(iog_crypto PUBLIC ${WOLFSSL_LIBRARY_DIRS})
    message(STATUS "iog_crypto (wolfSSL backend) configured")
endif()

# GnuTLS backend
if(GNUTLS_FOUND)
    add_library(iog_crypto_gnutls STATIC
        src/crypto/tls_gnutls.c
        src/crypto/tls_abstract.c
        src/crypto/session_cache.c
    )
    target_compile_definitions(iog_crypto_gnutls PUBLIC _GNU_SOURCE USE_GNUTLS)
    target_include_directories(iog_crypto_gnutls PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${GNUTLS_INCLUDE_DIRS}
    )
    target_link_libraries(iog_crypto_gnutls PUBLIC ${GNUTLS_LIBRARIES} pthread)
    target_link_directories(iog_crypto_gnutls PUBLIC ${GNUTLS_LIBRARY_DIRS})
    message(STATUS "iog_crypto_gnutls (GnuTLS backend) configured")
endif()

# --- PAM authentication backend ---
find_library(PAM_LIBRARY pam)
if(PAM_LIBRARY)
    add_library(iog_pam STATIC src/auth/pam.c)
    target_link_libraries(iog_pam PRIVATE ${PAM_LIBRARY})
    target_compile_definitions(iog_pam PRIVATE _GNU_SOURCE)
    target_include_directories(iog_pam PUBLIC ${CMAKE_SOURCE_DIR}/src)
    message(STATUS "iog_pam (PAM authentication backend) configured")
endif()

# --- Storage libraries (needed by sec-mod) ---

# libmdbx session store
find_path(MDBX_INCLUDE_DIR mdbx.h PATHS /usr/local/include)
find_library(MDBX_LIBRARY mdbx PATHS /usr/local/lib /usr/local/lib64)

if(MDBX_INCLUDE_DIR AND MDBX_LIBRARY)
    add_library(iog_mdbx STATIC src/storage/mdbx.c)
    target_include_directories(iog_mdbx PUBLIC ${CMAKE_SOURCE_DIR}/src ${MDBX_INCLUDE_DIR})
    target_link_libraries(iog_mdbx PUBLIC ${MDBX_LIBRARY})
    target_compile_definitions(iog_mdbx PUBLIC _GNU_SOURCE)
    message(STATUS "Found libmdbx: ${MDBX_LIBRARY}")
else()
    message(WARNING "libmdbx not found — skipping storage/mdbx")
endif()

# SQLite control plane
find_path(SQLITE3_INCLUDE_DIR sqlite3.h
    PATHS /usr/local/include /usr/include)
find_library(SQLITE3_LIBRARY sqlite3
    PATHS /usr/local/lib /usr/local/lib64 /usr/lib64)

if(SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)
    add_library(iog_sqlite STATIC src/storage/sqlite.c)
    target_include_directories(iog_sqlite PUBLIC
        ${CMAKE_SOURCE_DIR}/src ${SQLITE3_INCLUDE_DIR})
    target_link_libraries(iog_sqlite PUBLIC ${SQLITE3_LIBRARY})
    target_compile_definitions(iog_sqlite PUBLIC _GNU_SOURCE)
    message(STATUS "Found SQLite3: ${SQLITE3_LIBRARY}")
else()
    message(WARNING "SQLite3 not found — skipping storage/sqlite")
endif()

# --- Sprint 7: TOTP authentication library ---
add_library(iog_totp STATIC src/auth/totp.c)
target_include_directories(iog_totp PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(iog_totp PRIVATE _GNU_SOURCE)
target_compile_features(iog_totp PRIVATE c_std_23)
if(WOLFSSL_FOUND)
    target_include_directories(iog_totp PRIVATE ${WOLFSSL_INCLUDE_DIRS})
    target_link_libraries(iog_totp PRIVATE ${WOLFSSL_LIBRARIES})
    target_link_directories(iog_totp PRIVATE ${WOLFSSL_LIBRARY_DIRS})
    target_compile_definitions(iog_totp PRIVATE USE_WOLFSSL)
endif()

# --- Sprint 7: Crypto vault (AES-256-GCM field encryption) ---
add_library(iog_vault STATIC src/storage/vault.c)
target_include_directories(iog_vault PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(iog_vault PRIVATE _GNU_SOURCE)
target_compile_features(iog_vault PRIVATE c_std_23)
if(WOLFSSL_FOUND)
    target_include_directories(iog_vault PRIVATE ${WOLFSSL_INCLUDE_DIRS})
    target_link_libraries(iog_vault PRIVATE ${WOLFSSL_LIBRARIES})
    target_link_directories(iog_vault PRIVATE ${WOLFSSL_LIBRARY_DIRS})
    target_compile_definitions(iog_vault PRIVATE USE_WOLFSSL)
endif()

# --- Sprint 7: Auth backend registry ---
add_library(iog_auth_backend STATIC src/auth/auth_backend.c)
target_include_directories(iog_auth_backend PUBLIC ${CMAKE_SOURCE_DIR}/src)

# --- Sprint 7: RADIUS authentication backend ---
if(RADCLI_FOUND)
    add_library(iog_auth_radius STATIC src/auth/radius.c)
    target_include_directories(iog_auth_radius PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(iog_auth_radius PUBLIC iog_auth_backend)
    target_compile_definitions(iog_auth_radius PRIVATE USE_RADCLI)
    target_include_directories(iog_auth_radius PRIVATE ${RADCLI_INCLUDE_DIRS})
    target_link_libraries(iog_auth_radius PUBLIC ${RADCLI_LIBRARIES})
    target_link_directories(iog_auth_radius PUBLIC ${RADCLI_LIBRARY_DIRS})
    message(STATUS "iog_auth_radius (RADIUS backend via radcli) configured")
else()
    add_library(iog_auth_radius STATIC src/auth/radius.c)
    target_include_directories(iog_auth_radius PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(iog_auth_radius PUBLIC iog_auth_backend)
    message(STATUS "iog_auth_radius (config validation only, no radcli)")
endif()

# --- Sprint 7: LDAP authentication backend ---
if(LDAP_FOUND)
    add_library(iog_auth_ldap STATIC src/auth/ldap_auth.c)
    target_include_directories(iog_auth_ldap PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(iog_auth_ldap PUBLIC iog_auth_backend)
    target_compile_definitions(iog_auth_ldap PRIVATE USE_LDAP)
    target_include_directories(iog_auth_ldap PRIVATE ${LDAP_INCLUDE_DIRS})
    target_link_libraries(iog_auth_ldap PUBLIC ${LDAP_LIBRARIES})
    target_link_directories(iog_auth_ldap PUBLIC ${LDAP_LIBRARY_DIRS})
    message(STATUS "iog_auth_ldap (LDAP backend via libldap) configured")
else()
    add_library(iog_auth_ldap STATIC src/auth/ldap_auth.c)
    target_include_directories(iog_auth_ldap PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(iog_auth_ldap PUBLIC iog_auth_backend)
    message(STATUS "iog_auth_ldap (config validation only, no libldap)")
endif()

# --- Sprint 7: Certificate authentication backend ---
add_library(iog_auth_cert STATIC src/auth/cert_auth.c)
target_include_directories(iog_auth_cert PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(iog_auth_cert PUBLIC iog_auth_backend)
if(WOLFSSL_FOUND)
    target_compile_definitions(iog_auth_cert PRIVATE USE_WOLFSSL)
    target_include_directories(iog_auth_cert PRIVATE ${WOLFSSL_INCLUDE_DIRS})
    target_link_libraries(iog_auth_cert PRIVATE ${WOLFSSL_LIBRARIES})
    target_link_directories(iog_auth_cert PRIVATE ${WOLFSSL_LIBRARY_DIRS})
    message(STATUS "iog_auth_cert (certificate auth via wolfSSL) configured")
else()
    message(STATUS "iog_auth_cert (config validation only, no wolfSSL)")
endif()

# --- Sprint 7: Structured logging (stumpless) ---
find_path(STUMPLESS_INCLUDE_DIR stumpless.h
    PATHS /usr/local/include /usr/include)
find_library(STUMPLESS_LIBRARY stumpless
    PATHS /usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64)
if(STUMPLESS_INCLUDE_DIR AND STUMPLESS_LIBRARY)
    set(STUMPLESS_FOUND TRUE)
    message(STATUS "Found stumpless: ${STUMPLESS_LIBRARY}")
else()
    set(STUMPLESS_FOUND FALSE)
    message(STATUS "stumpless not found — logging uses stderr fallback")
endif()

add_library(iog_log STATIC src/log/iog_log.c)
target_include_directories(iog_log PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(STUMPLESS_FOUND)
    target_compile_definitions(iog_log PRIVATE USE_STUMPLESS)
    target_include_directories(iog_log PRIVATE ${STUMPLESS_INCLUDE_DIR})
    target_link_libraries(iog_log PRIVATE ${STUMPLESS_LIBRARY})
endif()

# --- Sprint 7: Prometheus metrics ---
add_library(iog_metrics STATIC src/metrics/prometheus.c src/metrics/iog_metrics.c)
target_include_directories(iog_metrics PUBLIC ${CMAKE_SOURCE_DIR}/src)

# --- sec-mod authentication process ---
if(TARGET iog_pam)
    add_library(iog_secmod STATIC src/core/secmod.c)
    target_include_directories(iog_secmod PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(iog_secmod PRIVATE _GNU_SOURCE)
    target_link_libraries(iog_secmod PUBLIC iog_ipc iog_session iog_pam iog_config)
    if(TARGET iog_mdbx)
        target_link_libraries(iog_secmod PUBLIC iog_mdbx)
    endif()
    if(TARGET iog_sqlite)
        target_link_libraries(iog_secmod PUBLIC iog_sqlite)
    endif()
    if(TARGET iog_totp)
        target_link_libraries(iog_secmod PUBLIC iog_totp)
    endif()
    if(TARGET iog_vault)
        target_link_libraries(iog_secmod PUBLIC iog_vault)
    endif()
    message(STATUS "iog_secmod (sec-mod authentication process) configured")
endif()

# ============================================================================
# Unit tests
# ============================================================================

if(BUILD_TESTING)
    enable_testing()

    # Find Unity testing framework
    find_path(UNITY_INCLUDE_DIR unity/unity.h
        PATHS /usr/local/include /usr/include
    )
    find_path(UNITY_SRC_DIR unity.c
        PATHS /usr/local/src/unity /usr/src/unity
    )

    if(UNITY_INCLUDE_DIR AND UNITY_SRC_DIR)
        message(STATUS "Found Unity testing framework")

        # Create Unity library
        add_library(unity STATIC ${UNITY_SRC_DIR}/unity.c)
        target_include_directories(unity PUBLIC ${UNITY_INCLUDE_DIR} ${UNITY_INCLUDE_DIR}/unity)

        macro(iog_add_test TEST_NAME TEST_SRC)
            add_executable(${TEST_NAME} ${TEST_SRC})
            target_link_libraries(${TEST_NAME} PRIVATE unity ${ARGN})
            target_compile_definitions(${TEST_NAME} PRIVATE
                TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
            add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
        endmacro()

        # Sprint 1 tests
        iog_add_test(test_memory tests/unit/test_memory.c iog_memory)
        iog_add_test(test_io_uring tests/unit/test_io_uring.c iog_io)
        iog_add_test(test_io_callback tests/unit/test_io_callback.c iog_io)
        iog_add_test(test_fdpass tests/unit/test_fdpass.c iog_fdpass)
        iog_add_test(test_main_bootstrap tests/unit/test_main_bootstrap.c iog_main_helpers)
        iog_add_test(test_ipc_transport tests/unit/test_ipc_transport.c iog_ipc)
        iog_add_test(test_ipc_messages tests/unit/test_ipc_messages.c iog_ipc)
        iog_add_test(test_config_toml tests/unit/test_config_toml.c iog_config)
        iog_add_test(test_process tests/unit/test_process.c iog_core)
        if(EXISTS ${CMAKE_SOURCE_DIR}/tests/integration/test_ipc_roundtrip.c)
            iog_add_test(test_ipc_roundtrip tests/integration/test_ipc_roundtrip.c iog_ipc iog_io)
        endif()
        if(TARGET iog_secmod AND EXISTS ${CMAKE_SOURCE_DIR}/tests/integration/test_auth_flow.c)
            iog_add_test(test_auth_flow tests/integration/test_auth_flow.c iog_secmod iog_ipc iog_session iog_pam iog_config iog_memory)
        endif()

        # Sprint 2 crypto tests
        if(TARGET iog_crypto)
            iog_add_test(test_tls_wolfssl tests/unit/test_tls_wolfssl.c iog_crypto)
            iog_add_test(test_priority_parser tests/unit/test_priority_parser.c iog_crypto)
        endif()
        if(TARGET iog_crypto_gnutls)
            iog_add_test(test_tls_gnutls tests/unit/test_tls_gnutls.c iog_crypto_gnutls)
        endif()

        # Sprint 2 network tests
        iog_add_test(test_http tests/unit/test_http.c iog_http)
        iog_add_test(test_xml_auth tests/unit/test_xml_auth.c iog_xml_auth)

        # Sprint 2 session tests (needs wolfSSL for wolfCrypt RNG)
        iog_add_test(test_session tests/unit/test_session.c iog_session)
        if(WOLFSSL_FOUND)
            target_link_libraries(test_session PRIVATE ${WOLFSSL_LIBRARIES})
            target_link_directories(test_session PRIVATE ${WOLFSSL_LIBRARY_DIRS})
        endif()

        # Sprint 2 PAM authentication tests
        if(TARGET iog_pam)
            iog_add_test(test_auth_pam tests/unit/test_auth_pam.c iog_pam)
        endif()

        # Sprint 2 sec-mod authentication process tests
        if(TARGET iog_secmod)
            iog_add_test(test_secmod tests/unit/test_secmod.c iog_secmod)

            # Sprint 6 — secmod storage integration
            if(TARGET iog_mdbx AND TARGET iog_sqlite)
                iog_add_test(test_secmod_storage tests/unit/test_secmod_storage.c
                    iog_secmod iog_mdbx iog_sqlite)
                target_link_libraries(test_secmod_storage PRIVATE
                    ${MDBX_LIBRARY} ${SQLITE3_LIBRARY})
                target_include_directories(test_secmod_storage PRIVATE
                    ${MDBX_INCLUDE_DIR} ${SQLITE3_INCLUDE_DIR})
            endif()
        endif()

        # Sprint 3 — CSTP framing
        add_library(iog_cstp STATIC src/network/cstp.c)
        target_include_directories(iog_cstp PUBLIC ${CMAKE_SOURCE_DIR}/src)

        iog_add_test(test_cstp tests/unit/test_cstp.c iog_cstp)

        # Sprint 3 — TUN device
        add_library(iog_tun STATIC src/network/tun.c)
        target_include_directories(iog_tun PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_tun PUBLIC _GNU_SOURCE)

        iog_add_test(test_tun tests/unit/test_tun.c iog_tun)

        # Sprint 3 — DPD state machine
        add_library(iog_dpd STATIC src/network/dpd.c)
        target_include_directories(iog_dpd PUBLIC ${CMAKE_SOURCE_DIR}/src)

        iog_add_test(test_dpd tests/unit/test_dpd.c iog_dpd)

        # Sprint 3 — Worker process context
        add_library(iog_worker STATIC src/core/worker.c)
        target_include_directories(iog_worker PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_worker PUBLIC _GNU_SOURCE)
        target_link_libraries(iog_worker PUBLIC iog_cstp iog_dpd iog_compress)

        iog_add_test(test_worker tests/unit/test_worker.c iog_worker iog_cstp iog_dpd)

        # Sprint 6 — Worker event loop
        add_library(iog_worker_loop STATIC src/core/worker_loop.c)
        target_include_directories(iog_worker_loop PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_worker_loop PUBLIC _GNU_SOURCE)
        target_link_libraries(iog_worker_loop PUBLIC iog_worker iog_io iog_fdpass iog_cstp iog_dpd iog_conn_data iog_compress)

        iog_add_test(test_worker_loop tests/unit/test_worker_loop.c
            iog_worker_loop iog_io iog_fdpass iog_cstp iog_dpd iog_worker iog_conn_data iog_compress)

        # Sprint 6 — Per-connection TLS handshake
        if(WOLFSSL_FOUND)
            add_library(iog_conn_tls STATIC src/core/conn_tls.c)
            target_include_directories(iog_conn_tls PUBLIC ${CMAKE_SOURCE_DIR}/src)
            target_compile_definitions(iog_conn_tls PRIVATE _GNU_SOURCE)
            target_link_libraries(iog_conn_tls PUBLIC iog_crypto)

            iog_add_test(test_conn_tls tests/unit/test_conn_tls.c
                iog_conn_tls iog_crypto)
            target_link_libraries(test_conn_tls PRIVATE pthread)
        endif()

        # Sprint 6 — CSTP data path (conn_data)
        add_library(iog_conn_data STATIC src/core/conn_data.c)
        target_include_directories(iog_conn_data PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_conn_data PRIVATE _GNU_SOURCE)
        target_link_libraries(iog_conn_data PUBLIC iog_cstp iog_dpd iog_compress)

        iog_add_test(test_conn_data tests/unit/test_conn_data.c
            iog_conn_data iog_cstp iog_dpd iog_compress)

        # Sprint 6 — DPD/keepalive timer integration
        add_library(iog_conn_timer STATIC src/core/conn_timer.c)
        target_include_directories(iog_conn_timer PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_conn_timer PRIVATE _GNU_SOURCE)
        target_link_libraries(iog_conn_timer PUBLIC iog_conn_data iog_dpd iog_cstp)

        iog_add_test(test_conn_timer tests/unit/test_conn_timer.c
            iog_conn_timer iog_conn_data iog_cstp iog_dpd iog_compress)

        # Sprint 3 — Data path integration test
        iog_add_test(test_data_path tests/integration/test_data_path.c iog_cstp iog_dpd iog_worker iog_io)

        # Sprint 4 — Compression abstraction
        add_library(iog_compress STATIC src/network/compress.c)
        target_include_directories(iog_compress PUBLIC ${CMAKE_SOURCE_DIR}/src)

        iog_add_test(test_compress tests/unit/test_compress.c iog_compress)

        # Sprint 4 — LZS compression
        add_library(iog_compress_lzs STATIC src/network/compress_lzs.c)
        target_include_directories(iog_compress_lzs PUBLIC ${CMAKE_SOURCE_DIR}/src)

        target_link_libraries(iog_compress PUBLIC iog_compress_lzs)
        iog_add_test(test_compress_lzs tests/unit/test_compress_lzs.c iog_compress_lzs)

        # Sprint 4 — LZ4 compression
        add_library(iog_compress_lz4 STATIC src/network/compress_lz4.c)
        target_include_directories(iog_compress_lz4 PUBLIC
            ${CMAKE_SOURCE_DIR}/src ${LZ4_INCLUDE_DIRS})
        target_link_libraries(iog_compress_lz4 PRIVATE ${LZ4_LIBRARIES})
        target_link_directories(iog_compress_lz4 PRIVATE ${LZ4_LIBRARY_DIRS})

        target_link_libraries(iog_compress PUBLIC iog_compress_lz4)
        iog_add_test(test_compress_lz4 tests/unit/test_compress_lz4.c iog_compress_lz4)
        target_link_libraries(test_compress_lz4 PRIVATE ${LZ4_LIBRARIES})
        target_link_directories(test_compress_lz4 PRIVATE ${LZ4_LIBRARY_DIRS})

        # Sprint 4 — DTLS context management
        add_library(iog_dtls STATIC src/network/dtls.c)
        target_include_directories(iog_dtls PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_dtls PUBLIC _GNU_SOURCE)
        if(WOLFSSL_FOUND)
            target_compile_definitions(iog_dtls PUBLIC USE_WOLFSSL)
            target_include_directories(iog_dtls PUBLIC ${WOLFSSL_INCLUDE_DIRS})
            target_link_libraries(iog_dtls PUBLIC ${WOLFSSL_LIBRARIES})
            target_link_directories(iog_dtls PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        endif()

        iog_add_test(test_dtls tests/unit/test_dtls.c iog_dtls)

        # Sprint 4 — DTLS keying material
        add_library(iog_dtls_keying STATIC src/network/dtls_keying.c)
        target_include_directories(iog_dtls_keying PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_dtls_keying PUBLIC _GNU_SOURCE)

        iog_add_test(test_dtls_keying tests/unit/test_dtls_keying.c iog_dtls_keying)

        # Sprint 4 — Channel state machine
        add_library(iog_channel STATIC src/network/channel.c)
        target_include_directories(iog_channel PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(iog_channel PUBLIC iog_dpd iog_compress)

        iog_add_test(test_channel tests/unit/test_channel.c iog_channel iog_dpd iog_compress)

        # Sprint 4 — DTLS HTTP headers
        add_library(iog_dtls_headers STATIC src/network/dtls_headers.c)
        target_include_directories(iog_dtls_headers PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(iog_dtls_headers PUBLIC iog_compress)

        iog_add_test(test_dtls_headers tests/unit/test_dtls_headers.c iog_dtls_headers iog_compress)

        # Sprint 4 — CSTP compression integration
        iog_add_test(test_compress_cstp tests/unit/test_compress_cstp.c iog_cstp iog_compress iog_worker iog_dpd)

        # Sprint 4 — DTLS + channel + compression integration
        iog_add_test(test_dtls_channel tests/integration/test_dtls_channel.c
            iog_channel iog_compress iog_cstp iog_dpd iog_dtls_headers iog_dtls_keying iog_worker)

        # Sprint 5 — libmdbx session store tests
        if(TARGET iog_mdbx)
            iog_add_test(test_storage_mdbx tests/unit/test_storage_mdbx.c iog_mdbx)
            target_link_libraries(test_storage_mdbx PRIVATE ${MDBX_LIBRARY})
            target_include_directories(test_storage_mdbx PRIVATE ${MDBX_INCLUDE_DIR})
        endif()

        # Sprint 5 — SQLite control plane tests
        if(TARGET iog_sqlite)
            iog_add_test(test_storage_sqlite tests/unit/test_storage_sqlite.c
                iog_sqlite)
            target_link_libraries(test_storage_sqlite PRIVATE ${SQLITE3_LIBRARY})
            target_include_directories(test_storage_sqlite PRIVATE
                ${SQLITE3_INCLUDE_DIR})
        endif()

        # Sprint 5 — wolfSentry IDPS
        find_path(WOLFSENTRY_INCLUDE_DIR wolfsentry/wolfsentry.h
            PATHS /usr/local/include)
        find_library(WOLFSENTRY_LIBRARY wolfsentry
            PATHS /usr/local/lib /usr/local/lib64)

        if(WOLFSENTRY_INCLUDE_DIR AND WOLFSENTRY_LIBRARY)
            add_library(iog_wolfsentry STATIC src/security/wolfsentry.c)
            target_include_directories(iog_wolfsentry PUBLIC
                ${CMAKE_SOURCE_DIR}/src ${WOLFSENTRY_INCLUDE_DIR})
            target_link_libraries(iog_wolfsentry PUBLIC ${WOLFSENTRY_LIBRARY})
            target_compile_definitions(iog_wolfsentry PUBLIC _GNU_SOURCE)

            iog_add_test(test_wolfsentry tests/unit/test_wolfsentry.c
                iog_wolfsentry)
            target_link_libraries(test_wolfsentry PRIVATE ${WOLFSENTRY_LIBRARY})
            target_include_directories(test_wolfsentry PRIVATE
                ${WOLFSENTRY_INCLUDE_DIR})
            # wolfSentry .a built without -fPIC; disable PIE for this target
            set_target_properties(test_wolfsentry PROPERTIES
                POSITION_INDEPENDENT_CODE OFF)
            target_link_options(test_wolfsentry PRIVATE -no-pie)
            target_compile_options(test_wolfsentry PRIVATE -fno-PIE)
            target_compile_options(iog_wolfsentry PRIVATE -fno-PIE)
            set_target_properties(iog_wolfsentry PROPERTIES
                POSITION_INDEPENDENT_CODE OFF)
            message(STATUS "Found wolfSentry: ${WOLFSENTRY_LIBRARY}")
        else()
            message(WARNING "wolfSentry not found — skipping security/wolfsentry")
        endif()

        # Sprint 5 — seccomp BPF sandbox
        find_library(SECCOMP_LIBRARY seccomp)
        find_path(SECCOMP_INCLUDE_DIR seccomp.h)

        if(SECCOMP_LIBRARY AND SECCOMP_INCLUDE_DIR)
            add_library(iog_sandbox STATIC src/security/sandbox.c)
            target_include_directories(iog_sandbox PUBLIC
                ${CMAKE_SOURCE_DIR}/src ${SECCOMP_INCLUDE_DIR})
            target_link_libraries(iog_sandbox PUBLIC ${SECCOMP_LIBRARY})
            target_compile_definitions(iog_sandbox PUBLIC _GNU_SOURCE)

            iog_add_test(test_sandbox tests/unit/test_sandbox.c iog_sandbox)
            target_link_libraries(test_sandbox PRIVATE ${SECCOMP_LIBRARY})
            message(STATUS "Found libseccomp: ${SECCOMP_LIBRARY}")
        else()
            message(WARNING "libseccomp not found — skipping security/sandbox")
        endif()

        # Sprint 5 — Landlock filesystem isolation
        add_library(iog_landlock STATIC src/security/landlock.c)
        target_include_directories(iog_landlock PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_landlock PUBLIC _GNU_SOURCE)

        iog_add_test(test_landlock tests/unit/test_landlock.c iog_landlock)

        # Sprint 5 — nftables per-user firewall
        if(LIBMNL_FOUND AND LIBNFTNL_FOUND)
            add_library(iog_firewall STATIC src/security/firewall.c)
            target_include_directories(iog_firewall PUBLIC ${CMAKE_SOURCE_DIR}/src)
            target_link_libraries(iog_firewall PUBLIC
                ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})
            target_include_directories(iog_firewall PUBLIC
                ${LIBMNL_INCLUDE_DIRS} ${LIBNFTNL_INCLUDE_DIRS})
            target_link_directories(iog_firewall PUBLIC
                ${LIBMNL_LIBRARY_DIRS} ${LIBNFTNL_LIBRARY_DIRS})
            target_compile_definitions(iog_firewall PUBLIC _GNU_SOURCE)

            iog_add_test(test_firewall tests/unit/test_firewall.c iog_firewall)
            target_link_libraries(test_firewall PRIVATE
                ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})
            target_link_directories(test_firewall PRIVATE
                ${LIBMNL_LIBRARY_DIRS} ${LIBNFTNL_LIBRARY_DIRS})
            message(STATUS "Found libmnl+libnftnl: nftables firewall enabled")
        else()
            message(WARNING "libmnl/libnftnl not found — skipping security/firewall")
        endif()

        # Sprint 6 — End-to-end VPN flow integration test
        iog_add_test(test_vpn_flow tests/integration/test_vpn_flow.c
            iog_conn_data iog_conn_timer iog_shutdown iog_worker
            iog_cstp iog_dpd iog_compress)

        # Sprint 6 — Graceful shutdown
        add_library(iog_shutdown STATIC src/core/shutdown.c)
        target_include_directories(iog_shutdown PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_shutdown PRIVATE _GNU_SOURCE)
        target_link_libraries(iog_shutdown PUBLIC iog_worker iog_cstp)

        iog_add_test(test_shutdown tests/unit/test_shutdown.c
            iog_shutdown iog_worker iog_cstp iog_dpd iog_compress)

        # Sprint 6 — Security activation hooks
        if(TARGET iog_sandbox AND TARGET iog_landlock AND TARGET iog_firewall)
            add_library(iog_security_hooks STATIC src/core/security_hooks.c)
            target_include_directories(iog_security_hooks PUBLIC ${CMAKE_SOURCE_DIR}/src)
            target_compile_definitions(iog_security_hooks PRIVATE _GNU_SOURCE)
            target_link_libraries(iog_security_hooks PUBLIC
                iog_sandbox iog_landlock iog_firewall iog_config)

            iog_add_test(test_security_hooks tests/unit/test_security_hooks.c
                iog_security_hooks iog_sandbox iog_landlock iog_firewall iog_config)
        endif()

        # Sprint 5 — Schema migration
        if(TARGET iog_sqlite AND TARGET iog_mdbx)
            add_library(iog_migrate STATIC src/storage/migrate.c)
            target_include_directories(iog_migrate PUBLIC ${CMAKE_SOURCE_DIR}/src)
            target_link_libraries(iog_migrate PUBLIC iog_sqlite iog_mdbx)

            iog_add_test(test_storage_migrate tests/unit/test_storage_migrate.c
                iog_migrate iog_sqlite iog_mdbx)
        else()
            message(WARNING "iog_sqlite or iog_mdbx missing — skipping storage/migrate")
        endif()

        # Sprint 5 — Storage integration test
        if(TARGET iog_mdbx AND TARGET iog_sqlite AND TARGET iog_migrate)
            iog_add_test(test_storage tests/integration/test_storage.c
                iog_mdbx iog_sqlite iog_migrate)
        endif()

        # Sprint 6 — IPAM (IP address pool management)
        add_library(iog_ipam STATIC src/network/ipam.c)
        target_include_directories(iog_ipam PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_ipam PRIVATE _GNU_SOURCE)
        iog_add_test(test_ipam tests/unit/test_ipam.c iog_ipam)

        # Sprint 6 — Split DNS configuration
        add_library(iog_dns STATIC src/network/dns.c)
        target_include_directories(iog_dns PUBLIC ${CMAKE_SOURCE_DIR}/src)
        target_compile_definitions(iog_dns PRIVATE _GNU_SOURCE)
        iog_add_test(test_dns tests/unit/test_dns.c iog_dns)

        # Sprint 7 — TOTP test
        iog_add_test(test_totp tests/unit/test_totp.c iog_totp)
        if(WOLFSSL_FOUND)
            target_include_directories(test_totp PRIVATE ${WOLFSSL_INCLUDE_DIRS})
            target_link_directories(test_totp PRIVATE ${WOLFSSL_LIBRARY_DIRS})
            target_compile_definitions(test_totp PRIVATE USE_WOLFSSL)
        endif()

        # Sprint 7 — Vault test
        iog_add_test(test_vault tests/unit/test_vault.c iog_vault)
        if(WOLFSSL_FOUND)
            target_include_directories(test_vault PRIVATE ${WOLFSSL_INCLUDE_DIRS})
            target_link_directories(test_vault PRIVATE ${WOLFSSL_LIBRARY_DIRS})
            target_compile_definitions(test_vault PRIVATE USE_WOLFSSL)
        endif()

        # Sprint 7 — Auth backend registry test
        iog_add_test(test_auth_backend tests/unit/test_auth_backend.c iog_auth_backend)

        # Sprint 7 — RADIUS authentication test
        iog_add_test(test_auth_radius tests/unit/test_auth_radius.c iog_auth_radius iog_auth_backend)

        # Sprint 7 — LDAP authentication test
        iog_add_test(test_auth_ldap tests/unit/test_auth_ldap.c iog_auth_ldap iog_auth_backend)

        # Sprint 7 — Certificate authentication test
        iog_add_test(test_auth_cert tests/unit/test_auth_cert.c iog_auth_cert iog_auth_backend)
        if(WOLFSSL_FOUND)
            target_include_directories(test_auth_cert PRIVATE ${WOLFSSL_INCLUDE_DIRS})
            target_link_directories(test_auth_cert PRIVATE ${WOLFSSL_LIBRARY_DIRS})
            target_compile_definitions(test_auth_cert PRIVATE USE_WOLFSSL)
        endif()

        # Sprint 7 — Structured logging test
        iog_add_test(test_log tests/unit/test_log.c iog_log)
        if(STUMPLESS_FOUND)
            target_compile_definitions(test_log PRIVATE USE_STUMPLESS)
            target_include_directories(test_log PRIVATE ${STUMPLESS_INCLUDE_DIR})
            target_link_libraries(test_log PRIVATE ${STUMPLESS_LIBRARY})
        endif()

        # Sprint 7 — Prometheus metrics test
        iog_add_test(test_prometheus tests/unit/test_prometheus.c iog_metrics)

        # Sprint 7 — MFA integration test
        if(TARGET iog_secmod AND TARGET iog_totp AND TARGET iog_vault AND TARGET iog_sqlite)
            iog_add_test(test_auth_mfa tests/integration/test_auth_mfa.c
                iog_secmod iog_totp iog_vault iog_sqlite)
            target_link_libraries(test_auth_mfa PRIVATE
                ${SQLITE3_LIBRARY})
            target_include_directories(test_auth_mfa PRIVATE
                ${SQLITE3_INCLUDE_DIR})
            if(WOLFSSL_FOUND)
                target_include_directories(test_auth_mfa PRIVATE ${WOLFSSL_INCLUDE_DIRS})
                target_link_directories(test_auth_mfa PRIVATE ${WOLFSSL_LIBRARY_DIRS})
                target_compile_definitions(test_auth_mfa PRIVATE USE_WOLFSSL)
            endif()
        endif()

        message(STATUS "Unit test infrastructure ready (iog_add_test macro)")
    else()
        message(WARNING "Unity testing framework not found - skipping unit tests")
    endif()
endif()

# ============================================================================
# Fuzzing targets (Clang + LibFuzzer only)
# ============================================================================

if(BUILD_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "Fuzzing requires Clang (LibFuzzer)")
    endif()

    macro(iog_add_fuzz FUZZ_NAME FUZZ_SRC)
        add_executable(${FUZZ_NAME} ${FUZZ_SRC})
        target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
        target_include_directories(${FUZZ_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(${FUZZ_NAME} PRIVATE ${ARGN})
        target_compile_definitions(${FUZZ_NAME} PRIVATE _GNU_SOURCE)
    endmacro()

    iog_add_fuzz(fuzz_cstp tests/fuzz/fuzz_cstp.c iog_cstp)
    iog_add_fuzz(fuzz_http tests/fuzz/fuzz_http.c iog_http)
    iog_add_fuzz(fuzz_toml tests/fuzz/fuzz_toml.c iog_config)
    iog_add_fuzz(fuzz_ipc tests/fuzz/fuzz_ipc.c iog_ipc)
    if(TARGET iog_mdbx)
        iog_add_fuzz(fuzz_session_key tests/fuzz/fuzz_session_key.c iog_mdbx)
    endif()

    message(STATUS "Building fuzzing targets (LibFuzzer)")
endif()

# ============================================================================
# Benchmark targets (S8)
# ============================================================================

if(BUILD_TESTING)
    add_executable(bench_cstp tests/bench/bench_cstp.c)
    target_include_directories(bench_cstp PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/bench)
    target_link_libraries(bench_cstp PRIVATE iog_cstp)
    target_compile_definitions(bench_cstp PRIVATE _GNU_SOURCE)

    if(WOLFSSL_FOUND)
        add_executable(bench_session tests/bench/bench_session.c)
        target_include_directories(bench_session PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/bench)
        target_link_libraries(bench_session PRIVATE iog_session iog_crypto)
        target_compile_definitions(bench_session PRIVATE _GNU_SOURCE USE_WOLFSSL)
        target_include_directories(bench_session PRIVATE ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(bench_session PRIVATE ${WOLFSSL_LIBRARY_DIRS})
    endif()
endif()

# ============================================================================
# Doxygen documentation
# ============================================================================

if(BUILD_DOCUMENTATION)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        if(EXISTS ${DOXYGEN_IN})
            configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)
            set(DOXYGEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)
        endif()

        add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )

        message(STATUS "Doxygen documentation target enabled - run 'make doc'")
    else()
        message(WARNING "Doxygen not found - documentation will not be built")
    endif()
endif()

# ============================================================================
# Code quality targets
# ============================================================================

# clang-format
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        -name "*.c" -o -name "*.h" | xargs clang-format -i
    COMMENT "Formatting code with clang-format"
    VERBATIM
)

# clang-format check (CI: fails if code is not formatted)
add_custom_target(format-check
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests
        -name "*.c" -o -name "*.h" | xargs clang-format --dry-run --Werror
    COMMENT "Checking code formatting with clang-format"
    VERBATIM
)

# clang-tidy (uses compile_commands.json)
add_custom_target(lint
    COMMAND run-clang-tidy -p ${CMAKE_BINARY_DIR}
        -header-filter='src/.*'
        ${CMAKE_SOURCE_DIR}/src/
    COMMENT "Running clang-tidy static analysis"
    VERBATIM
)

# cppcheck
add_custom_target(cppcheck
    COMMAND cppcheck
        --enable=all
        --inconclusive
        --std=c23
        --suppress=missingIncludeSystem
        --project=${CMAKE_BINARY_DIR}/compile_commands.json
        --error-exitcode=1
    COMMENT "Running cppcheck static analysis"
    VERBATIM
)

# Detect CPU count for parallel analysis
cmake_host_system_information(RESULT NPROC QUERY NUMBER_OF_LOGICAL_CORES)

# CodeChecker (clang-sa + clang-tidy with result management)
add_custom_target(codechecker
    COMMAND CodeChecker analyze ${CMAKE_BINARY_DIR}/compile_commands.json
        --analyzers clangsa clang-tidy
        --output ${CMAKE_BINARY_DIR}/codechecker-results
        -j ${NPROC}
    COMMAND ${CMAKE_COMMAND} -E echo "=== CodeChecker Results ==="
    COMMAND CodeChecker parse ${CMAKE_BINARY_DIR}/codechecker-results
        --print-steps || true
    COMMENT "Running CodeChecker analysis (clang-sa + clang-tidy)"
)

# PVS-Studio static analysis
add_custom_target(pvs-studio
    COMMAND pvs-studio-analyzer analyze
        -f ${CMAKE_BINARY_DIR}/compile_commands.json
        -o ${CMAKE_BINARY_DIR}/pvs-results.log
        -j ${NPROC}
        -e ${CMAKE_SOURCE_DIR}/tests/
    COMMAND plog-converter
        -a "GA:1,2;64:1,2;OP:1,2"
        -t tasklist
        ${CMAKE_BINARY_DIR}/pvs-results.log
    COMMENT "Running PVS-Studio static analysis"
    VERBATIM
)

# PVS-Studio with SARIF output (for CI integration)
add_custom_target(pvs-studio-sarif
    COMMAND pvs-studio-analyzer analyze
        -f ${CMAKE_BINARY_DIR}/compile_commands.json
        -o ${CMAKE_BINARY_DIR}/pvs-results.log
        -j ${NPROC}
        -e ${CMAKE_SOURCE_DIR}/tests/
    COMMAND plog-converter
        -a "GA:1,2;64:1,2;OP:1,2"
        -t sarif
        -o ${CMAKE_BINARY_DIR}/pvs-results.sarif
        ${CMAKE_BINARY_DIR}/pvs-results.log
    COMMENT "Running PVS-Studio (SARIF output for CI)"
    VERBATIM
)

# Run all static analyzers
add_custom_target(analyze
    DEPENDS codechecker pvs-studio
    COMMENT "Running all static analyzers"
)

# ============================================================================
# Configuration Summary
# ============================================================================

message(STATUS "")
message(STATUS "ioguard Configuration Summary")
message(STATUS "===================================")
message(STATUS "Version:           ${PROJECT_VERSION}")
message(STATUS "Build type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler:        ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "C standard:        C${CMAKE_C_STANDARD}")
message(STATUS "Install prefix:    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  liburing:        ${LIBURING_FOUND}")
message(STATUS "  tomlc99:         ${TOML_FOUND}")
message(STATUS "  protobuf-c:      ${PROTOBUF_C_FOUND}")
message(STATUS "  yyjson:          ${YYJSON_FOUND}")
message(STATUS "  cJSON:           ${CJSON_FOUND}")
message(STATUS "  mimalloc:        ${MIMALLOC_FOUND}")
message(STATUS "  c-ares:          ${CARES_FOUND}")
message(STATUS "  radcli:          ${RADCLI_FOUND}")
message(STATUS "  liboath:         ${LIBOATH_FOUND}")
message(STATUS "  libldap:         ${LDAP_FOUND}")
message(STATUS "  libmnl:          ${LIBMNL_FOUND}")
message(STATUS "  libnftnl:        ${LIBNFTNL_FOUND}")
message(STATUS "  LZ4:             ${LZ4_FOUND}")
message(STATUS "  libseccomp:      ${LIBSECCOMP_FOUND}")
message(STATUS "  PAM:             ${PAM_FOUND}")
message(STATUS "  Kerberos:        ${KRB5_FOUND}")
message(STATUS "  iohttpparser:    ${IOHTTPPARSER_FOUND}")
message(STATUS "  stumpless:       ${STUMPLESS_FOUND}")
message(STATUS "")
message(STATUS "TLS / Crypto:")
message(STATUS "  wolfSSL:         ${WOLFSSL_FOUND}")
message(STATUS "  GnuTLS:          ${GNUTLS_FOUND}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Build tests:     ${BUILD_TESTING}")
message(STATUS "  Build fuzz:      ${BUILD_FUZZ}")
message(STATUS "  Sanitizers:      ${ENABLE_SANITIZERS}")
message(STATUS "  Coverage:        ${ENABLE_COVERAGE}")
message(STATUS "  Documentation:   ${BUILD_DOCUMENTATION}")
message(STATUS "")
