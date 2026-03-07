# CMakeLists.txt for wolfguard
# Modern C23 VPN server with io_uring event loop
# Dual-compiler: Clang 22+ (dev) / GCC 15+ (release)
cmake_minimum_required(VERSION 3.25)

project(wolfguard
    VERSION 2.0.0
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
pkg_check_modules(LIBUV libuv>=1.44.0)
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
# wolfguard core libraries
# ============================================================================

add_library(wg_io STATIC src/io/uring.c)
target_link_libraries(wg_io PUBLIC ${LIBURING_LIBRARIES})
target_link_directories(wg_io PUBLIC ${LIBURING_LIBRARY_DIRS})
target_include_directories(wg_io PUBLIC ${CMAKE_SOURCE_DIR}/src ${LIBURING_INCLUDE_DIRS})
target_compile_definitions(wg_io PUBLIC _GNU_SOURCE)

add_library(wg_memory STATIC src/utils/memory.c)
target_include_directories(wg_memory PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(MIMALLOC_FOUND)
    target_link_libraries(wg_memory PUBLIC ${MIMALLOC_LIBRARY})
    target_include_directories(wg_memory PUBLIC ${MIMALLOC_INCLUDE_DIR})
    target_compile_definitions(wg_memory PUBLIC USE_MIMALLOC)
endif()

add_library(wg_config STATIC src/config/config.c)
target_include_directories(wg_config PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(TOML_FOUND)
    target_link_libraries(wg_config PUBLIC ${TOML_LIBRARY})
    target_include_directories(wg_config PUBLIC ${TOML_INCLUDE_DIR})
    target_compile_definitions(wg_config PUBLIC USE_TOML)
endif()

# Generate protobuf-c sources
set(PROTO_SRC ${CMAKE_SOURCE_DIR}/src/ipc/proto/wg_ipc.proto)
if(EXISTS ${PROTO_SRC})
    add_custom_command(
        OUTPUT ${PROTO_GEN_DIR}/wg_ipc.pb-c.h ${PROTO_GEN_DIR}/wg_ipc.pb-c.c
        COMMAND ${PROTOC_C} --c_out=${PROTO_GEN_DIR}
                --proto_path=${CMAKE_SOURCE_DIR}/src/ipc/proto
                ${PROTO_SRC}
        DEPENDS ${PROTO_SRC}
        COMMENT "Generating protobuf-c sources from wg_ipc.proto"
    )
    add_custom_target(proto_gen DEPENDS ${PROTO_GEN_DIR}/wg_ipc.pb-c.h)
    set(PROTO_GEN_SOURCES ${PROTO_GEN_DIR}/wg_ipc.pb-c.c)
else()
    set(PROTO_GEN_SOURCES "")
endif()

add_library(wg_ipc STATIC src/ipc/transport.c src/ipc/messages.c ${PROTO_GEN_SOURCES})
if(TARGET proto_gen)
    add_dependencies(wg_ipc proto_gen)
endif()
target_link_libraries(wg_ipc PUBLIC ${PROTOBUF_C_LIBRARIES} wg_memory)
target_link_directories(wg_ipc PUBLIC ${PROTOBUF_C_LIBRARY_DIRS})
target_include_directories(wg_ipc PUBLIC ${CMAKE_SOURCE_DIR}/src ${PROTOBUF_C_INCLUDE_DIRS} ${PROTO_GEN_DIR})

add_library(wg_xml_auth STATIC src/network/xml_auth.c)
target_include_directories(wg_xml_auth PUBLIC ${CMAKE_SOURCE_DIR}/src)

add_library(wg_http STATIC src/network/http.c)
target_include_directories(wg_http PUBLIC ${CMAKE_SOURCE_DIR}/src /usr/local/include)
target_link_libraries(wg_http PUBLIC llhttp)
target_link_directories(wg_http PUBLIC /usr/local/lib64)
target_compile_definitions(wg_http PUBLIC _GNU_SOURCE)

add_library(wg_core STATIC src/core/process.c)
target_include_directories(wg_core PUBLIC ${CMAKE_SOURCE_DIR}/src)

add_library(wg_session STATIC src/core/session.c)
target_include_directories(wg_session PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(wg_session PUBLIC _GNU_SOURCE)
if(WOLFSSL_FOUND)
    target_compile_definitions(wg_session PRIVATE USE_WOLFSSL)
    target_include_directories(wg_session PRIVATE ${WOLFSSL_INCLUDE_DIRS})
    target_link_libraries(wg_session PRIVATE ${WOLFSSL_LIBRARIES})
    target_link_directories(wg_session PRIVATE ${WOLFSSL_LIBRARY_DIRS})
endif()

# --- Crypto / TLS libraries ---
# wolfSSL backend
if(WOLFSSL_FOUND)
    add_library(wg_crypto STATIC
        src/crypto/tls_wolfssl.c
        src/crypto/tls_abstract.c
        src/crypto/priority_parser.c
        src/crypto/session_cache.c
    )
    target_compile_definitions(wg_crypto PUBLIC _GNU_SOURCE USE_WOLFSSL)
    target_include_directories(wg_crypto PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${WOLFSSL_INCLUDE_DIRS}
    )
    target_link_libraries(wg_crypto PUBLIC ${WOLFSSL_LIBRARIES} pthread)
    target_link_directories(wg_crypto PUBLIC ${WOLFSSL_LIBRARY_DIRS})
    message(STATUS "wg_crypto (wolfSSL backend) configured")
endif()

# GnuTLS backend
if(GNUTLS_FOUND)
    add_library(wg_crypto_gnutls STATIC
        src/crypto/tls_gnutls.c
        src/crypto/tls_abstract.c
        src/crypto/session_cache.c
    )
    target_compile_definitions(wg_crypto_gnutls PUBLIC _GNU_SOURCE USE_GNUTLS)
    target_include_directories(wg_crypto_gnutls PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/crypto
        ${GNUTLS_INCLUDE_DIRS}
    )
    target_link_libraries(wg_crypto_gnutls PUBLIC ${GNUTLS_LIBRARIES} pthread)
    target_link_directories(wg_crypto_gnutls PUBLIC ${GNUTLS_LIBRARY_DIRS})
    message(STATUS "wg_crypto_gnutls (GnuTLS backend) configured")
endif()

# --- PAM authentication backend ---
find_library(PAM_LIBRARY pam)
if(PAM_LIBRARY)
    add_library(wg_pam STATIC src/auth/pam.c)
    target_link_libraries(wg_pam PRIVATE ${PAM_LIBRARY})
    target_compile_definitions(wg_pam PRIVATE _GNU_SOURCE)
    target_include_directories(wg_pam PUBLIC ${CMAKE_SOURCE_DIR}/src)
    message(STATUS "wg_pam (PAM authentication backend) configured")
endif()

# --- sec-mod authentication process ---
if(TARGET wg_pam)
    add_library(wg_secmod STATIC src/core/secmod.c)
    target_include_directories(wg_secmod PUBLIC ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(wg_secmod PRIVATE _GNU_SOURCE)
    target_link_libraries(wg_secmod PUBLIC wg_ipc wg_session wg_pam wg_config)
    message(STATUS "wg_secmod (sec-mod authentication process) configured")
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

        macro(wg_add_test TEST_NAME TEST_SRC)
            add_executable(${TEST_NAME} ${TEST_SRC})
            target_link_libraries(${TEST_NAME} PRIVATE unity ${ARGN})
            add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
        endmacro()

        # Sprint 1 tests
        wg_add_test(test_memory tests/unit/test_memory.c wg_memory)
        wg_add_test(test_io_uring tests/unit/test_io_uring.c wg_io)
        wg_add_test(test_ipc_transport tests/unit/test_ipc_transport.c wg_ipc)
        wg_add_test(test_ipc_messages tests/unit/test_ipc_messages.c wg_ipc)
        wg_add_test(test_config_toml tests/unit/test_config_toml.c wg_config)
        wg_add_test(test_process tests/unit/test_process.c wg_core)
        if(EXISTS ${CMAKE_SOURCE_DIR}/tests/integration/test_ipc_roundtrip.c)
            wg_add_test(test_ipc_roundtrip tests/integration/test_ipc_roundtrip.c wg_ipc wg_io)
        endif()

        # Sprint 2 crypto tests
        if(TARGET wg_crypto)
            wg_add_test(test_tls_wolfssl tests/unit/test_tls_wolfssl.c wg_crypto)
            wg_add_test(test_priority_parser tests/unit/test_priority_parser.c wg_crypto)
        endif()
        if(TARGET wg_crypto_gnutls)
            wg_add_test(test_tls_gnutls tests/unit/test_tls_gnutls.c wg_crypto_gnutls)
        endif()

        # Sprint 2 network tests
        wg_add_test(test_http tests/unit/test_http.c wg_http)
        wg_add_test(test_xml_auth tests/unit/test_xml_auth.c wg_xml_auth)

        # Sprint 2 session tests
        wg_add_test(test_session tests/unit/test_session.c wg_session)

        # Sprint 2 PAM authentication tests
        if(TARGET wg_pam)
            wg_add_test(test_auth_pam tests/unit/test_auth_pam.c wg_pam)
        endif()

        # Sprint 2 sec-mod authentication process tests
        if(TARGET wg_secmod)
            wg_add_test(test_secmod tests/unit/test_secmod.c wg_secmod)
        endif()

        message(STATUS "Unit test infrastructure ready (wg_add_test macro)")
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

    file(GLOB FUZZ_SOURCES tests/fuzz/fuzz_*.c)
    foreach(FUZZ_SRC ${FUZZ_SOURCES})
        get_filename_component(FUZZ_NAME ${FUZZ_SRC} NAME_WE)
        add_executable(${FUZZ_NAME} ${FUZZ_SRC})
        target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
    endforeach()

    message(STATUS "Building fuzzing targets (LibFuzzer)")
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

# ============================================================================
# Configuration Summary
# ============================================================================

message(STATUS "")
message(STATUS "wolfguard Configuration Summary")
message(STATUS "===================================")
message(STATUS "Version:           ${PROJECT_VERSION}")
message(STATUS "Build type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler:        ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "C standard:        C${CMAKE_C_STANDARD}")
message(STATUS "Install prefix:    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  liburing:        ${LIBURING_FOUND}")
message(STATUS "  libuv:           ${LIBUV_FOUND}")
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
