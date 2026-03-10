# Makefile for ioguard
# Copyright (C) 2025 ioguard Contributors
#
# Build system for TLS abstraction layer with dual backend support

# ============================================================================
# Configuration
# ============================================================================

# Compiler (must support C23)
CC := gcc
AR := ar

# Backend selection (can be overridden: make BACKEND=wolfssl)
BACKEND ?= gnutls

# Compiler flags (C23 standard required)
CFLAGS := -std=c23 -Wall -Wextra -Wpedantic -Werror
CFLAGS += -g -O2
CFLAGS += -Isrc/crypto
CFLAGS += -fPIC

# Debug flags (enable with: make DEBUG=1)
ifdef DEBUG
CFLAGS += -DDEBUG -O0 -ggdb3
endif

# Sanitizers (enable with: make SANITIZE=1)
ifdef SANITIZE
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

# ============================================================================
# Backend-Specific Configuration
# ============================================================================

ifeq ($(BACKEND),gnutls)
    CFLAGS += -DUSE_GNUTLS
    BACKEND_LDFLAGS := $(shell pkg-config --libs gnutls 2>/dev/null || echo "-lgnutls")
    BACKEND_CFLAGS := $(shell pkg-config --cflags gnutls 2>/dev/null)
    BACKEND_SRC := src/crypto/tls_gnutls.c
    BACKEND_OBJ := src/crypto/tls_gnutls.o
    BACKEND_LIB := libtls_gnutls.a
else ifeq ($(BACKEND),wolfssl)
    CFLAGS += -DUSE_WOLFSSL
    BACKEND_LDFLAGS := $(shell pkg-config --libs wolfssl 2>/dev/null || echo "-lwolfssl")
    BACKEND_CFLAGS := $(shell pkg-config --cflags wolfssl 2>/dev/null)
    BACKEND_SRC := src/crypto/tls_wolfssl.c
    BACKEND_OBJ := src/crypto/tls_wolfssl.o
    BACKEND_LIB := libtls_wolfssl.a
else
    $(error Invalid BACKEND: $(BACKEND). Use 'gnutls' or 'wolfssl')
endif

CFLAGS += $(BACKEND_CFLAGS)
LDFLAGS += $(BACKEND_LDFLAGS)

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean test poc help install

all: $(BACKEND_LIB)

# Backend library
$(BACKEND_LIB): $(BACKEND_OBJ)
	@echo "  AR      $@"
	@$(AR) rcs $@ $^

$(BACKEND_OBJ): $(BACKEND_SRC) src/crypto/tls_abstract.h
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -c $< -o $@

# ============================================================================
# Unit Tests
# ============================================================================

# GnuTLS unit tests
tests/unit/test_tls_gnutls: tests/unit/test_tls_gnutls.c src/crypto/tls_gnutls.o
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -DUSE_GNUTLS $^ -o $@ $(shell pkg-config --libs gnutls 2>/dev/null || echo "-lgnutls")

# wolfSSL unit tests
tests/unit/test_tls_wolfssl: tests/unit/test_tls_wolfssl.c src/crypto/tls_wolfssl.o
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -DUSE_WOLFSSL $^ -o $@ $(shell pkg-config --libs wolfssl 2>/dev/null || echo "-lwolfssl")

# Priority parser unit tests (requires wolfSSL for implementation)
tests/unit/test_priority_parser: tests/unit/test_priority_parser.c src/crypto/priority_parser.c src/crypto/tls_wolfssl.o
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -DUSE_WOLFSSL $^ -o $@ $(shell pkg-config --libs wolfssl 2>/dev/null || echo "-lwolfssl")

# Run unit tests for current backend
test-unit: $(BACKEND_LIB)
ifeq ($(BACKEND),gnutls)
	@echo "Running GnuTLS unit tests..."
	@$(MAKE) -s tests/unit/test_tls_gnutls BACKEND=gnutls
	@./tests/unit/test_tls_gnutls
else
	@echo "Running wolfSSL unit tests..."
	@$(MAKE) -s tests/unit/test_tls_wolfssl BACKEND=wolfssl
	@LD_LIBRARY_PATH=/usr/local/lib:$$LD_LIBRARY_PATH ./tests/unit/test_tls_wolfssl
endif

# Run priority parser tests
test-priority-parser:
	@echo "Building priority parser tests..."
	@$(MAKE) -s tests/unit/test_priority_parser BACKEND=wolfssl
	@echo "Running priority parser tests..."
	@LD_LIBRARY_PATH=/usr/local/lib:$$LD_LIBRARY_PATH ./tests/unit/test_priority_parser

# Run unit tests for both backends
test-both:
	@echo "Testing GnuTLS backend..."
	@$(MAKE) -s clean
	@$(MAKE) -s test-unit BACKEND=gnutls
	@echo ""
	@echo "Testing wolfSSL backend..."
	@$(MAKE) -s clean
	@$(MAKE) -s test-unit BACKEND=wolfssl
	@echo ""
	@echo "All backend tests completed!"

# ============================================================================
# Proof of Concept (PoC) Server and Client
# ============================================================================

# TLS abstraction dispatcher
TLS_ABSTRACT_OBJ := src/crypto/tls_abstract.o

src/crypto/tls_abstract.o: src/crypto/tls_abstract.c src/crypto/tls_abstract.h src/crypto/tls_gnutls.h src/crypto/tls_wolfssl.h
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -c $< -o $@

poc-server: tests/poc/tls_poc_server.c $(TLS_ABSTRACT_OBJ) $(BACKEND_OBJ)
	@echo "  CC      $@ ($(BACKEND))"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

poc-client: tests/poc/tls_poc_client.c $(TLS_ABSTRACT_OBJ) $(BACKEND_OBJ)
	@echo "  CC      $@ ($(BACKEND))"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

poc: poc-server poc-client

poc-both:
	@echo "Building PoC with GnuTLS..."
	@$(MAKE) -s clean
	@$(MAKE) -s poc BACKEND=gnutls
	@mv poc-server poc-server-gnutls
	@mv poc-client poc-client-gnutls
	@echo ""
	@echo "Building PoC with wolfSSL..."
	@rm -f src/crypto/*.o
	@$(MAKE) -s poc BACKEND=wolfssl
	@mv poc-server poc-server-wolfssl
	@mv poc-client poc-client-wolfssl
	@echo ""
	@echo "PoC binaries created:"
	@ls -lh poc-server-* poc-client-*

# ============================================================================
# Testing Targets
# ============================================================================

test: test-unit

# Quick smoke test (build and run basic tests)
smoke:
	@echo "=== Smoke Test ==="
	@$(MAKE) -s clean
	@$(MAKE) -s all BACKEND=gnutls
	@$(MAKE) -s test-unit BACKEND=gnutls

# ============================================================================
# Utility Targets
# ============================================================================

clean:
	@echo "  CLEAN"
	@rm -f src/crypto/*.o
	@rm -f src/crypto/*.d
	@rm -f *.a
	@rm -f tests/unit/test_tls_gnutls tests/unit/test_tls_wolfssl
	@rm -f poc-server poc-client
	@rm -f poc-server-gnutls poc-server-wolfssl
	@rm -f poc-client-gnutls poc-client-wolfssl

help:
	@echo "ioguard Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build backend library (default: gnutls)"
	@echo "  test-unit        Run unit tests for current backend"
	@echo "  test-both        Run unit tests for both backends"
	@echo "  poc              Build PoC server and client"
	@echo "  poc-both         Build PoC with both backends"
	@echo "  smoke            Quick smoke test"
	@echo "  clean            Remove build artifacts"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  BACKEND=gnutls|wolfssl   Select TLS backend (default: gnutls)"
	@echo "  DEBUG=1                   Enable debug build"
	@echo "  SANITIZE=1                Enable sanitizers (ASan, UBSan)"
	@echo ""
	@echo "Examples:"
	@echo "  make                      # Build with GnuTLS"
	@echo "  make BACKEND=wolfssl      # Build with wolfSSL"
	@echo "  make test-unit            # Test current backend"
	@echo "  make test-both            # Test both backends"
	@echo "  make poc BACKEND=gnutls   # Build PoC server/client with GnuTLS"
	@echo "  make poc-both             # Build PoC with both backends"

# ============================================================================
# Installation (Future)
# ============================================================================

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

install: all
	@echo "  INSTALL $(LIBDIR)/$(BACKEND_LIB)"
	@install -d $(LIBDIR)
	@install -m 644 $(BACKEND_LIB) $(LIBDIR)/
	@echo "  INSTALL $(INCLUDEDIR)/tls_abstract.h"
	@install -d $(INCLUDEDIR)/ringwall
	@install -m 644 src/crypto/tls_abstract.h $(INCLUDEDIR)/ringwall/

# ============================================================================
# Dependency Tracking
# ============================================================================

-include $(BACKEND_OBJ:.o=.d)

%.o: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
