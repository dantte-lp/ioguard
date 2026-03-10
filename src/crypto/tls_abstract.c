/*
 * Copyright (C) 2025 ringwall Contributors
 *
 * This file is part of ringwall.
 *
 * ringwall is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ringwall is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * TLS Abstraction Layer - Backend Dispatcher
 *
 * This file provides the runtime backend selection and dispatching logic
 * for the TLS abstraction layer. It allows ringwall to dynamically
 * choose between GnuTLS and wolfSSL backends at initialization time.
 *
 * Architecture:
 * - Maintains global state tracking the active backend
 * - Provides thread-safe initialization using C23 atomics
 * - Dispatches API calls to the appropriate backend implementation
 * - Ensures single initialization prevents backend mixing
 *
 * Thread Safety:
 * - Initialization functions use atomic operations for thread safety
 * - Backend dispatch is lock-free after initialization
 * - Safe for concurrent session creation after init
 */

#include "tls_abstract.h"

// Conditionally include backend headers to avoid struct redefinition
#ifdef USE_GNUTLS
#    include <gnutls/gnutls.h>
#    include "tls_gnutls.h"
#endif

#ifdef USE_WOLFSSL
#    include "tls_wolfssl.h"
#endif

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Global State
 * ============================================================================ */

/**
 * Global backend state
 *
 * Uses C23 atomic_bool for thread-safe initialization checking.
 * The backend selection is immutable after initialization to prevent
 * runtime backend switching which would be unsafe.
 */
static atomic_bool g_initialized = false;
static tls_backend_t g_active_backend = TLS_BACKEND_NONE;

/* ============================================================================
 * Backend Initialization and Management
 * ============================================================================ */

/**
 * Initialize TLS backend
 *
 * This function performs runtime backend selection and initialization.
 * It can only be called once - subsequent calls with the same backend
 * succeed immediately, but calls with different backends fail.
 *
 * @param backend Backend to initialize (TLS_BACKEND_GNUTLS or TLS_BACKEND_WOLFSSL)
 * @return TLS_E_SUCCESS on success, error code on failure
 *
 * Thread Safety: Uses atomic compare-exchange for initialization guard
 */
[[nodiscard]] int tls_global_init(tls_backend_t backend)
{
    // Validate backend parameter
    if (backend != TLS_BACKEND_GNUTLS && backend != TLS_BACKEND_WOLFSSL) {
        fprintf(stderr, "tls_global_init: Invalid backend %d\n", backend);
        return TLS_E_INVALID_PARAMETER;
    }

    // Check if already initialized
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_initialized, &expected, true)) {
        // Already initialized - verify same backend
        if (g_active_backend != backend) {
            fprintf(stderr, "tls_global_init: Backend mismatch (active: %d, requested: %d)\n",
                    g_active_backend, backend);
            return TLS_E_BACKEND_ERROR;
        }
        // Same backend already initialized - this is OK
        return TLS_E_SUCCESS;
    }

    // Store active backend before calling backend init
    g_active_backend = backend;

    // Dispatch to backend-specific initialization
    int ret;
    switch (backend) {
    case TLS_BACKEND_GNUTLS:
#ifdef USE_GNUTLS
        ret = tls_gnutls_init();
#else
        fprintf(stderr, "tls_global_init: GnuTLS backend not compiled in\n");
        atomic_store(&g_initialized, false);
        g_active_backend = TLS_BACKEND_NONE;
        return TLS_E_BACKEND_ERROR;
#endif
        break;

    case TLS_BACKEND_WOLFSSL:
#ifdef USE_WOLFSSL
        ret = tls_wolfssl_init();
#else
        fprintf(stderr, "tls_global_init: wolfSSL backend not compiled in\n");
        atomic_store(&g_initialized, false);
        g_active_backend = TLS_BACKEND_NONE;
        return TLS_E_BACKEND_ERROR;
#endif
        break;

    default:
        // Should never reach here due to validation above
        fprintf(stderr, "tls_global_init: Unexpected backend %d\n", backend);
        atomic_store(&g_initialized, false);
        g_active_backend = TLS_BACKEND_NONE;
        return TLS_E_INVALID_PARAMETER;
    }

    // Handle initialization failure
    if (ret != TLS_E_SUCCESS) {
        fprintf(stderr, "tls_global_init: Backend initialization failed (ret=%d)\n", ret);
        atomic_store(&g_initialized, false);
        g_active_backend = TLS_BACKEND_NONE;
        return ret;
    }

    return TLS_E_SUCCESS;
}

/**
 * Cleanup TLS backend
 *
 * Safely deinitializes the active TLS backend and resets global state.
 * Safe to call multiple times (idempotent).
 *
 * Thread Safety: Uses atomic load/store for state management
 */
void tls_global_deinit(void)
{
    // Check if initialized
    if (!atomic_load(&g_initialized)) {
        return; // Not initialized, nothing to do
    }

    // Dispatch to backend-specific cleanup
    switch (g_active_backend) {
    case TLS_BACKEND_GNUTLS:
#ifdef USE_GNUTLS
        tls_gnutls_deinit();
#endif
        break;

    case TLS_BACKEND_WOLFSSL:
#ifdef USE_WOLFSSL
        tls_wolfssl_deinit();
#endif
        break;

    case TLS_BACKEND_NONE:
        // Should not happen, but handle gracefully
        break;
    }

    // Reset global state
    g_active_backend = TLS_BACKEND_NONE;
    atomic_store(&g_initialized, false);
}

/**
 * Get currently active backend
 *
 * @return Active backend type, or TLS_BACKEND_NONE if not initialized
 */
[[nodiscard]] tls_backend_t tls_get_backend(void)
{
    return g_active_backend;
}

/**
 * Get TLS library version string
 *
 * Returns a human-readable version string for the active backend.
 * The string includes both the backend name and version number.
 *
 * @return Version string (e.g., "GnuTLS 3.8.0" or "wolfSSL 5.8.2")
 *         Returns "Not initialized" if no backend is active
 *
 * Thread Safety: Safe to call from multiple threads after initialization
 */
[[nodiscard]] const char *tls_get_version_string(void)
{
    // Check initialization status
    if (!atomic_load(&g_initialized)) {
        return "Not initialized";
    }

    // Dispatch to backend-specific version function
    switch (g_active_backend) {
    case TLS_BACKEND_GNUTLS:
#ifdef USE_GNUTLS
    {
        // GnuTLS doesn't have a separate get_version export, so construct it here
        static char gnutls_version[64];
        const char *gnutls_ver = gnutls_check_version(nullptr);
        if (gnutls_ver) {
            snprintf(gnutls_version, sizeof(gnutls_version), "GnuTLS %s", gnutls_ver);
            return gnutls_version;
        }
        return "GnuTLS (unknown version)";
    }
#else
        return "GnuTLS (not compiled in)";
#endif

    case TLS_BACKEND_WOLFSSL:
#ifdef USE_WOLFSSL
        return tls_wolfssl_get_version();
#else
        return "wolfSSL (not compiled in)";
#endif

    case TLS_BACKEND_NONE:
    default:
        return "Unknown backend";
    }
}
