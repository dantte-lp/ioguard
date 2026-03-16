/*
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ioguard.
 *
 * ioguard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ioguard is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef IOGUARD_SESSION_CACHE_H
#define IOGUARD_SESSION_CACHE_H

/**
 * In-Memory TLS Session Cache Implementation
 *
 * This module provides a thread-safe in-memory cache for TLS session resumption.
 * It uses a hash table with LRU (Least Recently Used) eviction policy.
 *
 * Features:
 * - Fast O(1) lookup by session ID (hash table)
 * - Automatic expiration of old sessions
 * - LRU eviction when cache is full
 * - Thread-safe operations (mutex-protected)
 * - Configurable capacity and timeout
 * - Zero-copy where possible
 *
 * Design:
 * - Hash table: session_id (first 8 bytes) → cache entry
 * - LRU list: doubly-linked list tracking access order
 * - Cleanup: periodic expiration check (on access)
 *
 * Usage:
 *   session_cache_t *cache = session_cache_new(1000, 7200); // 1000 entries, 2h timeout
 *   tls_context_set_session_cache(ctx,
 *                                  session_cache_store,
 *                                  session_cache_retrieve,
 *                                  session_cache_remove,
 *                                  cache);
 *   // ... use TLS context ...
 *   session_cache_free(cache);
 */

#include <pthread.h>
#include "tls_abstract.h"

// C23 standard compliance
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

// Default configuration
constexpr size_t SESSION_CACHE_DEFAULT_CAPACITY = 1'000;
constexpr unsigned int SESSION_CACHE_DEFAULT_TIMEOUT_SECS = 7'200; // 2 hours

// Hash table configuration
constexpr size_t SESSION_CACHE_HASH_BUCKETS = 256; // Power of 2 for fast modulo

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/**
 * Session cache handle (opaque)
 */
typedef struct session_cache session_cache_t;

/* ============================================================================
 * Cache Management
 * ============================================================================ */

/**
 * Create new session cache
 *
 * @param capacity Maximum number of sessions to cache
 * @param timeout_secs Session timeout in seconds
 * @return Cache handle on success, nullptr on failure
 *
 * Note: capacity must be > 0, timeout_secs must be > 0
 */
[[nodiscard]] session_cache_t *session_cache_new(size_t capacity, unsigned int timeout_secs);

/**
 * Free session cache
 *
 * @param cache Cache handle
 *
 * Note: All cached sessions will be destroyed.
 *       This function is thread-safe and will wait for ongoing operations.
 */
void session_cache_free(session_cache_t *cache);

/**
 * Clear all sessions from cache
 *
 * @param cache Cache handle
 *
 * Note: Thread-safe operation.
 */
void session_cache_clear(session_cache_t *cache);

/**
 * Get cache statistics
 *
 * @param cache Cache handle
 * @param count Output: current number of cached sessions
 * @param capacity Output: maximum capacity
 * @param hits Output: number of successful retrievals
 * @param misses Output: number of failed retrievals
 * @param evictions Output: number of LRU evictions
 */
void session_cache_get_stats(session_cache_t *cache, size_t *count, size_t *capacity,
                             uint64_t *hits, uint64_t *misses, uint64_t *evictions);

/* ============================================================================
 * TLS Callback Functions
 * ============================================================================ */

/**
 * Store session in cache (TLS callback)
 *
 * @param userdata Cache handle (session_cache_t*)
 * @param entry Session to store
 * @return 0 on success, -1 on failure
 *
 * Note: This function is called by TLS backend when new session is established.
 *       It performs LRU eviction if cache is full.
 *       Expired sessions are automatically removed.
 */
[[nodiscard]] int session_cache_store(void *userdata, const tls_session_cache_entry_t *entry);

/**
 * Retrieve session from cache (TLS callback)
 *
 * @param userdata Cache handle (session_cache_t*)
 * @param session_id Session ID to look up
 * @param session_id_size Length of session ID
 * @param entry Output: retrieved session
 * @return 0 on success, -1 if not found or expired
 *
 * Note: This function is called by TLS backend during session resumption.
 *       Expired sessions are automatically removed and return -1.
 *       On successful retrieval, entry is moved to front of LRU list.
 */
[[nodiscard]] int session_cache_retrieve(void *userdata, const uint8_t *session_id,
                                         size_t session_id_size, tls_session_cache_entry_t *entry);

/**
 * Remove session from cache (TLS callback)
 *
 * @param userdata Cache handle (session_cache_t*)
 * @param session_id Session ID to remove
 * @param session_id_size Length of session ID
 * @return 0 on success, -1 if not found
 *
 * Note: This function is called by TLS backend when session should be invalidated.
 */
[[nodiscard]] int session_cache_remove(void *userdata, const uint8_t *session_id,
                                       size_t session_id_size);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Manually remove expired sessions
 *
 * @param cache Cache handle
 * @return Number of sessions removed
 *
 * Note: This function is optional - expiration happens automatically on access.
 *       Can be called periodically for proactive cleanup.
 */
[[nodiscard]] size_t session_cache_cleanup_expired(session_cache_t *cache);

/**
 * Check if cache is full
 *
 * @param cache Cache handle
 * @return true if at capacity, false otherwise
 */
[[nodiscard]] bool session_cache_is_full(session_cache_t *cache);

/**
 * Get current cache size
 *
 * @param cache Cache handle
 * @return Number of cached sessions
 */
[[nodiscard]] size_t session_cache_size(session_cache_t *cache);

/* ============================================================================
 * C23 Cleanup Attribute Support
 * ============================================================================ */

/**
 * Cleanup function for automatic cache freeing
 *
 * Usage:
 *   __attribute__((cleanup(session_cache_cleanup)))
 *   session_cache_t *cache = session_cache_new(1000, 7200);
 */
static inline void session_cache_cleanup(session_cache_t **cache_ptr)
{
    if (cache_ptr != nullptr && *cache_ptr != nullptr) {
        session_cache_free(*cache_ptr);
        *cache_ptr = nullptr;
    }
}

#endif // IOGUARD_SESSION_CACHE_H
