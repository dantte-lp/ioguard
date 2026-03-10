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

#include "session_cache.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// C23 standard compliance
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Internal Data Structures
 * ============================================================================ */

/**
 * Cache entry (hash table node + LRU list node)
 */
typedef struct cache_entry {
    // Session data
    tls_session_cache_entry_t session;

    // Hash table linkage (chaining for collisions)
    struct cache_entry *hash_next;
    struct cache_entry *hash_prev;

    // LRU list linkage (doubly linked)
    struct cache_entry *lru_next;
    struct cache_entry *lru_prev;

    // Timestamp for LRU tracking
    time_t last_access;
} cache_entry_t;

/**
 * Session cache (hash table + LRU list)
 */
struct session_cache {
    // Configuration
    size_t capacity;
    unsigned int timeout_secs;

    // Hash table (array of bucket heads)
    cache_entry_t *hash_table[SESSION_CACHE_HASH_BUCKETS];

    // LRU list (head = most recent, tail = least recent)
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;

    // Current state
    size_t count;

    // Statistics
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t expirations;

    // Thread safety
    pthread_mutex_t mutex;
};

/* ============================================================================
 * Hash Function (FNV-1a)
 * ============================================================================ */

/**
 * FNV-1a hash function for session IDs
 *
 * Uses first 8 bytes of session_id for fast hashing.
 * FNV-1a is chosen for:
 * - Excellent avalanche properties
 * - Fast computation
 * - No patent restrictions
 *
 * @param session_id Session ID bytes
 * @param session_id_size Length of session ID
 * @return Hash value (0 to SESSION_CACHE_HASH_BUCKETS-1)
 */
static inline size_t hash_session_id(const uint8_t *session_id, size_t session_id_size)
{
    // FNV-1a constants
    constexpr uint64_t FNV_OFFSET_BASIS = 14'695'981'039'346'656'037ULL;
    constexpr uint64_t FNV_PRIME = 1'099'511'628'211ULL;

    uint64_t hash = FNV_OFFSET_BASIS;

    // Hash first 8 bytes (or less if shorter)
    size_t hash_len = (session_id_size < 8) ? session_id_size : 8;
    for (size_t i = 0; i < hash_len; i++) {
        hash ^= session_id[i];
        hash *= FNV_PRIME;
    }

    // Map to bucket index (fast modulo using power-of-2)
    return hash & (SESSION_CACHE_HASH_BUCKETS - 1);
}

/**
 * Compare session IDs for equality
 */
static inline bool session_id_equal(const uint8_t *id1, size_t len1, const uint8_t *id2,
                                    size_t len2)
{
    if (len1 != len2) {
        return false;
    }
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len1; i++) {
        diff |= id1[i] ^ id2[i];
    }
    return diff == 0;
}

/* ============================================================================
 * LRU List Operations
 * ============================================================================ */

/**
 * Remove entry from LRU list
 */
static void lru_remove(session_cache_t *cache, cache_entry_t *entry)
{
    if (entry->lru_prev != nullptr) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        // entry is head
        cache->lru_head = entry->lru_next;
    }

    if (entry->lru_next != nullptr) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        // entry is tail
        cache->lru_tail = entry->lru_prev;
    }

    entry->lru_prev = nullptr;
    entry->lru_next = nullptr;
}

/**
 * Add entry to front of LRU list (most recently used)
 */
static void lru_add_front(session_cache_t *cache, cache_entry_t *entry)
{
    entry->lru_next = cache->lru_head;
    entry->lru_prev = nullptr;

    if (cache->lru_head != nullptr) {
        cache->lru_head->lru_prev = entry;
    } else {
        // First entry
        cache->lru_tail = entry;
    }

    cache->lru_head = entry;
    entry->last_access = time(nullptr);
}

/**
 * Move entry to front of LRU list (mark as recently used)
 */
static void lru_move_front(session_cache_t *cache, cache_entry_t *entry)
{
    if (cache->lru_head == entry) {
        // Already at front
        entry->last_access = time(nullptr);
        return;
    }

    lru_remove(cache, entry);
    lru_add_front(cache, entry);
}

/**
 * Get least recently used entry (tail of LRU list)
 */
static cache_entry_t *lru_get_tail(session_cache_t *cache)
{
    return cache->lru_tail;
}

/* ============================================================================
 * Hash Table Operations
 * ============================================================================ */

/**
 * Find entry in hash table by session ID
 */
static cache_entry_t *hash_find(session_cache_t *cache, const uint8_t *session_id,
                                size_t session_id_size)
{
    size_t bucket = hash_session_id(session_id, session_id_size);
    cache_entry_t *entry = cache->hash_table[bucket];

    while (entry != nullptr) {
        if (session_id_equal(entry->session.session_id, entry->session.session_id_size, session_id,
                             session_id_size)) {
            return entry;
        }
        entry = entry->hash_next;
    }

    return nullptr;
}

/**
 * Insert entry into hash table
 */
static void hash_insert(session_cache_t *cache, cache_entry_t *entry)
{
    size_t bucket = hash_session_id(entry->session.session_id, entry->session.session_id_size);

    // Insert at head of bucket chain
    entry->hash_next = cache->hash_table[bucket];
    entry->hash_prev = nullptr;

    if (cache->hash_table[bucket] != nullptr) {
        cache->hash_table[bucket]->hash_prev = entry;
    }

    cache->hash_table[bucket] = entry;
}

/**
 * Remove entry from hash table
 */
static void hash_remove(session_cache_t *cache, cache_entry_t *entry)
{
    size_t bucket = hash_session_id(entry->session.session_id, entry->session.session_id_size);

    if (entry->hash_prev != nullptr) {
        entry->hash_prev->hash_next = entry->hash_next;
    } else {
        // entry is head of bucket
        cache->hash_table[bucket] = entry->hash_next;
    }

    if (entry->hash_next != nullptr) {
        entry->hash_next->hash_prev = entry->hash_prev;
    }

    entry->hash_prev = nullptr;
    entry->hash_next = nullptr;
}

/* ============================================================================
 * Cache Entry Operations
 * ============================================================================ */

/**
 * Create new cache entry
 */
static cache_entry_t *entry_new(const tls_session_cache_entry_t *session)
{
    cache_entry_t *entry = calloc(1, sizeof(*entry));
    if (entry == nullptr) {
        return nullptr;
    }

    // Copy session data
    memcpy(&entry->session, session, sizeof(tls_session_cache_entry_t));
    entry->last_access = time(nullptr);

    return entry;
}

/**
 * Free cache entry
 */
static void entry_free(cache_entry_t *entry)
{
    if (entry != nullptr) {
        // Zero sensitive session data
        memset(&entry->session, 0, sizeof(tls_session_cache_entry_t));
        free(entry);
    }
}

/**
 * Check if entry is expired
 */
static bool entry_is_expired(cache_entry_t *entry, time_t now)
{
    return (entry->session.expiration > 0) && (now > entry->session.expiration);
}

/* ============================================================================
 * Cache Management Implementation
 * ============================================================================ */

session_cache_t *session_cache_new(size_t capacity, unsigned int timeout_secs)
{
    if (capacity == 0 || timeout_secs == 0) {
        errno = EINVAL;
        return nullptr;
    }

    session_cache_t *cache = calloc(1, sizeof(*cache));
    if (cache == nullptr) {
        return nullptr;
    }

    cache->capacity = capacity;
    cache->timeout_secs = timeout_secs;
    cache->count = 0;
    cache->hits = 0;
    cache->misses = 0;
    cache->evictions = 0;
    cache->expirations = 0;
    cache->lru_head = nullptr;
    cache->lru_tail = nullptr;

    // Initialize hash table to null
    for (size_t i = 0; i < SESSION_CACHE_HASH_BUCKETS; i++) {
        cache->hash_table[i] = nullptr;
    }

    // Initialize mutex
    if (pthread_mutex_init(&cache->mutex, nullptr) != 0) {
        free(cache);
        return nullptr;
    }

    return cache;
}

void session_cache_free(session_cache_t *cache)
{
    if (cache == nullptr) {
        return;
    }

    pthread_mutex_lock(&cache->mutex);

    // Free all entries
    cache_entry_t *entry = cache->lru_head;
    while (entry != nullptr) {
        cache_entry_t *next = entry->lru_next;
        entry_free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);

    free(cache);
}

void session_cache_clear(session_cache_t *cache)
{
    if (cache == nullptr) {
        return;
    }

    pthread_mutex_lock(&cache->mutex);

    // Free all entries
    cache_entry_t *entry = cache->lru_head;
    while (entry != nullptr) {
        cache_entry_t *next = entry->lru_next;
        entry_free(entry);
        entry = next;
    }

    // Reset state
    cache->lru_head = nullptr;
    cache->lru_tail = nullptr;
    cache->count = 0;

    // Clear hash table
    for (size_t i = 0; i < SESSION_CACHE_HASH_BUCKETS; i++) {
        cache->hash_table[i] = nullptr;
    }

    pthread_mutex_unlock(&cache->mutex);
}

void session_cache_get_stats(session_cache_t *cache, size_t *count, size_t *capacity,
                             uint64_t *hits, uint64_t *misses, uint64_t *evictions)
{
    if (cache == nullptr) {
        return;
    }

    pthread_mutex_lock(&cache->mutex);

    if (count != nullptr) {
        *count = cache->count;
    }
    if (capacity != nullptr) {
        *capacity = cache->capacity;
    }
    if (hits != nullptr) {
        *hits = cache->hits;
    }
    if (misses != nullptr) {
        *misses = cache->misses;
    }
    if (evictions != nullptr) {
        *evictions = cache->evictions;
    }

    pthread_mutex_unlock(&cache->mutex);
}

/* ============================================================================
 * TLS Callback Functions Implementation
 * ============================================================================ */

int session_cache_store(void *userdata, const tls_session_cache_entry_t *entry)
{
    if (userdata == nullptr || entry == nullptr) {
        return -1;
    }

    session_cache_t *cache = (session_cache_t *)userdata;

    pthread_mutex_lock(&cache->mutex);

    // Check if session already exists
    cache_entry_t *existing = hash_find(cache, entry->session_id, entry->session_id_size);

    if (existing != nullptr) {
        // Update existing entry
        memcpy(&existing->session, entry, sizeof(tls_session_cache_entry_t));
        lru_move_front(cache, existing);
        pthread_mutex_unlock(&cache->mutex);
        return 0;
    }

    // Need to add new entry
    // Check if cache is full
    if (cache->count >= cache->capacity) {
        // Evict LRU entry
        cache_entry_t *lru = lru_get_tail(cache);
        if (lru != nullptr) {
            hash_remove(cache, lru);
            lru_remove(cache, lru);
            entry_free(lru);
            cache->count--;
            cache->evictions++;
        }
    }

    // Create new entry
    cache_entry_t *new_entry = entry_new(entry);
    if (new_entry == nullptr) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }

    // Insert into hash table and LRU list
    hash_insert(cache, new_entry);
    lru_add_front(cache, new_entry);
    cache->count++;

    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

int session_cache_retrieve(void *userdata, const uint8_t *session_id, size_t session_id_size,
                           tls_session_cache_entry_t *entry)
{
    if (userdata == nullptr || session_id == nullptr || entry == nullptr) {
        return -1;
    }

    session_cache_t *cache = (session_cache_t *)userdata;

    pthread_mutex_lock(&cache->mutex);

    // Find entry
    cache_entry_t *found = hash_find(cache, session_id, session_id_size);

    if (found == nullptr) {
        cache->misses++;
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }

    // Check if expired
    time_t now = time(nullptr);
    if (entry_is_expired(found, now)) {
        // Remove expired entry
        hash_remove(cache, found);
        lru_remove(cache, found);
        entry_free(found);
        cache->count--;
        cache->expirations++;
        cache->misses++;
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }

    // Copy session data
    memcpy(entry, &found->session, sizeof(tls_session_cache_entry_t));

    // Move to front of LRU list
    lru_move_front(cache, found);
    cache->hits++;

    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

int session_cache_remove(void *userdata, const uint8_t *session_id, size_t session_id_size)
{
    if (userdata == nullptr || session_id == nullptr) {
        return -1;
    }

    session_cache_t *cache = (session_cache_t *)userdata;

    pthread_mutex_lock(&cache->mutex);

    // Find entry
    cache_entry_t *found = hash_find(cache, session_id, session_id_size);

    if (found == nullptr) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }

    // Remove from hash table and LRU list
    hash_remove(cache, found);
    lru_remove(cache, found);
    entry_free(found);
    cache->count--;

    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

/* ============================================================================
 * Utility Functions Implementation
 * ============================================================================ */

size_t session_cache_cleanup_expired(session_cache_t *cache)
{
    if (cache == nullptr) {
        return 0;
    }

    pthread_mutex_lock(&cache->mutex);

    time_t now = time(nullptr);
    size_t removed = 0;

    // Iterate through LRU list and remove expired entries
    cache_entry_t *entry = cache->lru_head;
    while (entry != nullptr) {
        cache_entry_t *next = entry->lru_next;

        if (entry_is_expired(entry, now)) {
            hash_remove(cache, entry);
            lru_remove(cache, entry);
            entry_free(entry);
            cache->count--;
            cache->expirations++;
            removed++;
        }

        entry = next;
    }

    pthread_mutex_unlock(&cache->mutex);
    return removed;
}

bool session_cache_is_full(session_cache_t *cache)
{
    if (cache == nullptr) {
        return false;
    }

    pthread_mutex_lock(&cache->mutex);
    bool full = (cache->count >= cache->capacity);
    pthread_mutex_unlock(&cache->mutex);

    return full;
}

size_t session_cache_size(session_cache_t *cache)
{
    if (cache == nullptr) {
        return 0;
    }

    pthread_mutex_lock(&cache->mutex);
    size_t size = cache->count;
    pthread_mutex_unlock(&cache->mutex);

    return size;
}
