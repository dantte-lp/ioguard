/**
 * @file mdbx.h
 * @brief libmdbx-backed session store with CRUD, iteration, and HSR callback.
 *
 * Stores VPN session records keyed by 32-byte session ID. Uses MDBX geometry
 * auto-growth (1 MB to 1 GB) and LIFO reclaim for optimal write-back cache
 * behaviour.
 */

#ifndef RINGWALL_STORAGE_MDBX_H
#define RINGWALL_STORAGE_MDBX_H

#include <mdbx.h>
#include <stdint.h>
#include <time.h>

constexpr size_t IOG_SESSION_ID_LEN = 32;
constexpr size_t RW_MDBX_MAX_READERS = 128;
constexpr size_t RW_MDBX_MAX_DBS = 8;
constexpr size_t RW_MDBX_SIZE_LOWER = 1 * 1024 * 1024;
constexpr size_t RW_MDBX_SIZE_UPPER = 1024 * 1024 * 1024;
constexpr size_t RW_MDBX_GROWTH_STEP = 16 * 1024 * 1024;
constexpr size_t RW_MDBX_SHRINK_THRESHOLD = 64 * 1024 * 1024;

/** VPN session record stored in libmdbx. */
typedef struct {
    uint8_t session_id[IOG_SESSION_ID_LEN];
    uint8_t cookie_hmac[32];
    uint8_t dtls_master_secret[48];
    uint32_t assigned_ipv4;
    time_t created_at;
    time_t expires_at;
    char username[256];
    char groupname[256];
    uint32_t source_ip;
    uint16_t source_port;
    bool deny_roaming;
} iog_session_record_t;

/** Opaque context owning an MDBX environment and session table handle. */
typedef struct {
    MDBX_env *env;
    MDBX_dbi dbi_sessions;
} rw_mdbx_ctx_t;

/**
 * @brief Initialise an MDBX environment and open the "sessions" sub-database.
 * @param ctx  Context to initialise (caller-owned, zeroed on failure).
 * @param path Filesystem path for the MDBX data file (NOSUBDIR mode).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_mdbx_init(rw_mdbx_ctx_t *ctx, const char *path);

/**
 * @brief Close the MDBX environment and release resources.
 * @param ctx  Context previously initialised with rw_mdbx_init().
 */
void rw_mdbx_close(rw_mdbx_ctx_t *ctx);

/**
 * @brief Create a new session record (fails if the key already exists).
 * @param ctx     Initialised MDBX context.
 * @param session Session record to store (session_id is the key).
 * @return 0 on success, -EEXIST if key exists, other negative errno on error.
 */
[[nodiscard]] int iog_mdbx_session_create(rw_mdbx_ctx_t *ctx, const iog_session_record_t *session);

/**
 * @brief Look up a session by its 32-byte ID.
 * @param ctx        Initialised MDBX context.
 * @param session_id 32-byte session identifier.
 * @param out        Output record (copied before txn ends).
 * @return 0 on success, -ENOENT if not found, other negative errno on error.
 */
[[nodiscard]] int iog_mdbx_session_lookup(rw_mdbx_ctx_t *ctx,
                                         const uint8_t session_id[IOG_SESSION_ID_LEN],
                                         iog_session_record_t *out);

/**
 * @brief Delete a session by its 32-byte ID.
 * @param ctx        Initialised MDBX context.
 * @param session_id 32-byte session identifier.
 * @return 0 on success, -ENOENT if not found, other negative errno on error.
 */
[[nodiscard]] int iog_mdbx_session_delete(rw_mdbx_ctx_t *ctx,
                                         const uint8_t session_id[IOG_SESSION_ID_LEN]);

/**
 * @brief Count the number of session records in the store.
 * @param ctx   Initialised MDBX context.
 * @param count Output count.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_mdbx_session_count(rw_mdbx_ctx_t *ctx, uint32_t *count);

/** Per-session callback for iog_mdbx_session_iterate(). Return non-zero to stop. */
typedef int (*iog_mdbx_session_iter_fn)(const iog_session_record_t *session, void *userdata);

/**
 * @brief Iterate over every session record, calling fn for each.
 * @param ctx      Initialised MDBX context.
 * @param fn       Callback invoked for each record.
 * @param userdata Opaque pointer forwarded to fn.
 * @return 0 on success (all records visited), negative errno on error,
 *         or the non-zero value returned by fn if iteration was stopped.
 */
[[nodiscard]] int iog_mdbx_session_iterate(rw_mdbx_ctx_t *ctx, iog_mdbx_session_iter_fn fn,
                                          void *userdata);

#endif /* RINGWALL_STORAGE_MDBX_H */
