/**
 * @file sqlite.h
 * @brief SQLite control plane for users, audit log, and IP ban list.
 *
 * Uses WAL journal mode with hardened PRAGMAs. All queries use prepared
 * statements with parameter binding — no string interpolation of user data.
 */

#ifndef RINGWALL_STORAGE_SQLITE_H
#define RINGWALL_STORAGE_SQLITE_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char username[256];
    char password_hash[256]; /* Argon2id encoded */
    char groups[1024];       /* JSON array */
    bool enabled;
    uint32_t failed_attempts;
    char locked_until[32]; /* ISO 8601 or empty */
    bool totp_enabled;
} rw_user_record_t;

typedef struct {
    char event_type[32];
    char username[256];
    char source_ip[46]; /* INET6_ADDRSTRLEN */
    uint16_t source_port;
    char auth_method[16];
    char result[16];
    char details[1024];  /* JSON */
    char session_id[65]; /* hex */
} rw_audit_entry_t;

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt_user_lookup;
    sqlite3_stmt *stmt_user_create;
    sqlite3_stmt *stmt_audit_insert;
    sqlite3_stmt *stmt_audit_query;
    sqlite3_stmt *stmt_ban_check;
    sqlite3_stmt *stmt_ban_add;
} rw_sqlite_ctx_t;

/**
 * @brief Initialise SQLite database with hardened settings and prepared statements.
 * @param ctx  Context to initialise (caller-owned, zeroed on failure).
 * @param path Database file path, or ":memory:" for in-memory database.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_sqlite_init(rw_sqlite_ctx_t *ctx, const char *path);

/**
 * @brief Close the SQLite database and finalise all prepared statements.
 * @param ctx  Context previously initialised with rw_sqlite_init().
 */
void rw_sqlite_close(rw_sqlite_ctx_t *ctx);

/**
 * @brief Create a new user record.
 * @param ctx  Initialised SQLite context.
 * @param user User record to insert.
 * @return 0 on success, -EEXIST if username exists, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_user_create(rw_sqlite_ctx_t *ctx, const rw_user_record_t *user);

/**
 * @brief Look up a user by username.
 * @param ctx      Initialised SQLite context.
 * @param username Username to search for.
 * @param out      Output record.
 * @return 0 on success, -ENOENT if not found, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_user_lookup(rw_sqlite_ctx_t *ctx, const char *username,
                                        rw_user_record_t *out);

/**
 * @brief Insert an audit log entry.
 * @param ctx   Initialised SQLite context.
 * @param entry Audit entry to insert.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_audit_insert(rw_sqlite_ctx_t *ctx, const rw_audit_entry_t *entry);

/**
 * @brief Query audit log entries by username (most recent first).
 * @param ctx         Initialised SQLite context.
 * @param username    Username to filter by.
 * @param out         Output array of audit entries.
 * @param max_entries Maximum number of entries to return.
 * @param count       Number of entries actually returned.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_audit_query_by_username(rw_sqlite_ctx_t *ctx, const char *username,
                                                    rw_audit_entry_t *out, size_t max_entries,
                                                    size_t *count);

/**
 * @brief Check whether an IP address is currently banned.
 * @param ctx       Initialised SQLite context.
 * @param ip        IP address string.
 * @param is_banned Output flag: true if banned and ban has not expired.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_ban_check(rw_sqlite_ctx_t *ctx, const char *ip, bool *is_banned);

/**
 * @brief Add an IP address to the ban list.
 * @param ctx              Initialised SQLite context.
 * @param ip               IP address string.
 * @param reason           Human-readable reason for the ban.
 * @param duration_minutes Ban duration in minutes.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_sqlite_ban_add(rw_sqlite_ctx_t *ctx, const char *ip, const char *reason,
                                    int duration_minutes);

#endif /* RINGWALL_STORAGE_SQLITE_H */
