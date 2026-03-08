/**
 * @file sqlite.c
 * @brief SQLite control plane implementation with hardened settings.
 */

#include "storage/sqlite.h"

#include <errno.h>
#include <string.h>

/* ---- Schema DDL ---- */

static const char *const DDL_USERS = "CREATE TABLE IF NOT EXISTS users ("
                                     "  username        TEXT PRIMARY KEY,"
                                     "  password_hash   TEXT NOT NULL,"
                                     "  groups          TEXT DEFAULT '[]',"
                                     "  enabled         INTEGER DEFAULT 1,"
                                     "  failed_attempts INTEGER DEFAULT 0,"
                                     "  locked_until    TEXT DEFAULT '',"
                                     "  totp_enabled    INTEGER DEFAULT 0"
                                     ")";

static const char *const DDL_AUDIT_LOG = "CREATE TABLE IF NOT EXISTS audit_log ("
                                         "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
                                         "  event_type  TEXT,"
                                         "  username    TEXT,"
                                         "  source_ip   TEXT,"
                                         "  source_port INTEGER,"
                                         "  auth_method TEXT,"
                                         "  result      TEXT,"
                                         "  details     TEXT,"
                                         "  session_id  TEXT,"
                                         "  created_at  TEXT DEFAULT (datetime('now'))"
                                         ")";

static const char *const DDL_BAN_LIST = "CREATE TABLE IF NOT EXISTS ban_list ("
                                        "  ip        TEXT PRIMARY KEY,"
                                        "  reason    TEXT,"
                                        "  banned_at TEXT DEFAULT (datetime('now')),"
                                        "  expires_at TEXT"
                                        ")";

/* ---- Prepared statement SQL ---- */

static const char *const SQL_USER_LOOKUP =
    "SELECT username, password_hash, groups, enabled, failed_attempts,"
    "       locked_until, totp_enabled"
    " FROM users WHERE username = ?";

static const char *const SQL_USER_CREATE =
    "INSERT INTO users (username, password_hash, groups, enabled,"
    "                   failed_attempts, locked_until, totp_enabled)"
    " VALUES (?, ?, ?, ?, ?, ?, ?)";

static const char *const SQL_AUDIT_INSERT =
    "INSERT INTO audit_log (event_type, username, source_ip, source_port,"
    "                       auth_method, result, details, session_id)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

static const char *const SQL_AUDIT_QUERY =
    "SELECT event_type, username, source_ip, source_port,"
    "       auth_method, result, details, session_id"
    " FROM audit_log WHERE username = ? ORDER BY created_at DESC LIMIT ?";

static const char *const SQL_BAN_CHECK =
    "SELECT 1 FROM ban_list"
    " WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))";

static const char *const SQL_BAN_ADD = "INSERT OR REPLACE INTO ban_list (ip, reason, expires_at)"
                                       " VALUES (?, ?, datetime('now', '+' || ? || ' minutes'))";

/* ---- Helpers ---- */

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
        return -EIO;
    }
    return 0;
}

static int prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **out)
{
    int rc = sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, out, nullptr);
    if (rc != SQLITE_OK) {
        return -EIO;
    }
    return 0;
}

static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (src == nullptr) {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dst_sz) {
        len = dst_sz - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* ---- Public API ---- */

int rw_sqlite_init(rw_sqlite_ctx_t *ctx, const char *path)
{
    if (ctx == nullptr || path == nullptr) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));

    int rc = sqlite3_open_v2(
        path, &ctx->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        ctx->db = nullptr;
        return -EIO;
    }

    /* Hardening: disable double-quoted strings and extension loading. */
    sqlite3_db_config(ctx->db, SQLITE_DBCONFIG_DQS_DML, 0, nullptr);
    sqlite3_db_config(ctx->db, SQLITE_DBCONFIG_DQS_DDL, 0, nullptr);
    sqlite3_db_config(ctx->db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);

    /* Hardening PRAGMAs. */
    int err = 0;
    err = err ? err : exec_sql(ctx->db, "PRAGMA journal_mode=WAL");
    err = err ? err : exec_sql(ctx->db, "PRAGMA synchronous=NORMAL");
    err = err ? err : exec_sql(ctx->db, "PRAGMA secure_delete=ON");
    err = err ? err : exec_sql(ctx->db, "PRAGMA foreign_keys=ON");
    err = err ? err : exec_sql(ctx->db, "PRAGMA max_page_count=262144");
    err = err ? err : exec_sql(ctx->db, "PRAGMA mmap_size=268435456");
    err = err ? err : exec_sql(ctx->db, "PRAGMA trusted_schema=OFF");
    err = err ? err : exec_sql(ctx->db, "PRAGMA cell_size_check=ON");
    if (err != 0) {
        goto cleanup;
    }

    /* Create schema. */
    err = err ? err : exec_sql(ctx->db, DDL_USERS);
    err = err ? err : exec_sql(ctx->db, DDL_AUDIT_LOG);
    err = err ? err : exec_sql(ctx->db, DDL_BAN_LIST);
    if (err != 0) {
        goto cleanup;
    }

    /* Prepare all statements. */
    err = err ? err : prepare_stmt(ctx->db, SQL_USER_LOOKUP, &ctx->stmt_user_lookup);
    err = err ? err : prepare_stmt(ctx->db, SQL_USER_CREATE, &ctx->stmt_user_create);
    err = err ? err : prepare_stmt(ctx->db, SQL_AUDIT_INSERT, &ctx->stmt_audit_insert);
    err = err ? err : prepare_stmt(ctx->db, SQL_AUDIT_QUERY, &ctx->stmt_audit_query);
    err = err ? err : prepare_stmt(ctx->db, SQL_BAN_CHECK, &ctx->stmt_ban_check);
    err = err ? err : prepare_stmt(ctx->db, SQL_BAN_ADD, &ctx->stmt_ban_add);
    if (err != 0) {
        goto cleanup;
    }

    return 0;

cleanup:
    rw_sqlite_close(ctx);
    return err;
}

void rw_sqlite_close(rw_sqlite_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    sqlite3_finalize(ctx->stmt_user_lookup);
    sqlite3_finalize(ctx->stmt_user_create);
    sqlite3_finalize(ctx->stmt_audit_insert);
    sqlite3_finalize(ctx->stmt_audit_query);
    sqlite3_finalize(ctx->stmt_ban_check);
    sqlite3_finalize(ctx->stmt_ban_add);

    if (ctx->db != nullptr) {
        sqlite3_close(ctx->db);
    }

    memset(ctx, 0, sizeof(*ctx));
}

int rw_sqlite_user_create(rw_sqlite_ctx_t *ctx, const rw_user_record_t *user)
{
    if (ctx == nullptr || user == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_user_create;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user->password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user->groups, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, user->enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 5, (int)user->failed_attempts);
    sqlite3_bind_text(stmt, 6, user->locked_until, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, user->totp_enabled ? 1 : 0);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_CONSTRAINT) {
        return -EEXIST;
    }
    if (rc != SQLITE_DONE) {
        return -EIO;
    }

    return 0;
}

int rw_sqlite_user_lookup(rw_sqlite_ctx_t *ctx, const char *username, rw_user_record_t *out)
{
    if (ctx == nullptr || username == nullptr || out == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_user_lookup;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        return -ENOENT;
    }
    if (rc != SQLITE_ROW) {
        return -EIO;
    }

    memset(out, 0, sizeof(*out));
    safe_copy(out->username, sizeof(out->username), (const char *)sqlite3_column_text(stmt, 0));
    safe_copy(out->password_hash, sizeof(out->password_hash),
              (const char *)sqlite3_column_text(stmt, 1));
    safe_copy(out->groups, sizeof(out->groups), (const char *)sqlite3_column_text(stmt, 2));
    out->enabled = sqlite3_column_int(stmt, 3) != 0;
    out->failed_attempts = (uint32_t)sqlite3_column_int(stmt, 4);
    safe_copy(out->locked_until, sizeof(out->locked_until),
              (const char *)sqlite3_column_text(stmt, 5));
    out->totp_enabled = sqlite3_column_int(stmt, 6) != 0;

    return 0;
}

int rw_sqlite_audit_insert(rw_sqlite_ctx_t *ctx, const rw_audit_entry_t *entry)
{
    if (ctx == nullptr || entry == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_audit_insert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, entry->event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, entry->source_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, entry->source_port);
    sqlite3_bind_text(stmt, 5, entry->auth_method, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, entry->result, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, entry->details, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, entry->session_id, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return -EIO;
    }

    return 0;
}

int rw_sqlite_audit_query_by_username(rw_sqlite_ctx_t *ctx, const char *username,
                                      rw_audit_entry_t *out, size_t max_entries, size_t *count)
{
    if (ctx == nullptr || username == nullptr || out == nullptr || count == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_audit_query;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)max_entries);

    *count = 0;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && *count < max_entries) {
        rw_audit_entry_t *e = &out[*count];
        memset(e, 0, sizeof(*e));
        safe_copy(e->event_type, sizeof(e->event_type), (const char *)sqlite3_column_text(stmt, 0));
        safe_copy(e->username, sizeof(e->username), (const char *)sqlite3_column_text(stmt, 1));
        safe_copy(e->source_ip, sizeof(e->source_ip), (const char *)sqlite3_column_text(stmt, 2));
        e->source_port = (uint16_t)sqlite3_column_int(stmt, 3);
        safe_copy(e->auth_method, sizeof(e->auth_method),
                  (const char *)sqlite3_column_text(stmt, 4));
        safe_copy(e->result, sizeof(e->result), (const char *)sqlite3_column_text(stmt, 5));
        safe_copy(e->details, sizeof(e->details), (const char *)sqlite3_column_text(stmt, 6));
        safe_copy(e->session_id, sizeof(e->session_id), (const char *)sqlite3_column_text(stmt, 7));
        (*count)++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        return -EIO;
    }

    return 0;
}

int rw_sqlite_ban_check(rw_sqlite_ctx_t *ctx, const char *ip, bool *is_banned)
{
    if (ctx == nullptr || ip == nullptr || is_banned == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_ban_check;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *is_banned = true;
    } else if (rc == SQLITE_DONE) {
        *is_banned = false;
    } else {
        return -EIO;
    }

    return 0;
}

int rw_sqlite_ban_add(rw_sqlite_ctx_t *ctx, const char *ip, const char *reason,
                      int duration_minutes)
{
    if (ctx == nullptr || ip == nullptr || reason == nullptr) {
        return -EINVAL;
    }

    sqlite3_stmt *stmt = ctx->stmt_ban_add;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, duration_minutes);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return -EIO;
    }

    return 0;
}
