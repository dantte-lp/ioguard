/**
 * @file migrate.c
 * @brief Schema migration for SQLite and libmdbx format versioning.
 */

#include "storage/migrate.h"

#include <errno.h>
#include <string.h>

/* ---- SQLite schema migration ---- */

static const char *const DDL_SCHEMA_VERSION = "CREATE TABLE IF NOT EXISTS schema_version ("
                                              "  version    INTEGER NOT NULL,"
                                              "  applied_at TEXT DEFAULT (datetime('now'))"
                                              ")";

static const char *const SQL_GET_VERSION = "SELECT MAX(version) FROM schema_version";

static const char *const SQL_INSERT_VERSION = "INSERT INTO schema_version (version) VALUES (?)";

int iog_sqlite_migrate(iog_sqlite_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->db == nullptr) {
        return -EINVAL;
    }

    int rc;
    char *errmsg = nullptr;

    /* Begin EXCLUSIVE transaction for safe migration. */
    rc = sqlite3_exec(ctx->db, "BEGIN EXCLUSIVE", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
        return -EIO;
    }

    /* Create schema_version table if it doesn't exist. */
    rc = sqlite3_exec(ctx->db, DDL_SCHEMA_VERSION, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
        goto rollback;
    }

    /* Check current version. */
    sqlite3_stmt *stmt = nullptr;
    rc = sqlite3_prepare_v2(ctx->db, SQL_GET_VERSION, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        goto rollback;
    }

    uint32_t current_version = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        /* MAX(version) returns NULL if no rows exist. */
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            current_version = (uint32_t)sqlite3_column_int(stmt, 0);
        }
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        goto rollback;
    }
    sqlite3_finalize(stmt);

    /* Already at current version — nothing to do. */
    if (current_version >= IOG_SQLITE_SCHEMA_VERSION) {
        sqlite3_exec(ctx->db, "COMMIT", nullptr, nullptr, nullptr);
        return 0;
    }

    /*
     * Apply migrations in order.  Version 1 is the base schema which
     * iog_sqlite_init() already creates (users, audit_log, ban_list),
     * so there is no DDL to run here — just record the version.
     */

    /* Insert version record. */
    rc = sqlite3_prepare_v2(ctx->db, SQL_INSERT_VERSION, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        goto rollback;
    }

    rc = sqlite3_bind_int(stmt, 1, (int)IOG_SQLITE_SCHEMA_VERSION);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        goto rollback;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        goto rollback;
    }

    rc = sqlite3_exec(ctx->db, "COMMIT", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        goto rollback;
    }

    return 0;

rollback:
    sqlite3_exec(ctx->db, "ROLLBACK", nullptr, nullptr, nullptr);
    return -EIO;
}

/* ---- libmdbx format version check ---- */

static const char META_DB_NAME[] = "meta";
static const char FORMAT_KEY[] = "format_version";

static int mdbx_rc_to_errno(int rc)
{
    switch (rc) {
    case MDBX_SUCCESS:
        return 0;
    case MDBX_NOTFOUND:
        return -ENOENT;
    case MDBX_KEYEXIST:
        return -EEXIST;
    case MDBX_MAP_FULL:
        return -ENOSPC;
    case MDBX_EINVAL:
        return -EINVAL;
    case MDBX_EACCESS:
        return -EACCES;
    case MDBX_ENOMEM:
        return -ENOMEM;
    default:
        return -EIO;
    }
}

int iog_mdbx_check_format(iog_mdbx_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->env == nullptr) {
        return -EINVAL;
    }

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(ctx->env, nullptr, 0, &txn);
    if (rc != MDBX_SUCCESS) {
        return mdbx_rc_to_errno(rc);
    }

    /* Open or create the "meta" sub-database. */
    MDBX_dbi dbi_meta = 0;
    rc = mdbx_dbi_open(txn, META_DB_NAME, MDBX_CREATE, &dbi_meta);
    if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return mdbx_rc_to_errno(rc);
    }

    MDBX_val key = {.iov_base = (void *)FORMAT_KEY, .iov_len = sizeof(FORMAT_KEY) - 1};
    MDBX_val data = {0};

    rc = mdbx_get(txn, dbi_meta, &key, &data);
    if (rc == MDBX_NOTFOUND) {
        /* First run — store the current format version. */
        uint32_t ver = IOG_MDBX_FORMAT_VERSION;
        MDBX_val val = {.iov_base = &ver, .iov_len = sizeof(ver)};
        rc = mdbx_put(txn, dbi_meta, &key, &val, 0);
        if (rc != MDBX_SUCCESS) {
            mdbx_txn_abort(txn);
            return mdbx_rc_to_errno(rc);
        }

        rc = mdbx_txn_commit(txn);
        return mdbx_rc_to_errno(rc);
    }

    if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return mdbx_rc_to_errno(rc);
    }

    /* Key found — check the stored version. */
    if (data.iov_len != sizeof(uint32_t)) {
        mdbx_txn_abort(txn);
        return -EPROTO;
    }

    uint32_t stored_version = 0;
    memcpy(&stored_version, data.iov_base, sizeof(stored_version));
    mdbx_txn_abort(txn);

    if (stored_version != IOG_MDBX_FORMAT_VERSION) {
        return -EPROTO;
    }

    return 0;
}
