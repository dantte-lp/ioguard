/**
 * @file migrate.h
 * @brief Schema migration for SQLite and libmdbx format versioning.
 *
 * Provides forward-only schema migration for the SQLite control plane
 * and format version tracking for the libmdbx session store.
 */

#ifndef IOGUARD_STORAGE_MIGRATE_H
#define IOGUARD_STORAGE_MIGRATE_H

#include "storage/mdbx.h"
#include "storage/sqlite.h"

constexpr uint32_t IOG_SQLITE_SCHEMA_VERSION = 1;
constexpr uint32_t IOG_MDBX_FORMAT_VERSION = 1;

/**
 * @brief Run schema migrations on the SQLite database.
 *
 * Creates the schema_version tracking table, checks the current version,
 * applies any outstanding migrations in order, and records the new version.
 * All work is done inside an EXCLUSIVE transaction.
 *
 * @param ctx  Initialised SQLite context.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_sqlite_migrate(iog_sqlite_ctx_t *ctx);

/**
 * @brief Verify or initialise the libmdbx format version.
 *
 * Opens (or creates) a "meta" sub-database and checks the "format_version"
 * key.  On first run the key is set to IOG_MDBX_FORMAT_VERSION.  On
 * subsequent runs the stored version must match; a mismatch returns -EPROTO.
 *
 * @param ctx  Initialised MDBX context.
 * @return 0 on success, -EPROTO on version mismatch, other negative errno on error.
 */
[[nodiscard]] int iog_mdbx_check_format(iog_mdbx_ctx_t *ctx);

#endif /* IOGUARD_STORAGE_MIGRATE_H */
