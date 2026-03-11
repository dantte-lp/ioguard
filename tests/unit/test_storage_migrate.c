#include <unity/unity.h>
#include "storage/migrate.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static iog_sqlite_ctx_t sql_ctx;
static iog_mdbx_ctx_t mdbx_ctx;
static char mdbx_path[256];

void setUp(void)
{
    int rc = iog_sqlite_init(&sql_ctx, ":memory:");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "iog_sqlite_init failed in setUp");

    snprintf(mdbx_path, sizeof(mdbx_path), "/tmp/test_migrate_%d.db", getpid());
    unlink(mdbx_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", mdbx_path);
    unlink(lck_path);

    rc = iog_mdbx_init(&mdbx_ctx, mdbx_path);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "iog_mdbx_init failed in setUp");
}

void tearDown(void)
{
    iog_sqlite_close(&sql_ctx);
    iog_mdbx_close(&mdbx_ctx);

    unlink(mdbx_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", mdbx_path);
    unlink(lck_path);
}

/* ---- SQLite migration tests ---- */

void test_migrate_fresh_db(void)
{
    /* Fresh in-memory DB should migrate to current version. */
    int rc = iog_sqlite_migrate(&sql_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_migrate_idempotent(void)
{
    /* Running migrate twice should succeed without error. */
    int rc = iog_sqlite_migrate(&sql_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_sqlite_migrate(&sql_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_migrate_version_check(void)
{
    /* After migration, verify the version is recorded correctly. */
    int rc = iog_sqlite_migrate(&sql_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Query schema_version directly to verify. */
    sqlite3_stmt *stmt = nullptr;
    rc = sqlite3_prepare_v2(sql_ctx.db, "SELECT MAX(version) FROM schema_version", -1, &stmt,
                            nullptr);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, rc);

    rc = sqlite3_step(stmt);
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, rc);
    TEST_ASSERT_EQUAL_INT(SQLITE_INTEGER, sqlite3_column_type(stmt, 0));

    int version = sqlite3_column_int(stmt, 0);
    TEST_ASSERT_EQUAL_INT((int)IOG_SQLITE_SCHEMA_VERSION, version);
    sqlite3_finalize(stmt);
}

/* ---- libmdbx format check tests ---- */

void test_mdbx_format_check_fresh(void)
{
    /* First call on a fresh env should set the version and succeed. */
    int rc = iog_mdbx_check_format(&mdbx_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_mdbx_format_check_current(void)
{
    /* Set version, then verify it passes on second check. */
    int rc = iog_mdbx_check_format(&mdbx_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_mdbx_check_format(&mdbx_ctx);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_migrate_fresh_db);
    RUN_TEST(test_migrate_idempotent);
    RUN_TEST(test_migrate_version_check);
    RUN_TEST(test_mdbx_format_check_fresh);
    RUN_TEST(test_mdbx_format_check_current);
    return UNITY_END();
}
