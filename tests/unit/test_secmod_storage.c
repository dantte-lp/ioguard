#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <unity/unity.h>

#include "config/config.h"
#include "core/secmod.h"
#include "storage/mdbx.h"
#include "storage/sqlite.h"

static iog_config_t config;
static char mdbx_path[PATH_MAX];
static char sqlite_path[PATH_MAX];
static char mdbx_lock_path[PATH_MAX];

void setUp(void)
{
    /* Create temp paths for storage */
    snprintf(mdbx_path, sizeof(mdbx_path), "/tmp/rw_test_mdbx_XXXXXX");
    int fd = mkstemp(mdbx_path);
    close(fd);
    unlink(mdbx_path); /* mdbx creates its own file */
    snprintf(mdbx_lock_path, sizeof(mdbx_lock_path), "%s-lck", mdbx_path);

    snprintf(sqlite_path, sizeof(sqlite_path), "/tmp/rw_test_sqlite_XXXXXX");
    fd = mkstemp(sqlite_path);
    close(fd);
    unlink(sqlite_path); /* sqlite creates its own file */

    iog_config_set_defaults(&config);
    snprintf(config.storage.mdbx_path, sizeof(config.storage.mdbx_path), "%s", mdbx_path);
    snprintf(config.storage.sqlite_path, sizeof(config.storage.sqlite_path), "%s", sqlite_path);
}

void tearDown(void)
{
    unlink(mdbx_path);
    unlink(mdbx_lock_path);
    unlink(sqlite_path);
}

void test_secmod_init_with_mdbx(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));

    int ret = rw_secmod_init(&ctx, sv[0], &config);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(ctx.mdbx);
    TEST_ASSERT_NOT_NULL(ctx.sqlite);
    TEST_ASSERT_NOT_NULL(ctx.sessions);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_mdbx_session_create_and_lookup(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Create a session record directly in mdbx */
    iog_session_record_t session;
    memset(&session, 0, sizeof(session));
    memset(session.session_id, 0xAA, IOG_SESSION_ID_LEN);
    snprintf(session.username, sizeof(session.username), "testuser");
    snprintf(session.groupname, sizeof(session.groupname), "vpn-users");
    session.created_at = time(nullptr);
    session.expires_at = session.created_at + 300;

    int ret = iog_mdbx_session_create(ctx.mdbx, &session);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Look up the session */
    iog_session_record_t out;
    memset(&out, 0, sizeof(out));
    ret = iog_mdbx_session_lookup(ctx.mdbx, session.session_id, &out);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("testuser", out.username);
    TEST_ASSERT_EQUAL_STRING("vpn-users", out.groupname);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_sqlite_audit_insert(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Insert an audit entry */
    rw_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.event_type, sizeof(entry.event_type), "AUTH");
    snprintf(entry.username, sizeof(entry.username), "alice");
    snprintf(entry.source_ip, sizeof(entry.source_ip), "10.0.0.1");
    snprintf(entry.result, sizeof(entry.result), "OK");

    int ret = rw_sqlite_audit_insert(ctx.sqlite, &entry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Query audit entries for alice */
    rw_audit_entry_t results[4];
    size_t count = 0;
    ret = rw_sqlite_audit_query_by_username(ctx.sqlite, "alice", results, 4, &count);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, count);
    TEST_ASSERT_EQUAL_STRING("AUTH", results[0].event_type);
    TEST_ASSERT_EQUAL_STRING("OK", results[0].result);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_auth_failure_audit(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Simulate a failed auth audit */
    rw_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.event_type, sizeof(entry.event_type), "AUTH");
    snprintf(entry.username, sizeof(entry.username), "bob");
    snprintf(entry.source_ip, sizeof(entry.source_ip), "10.0.0.2");
    snprintf(entry.result, sizeof(entry.result), "FAIL");

    int ret = rw_sqlite_audit_insert(ctx.sqlite, &entry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify the failure was logged */
    rw_audit_entry_t results[4];
    size_t count = 0;
    ret = rw_sqlite_audit_query_by_username(ctx.sqlite, "bob", results, 4, &count);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, count);
    TEST_ASSERT_EQUAL_STRING("FAIL", results[0].result);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_session_delete_cleans_mdbx(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Create session */
    iog_session_record_t session;
    memset(&session, 0, sizeof(session));
    memset(session.session_id, 0xCC, IOG_SESSION_ID_LEN);
    snprintf(session.username, sizeof(session.username), "delme");
    session.created_at = time(nullptr);
    session.expires_at = session.created_at + 300;

    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_create(ctx.mdbx, &session));

    /* Delete it */
    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_delete(ctx.mdbx, session.session_id));

    /* Verify gone */
    iog_session_record_t out;
    int ret = iog_mdbx_session_lookup(ctx.mdbx, session.session_id, &out);
    TEST_ASSERT_EQUAL_INT(-ENOENT, ret);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

/* Two-pass expired cleanup: collect IDs then delete (avoids read/write txn conflict) */
typedef struct {
    uint8_t ids[16][IOG_SESSION_ID_LEN];
    size_t count;
} test_expired_batch_t;

static int expired_session_collect_iter(const iog_session_record_t *session, void *userdata)
{
    test_expired_batch_t *batch = userdata;
    time_t now = time(nullptr);
    if (session->expires_at > 0 && session->expires_at < now) {
        if (batch->count < 16) {
            memcpy(batch->ids[batch->count], session->session_id, IOG_SESSION_ID_LEN);
            batch->count++;
        }
    }
    return 0;
}

void test_secmod_expired_session_cleanup(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Create an already-expired session */
    iog_session_record_t session;
    memset(&session, 0, sizeof(session));
    memset(session.session_id, 0xDD, IOG_SESSION_ID_LEN);
    snprintf(session.username, sizeof(session.username), "expired");
    session.created_at = time(nullptr) - 600;
    session.expires_at = time(nullptr) - 300; /* expired 5 min ago */

    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_create(ctx.mdbx, &session));

    /* Verify it exists */
    uint32_t count = 0;
    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_count(ctx.mdbx, &count));
    TEST_ASSERT_EQUAL_UINT(1, count);

    /* Pass 1: collect expired session IDs (read-only iterate) */
    test_expired_batch_t batch;
    memset(&batch, 0, sizeof(batch));
    TEST_ASSERT_EQUAL_INT(0,
                          iog_mdbx_session_iterate(ctx.mdbx, expired_session_collect_iter, &batch));
    TEST_ASSERT_EQUAL_UINT(1, batch.count);

    /* Pass 2: delete collected sessions (separate write txns) */
    for (size_t i = 0; i < batch.count; i++) {
        TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_delete(ctx.mdbx, batch.ids[i]));
    }

    /* Verify removed */
    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_count(ctx.mdbx, &count));
    TEST_ASSERT_EQUAL_UINT(0, count);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_ban_check_before_auth(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Ban an IP */
    int ret = rw_sqlite_ban_add(ctx.sqlite, "10.0.0.99", "brute force", 60);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify it's banned */
    bool banned = false;
    ret = rw_sqlite_ban_check(ctx.sqlite, "10.0.0.99", &banned);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(banned);

    /* Verify another IP is not banned */
    banned = true;
    ret = rw_sqlite_ban_check(ctx.sqlite, "10.0.0.1", &banned);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(banned);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

void test_secmod_validate_reads_mdbx(void)
{
    rw_secmod_ctx_t ctx;
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv));
    TEST_ASSERT_EQUAL_INT(0, rw_secmod_init(&ctx, sv[0], &config));

    /* Create session in mdbx */
    iog_session_record_t session;
    memset(&session, 0, sizeof(session));
    memset(session.session_id, 0xEE, IOG_SESSION_ID_LEN);
    snprintf(session.username, sizeof(session.username), "validate-test");
    session.created_at = time(nullptr);
    session.expires_at = session.created_at + 300;

    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_create(ctx.mdbx, &session));

    /* Look up directly via mdbx */
    iog_session_record_t out;
    memset(&out, 0, sizeof(out));
    int ret = iog_mdbx_session_lookup(ctx.mdbx, session.session_id, &out);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("validate-test", out.username);
    TEST_ASSERT_GREATER_THAN(0, out.expires_at);

    rw_secmod_destroy(&ctx);
    close(sv[0]);
    close(sv[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_secmod_init_with_mdbx);
    RUN_TEST(test_secmod_mdbx_session_create_and_lookup);
    RUN_TEST(test_secmod_sqlite_audit_insert);
    RUN_TEST(test_secmod_auth_failure_audit);
    RUN_TEST(test_secmod_session_delete_cleans_mdbx);
    RUN_TEST(test_secmod_expired_session_cleanup);
    RUN_TEST(test_secmod_ban_check_before_auth);
    RUN_TEST(test_secmod_validate_reads_mdbx);
    return UNITY_END();
}
