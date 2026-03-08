#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <unity/unity.h>
#include "storage/mdbx.h"
#include "storage/migrate.h"
#include "storage/sqlite.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static rw_mdbx_ctx_t mdbx_ctx;
static rw_sqlite_ctx_t sql_ctx;
static char mdbx_path[256];

static void make_session(rw_session_record_t *s, uint8_t id_byte)
{
    memset(s, 0, sizeof(*s));
    memset(s->session_id, id_byte, RW_SESSION_ID_LEN);
    memset(s->cookie_hmac, 0xAA, sizeof(s->cookie_hmac));
    s->assigned_ipv4 = 0x0A0A0001 + id_byte;
    s->created_at = 1000000;
    s->expires_at = 2000000;
    snprintf(s->username, sizeof(s->username), "user%u", id_byte);
    snprintf(s->groupname, sizeof(s->groupname), "group%u", id_byte);
    s->source_ip = 0xC0A80001;
    s->source_port = 4443;
    s->deny_roaming = false;
}

static void make_audit(rw_audit_entry_t *e, const char *user, const char *evt)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->event_type, sizeof(e->event_type), "%s", evt);
    snprintf(e->username, sizeof(e->username), "%s", user);
    snprintf(e->source_ip, sizeof(e->source_ip), "192.168.1.100");
    e->source_port = 4443;
    snprintf(e->auth_method, sizeof(e->auth_method), "pam");
    snprintf(e->result, sizeof(e->result), "success");
    snprintf(e->details, sizeof(e->details), "{\"reason\":\"test\"}");
    snprintf(e->session_id, sizeof(e->session_id), "abcdef0123456789abcdef0123456789");
}

void setUp(void)
{
    snprintf(mdbx_path, sizeof(mdbx_path), "/tmp/test_integration_%d.mdbx", getpid());

    /* Remove stale files from prior runs. */
    unlink(mdbx_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", mdbx_path);
    unlink(lck_path);

    int rc = rw_mdbx_init(&mdbx_ctx, mdbx_path);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_mdbx_init failed in setUp");

    rc = rw_mdbx_check_format(&mdbx_ctx);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_mdbx_check_format failed in setUp");

    rc = rw_sqlite_init(&sql_ctx, ":memory:");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_sqlite_init failed in setUp");

    rc = rw_sqlite_migrate(&sql_ctx);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_sqlite_migrate failed in setUp");
}

void tearDown(void)
{
    rw_sqlite_close(&sql_ctx);
    rw_mdbx_close(&mdbx_ctx);

    unlink(mdbx_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", mdbx_path);
    unlink(lck_path);
}

/* ---- Tests ---- */

/**
 * Create a session in mdbx, insert an audit entry in sqlite, verify both
 * operations succeed.
 */
void test_session_create_mdbx_audit_sqlite(void)
{
    rw_session_record_t sess;
    make_session(&sess, 0x01);

    int rc = rw_mdbx_session_create(&mdbx_ctx, &sess);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rw_audit_entry_t audit;
    make_audit(&audit, "user1", "session_create");

    rc = rw_sqlite_audit_insert(&sql_ctx, &audit);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

/**
 * Full flow: create session -> lookup -> verify all fields match.
 */
void test_session_lookup_after_create(void)
{
    rw_session_record_t sess;
    make_session(&sess, 0x42);

    int rc = rw_mdbx_session_create(&mdbx_ctx, &sess);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rw_session_record_t out;
    memset(&out, 0, sizeof(out));

    rc = rw_mdbx_session_lookup(&mdbx_ctx, sess.session_id, &out);
    TEST_ASSERT_EQUAL_INT(0, rc);

    TEST_ASSERT_EQUAL_MEMORY(sess.session_id, out.session_id, RW_SESSION_ID_LEN);
    TEST_ASSERT_EQUAL_MEMORY(sess.cookie_hmac, out.cookie_hmac, sizeof(sess.cookie_hmac));
    TEST_ASSERT_EQUAL_UINT32(sess.assigned_ipv4, out.assigned_ipv4);
    TEST_ASSERT_EQUAL_INT64(sess.created_at, out.created_at);
    TEST_ASSERT_EQUAL_INT64(sess.expires_at, out.expires_at);
    TEST_ASSERT_EQUAL_STRING(sess.username, out.username);
    TEST_ASSERT_EQUAL_STRING(sess.groupname, out.groupname);
    TEST_ASSERT_EQUAL_UINT32(sess.source_ip, out.source_ip);
    TEST_ASSERT_EQUAL_UINT16(sess.source_port, out.source_port);
    TEST_ASSERT_EQUAL(sess.deny_roaming, out.deny_roaming);
}

/**
 * Delete session from mdbx, verify it is gone, verify audit remains in sqlite.
 */
void test_session_delete_and_verify(void)
{
    rw_session_record_t sess;
    make_session(&sess, 0x77);

    int rc = rw_mdbx_session_create(&mdbx_ctx, &sess);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rw_audit_entry_t audit;
    make_audit(&audit, "user119", "session_create");

    rc = rw_sqlite_audit_insert(&sql_ctx, &audit);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Delete session from mdbx */
    rc = rw_mdbx_session_delete(&mdbx_ctx, sess.session_id);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Verify session is gone */
    rw_session_record_t out;
    rc = rw_mdbx_session_lookup(&mdbx_ctx, sess.session_id, &out);
    TEST_ASSERT_EQUAL_INT(-ENOENT, rc);

    /* Verify audit entry still exists in sqlite */
    rw_audit_entry_t audit_out[4];
    size_t count = 0;
    rc = rw_sqlite_audit_query_by_username(&sql_ctx, "user119", audit_out, 4, &count);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN(0, (int)count);
}

/**
 * Ban IP in sqlite, check ban, create session in mdbx (ban is policy layer,
 * doesn't block mdbx), verify session exists.
 */
void test_ban_flow_mdbx_to_sqlite(void)
{
    /* Add IP ban in sqlite */
    int rc = rw_sqlite_ban_add(&sql_ctx, "10.20.30.40", "brute force", 60);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Verify the IP is banned */
    bool banned = false;
    rc = rw_sqlite_ban_check(&sql_ctx, "10.20.30.40", &banned);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_TRUE(banned);

    /* Create session in mdbx despite ban (policy layer, not storage layer) */
    rw_session_record_t sess;
    make_session(&sess, 0xBB);

    rc = rw_mdbx_session_create(&mdbx_ctx, &sess);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Verify session exists in mdbx */
    rw_session_record_t out;
    rc = rw_mdbx_session_lookup(&mdbx_ctx, sess.session_id, &out);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_STRING("user187", out.username);
}

/**
 * Crash recovery: fork child, create session in mdbx, SIGKILL child,
 * parent reopens mdbx and verifies committed data survived.
 */
void test_crash_recovery_mdbx(void)
{
    /* Close mdbx in parent before forking — child will open its own. */
    rw_mdbx_close(&mdbx_ctx);

    /* Known session ID for verification */
    const uint8_t crash_id = 0xCC;

    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        /* Child process: open mdbx, create session, commit, then die */
        rw_mdbx_ctx_t child_ctx;
        int rc = rw_mdbx_init(&child_ctx, mdbx_path);
        if (rc != 0) {
            _exit(99);
        }

        rw_session_record_t sess;
        make_session(&sess, crash_id);

        rc = rw_mdbx_session_create(&child_ctx, &sess);
        if (rc != 0) {
            rw_mdbx_close(&child_ctx);
            _exit(98);
        }

        /* Close ensures commit is durable */
        rw_mdbx_close(&child_ctx);

        /* SIGKILL self to simulate crash after commit */
        kill(getpid(), SIGKILL);
        _exit(0); /* unreachable */
    }

    /* Parent: wait for child to be killed */
    int status = 0;
    pid_t waited = waitpid(pid, &status, 0);
    TEST_ASSERT_EQUAL(pid, waited);
    TEST_ASSERT_TRUE(WIFSIGNALED(status));
    TEST_ASSERT_EQUAL_INT(SIGKILL, WTERMSIG(status));

    /* Reopen mdbx and verify the committed session survived */
    int rc = rw_mdbx_init(&mdbx_ctx, mdbx_path);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_mdbx_init failed after crash recovery");

    rw_session_record_t out;
    memset(&out, 0, sizeof(out));

    uint8_t lookup_id[RW_SESSION_ID_LEN];
    memset(lookup_id, crash_id, RW_SESSION_ID_LEN);

    rc = rw_mdbx_session_lookup(&mdbx_ctx, lookup_id, &out);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_STRING("user204", out.username);
    TEST_ASSERT_EQUAL_UINT32(0x0A0A0001 + crash_id, out.assigned_ipv4);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_session_create_mdbx_audit_sqlite);
    RUN_TEST(test_session_lookup_after_create);
    RUN_TEST(test_session_delete_and_verify);
    RUN_TEST(test_ban_flow_mdbx_to_sqlite);
    RUN_TEST(test_crash_recovery_mdbx);
    return UNITY_END();
}
