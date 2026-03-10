#include <unity/unity.h>
#include "storage/mdbx.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static rw_mdbx_ctx_t ctx;
static char db_path[256];

static void make_session(iog_session_record_t *s, uint8_t id_byte)
{
    memset(s, 0, sizeof(*s));
    memset(s->session_id, id_byte, IOG_SESSION_ID_LEN);
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

void setUp(void)
{
    snprintf(db_path, sizeof(db_path), "/tmp/test_mdbx_%d.db", getpid());
    /* Remove stale files from prior runs. */
    unlink(db_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", db_path);
    unlink(lck_path);

    int rc = rw_mdbx_init(&ctx, db_path);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_mdbx_init failed in setUp");
}

void tearDown(void)
{
    rw_mdbx_close(&ctx);
    unlink(db_path);
    char lck_path[280];
    snprintf(lck_path, sizeof(lck_path), "%s-lck", db_path);
    unlink(lck_path);
}

/* ---- Tests ---- */

void test_mdbx_env_create_and_close(void)
{
    /* setUp already created and opened the env; just verify it's non-null. */
    TEST_ASSERT_NOT_NULL(ctx.env);
    /* Close and re-open to exercise the full lifecycle. */
    rw_mdbx_close(&ctx);
    TEST_ASSERT_NULL(ctx.env);

    int rc = rw_mdbx_init(&ctx, db_path);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(ctx.env);
}

void test_mdbx_session_create(void)
{
    iog_session_record_t s;
    make_session(&s, 1);
    int rc = iog_mdbx_session_create(&ctx, &s);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_mdbx_session_lookup_found(void)
{
    iog_session_record_t s;
    make_session(&s, 2);
    int rc = iog_mdbx_session_create(&ctx, &s);
    TEST_ASSERT_EQUAL_INT(0, rc);

    iog_session_record_t out;
    memset(&out, 0, sizeof(out));
    rc = iog_mdbx_session_lookup(&ctx, s.session_id, &out);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_MEMORY(s.session_id, out.session_id, IOG_SESSION_ID_LEN);
    TEST_ASSERT_EQUAL_UINT32(s.assigned_ipv4, out.assigned_ipv4);
    TEST_ASSERT_EQUAL_STRING(s.username, out.username);
    TEST_ASSERT_EQUAL_STRING(s.groupname, out.groupname);
    TEST_ASSERT_EQUAL(s.created_at, out.created_at);
    TEST_ASSERT_EQUAL(s.expires_at, out.expires_at);
}

void test_mdbx_session_lookup_not_found(void)
{
    uint8_t missing_id[IOG_SESSION_ID_LEN];
    memset(missing_id, 0xFF, IOG_SESSION_ID_LEN);

    iog_session_record_t out;
    int rc = iog_mdbx_session_lookup(&ctx, missing_id, &out);
    TEST_ASSERT_EQUAL_INT(-ENOENT, rc);
}

void test_mdbx_session_delete(void)
{
    iog_session_record_t s;
    make_session(&s, 3);
    int rc = iog_mdbx_session_create(&ctx, &s);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_mdbx_session_delete(&ctx, s.session_id);
    TEST_ASSERT_EQUAL_INT(0, rc);

    iog_session_record_t out;
    rc = iog_mdbx_session_lookup(&ctx, s.session_id, &out);
    TEST_ASSERT_EQUAL_INT(-ENOENT, rc);
}

void test_mdbx_session_duplicate(void)
{
    iog_session_record_t s;
    make_session(&s, 4);
    int rc = iog_mdbx_session_create(&ctx, &s);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_mdbx_session_create(&ctx, &s);
    TEST_ASSERT_EQUAL_INT(-EEXIST, rc);
}

void test_mdbx_session_count(void)
{
    iog_session_record_t s;
    for (uint8_t i = 10; i < 13; i++) {
        make_session(&s, i);
        int rc = iog_mdbx_session_create(&ctx, &s);
        TEST_ASSERT_EQUAL_INT(0, rc);
    }

    uint32_t count = 0;
    int rc = iog_mdbx_session_count(&ctx, &count);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_UINT32(3, count);
}

static int count_callback(const iog_session_record_t *session, void *userdata)
{
    (void)session;
    uint32_t *counter = (uint32_t *)userdata;
    (*counter)++;
    return 0;
}

void test_mdbx_session_iterate(void)
{
    iog_session_record_t s;
    for (uint8_t i = 20; i < 25; i++) {
        make_session(&s, i);
        int rc = iog_mdbx_session_create(&ctx, &s);
        TEST_ASSERT_EQUAL_INT(0, rc);
    }

    uint32_t visited = 0;
    int rc = iog_mdbx_session_iterate(&ctx, count_callback, &visited);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_UINT32(5, visited);
}

void test_mdbx_stale_reader_callback(void)
{
    /* Verify that the HSR callback was registered. */
    MDBX_hsr_func *hsr = mdbx_env_get_hsr(ctx.env);
    TEST_ASSERT_NOT_NULL(hsr);
}

void test_mdbx_geometry_limits(void)
{
    /* Read the environment info and verify geometry upper <= 1 GB. */
    MDBX_envinfo info;
    int rc = mdbx_env_info_ex(ctx.env, nullptr, &info, sizeof(info));
    TEST_ASSERT_EQUAL_INT(MDBX_SUCCESS, rc);
    TEST_ASSERT_LESS_OR_EQUAL(RW_MDBX_SIZE_UPPER, info.mi_geo.upper);
    TEST_ASSERT_GREATER_OR_EQUAL(RW_MDBX_SIZE_LOWER, info.mi_geo.lower);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mdbx_env_create_and_close);
    RUN_TEST(test_mdbx_session_create);
    RUN_TEST(test_mdbx_session_lookup_found);
    RUN_TEST(test_mdbx_session_lookup_not_found);
    RUN_TEST(test_mdbx_session_delete);
    RUN_TEST(test_mdbx_session_duplicate);
    RUN_TEST(test_mdbx_session_count);
    RUN_TEST(test_mdbx_session_iterate);
    RUN_TEST(test_mdbx_stale_reader_callback);
    RUN_TEST(test_mdbx_geometry_limits);
    return UNITY_END();
}
