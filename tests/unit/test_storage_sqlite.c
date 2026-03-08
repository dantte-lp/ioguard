#include <unity/unity.h>
#include "storage/sqlite.h"

#include <errno.h>
#include <string.h>

static rw_sqlite_ctx_t ctx;

void setUp(void)
{
	int rc = rw_sqlite_init(&ctx, ":memory:");
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_sqlite_init failed in setUp");
}

void tearDown(void)
{
	rw_sqlite_close(&ctx);
}

static void make_user(rw_user_record_t *u, const char *name)
{
	memset(u, 0, sizeof(*u));
	snprintf(u->username, sizeof(u->username), "%s", name);
	snprintf(u->password_hash, sizeof(u->password_hash),
	         "$argon2id$v=19$m=65536,t=3,p=4$salt$hash_%s", name);
	snprintf(u->groups, sizeof(u->groups), "[\"users\"]");
	u->enabled = true;
	u->failed_attempts = 0;
	u->locked_until[0] = '\0';
	u->totp_enabled = false;
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
	snprintf(e->session_id, sizeof(e->session_id),
	         "abcdef0123456789abcdef0123456789");
}

/* ---- Tests ---- */

void test_sqlite_init_and_close(void)
{
	/* setUp already opened the db; verify non-null. */
	TEST_ASSERT_NOT_NULL(ctx.db);
	TEST_ASSERT_NOT_NULL(ctx.stmt_user_lookup);
	TEST_ASSERT_NOT_NULL(ctx.stmt_user_create);
	TEST_ASSERT_NOT_NULL(ctx.stmt_audit_insert);
	TEST_ASSERT_NOT_NULL(ctx.stmt_audit_query);
	TEST_ASSERT_NOT_NULL(ctx.stmt_ban_check);
	TEST_ASSERT_NOT_NULL(ctx.stmt_ban_add);

	/* Close and re-open to exercise the full lifecycle. */
	rw_sqlite_close(&ctx);
	TEST_ASSERT_NULL(ctx.db);

	int rc = rw_sqlite_init(&ctx, ":memory:");
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_NOT_NULL(ctx.db);
}

void test_sqlite_user_create(void)
{
	rw_user_record_t u;
	make_user(&u, "alice");
	int rc = rw_sqlite_user_create(&ctx, &u);
	TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_sqlite_user_lookup_found(void)
{
	rw_user_record_t u;
	make_user(&u, "bob");
	int rc = rw_sqlite_user_create(&ctx, &u);
	TEST_ASSERT_EQUAL_INT(0, rc);

	rw_user_record_t out;
	memset(&out, 0, sizeof(out));
	rc = rw_sqlite_user_lookup(&ctx, "bob", &out);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_EQUAL_STRING("bob", out.username);
	TEST_ASSERT_EQUAL_STRING(u.password_hash, out.password_hash);
	TEST_ASSERT_EQUAL_STRING("[\"users\"]", out.groups);
	TEST_ASSERT_TRUE(out.enabled);
	TEST_ASSERT_EQUAL_UINT32(0, out.failed_attempts);
	TEST_ASSERT_FALSE(out.totp_enabled);
}

void test_sqlite_user_lookup_not_found(void)
{
	rw_user_record_t out;
	int rc = rw_sqlite_user_lookup(&ctx, "nonexistent", &out);
	TEST_ASSERT_EQUAL_INT(-ENOENT, rc);
}

void test_sqlite_user_duplicate(void)
{
	rw_user_record_t u;
	make_user(&u, "charlie");
	int rc = rw_sqlite_user_create(&ctx, &u);
	TEST_ASSERT_EQUAL_INT(0, rc);

	rc = rw_sqlite_user_create(&ctx, &u);
	TEST_ASSERT_EQUAL_INT(-EEXIST, rc);
}

void test_sqlite_audit_log_insert(void)
{
	rw_audit_entry_t e;
	make_audit(&e, "alice", "login");
	int rc = rw_sqlite_audit_insert(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_sqlite_audit_log_query_by_username(void)
{
	/* Insert several entries for different users. */
	rw_audit_entry_t e;
	make_audit(&e, "dave", "login");
	int rc = rw_sqlite_audit_insert(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, rc);

	make_audit(&e, "dave", "logout");
	rc = rw_sqlite_audit_insert(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, rc);

	make_audit(&e, "eve", "login");
	rc = rw_sqlite_audit_insert(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, rc);

	/* Query dave's entries. */
	rw_audit_entry_t results[10];
	size_t count = 0;
	rc = rw_sqlite_audit_query_by_username(&ctx, "dave", results, 10, &count);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_EQUAL_INT(2, (int)count);
	TEST_ASSERT_EQUAL_STRING("dave", results[0].username);
	TEST_ASSERT_EQUAL_STRING("dave", results[1].username);
}

void test_sqlite_ban_check_not_banned(void)
{
	bool banned = true;
	int rc = rw_sqlite_ban_check(&ctx, "10.0.0.1", &banned);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_FALSE(banned);
}

void test_sqlite_ban_add_and_check(void)
{
	int rc = rw_sqlite_ban_add(&ctx, "10.0.0.99", "brute force", 60);
	TEST_ASSERT_EQUAL_INT(0, rc);

	bool banned = false;
	rc = rw_sqlite_ban_check(&ctx, "10.0.0.99", &banned);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_TRUE(banned);

	/* Different IP should not be banned. */
	banned = true;
	rc = rw_sqlite_ban_check(&ctx, "10.0.0.100", &banned);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_FALSE(banned);
}

void test_sqlite_injection_prevention(void)
{
	/*
	 * Attempt SQL injection via username. The prepared statement should
	 * treat the entire string as a literal value, returning -ENOENT
	 * rather than leaking all rows.
	 */
	const char *evil = "' OR '1'='1";
	rw_user_record_t out;
	int rc = rw_sqlite_user_lookup(&ctx, evil, &out);
	TEST_ASSERT_EQUAL_INT(-ENOENT, rc);

	/* Also try via audit query — should return 0 results, not all rows. */
	rw_audit_entry_t e;
	make_audit(&e, "real_user", "login");
	rc = rw_sqlite_audit_insert(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, rc);

	rw_audit_entry_t results[10];
	size_t count = 99;
	rc = rw_sqlite_audit_query_by_username(&ctx, evil, results, 10, &count);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_EQUAL_INT(0, (int)count);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_sqlite_init_and_close);
	RUN_TEST(test_sqlite_user_create);
	RUN_TEST(test_sqlite_user_lookup_found);
	RUN_TEST(test_sqlite_user_lookup_not_found);
	RUN_TEST(test_sqlite_user_duplicate);
	RUN_TEST(test_sqlite_audit_log_insert);
	RUN_TEST(test_sqlite_audit_log_query_by_username);
	RUN_TEST(test_sqlite_ban_check_not_banned);
	RUN_TEST(test_sqlite_ban_add_and_check);
	RUN_TEST(test_sqlite_injection_prevention);
	return UNITY_END();
}
