/**
 * @file test_auth_mfa.c
 * @brief End-to-end MFA integration test exercising the full TOTP pipeline:
 *        config -> secmod -> vault -> TOTP -> SQLite -> IPC.
 *
 * Because PAM cannot authenticate synthetic test users inside the build
 * container, we exercise the TOTP second-factor path directly (OTP-only
 * requests bypass PAM) and verify PAM rejection produces no TOTP challenge.
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif

#include "auth/totp.h"
#include "config/config.h"
#include "core/secmod.h"
#include "core/session.h"
#include "ipc/messages.h"
#include "ipc/transport.h"
#include "storage/sqlite.h"
#include "storage/vault.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unity/unity.h>

/* ============================================================================
 * Shared fixtures
 * ============================================================================ */

static iog_ipc_channel_t ch;
static rw_secmod_ctx_t ctx;
static iog_config_t config;
static char vault_key_path[PATH_MAX];

/* Fixed 32-byte test key (hex-encoded in file) */
static const uint8_t test_key[IOG_VAULT_KEY_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

/* Fixed 20-byte TOTP secret for test user */
static const uint8_t test_totp_secret[RW_TOTP_SECRET_SIZE] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
};

static int write_hex_key_file(const char *path, const uint8_t *key, size_t len)
{
    FILE *f = fopen(path, "w");
    if (f == nullptr) {
        return -errno;
    }
    for (size_t i = 0; i < len; i++) {
        if (fprintf(f, "%02x", key[i]) < 0) {
            fclose(f);
            return -EIO;
        }
    }
    fprintf(f, "\n");
    fclose(f);
    return 0;
}

/**
 * Create a user in SQLite with TOTP enabled, encrypting the secret via vault.
 */
static int setup_totp_user(rw_sqlite_ctx_t *sqlite, rw_vault_t *vault, const char *username,
                           bool totp_enabled)
{
    /* Create base user record */
    rw_user_record_t user;
    memset(&user, 0, sizeof(user));
    snprintf(user.username, sizeof(user.username), "%s", username);
    snprintf(user.password_hash, sizeof(user.password_hash), "placeholder");
    user.enabled = true;

    int ret = rw_sqlite_user_create(sqlite, &user);
    if (ret < 0) {
        return ret;
    }

    if (!totp_enabled) {
        return 0;
    }

    /* Encrypt the TOTP secret via vault */
    uint8_t encrypted[RW_TOTP_SECRET_SIZE + IOG_VAULT_OVERHEAD];
    size_t enc_len = 0;
    ret = rw_vault_encrypt(vault, test_totp_secret, RW_TOTP_SECRET_SIZE, encrypted,
                           sizeof(encrypted), &enc_len);
    if (ret < 0) {
        return ret;
    }

    /* Store encrypted secret in SQLite */
    ret = rw_sqlite_user_totp_set(sqlite, username, encrypted, enc_len, "");
    return ret;
}

/**
 * Helper: pack an auth request, feed to secmod, read and unpack response.
 */
static int do_auth_roundtrip(const iog_ipc_auth_request_t *req, iog_ipc_auth_response_t *resp)
{
    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(req, buf, sizeof(buf));
    if (packed <= 0) {
        return -EINVAL;
    }

    int ret = rw_secmod_handle_message(&ctx, buf, (size_t)packed);
    if (ret < 0) {
        return ret;
    }

    /* Read response from child_fd */
    uint8_t recv_buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t n = iog_ipc_recv(ch.child_fd, recv_buf, sizeof(recv_buf));
    if (n <= 0) {
        return -EIO;
    }

    memset(resp, 0, sizeof(*resp));
    return iog_ipc_unpack_auth_response(recv_buf, (size_t)n, resp);
}

void setUp(void)
{
    memset(&ch, 0, sizeof(ch));
    memset(&ctx, 0, sizeof(ctx));

    /* Write vault key to temp file */
    snprintf(vault_key_path, sizeof(vault_key_path), "/tmp/rw_test_vault_XXXXXX");
    int fd = mkstemp(vault_key_path);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    close(fd);
    TEST_ASSERT_EQUAL_INT(0, write_hex_key_file(vault_key_path, test_key, IOG_VAULT_KEY_SIZE));

    /* Configure: in-memory SQLite, vault key, no mdbx */
    iog_config_set_defaults(&config);
    snprintf(config.storage.sqlite_path, sizeof(config.storage.sqlite_path), ":memory:");
    snprintf(config.storage.vault_key_path, sizeof(config.storage.vault_key_path), "%s",
             vault_key_path);
    /* Clear mdbx path to avoid file creation */
    config.storage.mdbx_path[0] = '\0';

    /* Create IPC channel */
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Init secmod with parent_fd as its IPC fd */
    ret = rw_secmod_init(&ctx, ch.parent_fd, &config);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify storage subsystems are available */
    TEST_ASSERT_NOT_NULL(ctx.sqlite);
    TEST_ASSERT_NOT_NULL(ctx.vault);
}

void tearDown(void)
{
    rw_secmod_destroy(&ctx);
    close(ch.parent_fd);
    close(ch.child_fd);
    unlink(vault_key_path);
}

/* ============================================================================
 * Tests
 * ============================================================================ */

/**
 * Full TOTP second-factor success path:
 * 1. Create user with TOTP enabled in SQLite (encrypted secret via vault)
 * 2. Generate a valid TOTP code from the known secret
 * 3. Send OTP-only auth request (simulates second round-trip after PAM success)
 * 4. Verify: success=true, session cookie issued
 */
void test_mfa_flow_totp_second_factor(void)
{
    /* Set up a user with TOTP */
    int ret = setup_totp_user(ctx.sqlite, ctx.vault, "alice", true);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Generate a valid TOTP code for current time */
    uint64_t time_step = (uint64_t)time(nullptr) / RW_TOTP_TIME_STEP;
    uint32_t code = 0;
    ret = rw_totp_generate(test_totp_secret, RW_TOTP_SECRET_SIZE, time_step, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Format as 6-digit zero-padded string */
    char otp_str[16];
    snprintf(otp_str, sizeof(otp_str), "%06u", code);

    /* Send OTP-only request (no password = TOTP second factor) */
    iog_ipc_auth_request_t req = {
        .username = "alice",
        .password = nullptr,
        .otp = otp_str,
        .source_ip = "10.0.0.1",
    };

    iog_ipc_auth_response_t resp;
    ret = do_auth_roundtrip(&req, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* TOTP valid — session created */
    TEST_ASSERT_TRUE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.session_cookie);
    TEST_ASSERT_EQUAL_size_t(IOG_SESSION_COOKIE_SIZE, resp.session_cookie_len);
    TEST_ASSERT_GREATER_THAN(0, resp.session_ttl);

    iog_ipc_free_auth_response(&resp);
}

/**
 * Wrong OTP code: user has TOTP enabled, but the code is incorrect.
 * Verify: success=false, appropriate error message.
 */
void test_mfa_flow_wrong_otp(void)
{
    int ret = setup_totp_user(ctx.sqlite, ctx.vault, "bob", true);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Use a deliberately wrong OTP */
    iog_ipc_auth_request_t req = {
        .username = "bob",
        .password = nullptr,
        .otp = "000000",
        .source_ip = "10.0.0.2",
    };

    iog_ipc_auth_response_t resp;
    ret = do_auth_roundtrip(&req, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);
    TEST_ASSERT_EQUAL_size_t(0, resp.session_cookie_len);

    iog_ipc_free_auth_response(&resp);
}

/**
 * User without TOTP enabled: OTP-only request should fail because
 * the user has no TOTP secret configured.
 */
void test_mfa_flow_no_totp_user(void)
{
    /* Create user WITHOUT TOTP */
    int ret = setup_totp_user(ctx.sqlite, ctx.vault, "charlie", false);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_ipc_auth_request_t req = {
        .username = "charlie",
        .password = nullptr,
        .otp = "123456",
        .source_ip = "10.0.0.3",
    };

    iog_ipc_auth_response_t resp;
    ret = do_auth_roundtrip(&req, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Should fail: TOTP not configured for this user */
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);

    iog_ipc_free_auth_response(&resp);
}

/**
 * PAM failure path: nonexistent user with password (first-factor attempt).
 * PAM rejects, so no TOTP challenge is issued — requires_totp must be false.
 */
void test_mfa_flow_pam_failure_no_totp_challenge(void)
{
    iog_ipc_auth_request_t req = {
        .username = "rw_nonexistent_mfa_user",
        .password = "wrongpass",
        .source_ip = "10.0.0.4",
    };

    iog_ipc_auth_response_t resp;
    int ret = do_auth_roundtrip(&req, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* PAM rejects — no session, no TOTP challenge */
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_FALSE(resp.requires_totp);
    TEST_ASSERT_NOT_NULL(resp.error_msg);
    TEST_ASSERT_EQUAL_size_t(0, resp.session_cookie_len);

    iog_ipc_free_auth_response(&resp);
}

/**
 * Audit trail: after TOTP success and failure, verify audit entries
 * were written to SQLite.
 */
void test_mfa_flow_audit_trail(void)
{
    int ret = setup_totp_user(ctx.sqlite, ctx.vault, "dave", true);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* First: wrong OTP */
    iog_ipc_auth_request_t req = {
        .username = "dave",
        .password = nullptr,
        .otp = "999999",
        .source_ip = "10.0.0.5",
    };

    iog_ipc_auth_response_t resp;
    ret = do_auth_roundtrip(&req, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(resp.success);
    iog_ipc_free_auth_response(&resp);

    /* Second: correct OTP */
    uint64_t time_step = (uint64_t)time(nullptr) / RW_TOTP_TIME_STEP;
    uint32_t code = 0;
    ret = rw_totp_generate(test_totp_secret, RW_TOTP_SECRET_SIZE, time_step, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char otp_str[16];
    snprintf(otp_str, sizeof(otp_str), "%06u", code);

    iog_ipc_auth_request_t req2 = {
        .username = "dave",
        .password = nullptr,
        .otp = otp_str,
        .source_ip = "10.0.0.5",
    };

    ret = do_auth_roundtrip(&req2, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(resp.success);
    iog_ipc_free_auth_response(&resp);

    /* Verify audit entries exist for dave */
    rw_audit_entry_t entries[8];
    size_t count = 0;
    ret = rw_sqlite_audit_query_by_username(ctx.sqlite, "dave", entries, 8, &count);
    TEST_ASSERT_EQUAL_INT(0, ret);
    /* At least a TOTP_FAIL and a TOTP OK + AUTH OK should be present */
    TEST_ASSERT_GREATER_OR_EQUAL(2, (int)count);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mfa_flow_totp_second_factor);
    RUN_TEST(test_mfa_flow_wrong_otp);
    RUN_TEST(test_mfa_flow_no_totp_user);
    RUN_TEST(test_mfa_flow_pam_failure_no_totp_challenge);
    RUN_TEST(test_mfa_flow_audit_trail);
    return UNITY_END();
}
