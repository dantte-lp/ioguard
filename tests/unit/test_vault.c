#include <errno.h>
#include <string.h>

#include <unity/unity.h>

#include "storage/vault.h"

static iog_vault_t *vault;

/* Fixed test key (32 bytes) */
static const uint8_t TEST_KEY[IOG_VAULT_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

void setUp(void)
{
    int ret = iog_vault_init_from_key(TEST_KEY, IOG_VAULT_KEY_SIZE, &vault);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void tearDown(void)
{
    iog_vault_destroy(vault);
    vault = nullptr;
}

void test_vault_encrypt_decrypt_roundtrip(void)
{
    const uint8_t plain[] = "TOTP secret data here";
    uint8_t blob[sizeof(plain) + IOG_VAULT_OVERHEAD];
    size_t blob_len = 0;

    int ret = iog_vault_encrypt(vault, plain, sizeof(plain), blob, sizeof(blob), &blob_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(sizeof(plain) + IOG_VAULT_OVERHEAD, blob_len);

    uint8_t decrypted[sizeof(plain)];
    size_t dec_len = 0;
    ret = iog_vault_decrypt(vault, blob, blob_len, decrypted, sizeof(decrypted), &dec_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(sizeof(plain), dec_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(plain, decrypted, sizeof(plain));
}

void test_vault_tampered_ciphertext_fails(void)
{
    const uint8_t plain[] = "secret";
    uint8_t blob[sizeof(plain) + IOG_VAULT_OVERHEAD];
    size_t blob_len = 0;

    int ret = iog_vault_encrypt(vault, plain, sizeof(plain), blob, sizeof(blob), &blob_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Flip a byte in ciphertext */
    blob[IOG_VAULT_IV_SIZE] ^= 0xFF;

    uint8_t out[sizeof(plain)];
    size_t out_len = 0;
    ret = iog_vault_decrypt(vault, blob, blob_len, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL_INT(-EACCES, ret);
}

void test_vault_different_iv_each_encrypt(void)
{
    const uint8_t plain[] = "same plaintext";
    uint8_t blob1[sizeof(plain) + IOG_VAULT_OVERHEAD];
    uint8_t blob2[sizeof(plain) + IOG_VAULT_OVERHEAD];
    size_t len1 = 0;
    size_t len2 = 0;

    TEST_ASSERT_EQUAL_INT(0, iog_vault_encrypt(vault, plain, sizeof(plain), blob1, sizeof(blob1),
                                               &len1));
    TEST_ASSERT_EQUAL_INT(0, iog_vault_encrypt(vault, plain, sizeof(plain), blob2, sizeof(blob2),
                                               &len2));

    /* IVs must differ (first 12 bytes) — use byte comparison to avoid
     * memcmp which is banned on security-related buffers by project rules */
    bool ivs_identical = true;
    for (size_t i = 0; i < IOG_VAULT_IV_SIZE; i++) {
        if (blob1[i] != blob2[i]) {
            ivs_identical = false;
            break;
        }
    }
    TEST_ASSERT_FALSE(ivs_identical);

    /* But both must decrypt to same plaintext */
    uint8_t dec1[sizeof(plain)];
    uint8_t dec2[sizeof(plain)];
    size_t d1 = 0;
    size_t d2 = 0;
    TEST_ASSERT_EQUAL_INT(0, iog_vault_decrypt(vault, blob1, len1, dec1, sizeof(dec1), &d1));
    TEST_ASSERT_EQUAL_INT(0, iog_vault_decrypt(vault, blob2, len2, dec2, sizeof(dec2), &d2));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(plain, dec1, sizeof(plain));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(plain, dec2, sizeof(plain));
}

void test_vault_wrong_key_fails(void)
{
    const uint8_t plain[] = "secret";
    uint8_t blob[sizeof(plain) + IOG_VAULT_OVERHEAD];
    size_t blob_len = 0;
    TEST_ASSERT_EQUAL_INT(0, iog_vault_encrypt(vault, plain, sizeof(plain), blob, sizeof(blob),
                                               &blob_len));

    /* Create vault with different key */
    uint8_t bad_key[IOG_VAULT_KEY_SIZE] = {0xFF};
    iog_vault_t *bad_vault = nullptr;
    TEST_ASSERT_EQUAL_INT(0, iog_vault_init_from_key(bad_key, IOG_VAULT_KEY_SIZE, &bad_vault));

    uint8_t out[sizeof(plain)];
    size_t out_len = 0;
    int ret = iog_vault_decrypt(bad_vault, blob, blob_len, out, sizeof(out), &out_len);
    TEST_ASSERT_EQUAL_INT(-EACCES, ret);

    iog_vault_destroy(bad_vault);
}

void test_vault_buffer_too_small(void)
{
    const uint8_t plain[] = "data";
    uint8_t blob[2]; /* too small */
    size_t blob_len = 0;
    int ret = iog_vault_encrypt(vault, plain, sizeof(plain), blob, sizeof(blob), &blob_len);
    TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);
}

void test_vault_null_params(void)
{
    uint8_t buf[64] = {0};
    size_t len = 0;
    // cppcheck-suppress uninitvar
    TEST_ASSERT_LESS_THAN_INT(0, iog_vault_encrypt(nullptr, buf, 4, buf, 64, &len));
    TEST_ASSERT_LESS_THAN_INT(0, iog_vault_decrypt(nullptr, buf, 32, buf, 32, &len));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vault_encrypt_decrypt_roundtrip);
    RUN_TEST(test_vault_tampered_ciphertext_fails);
    RUN_TEST(test_vault_different_iv_each_encrypt);
    RUN_TEST(test_vault_wrong_key_fails);
    RUN_TEST(test_vault_buffer_too_small);
    RUN_TEST(test_vault_null_params);
    return UNITY_END();
}
