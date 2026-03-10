#include "storage/vault.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#endif

struct rw_vault {
	uint8_t key[RW_VAULT_KEY_SIZE];
#ifdef USE_WOLFSSL
	WC_RNG rng;
	bool rng_init;
#endif
};

static int hex_to_bytes(const char *hex, size_t hex_len,
                        uint8_t *out, size_t out_size)
{
	if (hex_len != out_size * 2)
		return -EINVAL;

	for (size_t i = 0; i < out_size; i++) {
		unsigned int byte;
		char tmp[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
		if (sscanf(tmp, "%02x", &byte) != 1)
			return -EINVAL;
		out[i] = (uint8_t)byte;
	}
	return 0;
}

int rw_vault_init_from_key(const uint8_t *key, size_t key_len,
                           rw_vault_t **out)
{
	if (key == nullptr || key_len != RW_VAULT_KEY_SIZE || out == nullptr)
		return -EINVAL;

	rw_vault_t *v = calloc(1, sizeof(*v));
	if (v == nullptr)
		return -ENOMEM;

	memcpy(v->key, key, RW_VAULT_KEY_SIZE);

#ifdef USE_WOLFSSL
	if (wc_InitRng(&v->rng) != 0) {
		explicit_bzero(v, sizeof(*v));
		free(v);
		return -EIO;
	}
	v->rng_init = true;
#endif

	*out = v;
	return 0;
}

int rw_vault_init(const char *key_path, rw_vault_t **out)
{
	if (key_path == nullptr || out == nullptr)
		return -EINVAL;

	FILE *f = fopen(key_path, "r");
	if (f == nullptr)
		return -errno;

	uint8_t key[RW_VAULT_KEY_SIZE];
	char buf[128];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	/* Try hex format first (64 hex chars + optional newline) */
	size_t clean_len = n;
	while (clean_len > 0 &&
	       (buf[clean_len - 1] == '\n' || buf[clean_len - 1] == '\r'))
		clean_len--;

	int ret;
	if (clean_len == RW_VAULT_KEY_SIZE * 2) {
		ret = hex_to_bytes(buf, clean_len, key, RW_VAULT_KEY_SIZE);
		if (ret == 0) {
			ret = rw_vault_init_from_key(key, RW_VAULT_KEY_SIZE, out);
			explicit_bzero(key, sizeof(key));
			explicit_bzero(buf, sizeof(buf));
			return ret;
		}
	}

	/* Try raw bytes */
	if (n >= RW_VAULT_KEY_SIZE) {
		memcpy(key, buf, RW_VAULT_KEY_SIZE);
		ret = rw_vault_init_from_key(key, RW_VAULT_KEY_SIZE, out);
		explicit_bzero(key, sizeof(key));
		explicit_bzero(buf, sizeof(buf));
		return ret;
	}

	explicit_bzero(buf, sizeof(buf));
	return -EINVAL;
}

void rw_vault_destroy(rw_vault_t *vault)
{
	if (vault == nullptr)
		return;

#ifdef USE_WOLFSSL
	if (vault->rng_init)
		wc_FreeRng(&vault->rng);
#endif

	explicit_bzero(vault, sizeof(*vault));
	free(vault);
}

int rw_vault_encrypt(rw_vault_t *vault,
                     const uint8_t *plaintext, size_t plain_len,
                     uint8_t *out, size_t out_size,
                     size_t *out_len)
{
	if (vault == nullptr || plaintext == nullptr ||
	    out == nullptr || out_len == nullptr)
		return -EINVAL;

	size_t needed = plain_len + RW_VAULT_OVERHEAD;
	if (out_size < needed)
		return -ENOSPC;

#ifdef USE_WOLFSSL
	/* Generate random IV */
	uint8_t *iv = out;
	int ret = wc_RNG_GenerateBlock(&vault->rng, iv, RW_VAULT_IV_SIZE);
	if (ret != 0)
		return -EIO;

	uint8_t *ct = out + RW_VAULT_IV_SIZE;
	uint8_t *tag = out + RW_VAULT_IV_SIZE + plain_len;

	Aes aes;
	ret = wc_AesInit(&aes, nullptr, INVALID_DEVID);
	if (ret != 0)
		return -EIO;

	ret = wc_AesGcmSetKey(&aes, vault->key, RW_VAULT_KEY_SIZE);
	if (ret != 0) {
		wc_AesFree(&aes);
		return -EIO;
	}

	ret = wc_AesGcmEncrypt(&aes, ct, plaintext, (word32)plain_len,
	                        iv, RW_VAULT_IV_SIZE,
	                        tag, RW_VAULT_TAG_SIZE,
	                        nullptr, 0);
	wc_AesFree(&aes);

	if (ret != 0)
		return -EIO;

	*out_len = needed;
	return 0;
#else
	return -ENOTSUP;
#endif
}

int rw_vault_decrypt(rw_vault_t *vault,
                     const uint8_t *cipherblob, size_t blob_len,
                     uint8_t *out, size_t out_size,
                     size_t *out_len)
{
	if (vault == nullptr || cipherblob == nullptr ||
	    out == nullptr || out_len == nullptr)
		return -EINVAL;

	if (blob_len < RW_VAULT_OVERHEAD)
		return -EINVAL;

	size_t plain_len = blob_len - RW_VAULT_OVERHEAD;
	if (out_size < plain_len)
		return -ENOSPC;

#ifdef USE_WOLFSSL
	const uint8_t *iv = cipherblob;
	const uint8_t *ct = cipherblob + RW_VAULT_IV_SIZE;
	const uint8_t *tag = cipherblob + RW_VAULT_IV_SIZE + plain_len;

	Aes aes;
	int ret = wc_AesInit(&aes, nullptr, INVALID_DEVID);
	if (ret != 0)
		return -EIO;

	ret = wc_AesGcmSetKey(&aes, vault->key, RW_VAULT_KEY_SIZE);
	if (ret != 0) {
		wc_AesFree(&aes);
		return -EIO;
	}

	ret = wc_AesGcmDecrypt(&aes, out, ct, (word32)plain_len,
	                        iv, RW_VAULT_IV_SIZE,
	                        tag, RW_VAULT_TAG_SIZE,
	                        nullptr, 0);
	wc_AesFree(&aes);

	if (ret != 0)
		return -EACCES;

	*out_len = plain_len;
	return 0;
#else
	return -ENOTSUP;
#endif
}
