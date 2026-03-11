#ifndef IOGUARD_STORAGE_VAULT_H
#define IOGUARD_STORAGE_VAULT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/** AES-256-GCM key size in bytes. */
constexpr size_t IOG_VAULT_KEY_SIZE = 32;

/** AES-GCM IV size in bytes (96-bit recommended). */
constexpr size_t IOG_VAULT_IV_SIZE = 12;

/** AES-GCM authentication tag size. */
constexpr size_t IOG_VAULT_TAG_SIZE = 16;

/** Overhead per encrypted field: IV + tag. */
constexpr size_t IOG_VAULT_OVERHEAD = IOG_VAULT_IV_SIZE + IOG_VAULT_TAG_SIZE;

/** Opaque vault context. */
typedef struct iog_vault iog_vault_t;

/**
 * @brief Initialize vault with a master key loaded from file.
 *
 * Key file format: 32 raw bytes (or 64 hex characters + newline).
 *
 * @param key_path Path to master key file.
 * @param out      Output vault handle.
 * @return 0 on success, -EINVAL/-ENOENT/-EIO on error.
 */
[[nodiscard]] int iog_vault_init(const char *key_path, iog_vault_t **out);

/**
 * @brief Initialize vault from a raw key (for testing).
 *
 * @param key      32-byte master key.
 * @param key_len  Must be IOG_VAULT_KEY_SIZE.
 * @param out      Output vault handle.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_vault_init_from_key(const uint8_t *key, size_t key_len, iog_vault_t **out);

/**
 * @brief Destroy vault and zero all key material.
 */
void iog_vault_destroy(iog_vault_t *vault);

/**
 * @brief Encrypt a field value.
 *
 * Output format: [IV (12 bytes)][ciphertext (plain_len bytes)][tag (16 bytes)]
 * Total output: plain_len + IOG_VAULT_OVERHEAD.
 *
 * @param vault     Vault context.
 * @param plaintext Input data.
 * @param plain_len Input length.
 * @param out       Output buffer (must be >= plain_len + IOG_VAULT_OVERHEAD).
 * @param out_size  Output buffer capacity.
 * @param out_len   Actual bytes written.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_vault_encrypt(iog_vault_t *vault, const uint8_t *plaintext, size_t plain_len,
                                   uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @brief Decrypt a field value.
 *
 * Input format: [IV (12)][ciphertext][tag (16)].
 * Verifies authentication tag — returns -EACCES on tamper.
 *
 * @param vault      Vault context.
 * @param cipherblob Encrypted blob (IV + ciphertext + tag).
 * @param blob_len   Blob length.
 * @param out        Output buffer (must be >= blob_len - IOG_VAULT_OVERHEAD).
 * @param out_size   Output buffer capacity.
 * @param out_len    Actual plaintext bytes written.
 * @return 0 on success, -EACCES on authentication failure, negative errno on error.
 */
[[nodiscard]] int iog_vault_decrypt(iog_vault_t *vault, const uint8_t *cipherblob, size_t blob_len,
                                   uint8_t *out, size_t out_size, size_t *out_len);

#endif /* IOGUARD_STORAGE_VAULT_H */
