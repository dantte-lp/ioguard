/**
 * @file fuzz_session_key.c
 * @brief LibFuzzer target for MDBX session lookup with arbitrary keys.
 *
 * Initialises a temporary MDBX environment, feeds fuzzed bytes as a
 * session ID to iog_mdbx_session_lookup(), and tears down. Tests the
 * lookup path with arbitrary 32-byte (or shorter) input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <storage/mdbx.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Build a unique temp path per process (reused across iterations) */
    static char db_path[256];
    static rw_mdbx_ctx_t ctx;
    static bool initialised = false;

    if (!initialised) {
        snprintf(db_path, sizeof(db_path), "/tmp/fuzz_mdbx_%d.dat", (int)getpid());

        int rc = rw_mdbx_init(&ctx, db_path);
        if (rc != 0) {
            return 0;
        }
        initialised = true;
    }

    /* Pad or truncate input to exactly IOG_SESSION_ID_LEN bytes */
    uint8_t session_id[IOG_SESSION_ID_LEN];
    memset(session_id, 0, sizeof(session_id));
    size_t copy_len = size < IOG_SESSION_ID_LEN ? size : IOG_SESSION_ID_LEN;
    memcpy(session_id, data, copy_len);

    iog_session_record_t record;
    (void)iog_mdbx_session_lookup(&ctx, session_id, &record);

    return 0;
}
