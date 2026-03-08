/**
 * @file fuzz_toml.c
 * @brief LibFuzzer target for TOML parsing via tomlc99.
 *
 * Feeds arbitrary bytes as a NUL-terminated string to toml_parse() and
 * frees the result.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <toml.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* toml_parse requires a mutable NUL-terminated string */
    char *buf = malloc(size + 1);
    if (buf == nullptr) {
        return 0;
    }

    memcpy(buf, data, size);
    buf[size] = '\0';

    char errbuf[256];
    toml_table_t *tbl = toml_parse(buf, errbuf, sizeof(errbuf));
    if (tbl != nullptr) {
        toml_free(tbl);
    }

    free(buf);
    return 0;
}
