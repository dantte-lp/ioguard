/**
 * @file fuzz_http.c
 * @brief LibFuzzer target for HTTP request parsing via llhttp.
 *
 * Feeds arbitrary bytes to rw_http_parse() to find crashes or UB in the
 * llhttp-based request parser.
 */

#include <network/http.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rw_http_parser_t parser;

    int rc = rw_http_parser_init(&parser);
    if (rc != 0) {
        return 0;
    }

    (void)rw_http_parse(&parser, (const char *)data, size);
    return 0;
}
