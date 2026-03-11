/**
 * @file fuzz_http.c
 * @brief LibFuzzer target for HTTP request parsing via iohttpparser.
 *
 * Feeds arbitrary bytes to iog_http_parse() to find crashes or UB in the
 * iohttpparser-based request parser.
 */

#include <network/http.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    iog_http_parser_t parser;

    int rc = iog_http_parser_init(&parser);
    if (rc != 0) {
        return 0;
    }

    (void)iog_http_parse(&parser, (const char *)data, size);
    return 0;
}
