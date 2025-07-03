#include <cassert>
#include <cstdint>
#include <cstdio>

#include "parser.h"
#include "zxformat.h"

#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif

using std::size_t;

static char PARSER_KEY[16384];
static char PARSER_VALUE[16384];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parser_context_t ctx;
    parser_error_t rc;

    char buffer[10000];
    array_to_hexstr(buffer, sizeof(buffer), data, size);
    // fprintf(stderr, "input blob: %s\n", buffer);

    rc = parser_parse(&ctx, data, size);
    if (rc != parser_ok) {
        // fprintf(stderr, "parser error: %s\n", parser_getErrorDescription(rc));
        return 0;
    }

    /* assert(size <= UINT16_MAX && "too big!"); */

    rc = parser_validate(&ctx);
    if (rc != parser_ok) {
        // fprintf(stderr, "validation error: %s\n", parser_getErrorDescription(rc));
        return 0;
    }

    uint8_t num_items;
    rc = parser_getNumItems(&ctx, &num_items);
    if (rc != parser_ok) {
        fprintf(stderr, "error in parser_getNumItems: %s\n", parser_getErrorDescription(rc));
        assert(false);
    }

    for (uint8_t i = 0; i < num_items; i += 1) {
        uint8_t page_idx = 0;
        uint8_t page_count = 1;
        while (page_idx < page_count) {
            rc = parser_getItem(&ctx, i, PARSER_KEY, sizeof(PARSER_KEY), PARSER_VALUE, sizeof(PARSER_VALUE), page_idx,
                                &page_count);

            if (rc != parser_ok) {
                assert(fprintf(stderr, "error getting item %u at page index %u: %s\n", (unsigned)i, (unsigned)page_idx,
                               parser_getErrorDescription(rc)) != 0);
                assert(false);
            }

            page_idx += 1;
        }
    }

    return 0;
}
