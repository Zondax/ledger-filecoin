#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "hexutils.h"


#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif


using std::size_t;

static constexpr size_t SIZE = 512;
static char INPUT[SIZE];
static uint8_t OUTPUT[SIZE];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    if (size > sizeof(INPUT)) return 0;

    memcpy(INPUT, data, size);
    INPUT[size - 1] = '\0';

    size_t out_size = parseHexString(OUTPUT, (uint16_t)sizeof(OUTPUT), INPUT);
    assert (out_size <= sizeof(OUTPUT));

    return 0;
}
