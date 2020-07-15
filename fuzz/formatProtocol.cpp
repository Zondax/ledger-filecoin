#include <cassert>
#include <cstdint>
#include <cstdio>

#include "crypto.h"


#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif


using std::size_t;

static uint8_t OUTPUT[1024];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > UINT16_MAX) return 0;
    uint16_t data_size = (uint16_t)size;
    uint16_t output_size = formatProtocol(data, data_size, OUTPUT, sizeof(OUTPUT));
    if (output_size == 0) return 0;

    return 0;
}
