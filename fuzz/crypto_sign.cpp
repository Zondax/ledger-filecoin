#include <cassert>
#include <cstdint>
#include <cstdio>

#include "crypto.h"


#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif


using std::size_t;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > UINT16_MAX) return 0;
    uint16_t data_size = (uint16_t)size;

    uint8_t output[BLAKE2B_256_SIZE * 2];
    assert(sizeof(output) <= UINT16_MAX && "fuzzer bug: output buffer is too big");
    uint16_t unused_size = sizeof(output);
    // FIXME: Figure out how to fuzz the actual device implementation.
    // This is only exercising the test implementation of `crypto_sign`,
    // which is very boring compared to the actual device implementation.
    uint16_t output_size = crypto_sign(output, unused_size, data, data_size);
    if (output_size == 0) return 0;

    return 0;
}
