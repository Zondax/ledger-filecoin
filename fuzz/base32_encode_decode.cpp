#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "base32.h"


#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif


static uint8_t ENCODED[1024];
static uint8_t DECODED[1024];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t data_size)
{
    // memset(ENCODED, 0, sizeof(ENCODED));
    // memset(DECODED, 0, sizeof(DECODED));

    int encoded_size = base32_encode(data, (int)data_size, ENCODED, (int)sizeof(ENCODED));
    if (encoded_size == -1) {
        return 0;
    }

    int decoded_size = base32_decode(ENCODED, DECODED, (int)sizeof(DECODED));
    if (decoded_size != (int)data_size) {
        fprintf(stderr, "expected decoded size %d but got %d\n", (int)data_size, decoded_size);
        assert(false);
    }

    assert(memcmp(data, DECODED, (size_t)decoded_size) == 0 && "round-tripping failed!\n");

    return 0;
}
