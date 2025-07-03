#include <cassert>
#include <cstdint>
#include <cstdio>

#include "crypto.h"

#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif

using std::size_t;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint64_t output;
    if (decompressLEB128(data, size, &output) != 0) {
        return 1;
    }

    return 0;
}
