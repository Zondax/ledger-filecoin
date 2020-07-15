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
    // looking at the implementation of `decompressLEB128`, it looks at up to
    // 10 bytes of input (which is not expected to be NUL-terminated).
    if (size < 10) {
        return 0;
    }

    uint64_t output;
    if (decompressLEB128(data, &output) != 0) {
        return 1;
    }

    return 0;
}
