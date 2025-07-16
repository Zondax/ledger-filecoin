/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
// Implementation from methods that are needed for cpp_test
#if !defined(LEDGER_SPECIFIC)

#include <hexutils.h>

#include "coin.h"
#include "crypto_helper.h"
#include "zxerror.h"
#include "zxmacros.h"

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
// Fake implementations for fuzzing to avoid crashes
#include <string.h>

char *crypto_testPubKey;

zxerr_t blake_hash(const uint8_t *in, uint16_t inLen, uint8_t *out, uint16_t outLen) {
    if (in == NULL || out == NULL || outLen == 0) {
        return zxerr_unknown;
    }
    // Simple fake hash: just fill with zeros
    memset(out, 0, outLen);
    // Add some simple deterministic value based on input length
    if (outLen >= 4 && inLen > 0) {
        out[0] = (uint8_t)(inLen & 0xFF);
        out[1] = (uint8_t)((inLen >> 8) & 0xFF);
        out[2] = 0xAA;  // Fixed pattern
        out[3] = 0xBB;  // Fixed pattern
    }
    return zxerr_ok;
}

// Fake implementations for fuzzing

zxerr_t blake_hash_cid(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
    if (in == NULL || out == NULL || outLen == 0) {
        return zxerr_unknown;
    }
    // Simple fake hash with prefix
    memset(out, 0, outLen);
    if (outLen >= 4) {
        out[0] = 0xCD;  // Fixed pattern for CID
        out[1] = (uint8_t)(inLen & 0xFF);
        out[2] = (uint8_t)((inLen >> 8) & 0xFF);
        out[3] = 0xEF;  // Fixed pattern
    }
    return zxerr_ok;
}

static uint8_t fake_blake_state[32] = {0};
static uint16_t fake_blake_pos = 0;

zxerr_t blake_hash_init() {
    memset(fake_blake_state, 0, sizeof(fake_blake_state));
    fake_blake_pos = 0;
    return zxerr_ok;
}

zxerr_t blake_hash_update(const uint8_t *in, uint16_t inLen) {
    if (in == NULL) {
        return zxerr_unknown;
    }
    // Simple accumulation
    for (uint16_t i = 0; i < inLen && fake_blake_pos < sizeof(fake_blake_state); i++) {
        fake_blake_state[fake_blake_pos++] ^= in[i];
    }
    return zxerr_ok;
}

zxerr_t blake_hash_finish(uint8_t *out, uint16_t outLen) {
    if (out == NULL || outLen < BLAKE2B_256_SIZE) {
        return zxerr_unknown;
    }
    // Copy the fake state
    memset(out, 0, BLAKE2B_256_SIZE);
    memcpy(out, fake_blake_state, (fake_blake_pos < BLAKE2B_256_SIZE) ? fake_blake_pos : BLAKE2B_256_SIZE);
    return zxerr_ok;
}

#else
// Real implementation using BLAKE2

#include "blake2.h"

char *crypto_testPubKey;

typedef struct {
    blake2b_state state;
} cx_blake2b_t;

static cx_blake2b_t ctx_blake2b;

zxerr_t blake_hash(const uint8_t *in, uint16_t inLen, uint8_t *out, uint16_t outLen) {
    if (in == NULL || inLen == 0 || out == NULL) {
        return zxerr_unknown;
    }
    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);

    return zxerr_ok;
}

zxerr_t blake_hash_cid(const unsigned char *in, unsigned int inLen, unsigned char *out, unsigned int outLen) {
    uint8_t prefix[] = PREFIX;

    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, prefix, sizeof(prefix));
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);

    return zxerr_ok;
}

zxerr_t blake_hash_init() {
    MEMZERO(&ctx_blake2b, sizeof(ctx_blake2b));
    blake2b_init(&ctx_blake2b.state, BLAKE2B_256_SIZE);
    return zxerr_ok;
}

zxerr_t blake_hash_update(const uint8_t *in, uint16_t inLen) {
    if (in == NULL) {
        return zxerr_unknown;
    }
    blake2b_update(&ctx_blake2b.state, in, inLen);
    return zxerr_ok;
}

zxerr_t blake_hash_finish(uint8_t *out, uint16_t outLen) {
    if (out == NULL || outLen < BLAKE2B_256_SIZE) {
        return zxerr_unknown;
    }
    blake2b_final(&ctx_blake2b.state, out, BLAKE2B_256_SIZE);
    return zxerr_ok;
}
#endif

#endif
