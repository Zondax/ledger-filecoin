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
#include <hexutils.h>
#include "zxerror.h"
#include "coin.h"
#include "crypto_helper.h"

// Implementation from methods that are needed for cpp_test
#if !defined (TARGET_NANOS) && !defined(TARGET_NANOS2) && !defined(TARGET_NANOX) && !defined(TARGET_STAX)
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

zxerr_t blake_hash_cid(const unsigned char *in, unsigned int inLen,
                              unsigned char *out, unsigned int outLen) {

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

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen) {

    uint8_t tmp[BLAKE2B_256_SIZE];

    blake_hash(in, inLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, out, outLen);

    return 0;
}

zxerr_t keccak_digest(  const unsigned char *in, unsigned int inLen,
                    unsigned char *out, unsigned int outLen) {
    return zxerr_ok;
}

#endif
