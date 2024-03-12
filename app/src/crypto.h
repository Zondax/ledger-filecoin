/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include <stdbool.h>
#include <sigutils.h>
#include <zxerror.h>
#include "crypto_helper.h"

bool isTestnet();

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

zxerr_t blake_hash_cid(const unsigned char *in, unsigned int inLen,
                              unsigned char *out, unsigned int outLen);

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
#else
#include "blake2.h"
typedef struct {
    blake2b_state state;
} cx_blake2b_t;

#endif

zxerr_t blake_hash_setup(cx_blake2b_t *hasher);

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);
zxerr_t crypto_fillEthAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize);

zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize);

zxerr_t crypto_sign_raw_bytes(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *digest, uint16_t messageLen, uint16_t *sigSize);

#ifdef __cplusplus
}
#endif
