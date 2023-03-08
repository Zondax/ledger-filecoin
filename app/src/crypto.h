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
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include <zxerror.h>

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[MAX_BIP32_PATH];
extern uint32_t hdPath_len;

#define ADDRESS_PROTOCOL_LEN        1

#define BLAKE2B_256_SIZE            32
#define KECCAK_256_SIZE             32

#define PREFIX {0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20}

#define ADDRESS_PROTOCOL_ID         0x00
#define ADDRESS_PROTOCOL_SECP256K1  0x01
#define ADDRESS_PROTOCOL_ACTOR      0x02
#define ADDRESS_PROTOCOL_BLS        0x03
#define ADDRESS_PROTOCOL_DELEGATED  0x04

#define ADDRESS_PROTOCOL_ID_PAYLOAD_LEN         0x00
#define ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN  20
#define ADDRESS_PROTOCOL_ACTOR_PAYLOAD_LEN      20
#define ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN        48
#define ADDRESS_PROTOCOL_DELEGATED_MAX_SUBADDRESS_LEN  54

uint16_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v);

uint16_t formatProtocol(const uint8_t *addressBytes, uint16_t addressSize,
                        uint8_t *formattedAddress,
                        uint16_t formattedAddressSize);

bool isTestnet();

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

int keccak_digest(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

zxerr_t crypto_extractPublicKey(const uint32_t path[MAX_BIP32_PATH], uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen,
                    uint16_t *sigSize);

zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize);

#ifdef __cplusplus
}
#endif
