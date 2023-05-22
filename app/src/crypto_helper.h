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
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <zxerror.h>
#include "coin.h"

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[MAX_BIP32_PATH];
extern uint32_t hdPath_len;
extern uint8_t chain_code;

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

zxerr_t blake_hash_init();
zxerr_t blake_hash_update(const uint8_t *in, uint16_t inLen);
zxerr_t blake_hash_finish(uint8_t *out, uint16_t outLen);
zxerr_t blake_hash(const uint8_t *in, uint16_t inLen, uint8_t *out, uint16_t outLen);

uint16_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v);

uint16_t formatProtocol(const uint8_t *addressBytes, uint16_t addressSize,
                        uint8_t *formattedAddress,
                        uint16_t formattedAddressSize);

#ifdef __cplusplus
}
#endif
