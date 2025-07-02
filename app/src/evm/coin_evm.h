/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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

#define CLA_ETH 0xE0

#define HDPATH_ETH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_ETH_1_DEFAULT (0x80000000u | 0x3cu)

// transaction is sent as a blob of rlp encoded bytes,
#define P1_ETH_FIRST 0x00
#define P1_ETH_MORE 0x80
// eth address chain_code allowed valuec
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01

#define ETH_ADDR_LEN 20u
#define SELECTOR_LENGTH 4
#define BIGINT_LENGTH 32
#define DATA_BYTES_TO_PRINT 10

#define SECP256K1_PK_LEN 65u
#define SECP256K1_SK_LEN 64u
#define PK_LEN_SECP256K1_UNCOMPRESSED 65u
#define SK_LEN_25519 64u

#define INS_SIGN_ETH 0x04
#define INS_GET_ADDR_ETH 0x02
#define INS_SIGN_PERSONAL_MESSAGE 0x08

#define VIEW_ADDRESS_OFFSET_ETH (SECP256K1_PK_LEN + 1 + 1)

#define COIN_DECIMALS 18
#ifdef __cplusplus
}
#endif
