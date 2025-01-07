/*******************************************************************************
*  (c) 2018-2021 Zondax GmbH
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

#define CLA                             0x06
#define CLA_ETH                         0xE0

#include <stdint.h>
#include <stddef.h>

#define MAX_BIP32_PATH           10
#define HDPATH_LEN_DEFAULT       5

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x1cdu)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_ETH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_ETH_1_DEFAULT (0x80000000u | 0x3cu)

#define HDPATH_0_TESTNET     (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET     (0x80000000u | 0x1u)

#define SECP256K1_SK_LEN            64u
#define SECP256K1_PK_LEN            65u
#define ETH_ADDR_LEN                20u

typedef enum {
    addr_secp256k1 = 0,
} address_kind_e;

#define VIEW_ADDRESS_OFFSET_SECP256K1       (SECP256K1_PK_LEN + ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN + ADDRESS_PROTOCOL_LEN + 2)
// omit the pubkey + 1-byte pubkey len + 1-byte address len
#define VIEW_ADDRESS_OFFSET_ETH             (SECP256K1_PK_LEN + 1 + 1)

#define COIN_AMOUNT_DECIMAL_PLACES 18

#define COIN_SUPPORTED_TX_VERSION           0

// transaction is sent as a blob of rlp encoded bytes,
#define P1_ETH_FIRST                    0x00
#define P1_ETH_MORE                     0x80
// eth address chain_code allowed valuec
#define P2_NO_CHAINCODE                 0x00
#define P2_CHAINCODE                    0x01

#define INS_GET_VERSION                 0x00
#define INS_GET_ADDR_SECP256K1          0x01
#define INS_SIGN_SECP256K1              0x02
#define INS_SIGN_ETH                    0x04
#define INS_CLIENT_DEAL                 0x06
#define INS_SIGN_RAW_BYTES              0x07
#define INS_GET_ADDR_ETH                0x02

#define MENU_MAIN_APP_LINE1 "Filecoin"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET          "???"
#define APPVERSION_LINE1 "Version"
#define APPVERSION_LINE2 "v" APPVERSION

#ifdef __cplusplus
}
#endif
