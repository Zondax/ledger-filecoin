/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#define CBOR_PARSER_MAX_RECURSIONS 4

#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef enum {
    method0 = 0,
    method1 = 1,
    method2 = 2,
    method3 = 3,
    method4 = 4,
    method5 = 5,
    method6 = 6,
    method7 = 7,
    method8 = 8,
    method9 = 9,
    method10 = 10,
    method11 = 11,
    method12 = 12,
    method13 = 13,
    method14 = 14,
    method15 = 15,
    method16 = 16,
    method17 = 17,
    method18 = 18,
    method19 = 19,
    method20 = 20,
    method21 = 21,
    method22 = 22,
    method23 = 23
} method_e;

// https://github.com/filecoin-project/lotus/blob/65c669b0f2dfd8c28b96755e198b9cdaf0880df8/chain/address/address.go#L36
// https://github.com/filecoin-project/lotus/blob/65c669b0f2dfd8c28b96755e198b9cdaf0880df8/chain/address/address.go#L371-L373
// Should not be more than 64 bytes
typedef struct {
    uint8_t buffer[64];
    size_t len;
} address_t;

// https://github.com/filecoin-project/lotus/blob/3fda442bb3372c9055ec0e237c70dd30143b65d8/chain/types/bigint.go#L238-L240
typedef struct {
    // https://github.com/filecoin-project/lotus/blob/3fda442bb3372c9055ec0e237c70dd30143b65d8/chain/types/bigint.go#L17
    uint8_t buffer[129];
    size_t len;
} bigint_t;

// https://github.com/filecoin-project/lotus/blob/eb4f4675a5a765e4898ec6b005ba2e80da8e7e1a/chain/types/message.go#L24-L39
typedef struct {
    int64_t version;
    address_t to;
    address_t from;
    uint64_t nonce;
    bigint_t value;
    int64_t gaslimit;
    bigint_t gaspremium;
    bigint_t gasfeecap;
    uint64_t method;

    uint8_t numparams;
    uint8_t params[200];
} parser_tx_t;

#ifdef __cplusplus
}
#endif
