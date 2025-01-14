/*******************************************************************************
*  (c) 2018 - 2023 Zondax AG
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

#include "crypto.h"
#define CBOR_PARSER_MAX_RECURSIONS 4

#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include "rlp.h"

#define MAX_SUPPORT_METHOD      UINT64_MAX

#if defined(TARGET_NANOS)
#define MAX_PARAMS_BUFFER_SIZE 200
#else
#define MAX_PARAMS_BUFFER_SIZE 1256
#endif

#define ETH_ADDRESS_LEN         20
#define MAX_CHAIN_LEN           UINT64_MAX

// https://github.com/filecoin-project/go-state-types/blob/master/builtin/v9/market/policy.go#L30
#define MAX_DEAL_LABEL_SIZE     256

// This limit is not part of lotus but our restriction
#define MAX_CID_LEN             200


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

// https://github.com/filecoin-project/go-state-types/blob/master/builtin/v9/market/deal.go#L40
typedef struct {
    // add 1-byte for the null terminated string
    uint8_t data[MAX_DEAL_LABEL_SIZE + 1];
    size_t len;
    uint8_t is_string;
} deal_label_t;

// https://github.com/ipfs/go-cid/blob/master/cid.go#L173
typedef struct {
    // plus null
    uint8_t str[MAX_CID_LEN + 1];
    size_t len;
} cid_t;

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
    uint8_t params[MAX_PARAMS_BUFFER_SIZE];
    size_t params_len;
} fil_base_tx_t;

typedef struct {
    cx_blake2b_t ctx_blake2b;
    uint8_t digest[BLAKE2B_256_SIZE];
    size_t total;
    size_t current;
} raw_bytes_state_t;

typedef struct {
    union {
        fil_base_tx_t base_tx;
        raw_bytes_state_t raw_bytes_tx;
    };
} parser_tx_t;

// simple struct that holds a bigint(256)
typedef struct {
    uint32_t offset;
    // although bigInts are defined in
    // ethereum as 256 bits,
    // it is possible that it is smaller.
    uint32_t len;
} eth_big_int_t;

// chain_id
typedef struct {
    uint32_t offset;
    uint32_t len;
} chain_id_t;

// ripemd160(sha256(compress(secp256k1.publicKey()))
typedef struct {
    uint8_t addr[ETH_ADDRESS_LEN];
} eth_addr_t;

// Type that holds the common fields
// for legacy and eip2930 transactions
typedef struct {
    rlp_t nonce;
    rlp_t gasPrice;
    rlp_t gasLimit;
    rlp_t to;
    rlp_t value;
    rlp_t data;
} eth_base_t;

// EIP 2718 TransactionType
// Valid transaction types should be in [0x00, 0x7f]
typedef enum {
  eip2930 = 0x01,
  eip1559 = 0x02,
  // Legacy tx type is greater than or equal to 0xc0.
  legacy = 0xc0
} eth_tx_type_e;

typedef struct {
    eth_tx_type_e tx_type;
    rlp_t chainId;
    // lets use an anonymous
    // union to hold the 3 possible types of transactions:
    // legacy, eip2930, eip1559
    union {
        eth_base_t legacy;
    };

} eth_tx_t;

#ifdef __cplusplus
}
#endif
