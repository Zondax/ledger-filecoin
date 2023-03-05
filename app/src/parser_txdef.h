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

#define MAX_SUPPORT_METHOD      50
#define MAX_PARAMS_BUFFER_SIZE  200
#define ETH_ADDRESS_LEN         20
#define MAX_CHAIN_LEN           UINT64_MAX


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
    uint8_t params[MAX_PARAMS_BUFFER_SIZE];
} parser_tx_t;

// simple struct that holds a bigint(256) 
typedef struct {
    uint8_t *num;
    // although bigInts are defined in 
    // ethereum as 256 bits,
    // it is possible that it is smaller.
    uint32_t len;
} eth_big_int_t;

// chain_id
typedef struct {
    uint8_t *chain;
    uint32_t len;
} chain_id_t;

// // ripemd160(sha256(compress(secp256k1.publicKey()))
// #[derive(Clone, Copy, PartialEq, Eq)]
// #[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
// pub struct Address<'b>(&'b [u8; ADDRESS_LEN]);
typedef struct {
    uint8_t addr[ETH_ADDRESS_LEN];
} eth_addr_t;

// Type that holds the common fields 
// for legacy and eip2930 transactions
typedef struct {
    eth_big_int_t nonce;
    eth_big_int_t gas_price;
    eth_big_int_t gas_limit;
    eth_addr_t address;
    eth_big_int_t value;
    uint8_t *data;
    uint32_t dataLen;
} eth_base_t;

typedef struct {
    eth_base_t base_fields;
    uint8_t *r;
    uint32_t r_len;
    uint8_t *s;
    uint32_t s_len;
} legacy_tx_t;

// EIP 2718 TransactionType
// Valid transaction types should be in [0x00, 0x7f]
typedef enum eth_tx_type_t {
  eip2930 = 0x01,
  eip1559 = 0x02,
  // Legacy tx type is greater than or equal to 0xc0.
  legacy = 0xc0
} eth_tx_type_t;

typedef struct {
    eth_tx_type_t tx_type;
    chain_id_t chain_id;
    // lets use an anonymous 
    // union to hold the 3 possible types of transactions:
    // legacy, eip2930, eip1559
    union {
        legacy_tx_t legacy;
    };
 
} eth_tx_t;


#ifdef __cplusplus
}
#endif
