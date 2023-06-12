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

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include "common/parser_common.h"
#include "cbor.h"
#include "bignum.h"
#include "zxformat.h"
#include "crypto.h"
#include "parser_txdef.h"

#define STR_BUF_LEN 200
// special CBOR type that holds
// a CID, bellow the custom tag for this type
#define TAG_CID      42
// https://ipld.io/docs/codecs/known/dag-cbor/
#define DAG_CBOR     0x71
// https://github.com/filecoin-project/go-state-types/blob/master/abi/cid.go#L45-L49
#define CID_CODEC    DAG_CBOR
#define CID_VERSION  0x01
#define CID_BASE     0x00

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

#define CHECK_CBOR_MAP_ERR(CALL) { \
    CborError err = CALL;  \
    if (err!=CborNoError) return parser_mapCborError(err);}

#define CHECK_CBOR_TYPE(type, expected) {if ((type)!=(expected)) return parser_unexpected_type;}

#define INIT_CBOR_PARSER(c, it)  \
    CborParser parser;           \
    CHECK_CBOR_MAP_ERR(cbor_parser_init((c)->buffer + (c)->offset, (c)->bufferLen - (c)->offset, 0, &parser, &(it)))

#define LESS_THAN_64_DIGIT(num_digit) if (num_digit > 64) return parser_value_out_of_range;

// common functions

parser_error_t parser_mapCborError(CborError err);

parser_error_t readAddress(address_t *address, CborValue *value);

parser_error_t printAddress(const address_t *a,char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount);

parser_error_t printCid(cid_t *cid, char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount);

parser_error_t readBigInt(bigint_t *bigint, CborValue *value);

parser_error_t parser_printBigIntFixedPoint(const bigint_t *b,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount, uint16_t decimal_place);

bool format_quantity(const bigint_t *b,
                                uint8_t *bcd, uint16_t bcdSize,
                                char *bignum, uint16_t bignumSize);

parser_error_t renderByteString(uint8_t *in, uint16_t inLen,
                          char *outVal, uint16_t outValLen,
                          uint8_t pageIdx, uint8_t *pageCount);

parser_error_t parse_cid(cid_t *cid, CborValue *value);


#ifdef __cplusplus
}
#endif
