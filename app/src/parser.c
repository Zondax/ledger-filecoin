/*******************************************************************************
*   (c) 2019 ZondaX GmbH
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

#include <stdio.h>
#include <zxmacros.h>
#include "parser_impl.h"
#include "bignum.h"
#include "parser.h"
#include "parser_txdef.h"
#include "coin.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, uint16_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return _read(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    uint8_t numItems = parser_getNumItems(ctx);

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

uint8_t parser_getNumItems(const parser_context_t *ctx) {
    uint8_t itemCount = _getNumItems(ctx, &parser_tx_obj);
    return itemCount;
}

#define LESS_THAN_64_DIGIT(num_digit) if (num_digit > 64) return parser_value_out_of_range;

__Z_INLINE bool format_quantity(const bigint_t *b,
                                uint8_t *bcd, uint16_t bcdSize,
                                char *bignum, uint16_t bignumSize) {

    if (b->len < 2) {
        snprintf(bignum, bignumSize, "0");
        return true;
    }

    // first byte of b is the sign byte so we can remove this one
    bignumBigEndian_to_bcd(bcd, bcdSize, b->buffer + 1, b->len - 1);
    return bignumBigEndian_bcdprint(bignum, bignumSize, bcd, bcdSize);
}

__Z_INLINE parser_error_t parser_printBigInt(const bigint_t *b,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {

    LESS_THAN_64_DIGIT(b->len)

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(b, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    pageString(outVal, outValLen, bignum, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printBigIntFixedPoint(const bigint_t *b,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount) {

    LESS_THAN_64_DIGIT(b->len)

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(b, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, COIN_AMOUNT_DECIMAL_PLACES);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printAddress(const address_t *a,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {

    // the format :
    // network (1 byte) + protocol (1 byte) + base 32 [ payload (20 bytes or 48 bytes) + checksum (optional - 4bytes)]
    // Max we need 84 bytes to support BLS + 2 bytes
    char outBuffer[84 + 2];
    MEMZERO(outBuffer, sizeof(outBuffer));

    if (formatProtocol(a->buffer, a->len, (uint8_t *) outBuffer, sizeof(outBuffer)) == 0) {
        return parser_invalid_address;
    }

    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 0;

    if (displayIdx < 0 || displayIdx >= parser_getNumItems(ctx)) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "To");
        return parser_printAddress(&parser_tx_obj.to,
                                   outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From");
        return parser_printAddress(&parser_tx_obj.from,
                                   outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Nonce");
        if (uint64_to_str(outVal, outValLen, parser_tx_obj.nonce) != NULL) {
            return parser_unexepected_error;
        }
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Value");
        return parser_printBigIntFixedPoint(&parser_tx_obj.value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Gas Price");
        return parser_printBigIntFixedPoint(&parser_tx_obj.gasprice, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Gas Limit");
        return parser_printBigInt(&parser_tx_obj.gaslimit, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 6 && parser_tx_obj.method != method0) {
        snprintf(outKey, outKeyLen, "Method");
        snprintf(outVal, outValLen, "Unknown Method");
        return parser_ok;
    }

    if (displayIdx == 7) {
        snprintf(outKey, outKeyLen, "Params");
        return parser_ok;
    }

    return parser_ok;
}
