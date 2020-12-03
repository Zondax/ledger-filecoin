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

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return _read(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    return parser_ok;
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

parser_error_t parser_printParam(const parser_tx_t *tx, uint8_t paramIdx, char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    return _printParam(tx, paramIdx, outVal, outValLen, pageIdx, pageCount);
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
    // Max we need 84 bytes to support BLS + 16 bytes padding
    char outBuffer[84 + 16];
    MEMZERO(outBuffer, sizeof(outBuffer));

    if (formatProtocol(a->buffer, a->len, (uint8_t *) outBuffer, sizeof(outBuffer)) == 0) {
        return parser_invalid_address;
    }

    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 0;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx < 0 || displayIdx >= numItems) {
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
        snprintf(outKey, outKeyLen, "Gas Limit");
        if (int64_to_str(outVal, outValLen, parser_tx_obj.gaslimit) != NULL) {
            return parser_unexepected_error;
        }
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Gas Premium");
        return parser_printBigIntFixedPoint(&parser_tx_obj.gaspremium, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 6) {
        snprintf(outKey, outKeyLen, "Gas Fee Cap");
        return parser_printBigIntFixedPoint(&parser_tx_obj.gasfeecap, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 7) {
        snprintf(outKey, outKeyLen, "Method");
        *pageCount = 1;
        switch(parser_tx_obj.method) {
            case method0:
                snprintf(outVal, outValLen, "Transfer");
                return parser_ok;
            case method1:
                snprintf(outVal, outValLen, "1");
                return parser_ok;
            case method2:
                snprintf(outVal, outValLen, "2");
                return parser_ok;
            case method3:
                snprintf(outVal, outValLen, "3");
                return parser_ok;
            case method4:
                snprintf(outVal, outValLen, "4");
                return parser_ok;
            case method5:
                snprintf(outVal, outValLen, "5");
                return parser_ok;
            case method6:
                snprintf(outVal, outValLen, "6");
                return parser_ok;
            case method7:
                snprintf(outVal, outValLen, "7");
                return parser_ok;
            case method8:
                snprintf(outVal, outValLen, "8");
                return parser_ok;
            case method9:
                snprintf(outVal, outValLen, "9");
                return parser_ok;
            case method10:
                snprintf(outVal, outValLen, "10");
                return parser_ok;
            case method11:
                snprintf(outVal, outValLen, "11");
                return parser_ok;
            case method12:
                snprintf(outVal, outValLen, "12");
                return parser_ok;
            case method13:
                snprintf(outVal, outValLen, "13");
                return parser_ok;
            case method14:
                snprintf(outVal, outValLen, "14");
                return parser_ok;
            case method15:
                snprintf(outVal, outValLen, "15");
                return parser_ok;
            case method16:
                snprintf(outVal, outValLen, "16");
                return parser_ok;
            case method17:
                snprintf(outVal, outValLen, "17");
                return parser_ok;
            case method18:
                snprintf(outVal, outValLen, "18");
                return parser_ok;
            case method19:
                snprintf(outVal, outValLen, "19");
                return parser_ok;
            case method20:
                snprintf(outVal, outValLen, "20");
                return parser_ok;
            case method21:
                snprintf(outVal, outValLen, "21");
                return parser_ok;
            case method22:
                snprintf(outVal, outValLen, "22");
                return parser_ok;
            case method23:
                snprintf(outVal, outValLen, "23");
                return parser_ok;
        }
        return parser_unexpected_method;
    }

    if (parser_tx_obj.numparams == 0) {
        snprintf(outKey, outKeyLen, "Params");
        snprintf(outVal, outValLen, "-");
        return parser_ok;
    }

    // remaining display pages show the params
    int32_t paramIdxSigned = displayIdx - 8;

    // end of params
    if (paramIdxSigned < 0 || paramIdxSigned >= parser_tx_obj.numparams) {
        return parser_ok;
    }

    uint8_t paramIdx = (uint8_t)paramIdxSigned;
    *pageCount = 1;
    snprintf(outKey, outKeyLen, "Params - %d", paramIdx + 1);
    return parser_printParam(&parser_tx_obj, paramIdx, outVal, outValLen, pageIdx, pageCount);
}
