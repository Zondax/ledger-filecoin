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
#include "zxformat.h"

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
    zemu_log("parser_validate\n");
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    zemu_log("parser_validate::validated\n");

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char log_tmp[100];
    snprintf(log_tmp, sizeof(log_tmp), "parser_validate %d\n", numItems);
    zemu_log(log_tmp);

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    zemu_log("parser_validate::ok\n");
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    zemu_log("parser_getNumItems\n");
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

parser_error_t parser_printParam(const parser_tx_t *tx, uint8_t paramIdx,
                                 char *outVal, uint16_t outValLen,
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

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    char log_tmp[100];
    snprintf(log_tmp, sizeof(log_tmp), "getItem %d\n", displayIdx);
    zemu_log(log_tmp);
    uint8_t expert_mode = app_mode_expert();

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
        snprintf(outKey, outKeyLen, "To ");
        return _printAddress(&parser_tx_obj.to,
                             outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From ");
        return _printAddress(&parser_tx_obj.from,
                             outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Value ");
        return parser_printBigIntFixedPoint(&parser_tx_obj.value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Gas Limit ");
        if (int64_to_str(outVal, outValLen, parser_tx_obj.gaslimit) != NULL) {
            return parser_unexepected_error;
        }
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Gas Fee Cap ");
        return parser_printBigIntFixedPoint(&parser_tx_obj.gasfeecap, outVal, outValLen, pageIdx, pageCount);
    }

    if (expert_mode){
        if (displayIdx == 5) {
            snprintf(outKey, outKeyLen, "Gas Premium ");
            return parser_printBigIntFixedPoint(&parser_tx_obj.gaspremium, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 6) {
            snprintf(outKey, outKeyLen, "Nonce ");
            if (uint64_to_str(outVal, outValLen, parser_tx_obj.nonce) != NULL) {
                return parser_unexepected_error;
            }
            *pageCount = 1;
            return parser_ok;
        }
    }

    if ((displayIdx == 5 && !expert_mode) || (displayIdx == 7 && expert_mode)) {
        snprintf(outKey, outKeyLen, "Method ");
        *pageCount = 1;

        CHECK_PARSER_ERR(checkMethod(parser_tx_obj.method));
        if (parser_tx_obj.method == 0) {
            snprintf(outVal, outValLen, "Transfer ");
            return parser_ok;
        } else {
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            fpuint64_to_str(buffer, sizeof(buffer), parser_tx_obj.method, 0);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return parser_ok;
        }
    }

    if (parser_tx_obj.numparams == 0) {
        snprintf(outKey, outKeyLen, "Params ");
        snprintf(outVal, outValLen, "- NONE -");
        return parser_ok;
    }

    // remaining display pages show the params
    int32_t paramIdxSigned = displayIdx - (numItems - parser_tx_obj.numparams);

    // end of params
    if (paramIdxSigned < 0 || paramIdxSigned >= parser_tx_obj.numparams) {
        return parser_unexpected_field;
    }

    uint8_t paramIdx = (uint8_t) paramIdxSigned;
    *pageCount = 1;
    snprintf(outKey, outKeyLen, "Params |%d| ", paramIdx + 1);

    zemu_log_stack(outKey);
    return parser_printParam(&parser_tx_obj, paramIdx, outVal, outValLen, pageIdx, pageCount);
}
