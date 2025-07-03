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

#include "parser_evm.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "evm_utils.h"
#include "parser.h"
#include "parser_common.h"
#include "parser_impl_evm.h"

parser_error_t parser_parse_eth(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init_context(ctx, data, dataLen))
    return _readEth(ctx, &eth_tx_obj);
}

parser_error_t parser_validate_eth(parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTxEth())

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(_getNumItemsEth(&numItems));

    char tmpKey[40] = {0};
    char tmpVal[40] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItemEth(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItemsEth(const parser_context_t *ctx, uint8_t *num_items) {
    UNUSED(ctx);
    CHECK_PARSER_ERR(_getNumItemsEth(num_items));
    if (*num_items == 0) {
        return parser_unexpected_buffer_end;
    }
    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItemEth(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                 char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItemsEth(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_PARSER_ERR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    return _getItemEth(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_compute_eth_v(parser_context_t *ctx, unsigned int info, uint8_t *v, bool is_personal_message) {
    UNUSED(is_personal_message);
    return _computeV(ctx, &eth_tx_obj, info, v);
}
