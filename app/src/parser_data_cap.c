/*******************************************************************************
*  (c) 2023 Zondax AG
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

#include <string.h>
#include <zxmacros.h>
#include "common/parser_common.h"
// #include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor.h"
#include "app_mode.h"
#include "zxformat.h"
#include "crypto.h"
#include "fil_utils.h"
#include "coin.h"
#include "parser_data_cap.h"


#define MB_DECIMAL_PLACES 6

parser_error_t _readDataCap(const parser_context_t *ctx, remove_datacap_t *tx) {
    CborValue it;
    INIT_CBOR_PARSER(ctx, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

    // It is an array
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(&it), parser_unexpected_type)
    size_t arraySize;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &arraySize))

    // We expect [verifier_addr, client_addr, number]
    // We expect [proposal_id, allowance/amount,  client_addr]
    PARSER_ASSERT_OR_ERROR(arraySize == 3, parser_unexpected_number_items)

    CborValue arrayContainer;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &arrayContainer))

    // "verifier" field
    // CHECK_PARSER_ERR(readAddress(&tx->verifier, &arrayContainer))
    // PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    // CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // Assert we are listed as a verifier in this tx
    // PARSER_ASSERT_OR_ERROR(check_verifier(&tx->verifier) == true, parser_wrong_verifier)

    // proposal_id
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, (int64_t *)&tx->proposal_id))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "amount" field
    CHECK_PARSER_ERR(readBigInt(&tx->amount, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "client" field
    CHECK_PARSER_ERR(readAddress(&tx->client, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &arrayContainer))

    // End of buffer does not match end of parsed data
    PARSER_ASSERT_OR_ERROR(it.ptr == ctx->buffer + ctx->bufferLen, parser_cbor_unexpected_EOF)

    return parser_ok;
}

parser_error_t _validateDataCap(__Z_UNUSED const parser_context_t *c) {
    // Note: This is place holder for transaction level checks that the project may require before accepting
    // the parsed values. the parser already validates input
    // This function is called by parser_validate, where additional checks are made (formatting, UI/UX, etc.(
    return parser_ok;
}

uint8_t _getNumItemsDataCap(__Z_UNUSED const parser_context_t *c) {
    // from address(the signer)
    // client
    // allowance to be removed
    return 3;
}

parser_error_t _getItemDataCap(__Z_UNUSED const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");

    CHECK_APP_CANARY()

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "ProposalID");
        if (int64_to_str(outVal, outValLen, (int64_t)parser_tx_obj.rem_datacap_tx.proposal_id) != NULL) {
            return parser_unexepected_error;
        }
        *pageCount = 1;
        return parser_ok;

    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Client ");
        return printAddress(&parser_tx_obj.rem_datacap_tx.client,
                             outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "allowanceToRem(MB) ");
        return parser_printBigIntFixedPoint(&parser_tx_obj.rem_datacap_tx.amount, outVal, outValLen, pageIdx, pageCount, MB_DECIMAL_PLACES);
    }

    return parser_no_data;
}
