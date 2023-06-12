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

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <zxmacros.h>
#include "common/parser_common.h"
#include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor.h"
#include "app_mode.h"
#include "zxformat.h"
#include "crypto.h"
#include "fil_utils.h"
#include "coin.h"
#include "parser_client_deal.h"

#define MIN_DEAL_DURATION 518400

__Z_INLINE parser_error_t _readLabel(deal_label_t *label, CborValue *value) {
    CborType tpy = cbor_value_get_type(value);

    PARSER_ASSERT_OR_ERROR(( tpy == CborTextStringType ) || ( tpy == CborByteStringType ), parser_unexpected_type)

    // omit NULL
    size_t stlen = sizeof(label->data) - 1;

    switch (tpy) {
        case CborTextStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_text_string(value, (char *) label->data, &stlen, NULL))
            label->is_string = true;
            label->len = stlen;
            return parser_ok;
        }
        case CborByteStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, (uint8_t *) label->data, &stlen, NULL))
            label->is_string = false;
            label->len = stlen;
            return parser_ok;
        }
        default:
            return parser_unexpected_type;
    }
}

parser_error_t _readClientDeal(const parser_context_t *ctx, client_deal_t *tx) {
    CborValue it;
    INIT_CBOR_PARSER(ctx, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

    // It is an array
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(&it), parser_unexpected_type)
    size_t arraySize;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &arraySize))

    PARSER_ASSERT_OR_ERROR(arraySize == 11, parser_unexpected_number_items)

    CborValue arrayContainer;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &arrayContainer))

    // "cid" field
    CHECK_PARSER_ERR(parse_cid(&tx->cid, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // piece_size
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_raw_integer(&arrayContainer, &tx->piece_size))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "verified_deal" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_boolean(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_boolean(&arrayContainer, (bool *)&tx->verified_deal))
    CHECK_CBOR_MAP_ERR(cbor_value_advance_fixed(&arrayContainer))

    // "client" field
    CHECK_PARSER_ERR(readAddress(&tx->client, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "provider" field
    CHECK_PARSER_ERR(readAddress(&tx->provider, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    CHECK_PARSER_ERR(_readLabel(&tx->label, &arrayContainer))
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "start_epoch" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, &tx->start_epoch))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "end_epoch" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, &tx->end_epoch))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // lotus Docs defines that the minimal duration is 518400 blocks(~6 months)
    // so we add that check here. this might be subject to changes.
    if (tx->end_epoch < tx->start_epoch)
        return parser_unexpected_value;

    int64_t duration = tx->end_epoch - tx->start_epoch;
    if (duration < MIN_DEAL_DURATION)
        return parser_invalid_deal_duration;

    // "storage_price" field
    CHECK_PARSER_ERR(readBigInt(&tx->storage_price_x_epoch, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "provider_collateral" field
    CHECK_PARSER_ERR(readBigInt(&tx->provider_collateral, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "client_collateral" field
    CHECK_PARSER_ERR(readBigInt(&tx->client_collateral, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &arrayContainer))

    // End of buffer does not match end of parsed data
    PARSER_ASSERT_OR_ERROR(it.ptr == ctx->buffer + ctx->bufferLen, parser_cbor_unexpected_EOF)

    return parser_ok;
}

parser_error_t _validateClientDeal(__Z_UNUSED const parser_context_t *c) {
    return parser_ok;
}

uint8_t _getNumItemsClientDeal(__Z_UNUSED const parser_context_t *c) {

    // cid, client, provider, duration(end - start), price_x_epoch, verified_deal
    uint8_t itemCount = 4;

    if (app_mode_expert()){
        // all fields except storage_price
        itemCount = 10;
    }
    return itemCount;
}

__Z_INLINE parser_error_t render_label(
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    snprintf(outKey, outKeyLen, "DealLabel");

    bool is_string = parser_tx_obj.client_deal_tx.label.is_string;
    uint8_t *data = parser_tx_obj.client_deal_tx.label.data;
    uint16_t len = parser_tx_obj.client_deal_tx.label.len;

    if (is_string) {
        pageString(outVal, outValLen, (char *)data, pageIdx, pageCount);
        return parser_ok;
    }

    return renderByteString(data, len, outVal, outValLen, pageIdx, pageCount);
}

__Z_INLINE parser_error_t render_integer(int64_t value,
                              char *outVal, uint16_t outValLen,
                              uint8_t *pageCount) {

    if (int64_to_str(outVal, outValLen, value) != NULL) {
        return parser_unexepected_error;
    }
    *pageCount = 1;
    return parser_ok;

}

parser_error_t _getItemClientDeal(__Z_UNUSED const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");

    CHECK_APP_CANARY()

    const bool expert_mode = app_mode_expert();

    // Remapping displayIdx to simplify switch-case logic
    // VerifiedDeal should be placed at the 10th position for Expert mode
    if (expert_mode) {
        if (displayIdx == 3) {
            displayIdx = 9;
        } else if (displayIdx == 9) {
            displayIdx = 3;
        }
    }

    // Normal mode: 4 fields  [PieceCID | Client | Provider | VerifiedDeal]
    // Expert mode: 10 fields [PieceCID | Client | Provider | PieceSize(B) | DealLabel | StartEpoch | EndEpoch | ProvCollateral | ClientCollateral | VerifiedDeal]
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "PieceCID ");
            return printCid(&( parser_tx_obj.client_deal_tx.cid ), outVal, outValLen, pageIdx, pageCount);

        case 1:
            snprintf(outKey, outKeyLen, "Client ");
            return printAddress(&parser_tx_obj.client_deal_tx.client,
                                outVal, outValLen, pageIdx, pageCount);

        case 2:
            snprintf(outKey, outKeyLen, "Provider ");
            return printAddress(&parser_tx_obj.client_deal_tx.provider,
                                outVal, outValLen, pageIdx, pageCount);

        case 3:
            snprintf(outKey, outKeyLen, "VerifiedDeal ");
            if (parser_tx_obj.client_deal_tx.verified_deal > 0) {
                snprintf(outVal, outValLen, "true");
            } else {
                snprintf(outVal, outValLen, "false");
            }
            *pageCount = 1;
            return parser_ok;

        case 4:
            return render_label(outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case 5:
            snprintf(outKey, outKeyLen, "StartEpoch");
            return render_integer(parser_tx_obj.client_deal_tx.start_epoch, outVal, outValLen, pageCount);

        case 6:
            snprintf(outKey, outKeyLen, "EndEpoch");
            return render_integer(parser_tx_obj.client_deal_tx.end_epoch,  outVal, outValLen, pageCount);

        case 7:
            snprintf(outKey, outKeyLen, "ProvCollateral");
            return parser_printBigIntFixedPoint(&parser_tx_obj.client_deal_tx.provider_collateral, outVal, outValLen, pageIdx, pageCount, COIN_AMOUNT_DECIMAL_PLACES);

        case 8:
            snprintf(outKey, outKeyLen, "ClientCollateral");
            return parser_printBigIntFixedPoint(&parser_tx_obj.client_deal_tx.client_collateral, outVal, outValLen, pageIdx, pageCount, COIN_AMOUNT_DECIMAL_PLACES);

        case 9:
            snprintf(outKey, outKeyLen, "PieceSize(B)");
            return render_integer(parser_tx_obj.client_deal_tx.piece_size, outVal, outValLen, pageCount);

        default:
            break;
    }

    return parser_no_data;
}
