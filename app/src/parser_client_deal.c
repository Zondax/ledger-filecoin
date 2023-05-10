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

__Z_INLINE parser_error_t _readCid(cid_t *cid, CborValue *value) {

    // according to docs, cid is a string
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType)

    // omit null
    size_t cid_len = sizeof(cid->str) - 1;
    MEMZERO(cid->str, cid_len);

    CHECK_CBOR_MAP_ERR(cbor_value_copy_text_string(value, cid->str, &cid_len, NULL))

    cid->len = cid_len;

    return parser_ok;
}

__Z_INLINE parser_error_t _readLabel(deal_label_t *label, CborValue *value) {
    CborValue container;
    // Label is an array {data, is_string}
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(value), parser_unexpected_type)

    size_t arraySize;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(value, &arraySize))

    PARSER_ASSERT_OR_ERROR(arraySize == 2, parser_unexpected_number_items)

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(value, &container))


    // do not include null
    size_t stlen = sizeof(label->data) - 1;
    MEMZERO(label->data, stlen);
    CborValue dummy;

    CborType bs_type = cbor_value_get_type(&container);
    switch ( bs_type ) {
        case CborTextStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_text_string(&container, (char *) label->data, &stlen, &dummy))
            break;
        }
        case CborByteStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(&container, (uint8_t *) label->data, &stlen, &dummy))
            break;
        }
        default:{
            return parser_unexpected_type;
        }
    }
    label->len = stlen;
    PARSER_ASSERT_OR_ERROR(container.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&container))

    // now parse the is_string boolean flag
    PARSER_ASSERT_OR_ERROR(cbor_value_is_boolean(&container), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_boolean(&container, (bool *)&label->is_string))
    CHECK_CBOR_MAP_ERR(cbor_value_advance_fixed(&container))

    if ( ( bs_type == CborTextStringType && !label->is_string) || ( bs_type == CborByteStringType && label->is_string))
        return parser_unexpected_type;

    // leave this inner container
    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(value, &container))

    return parser_ok;
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
    CHECK_PARSER_ERR(_readCid(&tx->cid, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // piece_size
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, &tx->piece_size))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "client" field
    CHECK_PARSER_ERR(readAddress(&tx->client, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "provider" field
    CHECK_PARSER_ERR(readAddress(&tx->provider, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "Deal label" field
    // make a copy to parse inner array that contains our
    // deal label.
    CborValue label = arrayContainer;
    CHECK_PARSER_ERR(_readLabel(&tx->label, &label))
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

    // "verified_deal" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_boolean(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_boolean(&arrayContainer, (bool *)&tx->verified_deal))
    CHECK_CBOR_MAP_ERR(cbor_value_advance_fixed(&arrayContainer))

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

    snprintf(outKey, outKeyLen, "dealLabel");

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

    uint8_t expert_mode = app_mode_expert();

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "pieceCID ");
        pageString(outVal, outValLen, parser_tx_obj.client_deal_tx.cid.str, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Client ");
        return printAddress(&parser_tx_obj.client_deal_tx.client,
                             outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Provider ");
        return printAddress(&parser_tx_obj.client_deal_tx.provider,
                             outVal, outValLen, pageIdx, pageCount);
    }

    if (( displayIdx == 3 && !expert_mode ) || ( displayIdx == 9 && expert_mode )) {
        snprintf(outKey, outKeyLen, "VerifiedDeal ");

        if (parser_tx_obj.client_deal_tx.verified_deal > 0) {
            snprintf(outVal, outValLen, "True");
        } else {
            snprintf(outVal, outValLen, "False");
        }

        *pageCount = 1;

        return parser_ok;
    }

    if (displayIdx == 3 && expert_mode) {
        snprintf(outKey, outKeyLen, "pieceSize(B)");
        return render_integer(parser_tx_obj.client_deal_tx.piece_size, outVal, outValLen, pageCount);
    }

    if (expert_mode) {
        if (displayIdx == 4) {
            return render_label(outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 5) {
            snprintf(outKey, outKeyLen, "startEpoch");
            return render_integer(parser_tx_obj.client_deal_tx.start_epoch, outVal, outValLen, pageCount);
        }

        if (displayIdx == 6) {
            snprintf(outKey, outKeyLen, "endEpoch");
            return render_integer(parser_tx_obj.client_deal_tx.end_epoch,  outVal, outValLen, pageCount);
        }

        if (displayIdx == 7) {
            snprintf(outKey, outKeyLen, "ProvCollateral");
            return parser_printBigIntFixedPoint(&parser_tx_obj.client_deal_tx.provider_collateral, outVal, outValLen, pageIdx, pageCount, COIN_AMOUNT_DECIMAL_PLACES);
        }

        if (displayIdx == 8) {
            snprintf(outKey, outKeyLen, "ClientCollateral");
            return parser_printBigIntFixedPoint(&parser_tx_obj.client_deal_tx.client_collateral, outVal, outValLen, pageIdx, pageCount, COIN_AMOUNT_DECIMAL_PLACES);
        }
    }

    return parser_no_data;
}
