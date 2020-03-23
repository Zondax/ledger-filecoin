/*******************************************************************************
*  (c) 2019 ZondaX GmbH
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

#include <zxmacros.h>
#include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor_helper.h"

parser_tx_t parser_tx_obj;

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    parser_error_t err = parser_init_context(ctx, buffer, bufferSize);
    if (err != parser_ok)
        return err;

    return err;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexepected_error:
            return "Unexepected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        default:
            return "Unrecognized error code";
    }
}

__Z_INLINE parser_error_t _readAddress(address_t *address, CborValue *value) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    MEMZERO(address, sizeof(address_t));
    address->len = sizeof_field(address_t , buffer);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) address->buffer, &address->len, &dummy))

    if (address->len < 2) {
        // Addresses are at least 2 characters Protocol + random data
        return parser_invalid_address;
    }

    // Verify size and protocol
    switch (address->buffer[0]) {
        case ADDRESS_PROTOCOL_ID:
            // protocol 0
            if (address->len - 1 > 20 ) {
                return parser_invalid_address;
            }
            break;
        case ADDRESS_PROTOCOL_SECP256K1:
            // protocol 1
            if (address->len - 1 != ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN) {
                return parser_invalid_address;
            }
            break;
        case ADDRESS_PROTOCOL_ACTOR:
            // protocol 2
            if (address->len - 1 != ADDRESS_PROTOCOL_ACTOR_PAYLOAD_LEN) {
                return parser_invalid_address;
            }
            break;
        case ADDRESS_PROTOCOL_BLS:
            // protocol 3
            if (address->len -1 != ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN) {
                return parser_invalid_address;
            }
            break;
        default:
            return parser_invalid_address;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readBigInt(bigint_t *bigint, CborValue *value) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    MEMZERO(bigint, sizeof(address_t));
    bigint->len = sizeof_field(bigint_t , buffer);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) bigint->buffer, &bigint->len, &dummy))

    if (bigint->len == 0) {
        // We have an empty value == zero
        return parser_ok;
    }

    if (bigint->len < 2) {
        // We only have a byte sign, no good
        return parser_unexpected_value;
    }

    if (bigint->buffer[0] == 0x01) {
        // negative bigint, should be positive
        return parser_unexpected_value;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readMethod(parser_tx_t *v, CborValue *it) {

    uint64_t methodValue;
    CHECK_CBOR_ERR(cbor_value_get_uint64(it, &methodValue))

    switch(methodValue) {
        case method0:
            CHECK_CBOR_ERR(cbor_value_advance(it))
            CHECK_CBOR_TYPE(it->type, CborByteStringType)

            size_t arraySize;
            cbor_value_get_string_length(it, &arraySize);
            if (arraySize!=0) {
                return parser_unexpected_number_items;
            }
        break;
        default:
            return parser_unexpected_method;
    }

    v->method = methodValue;

    return parser_ok;
}

parser_error_t _read(const parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    // It is an array
    if (!cbor_value_is_array(&it)) {
        return parser_unexpected_type;
    }

    size_t arraySize;
    cbor_value_get_array_length(&it, &arraySize);

    // Depends if we have params or not
    if (arraySize != 8 && arraySize != 7) {
        return parser_unexpected_number_items;
    }

    CborValue arrayContainer;
    CHECK_CBOR_ERR(cbor_value_enter_container(&it, &arrayContainer))

    // "to" field
    CHECK_PARSER_ERR(_readAddress(&v->to, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "from" field
    CHECK_PARSER_ERR(_readAddress(&v->from, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "nonce" field
    CHECK_PARSER_ERR(cbor_value_get_uint64(&arrayContainer, &v->nonce))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "value" field
    CHECK_PARSER_ERR(_readBigInt(&v->value, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "gasPrice" field
    CHECK_PARSER_ERR(_readBigInt(&v->gasprice, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "gasLimit" field
    CHECK_PARSER_ERR(_readBigInt(&v->gaslimit, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "method" field
    CHECK_PARSER_ERR(_readMethod(v, &arrayContainer))
    CHECK_CBOR_ERR(cbor_value_advance(&arrayContainer))

    // "params" field is consumed inside readMethod

    CHECK_CBOR_ERR(cbor_value_leave_container(&it, &arrayContainer))

    // REVIEW: maybe use cbor_value_validate_basic to verify that there is no extra bytes
    if (it.ptr != c->buffer + c->bufferLen) {
        // End of buffer does not match end of parsed data
        return parser_cbor_unexpected_EOF;
    }

    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    // TODO: Complete this

    return parser_ok;
}

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    uint8_t itemCount = 8;

    if (v->method == method0) {
        // Don't show method so only 6 items
        itemCount = 6;
    }

    return itemCount;
}
