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

#include <zxmacros.h>
#include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor.h"

parser_tx_t parser_tx_obj;

__Z_INLINE parser_error_t parser_mapCborError(CborError err);

#define CHECK_CBOR_MAP_ERR(CALL) { \
    CborError err = CALL;  \
    if (err!=CborNoError) return parser_mapCborError(err);}

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

#define CHECK_CBOR_TYPE(type, expected) {if (type!=expected) return parser_unexpected_type;}

#define INIT_CBOR_PARSER(c, it)  \
    CborParser parser;           \
    CHECK_CBOR_MAP_ERR(cbor_parser_init(c->buffer + c->offset, c->bufferLen - c->offset, 0, &parser, &it))

__Z_INLINE parser_error_t _matchKey(CborValue *value, const char *expectedKey) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType)

    bool result;
    CHECK_CBOR_MAP_ERR(cbor_value_text_string_equals(value, expectedKey, &result))
    PARSER_ASSERT_OR_ERROR(result, parser_unexpected_field)

    return parser_ok;
}

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
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
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize));
    return parser_ok;
}

__Z_INLINE parser_error_t parser_mapCborError(CborError err) {
    switch (err) {
        case CborErrorUnexpectedEOF:
            return parser_cbor_unexpected_EOF;
        case CborErrorMapNotSorted:
            return parser_cbor_not_canonical;
        case CborNoError:
            return parser_ok;
        default:
            return parser_cbor_unexpected;
    }
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
    address->len = sizeof_field(address_t, buffer);

    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, (uint8_t *) address->buffer, &address->len, &dummy))

    // Addresses are at least 2 characters Protocol + random data
    PARSER_ASSERT_OR_ERROR(address->len > 1, parser_invalid_address)

    // Verify size and protocol
    switch (address->buffer[0]) {
        case ADDRESS_PROTOCOL_ID:
            // protocol 0
            PARSER_ASSERT_OR_ERROR(address->len - 1 < 21, parser_invalid_address)
            break;
        case ADDRESS_PROTOCOL_SECP256K1:
            // protocol 1
            PARSER_ASSERT_OR_ERROR(address->len - 1 == ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN, parser_invalid_address)
            break;
        case ADDRESS_PROTOCOL_ACTOR:
            // protocol 2
            PARSER_ASSERT_OR_ERROR(address->len - 1 == ADDRESS_PROTOCOL_ACTOR_PAYLOAD_LEN, parser_invalid_address)
            break;
        case ADDRESS_PROTOCOL_BLS:
            // protocol 3
            PARSER_ASSERT_OR_ERROR(address->len - 1 == ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN, parser_invalid_address)
            break;
        default:
            return parser_invalid_address;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readBigInt(bigint_t *bigint, CborValue *value) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;

    MEMZERO(bigint, sizeof(bigint_t));
    bigint->len = sizeof_field(bigint_t, buffer);

    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, (uint8_t *) bigint->buffer, &bigint->len, &dummy))

    // We have an empty value so value is default (zero)
    PARSER_ASSERT_OR_ERROR(bigint->len != 0, parser_ok)

    // We only have a byte sign, no good
    PARSER_ASSERT_OR_ERROR(bigint->len > 1, parser_unexpected_value)

    // negative bigint, should be positive
    PARSER_ASSERT_OR_ERROR(bigint->buffer[0] == 0x00, parser_unexpected_value)

    return parser_ok;
}

__Z_INLINE parser_error_t _readMethod(parser_tx_t *tx, CborValue *value) {

    uint64_t methodValue;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_unsigned_integer(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_uint64(value, &methodValue))

    switch (methodValue) {
        case method0: {
            PARSER_ASSERT_OR_ERROR(value->type != CborInvalidType, parser_unexpected_type)
            CHECK_CBOR_MAP_ERR(cbor_value_advance(value))
            CHECK_CBOR_TYPE(value->type, CborByteStringType)

            size_t arraySize;
            PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(value) || cbor_value_is_text_string(value), parser_unexpected_type)
            CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(value, &arraySize))

            // method0 should have zero arguments
            PARSER_ASSERT_OR_ERROR(arraySize == 0, parser_unexpected_number_items)
            break;
        }
        default:
            return parser_unexpected_method;
    }

    tx->method = methodValue;

    return parser_ok;
}

parser_error_t _read(const parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

    // It is an array
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(&it), parser_unexpected_type)
    size_t arraySize;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &arraySize))

    // Depends if we have params or not
    PARSER_ASSERT_OR_ERROR(arraySize == 9 || arraySize == 8, parser_unexpected_number_items);

    CborValue arrayContainer;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &arrayContainer))

    // "version" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_PARSER_ERR(cbor_value_get_int64(&arrayContainer, &v->version))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "to" field
    CHECK_PARSER_ERR(_readAddress(&v->to, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "from" field
    CHECK_PARSER_ERR(_readAddress(&v->from, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "nonce" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_unsigned_integer(&arrayContainer), parser_unexpected_type)
    CHECK_PARSER_ERR(cbor_value_get_uint64(&arrayContainer, &v->nonce))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "value" field
    CHECK_PARSER_ERR(_readBigInt(&v->value, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "gasPrice" field
    CHECK_PARSER_ERR(_readBigInt(&v->gasprice, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "gasLimit" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_PARSER_ERR(cbor_value_get_int64(&arrayContainer, &v->gaslimit))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "method" field
    CHECK_PARSER_ERR(_readMethod(v, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "params" field is consumed inside readMethod
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    PARSER_ASSERT_OR_ERROR(arrayContainer.type == CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &arrayContainer))

    // End of buffer does not match end of parsed data
    PARSER_ASSERT_OR_ERROR(it.ptr == c->buffer + c->bufferLen, parser_cbor_unexpected_EOF)

    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)
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
