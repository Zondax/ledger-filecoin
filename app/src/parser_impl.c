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

#include "parser_impl.h"

#include <zxmacros.h>

#include "app_mode.h"
#include "cbor.h"
#include "evm_erc20.h"
#include "fil_utils.h"
#include "parser_common.h"
#include "parser_invoke_evm.h"
#include "parser_txdef.h"
#include "zxformat.h"

extern const uint8_t ERC20_TRANSFER_PREFIX[4];
parser_tx_t parser_tx_obj;

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
        case parser_unexpected_error:
            return "Unexpected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
        case parser_unexpected_tx_version:
            return "tx version is not supported";
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
        case parser_unsupported_tx:
            return "Unsupported transaction type";
        case parser_invalid_rlp_data:
            return "Invalid rlp data";
        case parser_invalid_chain_id:
            return "Invalid eth chainId";
        case parser_chain_id_not_configured:
            return "ChainId not configured";
        case parser_invalid_rs_values:
            return "Invalid rs values";
        case parser_invalid_cid:
            return "Invalid CID";
        case parser_invalid_deal_duration:
            return "Client deal duration must be >= 518400";
        case parser_invalid_prefix:
            return "Invalid raw-bytes prefix";
        case parser_expert_mode_required:
            return "ExpertModeRequired";
        case parser_blindsign_mode_required:
            return "Blindsign Mode Required";
        default:
            return "Unrecognized error code";
    }
}

parser_error_t printValue(const struct CborValue *value, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                          uint8_t *pageCount) {
    uint8_t buff[STR_BUF_LEN] = {0};
    size_t buffLen = sizeof(buff);

    switch (value->type) {
        case CborByteStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, buff, &buffLen, NULL /* next */))
            CHECK_APP_CANARY()

            if (buffLen > 0) {
                CHECK_ERROR(renderByteString(buff, buffLen, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        }
        case CborTextStringType: {
            CHECK_CBOR_MAP_ERR(cbor_value_copy_text_string(value, (char *)buff, &buffLen, NULL /* next */))
            CHECK_APP_CANARY()

            if (buffLen > 0) {
                pageString(outVal, outValLen, (char *)buff, pageIdx, pageCount);
            }
            break;
        }
        case CborIntegerType: {
            int64_t paramValue = 0;
            CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(value, &paramValue))
            int64_to_str(outVal, outValLen, paramValue);
            break;
        }
        // Add support to render fields tagged as Tag(42) as described here:
        // https://github.com/ipld/cid-cbor/
        case CborTagType: {
            CborTag tag;
            CHECK_CBOR_MAP_ERR(cbor_value_get_tag(value, &tag))
            if (tag == TAG_CID) {
                CHECK_CBOR_MAP_ERR(cbor_value_copy_tag(value, buff, &buffLen, NULL /* next */))
                CHECK_APP_CANARY()
                CHECK_ERROR(renderByteString(buff, buffLen, outVal, outValLen, pageIdx, pageCount))
                break;
            }
            return parser_unexpected_type;
        }

        default:
            snprintf(outVal, outValLen, "Type: %d", value->type);
    }

    // Print EMPTY when buffLen is zero
    if (buffLen == 0) {
        snprintf(outVal, outValLen, "-- EMPTY --");
        *pageCount = 1;
    }

    return parser_ok;
}

parser_error_t _printParam(const fil_base_tx_t *tx, uint8_t paramIdx, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                           uint8_t *pageCount) {
    CHECK_APP_CANARY()

    if (paramIdx >= tx->numparams) {
        return parser_value_out_of_range;
    }

    CborParser parser;
    CborValue itContainer;
    CHECK_CBOR_MAP_ERR(cbor_parser_init(tx->params, MAX_PARAMS_BUFFER_SIZE, 0, &parser, &itContainer))
    CHECK_APP_CANARY()

    CborValue itParams = itContainer;

    switch (itContainer.type) {
        case CborByteStringType: {
            address_t tmpAddr;
            MEMZERO(&tmpAddr, sizeof(address_t));
            if (readAddress(&tmpAddr, &itContainer) != parser_ok) {
                // Non addresses string will be printed as hexstring
                return printValue(&itParams, outVal, outValLen, pageIdx, pageCount);
            }
            PARSER_ASSERT_OR_ERROR(itContainer.type != CborInvalidType, parser_unexpected_type)
            // Not every ByteStringType must be interpreted as address. Depends on
            // method number and actor.
            CHECK_ERROR(printAddress(&tmpAddr, outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case CborMapType:
        case CborArrayType: {
            /// Enter container?
            CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&itContainer, &itParams))
            CHECK_APP_CANARY()
            for (uint8_t i = 0; i < paramIdx; ++i) {
                CHECK_CBOR_MAP_ERR(cbor_value_advance(&itParams))
                CHECK_APP_CANARY()
            }

            CHECK_ERROR(printValue(&itParams, outVal, outValLen, pageIdx, pageCount))

            /// Leave container
            while (!cbor_value_at_end(&itParams)) {
                CHECK_CBOR_MAP_ERR(cbor_value_advance(&itParams))
            }
            CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&itContainer, &itParams))
            CHECK_APP_CANARY()
            break;
        }

        // In the process of parsing the params the default was to treat it as an array of bytes.
        // Here we can simply copy the params byte array to outVal and set the pageCount to 1.
        // If the array hold non printable bytes we print the hex array.
        default: {
            for (size_t i = 0; i < tx->params_len; i++) {
                if (!IS_PRINTABLE(tx->params[i])) {
                    pageStringHex(outVal, outValLen, (const char *)tx->params, tx->params_len, pageIdx, pageCount);
                    return parser_ok;
                }
            }

            pageString(outVal, outValLen, (char *)tx->params, pageIdx, pageCount);
        }
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readMethod(fil_base_tx_t *tx, CborValue *value) {
    uint64_t methodValue;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_unsigned_integer(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_uint64(value, &methodValue))

    tx->numparams = 0;
    MEMZERO(tx->params, sizeof(tx->params));

    // This area reads the entire params byte string (if present) into the
    // txn->params and sets txn->numparams to the number of params within cbor
    // container Parsing of the individual params is deferred until the display
    // stage

    PARSER_ASSERT_OR_ERROR(cbor_value_is_valid(value), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(value))
    CHECK_CBOR_TYPE(value->type, CborByteStringType)

    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(value), parser_unexpected_type)

    size_t paramsBufferSize = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(value, &paramsBufferSize))
    PARSER_ASSERT_OR_ERROR(paramsBufferSize <= sizeof(tx->params), parser_unexpected_number_items)

    // short-circuit if there are no params
    if (paramsBufferSize != 0) {
        size_t paramsLen = sizeof(tx->params);
        CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, tx->params, &paramsLen, NULL /* next */))
        PARSER_ASSERT_OR_ERROR(paramsLen <= sizeof(tx->params), parser_unexpected_value)
        PARSER_ASSERT_OR_ERROR(paramsLen == paramsBufferSize, parser_unexpected_number_items)

        CborParser parser;
        CborValue itParams;
        CHECK_CBOR_MAP_ERR(cbor_parser_init(tx->params, paramsLen, 0, &parser, &itParams))

        switch (itParams.type) {
            case CborArrayType: {
                size_t arrayLength = 0;
                CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&itParams, &arrayLength))
                PARSER_ASSERT_OR_ERROR(arrayLength < UINT8_MAX, parser_value_out_of_range)
                tx->numparams = arrayLength;
                break;
            }
            case CborMapType: {
                size_t mapLength = 0;
                CHECK_CBOR_MAP_ERR(cbor_value_get_map_length(&itParams, &mapLength))
                PARSER_ASSERT_OR_ERROR(mapLength < UINT8_MAX, parser_value_out_of_range)
                tx->numparams = mapLength;
                break;
            }
            case CborByteStringType: {
                // Only one parameter is expected when ByteStringType is received.
                PARSER_ASSERT_OR_ERROR(itParams.remaining == 1, parser_value_out_of_range)
                tx->numparams = 1;

                // If Invoke + ERC20 Transfer discard encoded cbor bytes at the beginning
                if (methodValue == INVOKE_EVM_METHOD && tx->params[0] == 0x58 && tx->params[1] == ERC20_DATA_LENGTH &&
                    MEMCMP(tx->params + 2, ERC20_TRANSFER_PREFIX, sizeof(ERC20_TRANSFER_PREFIX)) == 0) {
                    MEMMOVE(tx->params, tx->params + 2, ERC20_DATA_LENGTH);
                }
                break;
            }

            // If the type is unknown, treat it as an array of bytes and copy it directly to params.
            // This implies that the current container on value is the last valid one, and ParamsBufferSize indicates
            // the length of the params byte array. The itParams container is already positioned within the params
            // content, which may lead to unexpected results. Set numparams to 1 to indicate that there is a single
            // array of bytes present. Set params_len to the length of the params byte array so we print later
            case CborInvalidType:
            default: {
                MEMCPY(tx->params, itParams.ptr, paramsBufferSize);
                tx->params_len = paramsBufferSize;
                tx->numparams = 1;
                break;
            }
        }
    }
    tx->method = methodValue;

    return parser_ok;
}

parser_error_t _read(const parser_context_t *c, fil_base_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

    // It is an array
    PARSER_ASSERT_OR_ERROR(cbor_value_is_array(&it), parser_unexpected_type)
    size_t arraySize;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &arraySize))

    // Depends if we have params or not
    PARSER_ASSERT_OR_ERROR(arraySize == 10 || arraySize == 9, parser_unexpected_number_items)

    CborValue arrayContainer;
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &arrayContainer))

    // "version" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, &v->version))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    if (v->version != COIN_SUPPORTED_TX_VERSION) {
        return parser_unexpected_tx_version;
    }

    // "to" field
    CHECK_ERROR(readAddress(&v->to, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "from" field
    CHECK_ERROR(readAddress(&v->from, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "nonce" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_unsigned_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_uint64(&arrayContainer, &v->nonce))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "value" field
    CHECK_ERROR(readBigInt(&v->value, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "gasLimit" field
    PARSER_ASSERT_OR_ERROR(cbor_value_is_integer(&arrayContainer), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_get_int64_checked(&arrayContainer, &v->gaslimit))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "gasFeeCap" field
    CHECK_ERROR(readBigInt(&v->gasfeecap, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "gasPremium" field
    CHECK_ERROR(readBigInt(&v->gaspremium, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    // "method" field
    CHECK_ERROR(readMethod(v, &arrayContainer))
    PARSER_ASSERT_OR_ERROR(arrayContainer.type != CborInvalidType, parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_advance(&arrayContainer))

    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &arrayContainer))

    // End of buffer does not match end of parsed data
    PARSER_ASSERT_OR_ERROR(it.ptr == c->buffer + c->bufferLen, parser_cbor_unexpected_EOF)

    return parser_ok;
}

parser_error_t _validateTx(__Z_UNUSED const parser_context_t *c, __Z_UNUSED const fil_base_tx_t *v) {
    // Note: This is place holder for transaction level checks that the project
    // may require before accepting the parsed values. the parser already
    // validates input This function is called by parser_validate, where
    // additional checks are made (formatting, UI/UX, etc.(
    return parser_ok;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const fil_base_tx_t *v) {
    uint32_t itemCount = 6;

    // Items for InvokeEVM + ERC20 transfer
    if (isInvokeEVM_ERC20Transfer(v)) {
        if (getNumItemsInvokeEVM((uint8_t *)&itemCount, v) != parser_ok) {
            return 0;
        }
        if (itemCount > UINT8_MAX) {
            return 0;
        }
        return (uint8_t)itemCount;
    }

    if (app_mode_expert()) {
        itemCount = 8;
    }

    // For f4 addresses display f4 and 0x addresses
    if (v->from.buffer[0] == ADDRESS_PROTOCOL_DELEGATED) {
        itemCount++;
    }
    if (v->to.buffer[0] == ADDRESS_PROTOCOL_DELEGATED) {
        itemCount++;
    }

    uint32_t total;
    if (__builtin_add_overflow(itemCount, v->numparams, &total) || total > UINT8_MAX) {
        return 0;
    }

    return (uint8_t)total;
}
