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
#include "fil_utils.h"

parser_error_t parser_mapCborError(CborError err) {
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

parser_error_t readAddress(address_t *address, CborValue *value) {
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
        case ADDRESS_PROTOCOL_DELEGATED: {
            // protocol 4
            uint64_t actorId = 0;
            const uint16_t actorIdSize = decompressLEB128(address->buffer + 1, address->len - 1, &actorId);
            PARSER_ASSERT_OR_ERROR(actorIdSize > 0, parser_invalid_address)
            // At least 1 byte in subaddress
            PARSER_ASSERT_OR_ERROR(address->len > actorIdSize + 1, parser_invalid_address)
            break;
        }
        default:
            return parser_invalid_address;
    }

    return parser_ok;
}

parser_error_t printAddress(const address_t *a,char *outVal, uint16_t outValLen,
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

parser_error_t readBigInt(bigint_t *bigint, CborValue *value) {
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

bool format_quantity(const bigint_t *b,
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
