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

#include "fil_utils.h"
#include "base32.h"
#include <stdio.h>

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

parser_error_t parser_printBigIntFixedPoint(const bigint_t *b,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount, uint16_t decimals) {

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

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, decimals);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t renderByteString(uint8_t *in, uint16_t inLen,
                          char *outVal, uint16_t outValLen,
                          uint8_t pageIdx, uint8_t *pageCount) {
    const uint32_t len = inLen * 2;

    // check bounds
    if (inLen > 0 && inLen <= STR_BUF_LEN) {
        char hexStr[STR_BUF_LEN * 2 + 1] = {0};
        const uint32_t count = array_to_hexstr(hexStr, sizeof(hexStr), in, inLen);
        PARSER_ASSERT_OR_ERROR(count == len, parser_value_out_of_range)
        CHECK_APP_CANARY()

        pageString(outVal, outValLen, hexStr, pageIdx, pageCount);
        CHECK_APP_CANARY()
        return parser_ok;
    }

    return parser_value_out_of_range;
}

parser_error_t parse_cid(cid_t *cid, CborValue *value) {

    MEMZERO(cid->str, sizeof(cid->str));

    // CID is a custom type tagged with 42, as described here: https://github.com/ipld/cid-cbor/
    CborTag tag;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTagType)

    CHECK_CBOR_MAP_ERR(cbor_value_get_tag(value, &tag))
    // advance to the next element in the tag.
    CHECK_CBOR_MAP_ERR(cbor_value_skip_tag(value));

    // Tag is defined as an uint64_t, so we need to cast it here.
    // in order to get the right value(a byte_string).
    uint8_t tmp[100] = {0};
    size_t cid_len = sizeof(tmp);

    size_t bytes_read = 0;

    if ((uint8_t)tag == TAG_CID) {
        CHECK_CBOR_MAP_ERR(cbor_value_copy_byte_string(value, tmp, &cid_len, NULL /* next */))

        // CID docs says base can be omitted, but DagCbor protocol prefixes
        // CID binary data with it.
        // https://ipld.io/specs/codecs/dag-cbor/spec/#links
        uint64_t base;
        uint64_t version;
        uint64_t codec;

        uint8_t base_offset = decompressLEB128(tmp,  cid_len, &base);
        bytes_read += base_offset;

        bytes_read += decompressLEB128(tmp + bytes_read, cid_len - bytes_read, &version);
        decompressLEB128(tmp + bytes_read, cid_len - bytes_read, &codec);

        if ((uint8_t)codec != CID_CODEC || (uint8_t)version != CID_VERSION || (uint8_t)base != CID_BASE)
            return parser_invalid_cid;

        // skip first byte as it is CID_BASE, which was added as a prefix by
        // DagCbor protocol. everything else is our cid.
        MEMCPY(cid->str, tmp + base_offset, cid_len - base_offset);
        cid->len = cid_len - base_offset;

        return parser_ok;
    }

    return parser_invalid_cid;
}

// return lenght
parser_error_t printCid(cid_t *cid, char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    // 100-bytes is good enough
    char outBuffer[100] = {0};

    // We need to add the encoder prefix.
    // https://github.com/multiformats/go-multibase/blob/master/multibase.go#L98
    // filecoin uses base32 which base prefix is b.
    *outBuffer = 'b';

    if (base32_encode(cid->str, cid->len, outBuffer + 1, sizeof(outBuffer)- 1) == 0) {
        return parser_no_data;
    }

    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}
