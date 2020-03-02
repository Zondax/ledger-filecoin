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
#pragma once

#include <zxmacros.h>

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

#define CHECK_CBOR_ERR(CALL) { \
    CborError err = CALL;  \
    if (err!=CborNoError) return parser_mapCborError(err);}
#define CHECK_CBOR_TYPE(type, expected) {if (type!=expected) return parser_unexpected_type;}
#define CHECK_CBOR_MAP_LEN(map, expected_count) { \
    size_t numItems; CHECK_CBOR_ERR(cbor_value_get_map_length(map, &numItems)); \
    if (numItems != expected_count)  return parser_unexpected_number_items; }

#define INIT_CBOR_PARSER(c, it)  \
    CborParser parser;           \
    CHECK_CBOR_ERR(cbor_parser_init(c->buffer + c->offset, c->bufferLen - c->offset, 0, &parser, &it))

__Z_INLINE parser_error_t _matchKey(CborValue *value, const char *expectedKey) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType)

    bool result;
    CHECK_CBOR_ERR(cbor_value_text_string_equals(value, expectedKey, &result))
    if (!result) {
        return parser_unexpected_field;
    }

    return parser_ok;
}
#define CBOR_KEY_MATCHES(v, key) (_matchKey(v, key) == parser_ok)
