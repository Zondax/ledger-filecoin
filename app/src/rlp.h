/*******************************************************************************
 *   (c) 2018 - 2023 ZondaX AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include "parser_common.h"
#include "rlp_def.h"
#include "uint256.h"

parser_error_t rlp_parseStream(parser_context_t *ctx, rlp_t *rlp, uint16_t *fields, uint16_t maxFields);
parser_error_t rlp_read(parser_context_t *ctx, rlp_t *rlp);
parser_error_t rlp_readList(const rlp_t *list, rlp_t *fields, uint16_t *listFields, uint16_t maxFields);
parser_error_t rlp_readUInt256(const rlp_t *rlp, uint256_t *value);

parser_error_t rlpNumberToString(rlp_t *num, char *symbol, uint8_t decimals, char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount);

#if 0
int16_t rlp_decode(const uint8_t *data,
                   uint8_t *kind,
                   uint16_t *len,
                   uint16_t *valueOffset);

// reads a byte from the field
int8_t rlp_readByte(const uint8_t *data,
                    const rlp_field_t *field,
                    uint8_t *value);

// reads a buffer into value. These are not actually zero terminate strings but buffers
int8_t rlp_readStringPaging(const uint8_t *data,
                            const rlp_field_t *field,
                            char *value,
                            uint16_t maxLen,
                            uint16_t *valueLen,
                            uint8_t pageIdx,
                            uint8_t *pageCount);

// reads a buffer into value. These are not actually zero terminate strings but buffers
int8_t rlp_readString(const uint8_t *data,
                      const rlp_field_t *field,
                      char *value,
                      uint16_t maxLen);

// reads a list and splits into rootFields
int8_t rlp_readList(const uint8_t *data,
                    const rlp_field_t *field,
                    rlp_field_t *listFields,
                    uint8_t maxListFieldCount,
                    uint16_t *listFieldCount);

#endif

#ifdef __cplusplus
}
#endif
