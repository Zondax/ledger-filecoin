/*******************************************************************************
 *   (c) 2018 - 2024 ZondaX AG
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
#ifndef _RPL_H_
#define _RPL_H_

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

#ifdef __cplusplus
}
#endif
#endif
