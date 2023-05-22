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
#pragma once

#include "parser_common.h"
#include "parser_txdef.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

extern parser_tx_t parser_tx_obj;

parser_error_t _read(const parser_context_t *c, fil_base_tx_t *v);

parser_error_t _validateTx(const parser_context_t *c, const fil_base_tx_t *v);

parser_error_t _printParam(const fil_base_tx_t *tx, uint8_t paramIdx,
                           char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);

uint8_t _getNumItems(const parser_context_t *c, const fil_base_tx_t *v);

parser_error_t checkMethod(uint64_t methodValue);

#ifdef __cplusplus
}
#endif
