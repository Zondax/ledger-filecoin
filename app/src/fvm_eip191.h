/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

#include <stdbool.h>
#include <stdint.h>

#include "coin_evm.h"
#include "parser_common.h"
#include "zxerror.h"
#include "zxmacros.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t fvm_eip191_msg_parse();
zxerr_t fvm_eip191_msg_getNumItems(uint8_t *num_items);
zxerr_t fvm_eip191_msg_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                               uint8_t pageIdx, uint8_t *pageCount);
zxerr_t fvm_eip191_hash_message(const uint8_t *message, uint16_t messageLen, uint8_t *hash);
#ifdef __cplusplus
}
#endif