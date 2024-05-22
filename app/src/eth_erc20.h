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

#include <stdint.h>
#include "parser_common.h"
#include "rlp.h"
#include "coin.h"
#include "parser_txdef.h"


#ifdef __cplusplus
extern "C" {
#endif

#define ERC20_TRANSFER_DATA_LENGTH 68 // 4 + 32 + 32
#define MAX_SYMBOL_LEN 10
typedef struct {
    uint8_t address[ETH_ADDR_LEN];
    char symbol[MAX_SYMBOL_LEN];
    uint8_t decimals;
} erc20_tokens_t;

bool validateERC20(eth_tx_t *ethObj);
parser_error_t getERC20Token(const eth_tx_t *ethObj, char tokenSymbol[MAX_SYMBOL_LEN], uint8_t *decimals);
parser_error_t printERC20Value(const eth_tx_t *ethObj, char *outVal, uint16_t outValLen,
                               uint8_t pageIdx, uint8_t *pageCount);

#ifdef __cplusplus
}
#endif
