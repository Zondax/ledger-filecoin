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
#include "parser_invoke_evm.h"
#include "rlp.h"
#include "eth_erc20.h"
#include "fil_utils.h"
#include "app_mode.h"
#include "eth_utils.h"

#define INVOKE_EVM_METHOD 3844450837
#define F4_ADDRESS_IDENTIFIER 0x040A

parser_error_t getNumItemsInvokeEVM(uint8_t *numItems, const fil_base_tx_t *txObj) {
    if (numItems == NULL || txObj == NULL) {
        return parser_unexpected_error;
    }
    const bool expertMode = app_mode_expert();
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;

    const uint16_t addressIdentifier = txObj->to.buffer[0] << 8 | txObj->to.buffer[1];
    if (txObj->value.len != 0 || txObj->to.len != 22 || addressIdentifier != F4_ADDRESS_IDENTIFIER) {
        return parser_unexpected_error;;
    }
    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.legacy.value = tmpValue, .legacy.to = tokenContract, .legacy.data = data};

    CHECK_PARSER_ERR(getERC20Token(&tmpEthObj, tokenSymbol, &decimals));
    const bool unknownToken  = (memcmp(tokenSymbol, "?? ", 3) == 0);

    *numItems = 5;

    const uint16_t fromIdentifier = txObj->from.buffer[0] << 8 | txObj->from.buffer[1];
    if (fromIdentifier == F4_ADDRESS_IDENTIFIER) {
        (*numItems)++;
    }

    if (unknownToken) {
        (*numItems)++;
    }
    if (expertMode) {
        (*numItems) += 3;
    }
    return parser_ok;
}

parser_error_t printInvokeEVM(const fil_base_tx_t *txObj,
                            uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                            char *outVal, uint16_t outValLen, uint8_t pageIdx,
                            uint8_t *pageCount) {
    if (txObj == NULL || outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    if (txObj->method != INVOKE_EVM_METHOD || !isInvokeEVM_ERC20Transfer(txObj)) {
        return parser_value_out_of_range;
    }

    const uint16_t addressIdentifier = txObj->to.buffer[0] << 8 | txObj->to.buffer[1];
    if (txObj->value.len != 0 || txObj->to.len != 22 || addressIdentifier != F4_ADDRESS_IDENTIFIER) {
        return parser_unexpected_error;;
    }
    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.legacy.value = tmpValue, .legacy.to = tokenContract, .legacy.data = data};

    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_PARSER_ERR(getERC20Token(&tmpEthObj, tokenSymbol, &decimals));
    const bool knownToken  = (memcmp(tokenSymbol, "?? ", 3) != 0);

    const uint16_t fromIdentifier = txObj->from.buffer[0] << 8 | txObj->from.buffer[1];

    uint8_t adjustedIndex = displayIdx;
    if (adjustedIndex >= 1 && fromIdentifier != F4_ADDRESS_IDENTIFIER) {
        adjustedIndex++;
    }

    if (adjustedIndex >= 4 && knownToken) {
         adjustedIndex++;
    }

    switch (adjustedIndex) {
        case 0:
            snprintf(outKey, outKeyLen, "Method");
            snprintf(outVal, outValLen, "ERC20 Transfer");
            break;

        case 1:
            snprintf(outKey, outKeyLen, "From");
            return printEthAddress(&txObj->from, outVal, outValLen, pageIdx, pageCount);

        case 2:
            snprintf(outKey, outKeyLen, "From");
            return printAddress(&txObj->from, outVal, outValLen, pageIdx, pageCount);

        case 3:
            snprintf(outKey, outKeyLen, "To");
            rlp_t to = {.kind = RLP_KIND_STRING, .ptr = (txObj->params + 4 + 12), .rlpLen = ETH_ADDRESS_LEN};
            CHECK_PARSER_ERR(printEVMAddress(&to, outVal, outValLen, pageIdx, pageCount));
            break;

         case 4:
             snprintf(outKey, outKeyLen, "Contract");
             rlp_t contractAddress = {.kind = RLP_KIND_STRING, .ptr = (txObj->to.buffer + 2), .rlpLen = ETH_ADDRESS_LEN};
             CHECK_PARSER_ERR(printEVMAddress(&contractAddress, outVal, outValLen, pageIdx, pageCount));
             break;

        case 5:
            snprintf(outKey, outKeyLen, "Value");
            CHECK_PARSER_ERR(printERC20Value(&tmpEthObj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 6:
            snprintf(outKey, outKeyLen, "Gas Limit");
            if (int64_to_str(outVal, outValLen, txObj->gaslimit) != NULL) {
                return parser_unexpected_error;
            }
            *pageCount = 1;
            return parser_ok;

        case 7:
            snprintf(outKey, outKeyLen, "Gas Fee Cap");
            CHECK_PARSER_ERR(parser_printBigIntFixedPoint(&txObj->gasfeecap,
                                                outVal, outValLen, pageIdx, pageCount,
                                                COIN_AMOUNT_DECIMAL_PLACES));
            break;

        case 8:
            snprintf(outKey, outKeyLen, "Gas Premium");
            CHECK_PARSER_ERR(parser_printBigIntFixedPoint(&txObj->gaspremium,
                                                outVal, outValLen, pageIdx, pageCount,
                                                COIN_AMOUNT_DECIMAL_PLACES));
            break;

        case 9:
            *pageCount = 1;
            snprintf(outKey, outKeyLen, "Nonce");
            if (uint64_to_str(outVal, outValLen, txObj->nonce) != NULL) {
                return parser_unexpected_error;
            }
            break;

        default:
            return parser_display_page_out_of_range;
    }


    return parser_ok;
}

bool isInvokeEVM_ERC20Transfer(const fil_base_tx_t *txObj) {
    if (txObj == NULL || txObj->method != INVOKE_EVM_METHOD) {
        return false;
    }

    const uint16_t addressIdentifier = txObj->to.buffer[0] << 8 | txObj->to.buffer[1];
    if (txObj->value.len != 0 || txObj->to.len != 22 || addressIdentifier != F4_ADDRESS_IDENTIFIER) {
        return false;
    }

    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.legacy.value = tmpValue, .legacy.to = tokenContract, .legacy.data = data};
    return validateERC20(&tmpEthObj);
}
