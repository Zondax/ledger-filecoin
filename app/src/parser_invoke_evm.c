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

#define INVOKE_EVM_METHOD 3844450837

parser_error_t getNumItemsInvokeEVM(uint8_t *numItems) {
    if (numItems == NULL) {
        return parser_unexpected_error;
    }
    *numItems = 5;
    return parser_ok;
}

parser_error_t printInvokeEVM(const fil_base_tx_t *txObj,
                            uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                            char *outVal, uint16_t outValLen, uint8_t pageIdx,
                            uint8_t *pageCount) {
    if (txObj == NULL || outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    if (txObj->method != INVOKE_EVM_METHOD) {
        return parser_value_out_of_range;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "To");
            return printAddress(&txObj->to, outVal, outValLen, pageIdx, pageCount);

        case 1:
            snprintf(outKey, outKeyLen, "From");
            return printAddress(&txObj->from, outVal, outValLen, pageIdx, pageCount);
            break;

        case 2:
            snprintf(outKey, outKeyLen, "Value");
            snprintf(outVal, outValLen, "Define value");
            // CHECK_PARSER_ERR(printERC20Value(&legacy->data, outVal, outValLen, pageIdx, pageCount));
            break;

        case 3:
            snprintf(outKey, outKeyLen, "Nonce");
            snprintf(outVal, outValLen, "Define value");
            // CHECK_PARSER_ERR(printRLPNumber(&legacy->nonce, outVal, outValLen, pageIdx, pageCount));
            break;

        case 4:
            snprintf(outKey, outKeyLen, "Gas price");
            snprintf(outVal, outValLen, "Define value");
            // CHECK_PARSER_ERR(printRLPNumber(&legacy->gasPrice, outVal, outValLen, pageIdx, pageCount));
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Gas limit");
            snprintf(outVal, outValLen, "Define value");
            // CHECK_PARSER_ERR(printRLPNumber(&legacy->gasLimit, outVal, outValLen, pageIdx, pageCount));
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

    rlp_t rlp = {.ptr = txObj->params, .rlpLen = ERC20_DATA_LENGTH, .kind = RLP_KIND_STRING};
    return validateERC20(rlp);
}

//  0x095ea7b3
//  0000000000000000000000006a3f21d2a92a15752912974bbbd5b1469a72b261
//  0000000000000000000000000000000000000000000009780178fba9d2bd7400
