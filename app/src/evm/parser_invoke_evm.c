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

#include "app_mode.h"
#include "coin_evm.h"
#include "evm_erc20.h"
#include "evm_utils.h"
#include "fil_utils.h"
#include "rlp.h"

#define F4_ETH_ADDRESS_IDENTIFIER 0x040A

parser_error_t getNumItemsInvokeEVM(uint8_t *numItems, const fil_base_tx_t *txObj) {
    if (numItems == NULL || txObj == NULL) {
        return parser_unexpected_error;
    }
    const bool expertMode = app_mode_expert();
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;

    const uint16_t addressIdentifier = txObj->to.buffer[0] << 8 | txObj->to.buffer[1];
    if (txObj->value.len != 0 || txObj->to.len != F4_ETH_ADDRESS_BYTES_LEN ||
        addressIdentifier != F4_ETH_ADDRESS_IDENTIFIER) {
        return parser_unexpected_error;
        ;
    }
    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.tx.value = tmpValue, .tx.to = tokenContract, .tx.data = data};

    CHECK_PARSER_ERR(getERC20Token(&tmpEthObj, tokenSymbol, &decimals));
    const bool unknownToken = (memcmp(tokenSymbol, "?? ", 3) == 0);

    *numItems = 5;

    const uint16_t fromIdentifier = txObj->from.buffer[0] << 8 | txObj->from.buffer[1];
    if (fromIdentifier == F4_ETH_ADDRESS_IDENTIFIER) {
        (*numItems)++;
    }

    const uint8_t *toIdentifier = txObj->params + SELECTOR_LENGTH + (BIGINT_LENGTH - ETH_ADDRESS_LEN);
    uint64_t id = 0;
    for (uint8_t i = 1; i < ETH_ADDRESS_LEN; i++) {
        id = (id << 8) + *(toIdentifier + i);
    }
    if (*toIdentifier == 0xFF && id <= UINT64_MAX) {
        (*numItems)++;
    }

    if (unknownToken) {
        (*numItems) += 2;
    }
    if (expertMode) {
        (*numItems) += 3;
    }
    return parser_ok;
}

/**
 * @brief Parses and prints details of an Ethereum Virtual Machine (EVM) transaction.
 *
 * This function processes an EVM transaction object (`txObj`) and generates human-readable
 * output for display. It validates the transaction, extracts relevant details, and formats
 * them into key-value pairs for display purposes.
 *
 * @param txObj Pointer to the transaction object to be processed.
 * @param displayIdx Index of the display item to be printed.
 * @param outKey Buffer to store the key string for the display item.
 * @param outKeyLen Length of the `outKey` buffer.
 * @param outVal Buffer to store the value string for the display item.
 * @param outValLen Length of the `outVal` buffer.
 * @param pageIdx Index of the page to be displayed (for paginated output).
 * @param pageCount Pointer to store the total number of pages for the display.
 * @return `parser_ok` on success, or an error code on failure.
 */
parser_error_t printInvokeEVM(const fil_base_tx_t *txObj, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    // Check if the transaction object, output key, output value, or page count is NULL.
    if (txObj == NULL || outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    // Check if the transaction method is INVOKE_EVM_METHOD and if it is an ERC20 transfer.
    if (txObj->method != INVOKE_EVM_METHOD || !isInvokeEVM_ERC20Transfer(txObj)) {
        return parser_value_out_of_range;
    }

    // Initialize the page count to 1.
    *pageCount = 1;

    // Check if the transaction is an ERC20 transfer.
    const uint16_t addressIdentifier = txObj->to.buffer[0] << 8 | txObj->to.buffer[1];
    if (txObj->value.len != 0 || txObj->to.len != F4_ETH_ADDRESS_BYTES_LEN ||
        addressIdentifier != F4_ETH_ADDRESS_IDENTIFIER) {
        return parser_unexpected_error;
    }
    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.tx.value = tmpValue, .tx.to = tokenContract, .tx.data = data};

    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_PARSER_ERR(getERC20Token(&tmpEthObj, tokenSymbol, &decimals));
    const bool knownToken = (memcmp(tokenSymbol, "?? ", 3) != 0);

    // Check if the from identifier is an F4 address.
    const uint16_t fromIdentifier = txObj->from.buffer[0] << 8 | txObj->from.buffer[1];

    // Adjust the display index if the from identifier is not an F4 address.
    uint8_t adjustedIndex = displayIdx;
    if (adjustedIndex >= 1 && fromIdentifier != F4_ETH_ADDRESS_IDENTIFIER) {
        adjustedIndex++;
    }

    // Check if the to identifier is an F4 address.
    const uint8_t *toIdentifier = txObj->params + SELECTOR_LENGTH + (BIGINT_LENGTH - ETH_ADDRESS_LEN);

    // Adjust the display index if the to identifier is not an F4 address.
    if (adjustedIndex >= 4 && *toIdentifier != 0xFF) {
        adjustedIndex++;
    }

    if (adjustedIndex >= 5 && knownToken) {
        adjustedIndex += 2;
    }

    switch (adjustedIndex) {
        case 0:
            snprintf(outKey, outKeyLen, "Method");
            snprintf(outVal, outValLen, "ERC20 Transfer");
            break;

        case 1:
            snprintf(outKey, outKeyLen, "From");
            CHECK_PARSER_ERR(printEthAddress(&txObj->from, outVal, outValLen, pageIdx, pageCount));
            break;

        case 2:
            snprintf(outKey, outKeyLen, "From");
            CHECK_PARSER_ERR(printAddress(&txObj->from, outVal, outValLen, pageIdx, pageCount));
            break;

        case 3:
            snprintf(outKey, outKeyLen, "To");
            rlp_t to = {.kind = RLP_KIND_STRING,
                        .ptr = (txObj->params + SELECTOR_LENGTH + (BIGINT_LENGTH - ETH_ADDRESS_LEN)),
                        .rlpLen = ETH_ADDRESS_LEN};
            CHECK_PARSER_ERR(printEVMAddress(&to, outVal, outValLen, pageIdx, pageCount));
            break;

        case 4: {
            snprintf(outKey, outKeyLen, "To");
            const uint8_t *toPtr = txObj->params + SELECTOR_LENGTH + (BIGINT_LENGTH - ETH_ADDRESS_LEN);
            CHECK_PARSER_ERR(print0xToF0(toPtr, ETH_ADDRESS_LEN, outVal, outValLen, pageIdx, pageCount));
            break;
        }

        case 5: {
            snprintf(outKey, outKeyLen, "Token Contract");
            rlp_t contractAddress = {.kind = RLP_KIND_STRING, .ptr = (txObj->to.buffer + 2), .rlpLen = ETH_ADDRESS_LEN};
            CHECK_PARSER_ERR(printEVMAddress(&contractAddress, outVal, outValLen, pageIdx, pageCount));
            break;
        }

        case 6:
            snprintf(outKey, outKeyLen, "Token Contract");
            CHECK_PARSER_ERR(printAddress(&txObj->to, outVal, outValLen, pageIdx, pageCount));
            break;

        case 7:
            snprintf(outKey, outKeyLen, "Value");
            CHECK_PARSER_ERR(printERC20Value(&tmpEthObj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 8: {
            char tmpBuffer[80] = {0};
            snprintf(outKey, outKeyLen, "Gas Limit");
            if (int64_to_str(tmpBuffer, sizeof(tmpBuffer), txObj->gaslimit) != NULL) {
                return parser_unexpected_error;
            }
            if (insertDecimalPoint(tmpBuffer, sizeof(tmpBuffer), COIN_AMOUNT_DECIMAL_PLACES) != zxerr_ok) {
                return parser_unexpected_error;
            }
            if (z_str3join(tmpBuffer, sizeof(tmpBuffer), "FIL ", NULL) != zxerr_ok) {
                return parser_unexpected_error;
            }
            pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
            break;
        }

        case 9:
            snprintf(outKey, outKeyLen, "Gas Fee Cap");
            CHECK_PARSER_ERR(parser_printBigIntFixedPoint(&txObj->gasfeecap, outVal, outValLen, pageIdx, pageCount,
                                                          COIN_AMOUNT_DECIMAL_PLACES));
            break;

        case 10:
            snprintf(outKey, outKeyLen, "Gas Premium");
            CHECK_PARSER_ERR(parser_printBigIntFixedPoint(&txObj->gaspremium, outVal, outValLen, pageIdx, pageCount,
                                                          COIN_AMOUNT_DECIMAL_PLACES));
            break;

        case 11:
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
    if (txObj->value.len != 0 || txObj->to.len != F4_ETH_ADDRESS_BYTES_LEN ||
        addressIdentifier != F4_ETH_ADDRESS_IDENTIFIER) {
        return false;
    }

    rlp_t tmpValue = {0};
    rlp_t tokenContract = {.ptr = txObj->to.buffer + 2, .rlpLen = ETH_ADDRESS_LEN, .kind = RLP_KIND_STRING};
    rlp_t data = {.ptr = txObj->params, .rlpLen = ERC20_TRANSFER_DATA_LENGTH, .kind = RLP_KIND_STRING};
    eth_tx_t tmpEthObj = {.tx.value = tmpValue, .tx.to = tokenContract, .tx.data = data};
    return validateERC20(&tmpEthObj);
}
