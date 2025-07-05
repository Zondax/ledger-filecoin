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

#include "evm_erc20.h"

#include "zxformat.h"

#define EVM_SELECTOR_LENGTH 4
#define ERC20_ADDRESS_PADDING_LENGTH 12

// Prefix is calculated as: keccak256("transfer(address,uint256)") = 0xa9059cbb
const uint8_t ERC20_TRANSFER_PREFIX[] = {0xa9, 0x05, 0x9c, 0xbb};
#define DECIMAL_BASE 10

parser_error_t getERC20Token(const eth_tx_t *ethObj, char tokenSymbol[MAX_SYMBOL_LEN], uint8_t *decimals) {
    if (ethObj == NULL || tokenSymbol == NULL || decimals == NULL || ethObj->tx.data.rlpLen != ERC20_DATA_LENGTH ||
        memcmp(ethObj->tx.data.ptr, ERC20_TRANSFER_PREFIX, EVM_SELECTOR_LENGTH) != 0) {
        return parser_unexpected_value;
    }

    // Verify address contract: first 12 bytes must be 0
    const uint8_t *addressPtr = ethObj->tx.data.ptr + 4;
    for (uint8_t i = 0; i < ERC20_ADDRESS_PADDING_LENGTH; i++) {
        if (*(addressPtr++) != 0) {
            return parser_unexpected_value;
        }
    }

    // Check if token is in the list
    for (uint8_t i = 0; i < supportedTokensSize; i++) {
        if (memcmp(ethObj->tx.to.ptr, supportedTokens[i].address, ETH_ADDRESS_LEN) == 0) {
            // Set symbol and decimals
            snprintf(tokenSymbol, 10, "%s", (char *)PIC(supportedTokens[i].symbol));
            *decimals = supportedTokens[i].decimals;
            return parser_ok;
        }
    }

    snprintf(tokenSymbol, 10, "?? ");
    *decimals = 0;
    return parser_ok;
}

parser_error_t printERC20Value(const eth_tx_t *ethObj, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {
    if (ethObj == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    // [identifier (4) | token contract (12 + 20) | value (32)]
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_ERROR(getERC20Token(ethObj, tokenSymbol, &decimals))

    uint256_t value = {0};
    const uint8_t *valuePtr = ethObj->tx.data.ptr + SELECTOR_LENGTH + BIGINT_LENGTH;
    parser_context_t tmpCtx = {.buffer = valuePtr, .bufferLen = BIGINT_LENGTH, .offset = 0};
    CHECK_ERROR(readu256BE(&tmpCtx, &value));

    char bufferUI[100] = {0};
    if (!tostring256(&value, DECIMAL_BASE, bufferUI, sizeof(bufferUI))) {
        return parser_unexpected_error;
    }

    // Add symbol, add decimals, page number
    if (intstr_to_fpstr_inplace(bufferUI, sizeof(bufferUI), decimals) == 0) {
        return parser_unexpected_value;
    }

    if (z_str3join(bufferUI, sizeof(bufferUI), tokenSymbol, NULL) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    number_inplace_trimming(bufferUI, 1);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);

    return parser_ok;
}

bool validateERC20(eth_tx_t *ethObj) {
    if (ethObj == NULL) {
        return false;
    }
    // Check that data start with ERC20 prefix
    if (ethObj->tx.to.rlpLen != ETH_ADDRESS_LEN || ethObj->tx.data.ptr == NULL ||
        ethObj->tx.data.rlpLen != ERC20_DATA_LENGTH ||
        memcmp(ethObj->tx.data.ptr, ERC20_TRANSFER_PREFIX, sizeof(ERC20_TRANSFER_PREFIX)) != 0) {
        ethObj->is_erc20_transfer = false;
        return false;
    }
    ethObj->is_erc20_transfer = true;
    return true;
}
