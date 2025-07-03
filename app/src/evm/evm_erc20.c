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

// Prefix is calculated as: keccak256("transfer(address,uint256)") = 0xa9059cbb
const uint8_t ERC20_TRANSFER_PREFIX[] = {0xa9, 0x05, 0x9c, 0xbb};
#define DECIMAL_BASE 10
const erc20_tokens_t supportedTokens[] = {

    {{0x60, 0xE1, 0x77, 0x36, 0x36, 0xCF, 0x5E, 0x4A, 0x22, 0x7d,
      0x9A, 0xC2, 0x4F, 0x20, 0xfE, 0xca, 0x03, 0x4e, 0xe2, 0x5A},
     "WFIL ",
     18},

    {{0x3C, 0x35, 0x01, 0xE6, 0xC3, 0x53, 0xDb, 0xaE, 0xDD, 0xFA,
      0x90, 0x37, 0x69, 0x75, 0xCe, 0x7a, 0xCe, 0x4A, 0xc7, 0xa8},
     "stFIL ",
     18},

    {{0x6A, 0x3F, 0x21, 0xd2, 0xA9, 0x2a, 0x15, 0x75, 0x29, 0x12,
      0x97, 0x4B, 0xbB, 0xD5, 0xb1, 0x46, 0x9A, 0x72, 0xB2, 0x61},
     "wstFIL ",
     18},

    {{0x69, 0x09, 0x08, 0xf7, 0xfa, 0x93, 0xaf, 0xC0, 0x40, 0xCF,
      0xbD, 0x9f, 0xE1, 0xdD, 0xd2, 0xC2, 0x66, 0x8A, 0xa0, 0xe0},
     "iFIL ",
     18},

    {{0xd0, 0x43, 0x77, 0x65, 0xD1, 0xDc, 0x0e, 0x2f, 0xA1, 0x4E,
      0x97, 0xd2, 0x90, 0xF1, 0x35, 0xeF, 0xdF, 0x1a, 0x8a, 0x9A},
     "clFIL ",
     18},

    {{0xeb, 0x46, 0x63, 0x42, 0xc4, 0xd4, 0x49, 0xbc, 0x9f, 0x53,
      0xa8, 0x65, 0xd5, 0xcb, 0x90, 0x58, 0x6f, 0x40, 0x52, 0x15},
     "axlUSDC ",
     6},

    {{0xaa, 0xa9, 0x3a, 0xc7, 0x2b, 0xec, 0xfb, 0xbc, 0x91, 0x49,
      0xf2, 0x93, 0x46, 0x6b, 0xbd, 0xaa, 0x4b, 0x5e, 0xf6, 0x8c},
     "pFIL ",
     18},

    {{0x57, 0xe3, 0xbb, 0x9f, 0x79, 0x01, 0x85, 0xcf, 0xe7, 0x0c,
      0xc2, 0xc1, 0x5e, 0xd5, 0xd6, 0xb8, 0x4d, 0xcf, 0x4a, 0xdb},
     "wpFIL ",
     18},

    {{0xC5, 0xeA, 0x96, 0xDd, 0x36, 0x59, 0x83, 0xcf, 0xEc, 0x90,
      0xE7, 0x2b, 0x6A, 0x2d, 0xaC, 0x95, 0x62, 0xf4, 0x58, 0xBa},
     "SFT ",
     18},

    {{0x84, 0xb0, 0x38, 0xdb, 0x0f, 0xcd, 0xe4, 0xfa, 0xe5, 0x28,
      0x10, 0x86, 0x03, 0xc7, 0x37, 0x66, 0x95, 0xdc, 0x21, 0x7f},
     "NFIL ",
     18},

    {{0x80, 0xB9, 0x8d, 0x3a, 0xa0, 0x9f, 0xff, 0xf2, 0x55, 0xc3,
      0xba, 0x4A, 0x24, 0x11, 0x11, 0xFf, 0x12, 0x62, 0xF0, 0x45},
     "USDFC ",
     18},

    {{0x2a, 0x0a, 0xaf, 0x86, 0xb2, 0xFA, 0x64, 0xE8, 0x8D, 0x37,
      0x39, 0x09, 0x1e, 0x77, 0x73, 0x10, 0x6F, 0x3e, 0xbC, 0xF5},
     "GLF ",
     18},
};

parser_error_t getERC20Token(const eth_tx_t *ethObj, char tokenSymbol[MAX_SYMBOL_LEN], uint8_t *decimals) {
    if (ethObj == NULL || tokenSymbol == NULL || decimals == NULL ||
        ethObj->tx.data.rlpLen != ERC20_TRANSFER_DATA_LENGTH ||
        memcmp(ethObj->tx.data.ptr, ERC20_TRANSFER_PREFIX, 4) != 0) {
        return parser_unexpected_value;
    }

    // Verify address contract: first 12 bytes must be 0
    const uint8_t *addressPtr = ethObj->tx.data.ptr + 4;
    for (uint8_t i = 0; i < 12; i++) {
        if (*(addressPtr++) != 0) {
            return parser_unexpected_value;
        }
    }

    // Check if token is in the list
    const uint8_t supportedTokensSize = sizeof(supportedTokens) / sizeof(supportedTokens[0]);
    for (uint8_t i = 0; i < supportedTokensSize; i++) {
        if (memcmp(ethObj->tx.to.ptr, supportedTokens[i].address, ETH_ADDRESS_LEN) == 0) {
            // Set symbol and decimals
            snprintf(tokenSymbol, 10, "%s", (char *)PIC(supportedTokens[i].symbol));
            *decimals = supportedTokens[i].decimals;
            return parser_ok;
        }
    }

    // Unknonw token
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
    parser_context_t tmpCtx = {.buffer = valuePtr, .bufferLen = BIGINT_LENGTH, .offset = 0, .tx_type = eth_tx};
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
    // Check that data start with ERC20 prefix
    const bool isPayable = false;  // ethObj->tx.value;

    if (ethObj == NULL || isPayable || ethObj->tx.to.rlpLen != ETH_ADDRESS_LEN || ethObj->tx.data.ptr == NULL ||
        ethObj->tx.data.rlpLen != ERC20_TRANSFER_DATA_LENGTH ||
        memcmp(ethObj->tx.data.ptr, ERC20_TRANSFER_PREFIX, sizeof(ERC20_TRANSFER_PREFIX)) != 0) {
        return false;
    }

    return true;
}
