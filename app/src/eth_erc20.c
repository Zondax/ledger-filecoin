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

#include "eth_erc20.h"
#include "zxformat.h"

// Prefix is calculated as: keccak256("transfer(address,uint256)") = 0xa9059cbb
const uint8_t ERC20_TRANSFER_PREFIX[] = {0xa9, 0x05, 0x9c, 0xbb};
#define ERC20_DATA_LENGTH 68 // 4 + 32 + 32
#define ADDRESS_CONTRACT_LENGTH 20
#define DECIMAL_BASE 10
const erc20_tokens_t supportedTokens[] = {


    {{0x3C, 0x35, 0x01, 0xE6, 0xC3, 0x53, 0xDb, 0xaE, 0xDD, 0xFA, 0x90, 0x37, 0x69, 0x75, 0xCe, 0x7a, 0xCe, 0x4A, 0xc7, 0xa8},
    "stFIL ",
    18},

    {{0x60, 0xE1, 0x77, 0x36, 0x36, 0xCF, 0x5E, 0x4A, 0x22, 0x7d, 0x9A, 0xC2, 0x4F, 0x20, 0xfE, 0xca, 0x03, 0x4e, 0xe2, 0x5A},
    "WFIL ",
    18},

    {{0x69, 0x09, 0x08, 0xf7, 0xfa, 0x93, 0xaf, 0xC0, 0x40, 0xCF, 0xbD, 0x9f, 0xE1, 0xdD, 0xd2, 0xC2, 0x66, 0x8A, 0xa0, 0xe0},
    "iFIL ",
    18},

    {{0x6A, 0x3F, 0x21, 0xd2, 0xA9, 0x2a, 0x15, 0x75, 0x29, 0x12, 0x97, 0x4B, 0xbB, 0xD5, 0xb1, 0x46, 0x9A, 0x72, 0xB2, 0x61},
    "wstFIL ",
    18},

    {{0xd0, 0x43, 0x77, 0x65, 0xD1, 0xDc, 0x0e, 0x2f, 0xA1, 0x4E, 0x97, 0xd2, 0x90, 0xF1, 0x35, 0xeF, 0xdF, 0x1a, 0x8a, 0x9A},
    "clFIL ",
    18},

    {{0x42, 0x28, 0x49, 0xB3, 0x55, 0x03, 0x9b, 0xC5, 0x8F, 0x27, 0x80, 0xcc, 0x48, 0x54, 0x91, 0x9f, 0xC9, 0xcf, 0xaF, 0x94},
    "USDT ",
    6},
};

parser_error_t getERC20Token(const rlp_t *data, char tokenSymbol[MAX_SYMBOL_LEN], uint8_t *decimals) {
    if (data == NULL || tokenSymbol == NULL || decimals == NULL ||
        data->rlpLen != ERC20_DATA_LENGTH || memcmp(data->ptr, ERC20_TRANSFER_PREFIX, 4) != 0) {
        return parser_unexpected_value;
    }

    // Verify address contract: first 12 bytes must be 0
    const uint8_t *addressPtr = data->ptr + 4;
    for (uint8_t i = 0; i < 12; i++) {
        if (*(addressPtr++) != 0 ) {
            return parser_unexpected_value;
        }
    }

    // Check if token is in the list
    const uint8_t supportedTokensSize = sizeof(supportedTokens)/sizeof(supportedTokens[0]);
    for (uint8_t i = 0; i < supportedTokensSize; i++) {
        if (memcmp(addressPtr, supportedTokens[i].address, ADDRESS_CONTRACT_LENGTH) == 0) {
            // Set symbol and decimals
            snprintf(tokenSymbol, 10, "%s", (char*) PIC(supportedTokens[i].symbol));
            *decimals = supportedTokens[i].decimals;
            return parser_ok;
        }
    }

    // Unknonw token
    snprintf(tokenSymbol, 10, "?? ");
    *decimals = 0;
    return parser_ok;
}
parser_error_t printERC20Value(const rlp_t *data, char *outVal, uint16_t outValLen,
                               uint8_t pageIdx, uint8_t *pageCount) {
    if (data == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    // [identifier (4) | token contract (12 + 20) | value (32)]
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_PARSER_ERR(getERC20Token(data, tokenSymbol, &decimals))

    uint256_t value = {0};
    const uint8_t *valuePtr = data->ptr + 4 + 12 + ADDRESS_CONTRACT_LENGTH;
    parser_context_t tmpCtx = {.buffer = valuePtr, .bufferLen = 32, .offset = 0, .tx_type = eth_tx};
    CHECK_PARSER_ERR(readu256BE(&tmpCtx, &value));

    char bufferUI[100] = {0};
    if (!tostring256(&value, DECIMAL_BASE, bufferUI, sizeof(bufferUI))) {
        return parser_unexpected_error;
    }

    //Add symbol, add decimals, page number
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

bool validateERC20(rlp_t data) {
    // Check that data start with ERC20 prefix
    if (data.ptr == NULL || data.rlpLen != ERC20_DATA_LENGTH || memcmp(data.ptr, ERC20_TRANSFER_PREFIX, 4) != 0) {
        return false;
    }

    return true;
}
