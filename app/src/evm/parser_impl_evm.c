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

#include "parser_impl_evm.h"

#include <stdio.h>
#include <zxmacros.h>

#include "app_mode.h"
#include "crypto.h"
#include "evm_erc20.h"
#include "evm_utils.h"
#include "parser_common.h"
#include "parser_txdef.h"
#include "rlp.h"
#include "uint256.h"
#include "zxformat.h"

eth_tx_t eth_tx_obj;
#define FILECOIN_MAINNET_CHAINID 314
#define FILECOIN_CALIBRATION_CHAINID 314159

static parser_error_t readChainID(parser_context_t *ctx, rlp_t *chainId) {
    if (ctx == NULL || chainId == NULL) {
        return parser_unexpected_error;
    }

    CHECK_PARSER_ERR(rlp_read(ctx, chainId));
    uint64_t tmpChainId = 0;
    CHECK_PARSER_ERR(be_bytes_to_u64(chainId->ptr, chainId->rlpLen, &tmpChainId))

    // Check allowed values for chain id
    if (tmpChainId != FILECOIN_MAINNET_CHAINID && tmpChainId != FILECOIN_CALIBRATION_CHAINID) {
        return parser_invalid_chain_id;
    }

    return parser_ok;
}

static parser_error_t parse_legacy_tx(parser_context_t *ctx, eth_tx_t *tx_obj) {
    if (ctx == NULL || tx_obj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_PARSER_ERR(rlp_read(ctx, &tx_obj->tx.nonce));
    CHECK_PARSER_ERR(rlp_read(ctx, &(tx_obj->tx.gasPrice)));
    CHECK_PARSER_ERR(rlp_read(ctx, &(tx_obj->tx.gasLimit)));
    CHECK_PARSER_ERR(rlp_read(ctx, &(tx_obj->tx.to)));
    CHECK_PARSER_ERR(rlp_read(ctx, &(tx_obj->tx.value)));
    CHECK_PARSER_ERR(rlp_read(ctx, &(tx_obj->tx.data)));

    // Check for legacy no EIP155 which means no chain_id
    // There is not more data no eip155 compliant tx
    if (ctx->offset == ctx->bufferLen) {
        tx_obj->chainId.kind = RLP_KIND_BYTE;
        tx_obj->chainId.ptr = NULL;
        tx_obj->chainId.rlpLen = 0;
        return parser_ok;
    }

    // Otherwise legacy EIP155 in which case should come with empty r and s values
    // Transaction comes with a chainID so it is EIP155 compliant
    CHECK_PARSER_ERR(readChainID(ctx, &tx_obj->chainId));

    // Check R and S fields
    rlp_t sig_r = {0};
    CHECK_PARSER_ERR(rlp_read(ctx, &sig_r));

    rlp_t sig_s = {0};
    CHECK_PARSER_ERR(rlp_read(ctx, &sig_s));

    // R and S values should be either 0 or 0x80
    if ((sig_r.rlpLen == 0 && sig_s.rlpLen == 0) ||
        ((sig_r.rlpLen == 1 && sig_s.rlpLen == 1) && !(*sig_r.ptr | *sig_s.ptr))) {
        return parser_ok;
    }
    return parser_invalid_rs_values;
}

static parser_error_t parse_2930(parser_context_t *ctx, eth_tx_t *tx_obj) {
    // the chain_id is the first field for this transaction
    // later we can implement the parser for the other fields
    CHECK_PARSER_ERR(readChainID(ctx, &tx_obj->chainId));

    return parser_ok;
}

static parser_error_t parse_1559(parser_context_t *ctx, eth_tx_t *tx_obj) {
    // the chain_id is the first field for this transaction
    // later we can implement the parser for the other fields
    CHECK_PARSER_ERR(readChainID(ctx, &tx_obj->chainId));

    return parser_ok;
}

static parser_error_t readTxnType(parser_context_t *ctx, eth_tx_type_e *type) {
    if (ctx == NULL || type == NULL || ctx->bufferLen == 0 || ctx->offset != 0) {
        return parser_unexpected_error;
    }
    // Check first byte:
    //    0x01 --> EIP2930
    //    0x02 --> EIP1559
    // >= 0xC0 --> Legacy
    uint8_t marker = *(ctx->buffer + ctx->offset);

    if (marker == eip2930 || marker == eip1559) {
        *type = (eth_tx_type_e)marker;
        ctx->offset++;
        return parser_ok;
    }

    // Legacy tx type is greater than or equal to 0xc0.
    if (marker < legacy) {
        return parser_unsupported_tx;
    }

    *type = legacy;
    return parser_ok;
}

parser_error_t _readEth(parser_context_t *ctx, eth_tx_t *tx_obj) {
    MEMZERO(&eth_tx_obj, sizeof(eth_tx_obj));
    CHECK_PARSER_ERR(readTxnType(ctx, &tx_obj->tx_type))
    // We expect a list with all the fields from the transaction
    rlp_t list = {0};
    CHECK_PARSER_ERR(rlp_read(ctx, &list));

    // Check that the first RLP element is a list
    if (list.kind != RLP_KIND_LIST) {
        return parser_unexpected_value;
    }

    // All bytes must be read
    if (ctx->offset != ctx->bufferLen) {
        return parser_unexpected_characters;
    }

    parser_context_t txCtx = {.buffer = list.ptr, .bufferLen = list.rlpLen, .offset = 0, .tx_type = eth_tx};
    switch (tx_obj->tx_type) {
        case eip1559: {
            return parse_1559(&txCtx, tx_obj);
        }

        case eip2930: {
            return parse_2930(&txCtx, tx_obj);
        }

        case legacy: {
            return parse_legacy_tx(&txCtx, tx_obj);
        }
    }
    return parser_unexpected_error;
}

parser_error_t _validateTxEth() {
    if (!validateERC20(&eth_tx_obj) && !app_mode_blindsign()) {
        return parser_blindsign_mode_required;
    }

    return parser_ok;
}

static parser_error_t printERC20(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    *pageCount = 1;

    const eth_base_t *legacy = &eth_tx_obj.tx;
    char tokenSymbol[10] = {0};
    uint8_t decimals = 0;
    CHECK_PARSER_ERR(getERC20Token(&eth_tx_obj, tokenSymbol, &decimals));
    bool hideContract = (memcmp(tokenSymbol, "?? ", 3) != 0);

    displayIdx += (displayIdx && hideContract) ? 1 : 0;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "To");
            rlp_t to = {.kind = RLP_KIND_STRING, .ptr = (eth_tx_obj.tx.data.ptr + 4 + 12), .rlpLen = ETH_ADDRESS_LEN};
            CHECK_PARSER_ERR(printEVMAddress(&to, outVal, outValLen, pageIdx, pageCount));
            break;

        case 1:
            snprintf(outKey, outKeyLen, "Token Contract");
            rlp_t contractAddress = {.kind = RLP_KIND_STRING, .ptr = eth_tx_obj.tx.to.ptr, .rlpLen = ETH_ADDRESS_LEN};
            CHECK_PARSER_ERR(printEVMAddress(&contractAddress, outVal, outValLen, pageIdx, pageCount));
            break;

        case 2:
            snprintf(outKey, outKeyLen, "Value");
            CHECK_PARSER_ERR(printERC20Value(&eth_tx_obj, outVal, outValLen, pageIdx, pageCount));
            break;

        case 3:
            snprintf(outKey, outKeyLen, "Nonce");
            CHECK_PARSER_ERR(printRLPNumber(&legacy->nonce, outVal, outValLen, pageIdx, pageCount));
            break;

        case 4:
            snprintf(outKey, outKeyLen, "Gas price");
            CHECK_PARSER_ERR(printRLPNumber(&legacy->gasPrice, outVal, outValLen, pageIdx, pageCount));
            break;

        case 5:
            snprintf(outKey, outKeyLen, "Gas limit");
            CHECK_PARSER_ERR(printRLPNumber(&legacy->gasLimit, outVal, outValLen, pageIdx, pageCount));
            break;

        default:
            return parser_display_page_out_of_range;
    }

    return parser_ok;
}

parser_error_t _getItemEth(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                           char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    // At the moment, clear signing is available only for ERC20
    if (validateERC20(&eth_tx_obj)) {
        return printERC20(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    // Otherwise, check that Blindsign is enabled
    if (!app_mode_blindsign()) {
        return parser_blindsign_mode_required;
    }

    if (displayIdx > 1) {
        return parser_display_idx_out_of_range;
    }

    // we need to get keccak hash of the transaction data
    uint8_t hash[32] = {0};
    keccak_digest(ctx->buffer, ctx->bufferLen, hash, 32);

    // now get the hex string of the hash
    char hex[65] = {0};
    array_to_hexstr(hex, 65, hash, 32);

    snprintf(outKey, outKeyLen, "Eth-Hash:");

    pageString(outVal, outValLen, hex, pageIdx, pageCount);

    return parser_ok;
}

// returns the number of items to display on the screen.
// Note: we might need to add a transaction state object,
// Defined with one parameter for now.
parser_error_t _getNumItemsEth(uint8_t *numItems) {
    if (numItems == NULL) {
        return parser_unexpected_error;
    }
    // Verify that tx is ERC20

    if (validateERC20(&eth_tx_obj)) {
        char tokenSymbol[10] = {0};
        uint8_t decimals = 0;
        CHECK_PARSER_ERR(getERC20Token(&eth_tx_obj, tokenSymbol, &decimals));
        // If token is not recognized, print value address
        *numItems = (memcmp(tokenSymbol, "?? ", 3) != 0) ? 5 : 6;
        return parser_ok;
    }

    // Eth transaction hash.
    *numItems = 1;
    return parser_ok;
}

parser_error_t _computeV(parser_context_t *ctx, eth_tx_t *tx_obj, unsigned int info, uint8_t *v) {
    if (ctx == NULL || tx_obj == NULL || v == NULL) {
        return parser_unexpected_error;
    }

    uint8_t type = eth_tx_obj.tx_type;
    uint8_t parity = (info & CX_ECCINFO_PARITY_ODD) == 1;

    if (type == eip2930 || type == eip1559) {
        *v = parity;
        return parser_ok;
    }

    // we need chainID info
    if (tx_obj->chainId.rlpLen == 0) {
        // according to app-ethereum this is the legacy non eip155 conformant
        // so V should be made before EIP155 which had
        // 27 + {0, 1}
        // 27, decided by the parity of Y
        // see https://bitcoin.stackexchange.com/a/112489
        //     https://ethereum.stackexchange.com/a/113505
        //     https://eips.ethereum.org/EIPS/eip-155
        *v = 27 + parity;

    } else {
        uint64_t id = 0;
        CHECK_PARSER_ERR(be_bytes_to_u64(tx_obj->chainId.ptr, tx_obj->chainId.rlpLen, &id));

        uint32_t cv = 35 + parity;
        cv = saturating_add_u32(cv, (uint32_t)id * 2);
        *v = (uint8_t)cv;
    }

    return parser_ok;
}
