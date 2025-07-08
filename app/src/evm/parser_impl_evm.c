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

// External implementation specific to each app
extern parser_error_t getNumItemsEthAppSpecific(uint8_t *numItems);
extern parser_error_t printGenericAppSpecific(const parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                              uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                              uint8_t *pageCount);
extern parser_error_t printERC20TransferAppSpecific(eth_tx_t *ethTxObj, uint8_t displayIdx, char *outKey,
                                                    uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                    uint8_t pageIdx, uint8_t *pageCount);

eth_tx_t eth_tx_obj;

#define ETHEREUM_RECOVERY_OFFSET 27
#define EIP155_V_BASE 35

static parser_error_t readChainID(parser_context_t *ctx, rlp_t *chainId) {
    if (ctx == NULL || chainId == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(rlp_read(ctx, chainId));
    uint64_t tmpChainId = 0;
    if (chainId->rlpLen > 1) {
        CHECK_ERROR(be_bytes_to_u64(chainId->ptr, chainId->rlpLen, &tmpChainId))
    } else if (chainId->kind == RLP_KIND_BYTE) {
        // case were the prefix is the byte itself
        tmpChainId = chainId->ptr[0];
    } else {
        return parser_unexpected_error;
    }

    if (supported_networks_evm_len < 1) {
        return parser_chain_id_not_configured;
    }

    // Check allowed values for chain id using external configuration
    for (uint8_t i = 0; i < supported_networks_evm_len; i++) {
        if (tmpChainId == supported_networks_evm[i]) {
            chainId->chain_id_decoded = tmpChainId;
            return parser_ok;
        }
    }

    return parser_invalid_chain_id;
}

static parser_error_t parse_legacy_tx(parser_context_t *ctx, eth_tx_t *tx_obj) {
    if (ctx == NULL || tx_obj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(rlp_read(ctx, &tx_obj->tx.nonce));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.gasPrice)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.gasLimit)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.to)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.value)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.data)));

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
    CHECK_ERROR(readChainID(ctx, &tx_obj->chainId));

    // Check R and S fields
    rlp_t sig_r = {0};
    CHECK_ERROR(rlp_read(ctx, &sig_r));

    rlp_t sig_s = {0};
    CHECK_ERROR(rlp_read(ctx, &sig_s));

    // R and S values should be either 0 or 0x80
    if ((sig_r.rlpLen == 0 && sig_s.rlpLen == 0) ||
        ((sig_r.rlpLen == 1 && sig_s.rlpLen == 1) && !(*sig_r.ptr | *sig_s.ptr))) {
        return parser_ok;
    }
    return parser_invalid_rs_values;
}

static parser_error_t parse_2930(parser_context_t *ctx, eth_tx_t *tx_obj) {
    if (ctx == NULL || tx_obj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readChainID(ctx, &tx_obj->chainId));
    CHECK_ERROR(rlp_read(ctx, &tx_obj->tx.nonce));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.gasPrice)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.gasLimit)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.to)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.value)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.data)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.access_list)));

    // R and S fields should be empty
    if (ctx->offset < ctx->bufferLen) {
        return parser_unsupported_tx;
    }

    return parser_ok;
}

static parser_error_t parse_1559(parser_context_t *ctx, eth_tx_t *tx_obj) {
    if (ctx == NULL || tx_obj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readChainID(ctx, &tx_obj->chainId));
    CHECK_ERROR(rlp_read(ctx, &tx_obj->tx.nonce));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.max_priority_fee_per_gas)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.max_fee_per_gas)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.gasLimit)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.to)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.value)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.data)));
    CHECK_ERROR(rlp_read(ctx, &(tx_obj->tx.access_list)));

    // R and S fields should be empty
    if (ctx->offset < ctx->bufferLen) {
        return parser_unsupported_tx;
    }

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
    if (ctx == NULL || tx_obj == NULL) {
        return parser_unexpected_value;
    }

    MEMZERO(&eth_tx_obj, sizeof(eth_tx_obj));
    CHECK_ERROR(readTxnType(ctx, &tx_obj->tx_type))
    // We expect a list with all the fields from the transaction
    rlp_t list = {0};
    CHECK_ERROR(rlp_read(ctx, &list));

    // Check that the first RLP element is a list
    if (list.kind != RLP_KIND_LIST) {
        return parser_unexpected_value;
    }

    // All bytes must be read
    if (ctx->offset != ctx->bufferLen) {
        return parser_unsupported_tx;
    }

    parser_context_t txCtx = {.buffer = list.ptr, .bufferLen = list.rlpLen, .offset = 0};
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

parser_error_t printEthHash(const parser_context_t *ctx, char *outKey, uint16_t outKeyLen, char *outVal,
                            uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (ctx == NULL || outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    // we need to get keccak hash of the transaction data
    uint8_t hash[32] = {0};
#if defined(LEDGER_SPECIFIC)
    keccak_digest(ctx->buffer, ctx->bufferLen, hash, 32);
#endif

    // now get the hex string of the hash
    char hex[65] = {0};
    array_to_hexstr(hex, 65, hash, 32);

    snprintf(outKey, outKeyLen, "Eth-Hash:");

    pageString(outVal, outValLen, hex, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t _validateTxEth() {
    eth_tx_obj.is_blindsign = true;
    if (eth_tx_obj.tx.data.rlpLen == 0 || validateERC20(&eth_tx_obj)) {
        app_mode_skip_blindsign_ui();
        eth_tx_obj.is_blindsign = false;
    } else if (!app_mode_blindsign()) {
        return parser_blindsign_mode_required;
    }

    return parser_ok;
}

static parser_error_t printERC20Transfer(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                         uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    *pageCount = 1;

    return printERC20TransferAppSpecific(&eth_tx_obj, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                         pageCount);
}

static parser_error_t printGeneric(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    if (outKey == NULL || outVal == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    *pageCount = 1;

    return printGenericAppSpecific(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t _getItemEth(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                           char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    // At the moment, clear signing is available only for ERC20
    if (eth_tx_obj.is_erc20_transfer) {
        return printERC20Transfer(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
    }

    return printGeneric(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

// returns the number of items to display on the screen.
// Note: we might need to add a transaction state object,
// Defined with one parameter for now.
parser_error_t _getNumItemsEth(uint8_t *numItems) { return getNumItemsEthAppSpecific(numItems); }

// https://github.com/LedgerHQ/ledger-live/commit/b93a421866519b80fdd8a029caea97323eceae93
parser_error_t _computeV(parser_context_t *ctx, eth_tx_t *tx_obj, unsigned int info, uint8_t *v,
                         bool is_personal_message) {
    if (ctx == NULL || tx_obj == NULL || v == NULL) {
        return parser_unexpected_error;
    }

    uint8_t parity = info & CX_ECCINFO_PARITY_ODD;

    if (is_personal_message) {
        *v = ETHEREUM_RECOVERY_OFFSET + parity;
        return parser_ok;
    }

    uint8_t type = eth_tx_obj.tx_type;

    if (type == eip2930 || type == eip1559) {
        *v = parity;
        return parser_ok;
    }

    uint32_t chainId = (uint32_t)eth_tx_obj.chainId.chain_id_decoded;
    *v = (uint8_t)saturating_add_u32(EIP155_V_BASE + parity, chainId * 2);

    return parser_ok;
}
