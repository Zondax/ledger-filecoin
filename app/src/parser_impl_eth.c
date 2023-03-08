/*******************************************************************************
 *   (c) 2019 Zondax GmbH
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

#include "parser_impl_eth.h"
#include "app_mode.h"
#include "common/parser_common.h"
#include "crypto.h"
#include "eth_utils.h"
#include "parser_txdef.h"
#include "zxformat.h"
#include <stdio.h>
#include <zxmacros.h>

eth_tx_t eth_tx_obj;

parser_error_t readBigInt(parser_context_t *ctx, eth_big_int_t *big_int);
parser_error_t readAddress(parser_context_t *ctx, eth_addr_t *addr);
parser_error_t readChainID(parser_context_t *ctx, chain_id_t *chain_id);
parser_error_t parse_field( parser_context_t *parser, uint32_t *itemOffset, uint32_t *len);

parser_error_t parse_legacy_tx(parser_context_t *ctx, eth_tx_t *tx_obj);
parser_error_t parse_1559(parser_context_t *ctx, eth_tx_t *tx_obj);
parser_error_t parse_2930(parser_context_t *ctx, eth_tx_t *tx_obj);

parser_error_t readChainID(parser_context_t *ctx, chain_id_t *chain_id) {
    if ( parse_field(ctx, &(chain_id->offset), &(chain_id->len)) != parser_ok)
        return parser_invalid_rlp_data;

    return parser_ok;
}

parser_error_t readBigInt(parser_context_t *ctx, eth_big_int_t *big_int) {
    uint32_t offset;
    uint32_t len = 0;

    if ( parse_field(ctx, &(big_int->offset), &(big_int->len)) != rlp_ok)
        return parser_invalid_rlp_data;

    big_int->offset = offset;

    return parser_ok;
}

parser_error_t readAddress(parser_context_t *ctx, eth_addr_t *addr) {
    uint32_t addr_len = 0;
    uint32_t offset = 0;

    if ( parse_field(ctx, &offset, &addr_len) != parser_ok)
        return parser_invalid_rlp_data;

    // it is ok to have an empty address
    if (addr_len == 0){
        return parser_ok;
    }

    if (addr_len != ETH_ADDRESS_LEN || offset > ctx->bufferLen)
        return parser_invalid_address;

    MEMCPY(addr->addr, &ctx->buffer[offset], ETH_ADDRESS_LEN);

    // update offset 
    return parser_ok;
}

parser_error_t parse_field(parser_context_t *ctx, uint32_t *fieldOffset, uint32_t *len) {
    if (ctx->offset >= ctx->bufferLen)
        return parser_unexpected_buffer_end;


    uint32_t read = 0;

    uint8_t *data = &ctx->buffer[ctx->offset];

    if ( parse_rlp_item(data, ctx->bufferLen - ctx->offset, &read, len) != rlp_ok)
        return parser_invalid_rlp_data;

    *fieldOffset = ctx->offset + read;

    if (*fieldOffset > ctx->bufferLen)
        return parser_invalid_rlp_data;

    ctx->offset += read + *len; 

    return parser_ok;
}

parser_error_t parse_legacy_tx(parser_context_t *ctx, eth_tx_t *tx_obj) {
    // parse nonce 
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.nonce)));
    // parse gas_price
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.gas_price)));
    // parse gas_limit
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.gas_limit)));
    // parse address
    CHECK_PARSER_ERR(readAddress(ctx, &(tx_obj->legacy.address)));
    // parse_value
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.value)));
    // parse data
    CHECK_PARSER_ERR(parse_field(ctx, &(tx_obj->legacy.data_at), &tx_obj->legacy.dataLen));
    // two cases:
    // - legacy no EIP155 which means no chain_id
    // - legacy EIP155 in which case should come with empty r and s values
    if (ctx->bufferLen <= ctx->offset) {
        // there is not more data no eip155 compliant tx 
        tx_obj->chain_id.len = 0;
        return parser_ok;
    }

    // Transaction comes with a chainID so it is EIP155 compliant
    CHECK_PARSER_ERR(readChainID(ctx, &(tx_obj->chain_id)));

    if (tx_obj->chain_id.len == 0 || tx_obj->chain_id.len > MAX_CHAIN_LEN)
        return parser_invalid_chain_id;

    // r and s if not empty, should contain only one value which must be zero.
    // Usually for an eip155 transaction the last two bytes represent r and s and are 0x8080 
    uint32_t r_len = 0;
    uint32_t s_len = 0;
    uint32_t r_offset = 0;
    uint32_t s_offset = 0;

    // parse r
    CHECK_PARSER_ERR(parse_field(ctx, &r_offset, &r_len));
    // parse s
    CHECK_PARSER_ERR(parse_field(ctx, &s_offset, &s_len));

    if (r_len == 1 && s_len == 1 && ( ctx->buffer[r_offset] | ctx->buffer[s_offset])) {
        return parser_invalid_rs_values;
    } else if (r_len == 0 && s_len == 0 ) {
        return parser_ok;
    }

    return parser_invalid_rs_values;
}

parser_error_t parse_2930(parser_context_t *ctx, eth_tx_t *tx_obj) {
    // the chain_id is the first field for this transaction
    // later we can implement the parser for the other fields
    CHECK_PARSER_ERR(readChainID(ctx, &(tx_obj->chain_id)));

    if (tx_obj->chain_id.len == 0)
        return parser_invalid_chain_id;

    return parser_ok;
}

parser_error_t parse_1559(parser_context_t *ctx, eth_tx_t *tx_obj) {
    // the chain_id is the first field for this transaction
    // later we can implement the parser for the other fields
    CHECK_PARSER_ERR(readChainID(ctx, &(tx_obj->chain_id)));

    if (tx_obj->chain_id.len == 0)
        return parser_invalid_chain_id;

    return parser_ok;
}

parser_error_t parseEthTx(parser_context_t *ctx, eth_tx_t *tx_obj) {
    switch (tx_obj->tx_type) {
        case eip1559: {
            return parse_1559(ctx, tx_obj);
        }
        case eip2930:{
            return parse_2930(ctx, tx_obj);
        }
        default:{
            return parse_legacy_tx(ctx, tx_obj);
        }
    }
}

parser_error_t _readEth(parser_context_t *ctx, eth_tx_t *tx_obj)
{
    zemu_log_stack("_readEth");

    uint8_t marker = ctx->buffer[0];
    uint32_t start = ctx->offset;

    if (marker != eip2930 && marker != eip1559 && marker < 0xc0)
        return parser_unsupported_tx;

    if (marker == eip2930 || marker == eip1559)
        ctx->offset += 1; 


    // read the first byte, it indicates if transaction falls in one of the following:
    // - EIP1559
    // - EIP2930
    // -legacy
    tx_obj->tx_type = marker;

    uint32_t read = 0;
    uint32_t len = 0;

    // read out transaction rlp header(which indicates tx data length)
    if (parse_rlp_item(ctx->buffer + ctx->offset, ctx->bufferLen, &read, &len) != rlp_ok)
        // should not happen as this was check before
        return parser_unexepected_error;

    ctx->offset += read;

    if (ctx->offset > ctx->bufferLen)
        // should not happend though
        return parser_unexepected_error;

    // parser transaction
    parser_error_t err = parseEthTx(ctx, tx_obj);

    ctx->offset = start;

    if (err != parser_ok)
        return err;

    return parser_ok;
}

parser_error_t _validateTxEth(__Z_UNUSED const parser_context_t *ctx)
{
    return parser_ok;
}

parser_error_t _getItemEth(const parser_context_t *ctx,
            uint8_t displayIdx,
            char *outKey,
            uint16_t outKeyLen,
            char *outVal,
            uint16_t outValLen,
            uint8_t pageIdx,
            uint8_t *pageCount)
{
    if (displayIdx != 0)
        return parser_unexpected_number_items;

    // we need to get keccak hash of the transaction data
    uint8_t hash[32] = { 0 };
    keccak_digest(ctx->buffer, ctx->bufferLen, hash, 32);

    // now get the hex string of the hash
    char hex[65] = { 0 };
    array_to_hexstr(hex, 65, hash, 32);

    snprintf(outKey, outKeyLen, "Eth-Hash:");

    pageString(outVal, outValLen, hex, pageIdx, pageCount);

    return parser_ok;
}

// returns the number of items to display on the screen.
// Note: we might need to add a transaction state object,
// Defined with one parameter for now.
uint8_t _getNumItemsEth(__Z_UNUSED const parser_context_t *ctx)
{
    // just the eth transaction hash for now.
    return 1;
}

parser_error_t _computeV(parser_context_t *ctx, eth_tx_t *tx_obj, unsigned int info, uint8_t *v) {
    uint8_t parity = 0;
    if (info & CX_ECCINFO_PARITY_ODD) {
        parity = 1;
    }
    switch (eth_tx_obj.tx_type) {
        case eip2930:
        case eip1559: {
            *v = parity;
            break;
        }
        case legacy: {
            uint8_t gtn = (info & CX_ECCINFO_xGTn) == 1;
            // we need chainID info
            if (tx_obj->chain_id.len == 0) {
                // according to app-ethereum this is the legacy non eip155 conformant
                // so V should be made before EIP155 which had
                // 27 + {0, 1}
                // 27, decided by the parity of Y
                // see https://bitcoin.stackexchange.com/a/112489
                //     https://ethereum.stackexchange.com/a/113505
                //     https://eips.ethereum.org/EIPS/eip-155
                *v = 27 + parity;

            } else {
                // app-ethereum reads the first 4 bytes then cast it to an u8
                // this is not good but it relies on hw-eth-app lib from ledger
                // to recover the right chain_id from the V component being computed here, and
                // which is returned with the signature
                uint32_t len = MIN(UINT32_MAX, tx_obj->chain_id.len);
                uint8_t *chain = ctx->buffer + tx_obj->chain_id.offset;

                uint64_t id = 0;

                if (be_bytes_to_u64(chain, len, &id) != rlp_ok) {
                    return parser_invalid_chain_id;
                }

                uint32_t cv = 35 + parity;
                cv = saturating_add_u32(cv, (uint32_t)id * 2);
                *v = (uint8_t)cv;
            }
            if (gtn) 
                *v += 2;

            break;
        }
        default:
            return parser_unexepected_error;
    }
    return parser_ok;
}
