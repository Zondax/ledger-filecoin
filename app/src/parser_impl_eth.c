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

typedef struct {
    uint8_t *buffer;
    uint32_t buffer_len;
    uint32_t offset;
} rlp_parser;

#define INIT_RLP_PARSER(c)  \
    rlp_parser parser;           \
    parser.buffer = (c)->buffer + (c)->offset; \
    parser.buffer_len = (c)->bufferLen - (c)->offset; \
    parser.offset = (c)->offset;

parser_error_t readBigInt(rlp_parser *ctx, eth_big_int_t *big_int);
parser_error_t readAddress(rlp_parser *ctx, eth_addr_t *addr);
parser_error_t readChainID(rlp_parser *ctx, chain_id_t *chain_id);
parser_error_t parse_field( rlp_parser *parser, uint8_t *field, uint8_t *len);

parser_error_t parse_legacy_tx(rlp_parser *ctx, eth_tx_t *tx_obj);


parser_error_t readChainID(rlp_parser *ctx, chain_id_t *chain_id) {
    uint8_t *data = ctx->buffer + ctx->offset;

    if ( parse_field(ctx, &(chain_id->chain), &(chain_id->len)) != rlp_ok)
        return parser_invalid_rlp_data;

    return parser_ok;
}

parser_error_t readBigInt(rlp_parser *ctx, eth_big_int_t *big_int) {

    if ( parse_field(ctx, big_int->num, &(big_int->len)) != rlp_ok)
        return parser_invalid_rlp_data;

    return parser_ok;
}

parser_error_t readAddress(rlp_parser *ctx, eth_addr_t *addr) {
    uint8_t *address = NULL;
    uint32_t addr_len = 0;

    if ( parse_filed(ctx, address, &addr_len) != parser_ok)
        return parser_invalid_rlp_data;

    // it is ok to have and empty address
    if (addr_len == 0){
        return parser_ok;
    }
    
    if (addr_len != ETH_ADDRESS_LEN)
        return parser_invalid_address;

    MEMCPY(&(addr->addr), address, ETH_ADDRESS_LEN);

    // update offset 
    return parser_ok;
}

parser_error_t parse_field(rlp_parser *ctx, uint8_t *field, uint8_t *len) {
    field = NULL;
    *len = 0;

    if (ctx->offset >= ctx->buffer_len)
        return parser_unexpected_buffer_end;


    uint8_t *data = ctx->buffer + ctx->offset;

    if ( parse_rlp_item(data, ctx->buffer_len - ctx->offset, field, len) != rlp_ok)
        return parser_invalid_rlp_data;

    uint32_t read = field - data;
    ctx->offset += read + *len; 

    return parser_ok;
}

parser_error_t parse_legacy_tx(rlp_parser *ctx, eth_tx_t *tx_obj) {
    // parse nonce 
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.base_fields.nonce)));
    // parse gas_price
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.base_fields.gas_price)));
    // parse gas_limit
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.base_fields.gas_limit)));
    // parse address
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.base_fields.address)));
    // parse_value
    CHECK_PARSER_ERR(readBigInt(ctx, &(tx_obj->legacy.base_fields.value)));
    // parse data
    CHECK_PARSER_ERR(parse_field(ctx, tx_obj->legacy.base_fields.data, &tx_obj->legacy.base_fields.dataLen));
    // two cases:
    // - legacy no EIP155 which means no chain_id
    // - legacy EIP155 in which case should come with empty r and s values
    if (ctx->buffer_len <= ctx->offset) {
        // there is not more data no eip155 compliant tx 
        tx_obj->chain_id.chain = NULL;
        tx_obj->chain_id.len = 0;
        return parser_ok;
    }

    // Transaction comes with a chainID so it is EIP155 compliant
    CHECK_PARSER_ERR(parse_field(ctx, tx_obj->chain_id.chain, &tx_obj->chain_id.len));
    
    if (tx_obj->chain_id.len == 0 || tx_obj->chain_id.len > MAX_CHAIN_LEN)
        return parser_invalid_chain_id;

    // r and s if not empty, should contain only one value which must be zero.
    // Usually for an eip155 transaction the last two bytes represent r and s and are 0x8080 
    uint8_t *r = tx_obj->legacy.r;
    uint8_t *s = tx_obj->legacy.s;
    uint32_t *r_len = &tx_obj->legacy.r_len;
    uint32_t *s_len = &tx_obj->legacy.s_len;

    // parse r
    CHECK_PARSER_ERR(parse_field(ctx, r, r_len));
    // parse s
    CHECK_PARSER_ERR(parse_field(ctx, s, s_len));

    if (*r_len == 1 && *s_len == 1 && (*s | *r)) {
        return parser_invalid_rs_values;
    } else if (*r_len == 0 && *s_len == 0 )
        return parser_ok;
        
    return parser_invalid_rs_values;
}

parser_error_t
_readEth(parser_context_t *ctx, eth_tx_t *eth_tx_obj)
{
    // read the first byte, it indicates if transaction falls in one of the following:
    // - EIP1559
    // - EIP2930
    // -legacy
    uint8_t marker = ctx->buffer[0];

    switch (marker) {
        case eip1559:
        case eip2930:
            eth_tx_obj->tx_type = marker;
            zemu_log_stack("Unsupported eth transaction. Valid tx: Legacy");
            return parser_unsupported_tx;
        default: {
            // legacy transaction byte must be >= legacy(0xC0)
            INIT_RLP_PARSER(ctx)
            if (eth_tx_obj->tx_type < legacy) {
                return parser_unsupported_tx;
            } 
            eth_tx_obj->tx_type = legacy;
            CHECK_PARSER_ERR(parse_legacy_tx(&parser, &eth_tx_obj));
        }
    }

    // just place holder. depending on tx type we 
    // start calling parse_rlp_item, to get transaction 
    // fields and so on.
    return parser_ok;
}

parser_error_t
_validateTxEth(__Z_UNUSED const parser_context_t *ctx)
{
    return parser_ok;
}

parser_error_t
_getItemEth(const parser_context_t *ctx,
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

    snprintf(outKey, outKeyLen, "Eth-Hash:");

    // we need to get keccak hash of the transaction data
    uint8_t hash[32] = { 0 };
    keccak_digest(ctx->buffer, ctx->bufferLen, hash, 32);

    // now get the hex string of the hash
    char hex[65] = { 0 };
    array_to_hexstr(hex, 65, hash, 32);


    pageString(outVal, outValLen, hex, pageIdx, pageCount);

    return parser_ok;
}

// returns the number of items to display on the screen.
// Note: we might need to add a transaction state object,
// Defined with one parameter for now.
uint8_t
_getNumItemsEth(__Z_UNUSED const parser_context_t *ctx)
{
    // just the eth transaction hash for now.
    return 1;
}

parser_error_t _computeV(unsigned int info, uint8_t *v) {
    switch (eth_tx_obj.tx_type) {
        case eip2930:
        case eip1559: {
            *v = info == 1;
            return parser_ok;
        }
        case legacy: {
            // we need chainID info
             
            // let chain_id = self.tx.chain_id();
            // if chain_id.is_empty() {
            //     // according to app-ethereum this is the legacy non eip155 conformant
            //     // so V should be made before EIP155 which had
            //     // 27 + {0, 1}
            //     // 27, decided by the parity of Y
            //     // see https://bitcoin.stackexchange.com/a/112489
            //     //     https://ethereum.stackexchange.com/a/113505
            //     //     https://eips.ethereum.org/EIPS/eip-155
            //     out[tx] = 27 + flags.contains(ECCInfo::ParityOdd) as u8;
            // } else {
            //     // app-ethereum reads the first 4 bytes then cast it to an u8
            //     // this is not good but it relies on hw-eth-app lib from ledger
            //     // to recover the right chain_id from the V component being computed here, and
            //     // which is returned with the signature
            //     let len = core::cmp::min(U32_SIZE, chain_id.len());
            //     if let Ok(chain_id) = bytes_to_u64(&chain_id[..len]) {
            //         let v = (35 + flags.contains(ECCInfo::ParityOdd) as u32)
            //             .saturating_add((chain_id as u32) << 1);
            //         out[tx] = v as u8;
            //     }
            // }

        }
            
    }
}
