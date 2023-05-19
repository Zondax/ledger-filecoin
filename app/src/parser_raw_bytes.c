/*******************************************************************************
*  (c) 2023 Zondax AG
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

#include <stdio.h>
#include <string.h>
#include <zxmacros.h>
#include "common/parser_common.h"
#include "parser_impl.h"
#include "parser_raw_bytes.h"
#include "parser_txdef.h"
#include "fil_utils.h"
#include "cbor.h"
#include "app_mode.h"
#include "zxformat.h"
#include "crypto.h"

static const char messagePrefix[] = "Filecoin Sign Bytes:\n";

// at init we need to initializae our hasher ctx,
// then, get the data lenght by parsing the varint that comes at
// the begining of the message.
// and, finally, check that the data comes prefixed
parser_error_t raw_bytes_init(uint8_t *buf, size_t buf_len) {

    if (buf_len == 0)
        return parser_unexpected_buffer_end;

    // init hash context
    blake_hash_init(&parser_tx_obj.raw_bytes_tx.ctx, BLAKE2B_256_SIZE);

    // get message len in bytes
    uint64_t total = 0;
    size_t bytes_read = parse_varint(buf, buf_len, &total);

    if (total == 0 || bytes_read == buf_len)
        return parser_unexpected_buffer_end;

    // skip the bytes used by varint
    size_t rx = buf_len - bytes_read;

    if (rx <= sizeof(messagePrefix))
        return parser_unexpected_buffer_end;

    // get pointer to the message: prefix + raw_bytes
    uint8_t *msg = buf + bytes_read;

    uint8_t prefix_len = strlen(messagePrefix);

    // check for prefix
    if (memcmp(messagePrefix, (const char *)msg, prefix_len))
        return parser_invalid_prefix;

    // Initialize the other fields of the raw_bytes state.
    parser_tx_obj.raw_bytes_tx.total = total;
    parser_tx_obj.raw_bytes_tx.current = 0;
    MEMZERO(parser_tx_obj.raw_bytes_tx.digest, BLAKE2B_256_SIZE);

    return raw_bytes_update(msg, rx);
}

parser_error_t raw_bytes_update(uint8_t *buf, size_t buf_len) {
    if (buf_len == 0)
        return parser_unexpected_buffer_end;

    if (blake_hash_update(&parser_tx_obj.raw_bytes_tx.ctx, buf, buf_len) != 0)
        return parser_value_out_of_range;

    parser_tx_obj.raw_bytes_tx.current += buf_len;

    return parser_ok;
}

parser_error_t _readRawBytes(__Z_UNUSED const parser_context_t *ctx, raw_bytes_state_t *tx) {

    size_t total = tx->total;
    size_t current = tx->current;

    uint8_t tmp[BLAKE2B_256_SIZE] = {0};

    if (total != current)
        return parser_no_data;

    if (blake_hash_finish(&tx->ctx, tmp) != 0)
        return parser_value_out_of_range;

    blake_hash_cid(tmp, BLAKE2B_256_SIZE, tx->digest, BLAKE2B_256_SIZE);

    return parser_ok;
}

parser_error_t _validateRawBytes(__Z_UNUSED const parser_context_t *ctx) {
    return parser_ok;
}

uint8_t _getNumItemsRawBytes(__Z_UNUSED const parser_context_t *ctx) {
    // show the final hash as an hex string
    return 1;
}

parser_error_t _getItemRawBytes(__Z_UNUSED const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    if (displayIdx > 0)
        return parser_display_idx_out_of_range;

    // get the hash of the buffer
    uint8_t hex[BLAKE2B_256_SIZE * 2 + 1] = {0};

    // get hash
    array_to_hexstr((char*)hex, 65, parser_tx_obj.raw_bytes_tx.digest, BLAKE2B_256_SIZE);

    snprintf(outKey, outKeyLen, "BytesHash:");

    pageString(outVal, outValLen, (const char*)hex, pageIdx, pageCount);

    return parser_ok;
}
