/*******************************************************************************
 *  (c) 2019 Zondax GmbH
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define CHECK_PARSER_ERR(__CALL)              \
    {                                         \
        parser_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                    \
        if (__err != parser_ok) return __err; \
    }

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,
    // Cbor
    parser_cbor_unexpected,
    parser_cbor_unexpected_EOF,
    parser_cbor_not_canonical,
    // Coin specific
    parser_unexpected_tx_version,
    parser_unexpected_type,
    parser_unexpected_method,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_value_out_of_range,
    parser_invalid_address,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    parser_required_nonce,
    parser_required_method,
    parser_unsupported_tx,
    parser_invalid_rlp_data,
    parser_invalid_chain_id,
    parser_invalid_rs_values,
    parser_invalid_cid,
    parser_invalid_deal_duration,
    parser_invalid_prefix,
    // Customs
    parser_expert_mode_required,
    parser_blindsign_mode_required,
} parser_error_t;

// Define the three types
// of supported transactions/msgs.
// there are other sub-categories for each
// that can be handled by their respective parser.
// this type helps defining which parser to call
typedef enum {
    fil_tx = 0,
    eth_tx,
    raw_bytes,
} tx_type_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    tx_type_t tx_type;
} parser_context_t;

#ifdef __cplusplus
}
#endif
