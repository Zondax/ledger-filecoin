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

#include "tx_evm.h"

#include <string.h>

#include "apdu_codes.h"
#include "buffering.h"
#include "parser.h"
#include "zxmacros.h"

static parser_context_t ctx_parsed_tx;

// const char *tx_parse_eth(uint8_t *error_code) {
//     uint8_t err = parser_parse_eth(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length());

//     CHECK_APP_CANARY()

//     if (err != parser_ok) {
//         return parser_getErrorDescription(err);
//     }

//     err = parser_validate_eth(&ctx_parsed_tx);
//     CHECK_APP_CANARY()

//     *error_code = err;
//     if (err != parser_ok) {
//         return parser_getErrorDescription(err);
//     }

//     return NULL;
// }

zxerr_t tx_compute_eth_v(unsigned int info, uint8_t *v, bool is_personal_message) {
    UNUSED(is_personal_message);
    // TODO: change to parser_compute_eth_v_evm
    parser_error_t err = parser_compute_eth_v(&ctx_parsed_tx, info, v);

    if (err != parser_ok) return zxerr_unknown;

    return zxerr_ok;
}

// zxerr_t tx_getNumItemsEth(uint8_t *num_items) {
//     parser_error_t err = parser_getNumItemsEth(&ctx_parsed_tx, num_items);

//     if (err != parser_ok) {
//         return zxerr_unknown;
//     }

//     return zxerr_ok;
// }

// zxerr_t tx_getItemEth(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
//                       uint8_t pageIdx, uint8_t *pageCount) {
//     uint8_t numItems = 0;

//     CHECK_ZXERR(tx_getNumItemsEth(&numItems))

//     if (displayIdx > numItems) {
//         return zxerr_no_data;
//     }

//     parser_error_t err =
//         parser_getItemEth(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

//     // Convert error codes
//     if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range)
//         return zxerr_no_data;

//     if (err != parser_ok) return zxerr_unknown;

//     return zxerr_ok;
// }
