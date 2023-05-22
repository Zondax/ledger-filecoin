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

#include "tx.h"
#include "apdu_codes.h"
#include "buffering.h"
#include "parser.h"
#include "parser_common.h"
#include <string.h>
#include "zxmacros.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define RAM_BUFFER_SIZE 8192
#define FLASH_BUFFER_SIZE 16384
#elif defined(TARGET_NANOS)
#define RAM_BUFFER_SIZE 384
#define FLASH_BUFFER_SIZE 8192
#endif

// Ram
uint8_t ram_buffer[RAM_BUFFER_SIZE];

// Flash
typedef struct {
    uint8_t buffer[FLASH_BUFFER_SIZE];
} storage_t;

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
storage_t NV_CONST N_appdata_impl __attribute__ ((aligned(64)));
#define N_appdata (*(NV_VOLATILE storage_t *)PIC(&N_appdata_impl))
#endif

parser_context_t ctx_parsed_tx;

void tx_initialize() {
    buffering_init(
            ram_buffer,
            sizeof(ram_buffer),
            (uint8_t *) N_appdata.buffer,
            sizeof(N_appdata.buffer)
    );
}

void tx_context_fil() {
  ctx_parsed_tx.tx_type = fil_tx;
}

void tx_context_eth() {
  ctx_parsed_tx.tx_type = eth_tx;
}

void tx_context_datacap() {
  ctx_parsed_tx.tx_type = datacap_tx;
}

void tx_context_client_deal() {
  ctx_parsed_tx.tx_type = clientdeal_tx;
}

void tx_context_raw_bytes() {
  ctx_parsed_tx.tx_type = raw_bytes;
}

uint8_t tx_is_rawbytes() {
    return ctx_parsed_tx.tx_type == raw_bytes;
}

void tx_reset() {
    buffering_reset();
}

uint32_t tx_append(unsigned char *buffer, uint32_t length) {
    return buffering_append(buffer, length);
}

uint32_t tx_get_buffer_length() {
    if (tx_is_rawbytes())
        return parser_rawbytes_hash_len();

    return buffering_get_buffer()->pos;
}

uint8_t *tx_get_buffer() {
    if (tx_is_rawbytes())
        return parser_rawbytes_hash();

    return buffering_get_buffer()->data;
}

const char *tx_parse() {
    uint8_t err = parser_parse(
            &ctx_parsed_tx,
            tx_get_buffer(),
            tx_get_buffer_length());

    if (err != parser_ok)
        return parser_getErrorDescription(err);

    err = parser_validate(&ctx_parsed_tx);
    CHECK_APP_CANARY()

    if (err != parser_ok)
        return parser_getErrorDescription(err);

    return NULL;
}

zxerr_t tx_getNumItems(uint8_t *num_items) {
    parser_error_t err = parser_getNumItems(&ctx_parsed_tx, num_items);

    if (err != parser_ok) {
        return zxerr_no_data;
    }

    return zxerr_ok;
}

zxerr_t tx_getItem(int8_t displayIdx,
                   char *outKey, uint16_t outKeyLen,
                   char *outVal, uint16_t outValLen,
                   uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;

    CHECK_ZXERR(tx_getNumItems(&numItems))

    if (displayIdx < 0 || displayIdx > numItems) {
        return zxerr_no_data;
    }

    parser_error_t err = parser_getItem(&ctx_parsed_tx,
                                        displayIdx,
                                        outKey, outKeyLen,
                                        outVal, outValLen,
                                        pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data ||
        err == parser_display_idx_out_of_range ||
        err == parser_display_page_out_of_range)
        return zxerr_no_data;

    if (err != parser_ok)
        return zxerr_unknown;

    return zxerr_ok;
}

zxerr_t tx_compute_eth_v(unsigned int info, uint8_t *v) {
    parser_error_t err = parser_compute_eth_v(&ctx_parsed_tx, info, v);

    if (err != parser_ok)
        return zxerr_unknown;

    return zxerr_ok;
}

zxerr_t  tx_rawbytes_init_state(uint8_t *buf, size_t buf_len) {
    if ( parser_rawbytes_init(buf, buf_len) != parser_ok )
        return zxerr_unknown;

    return zxerr_ok;
}

zxerr_t tx_rawbytes_update(uint8_t *buf, size_t buf_len) {
    if ( parser_rawbytes_update(buf, buf_len) != parser_ok )
 	       return zxerr_unknown;

    return zxerr_ok;
}
