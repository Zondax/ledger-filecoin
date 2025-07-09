/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
 *   (c) 2016 Ledger
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
#include "apdu_handler_evm.h"

#include "actions.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin_evm.h"
#include "crypto_evm.h"
#include "evm_addr.h"
#include "evm_eip191.h"
#include "evm_utils.h"
#include "parser.h"
#include "tx_evm.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

static bool tx_initialized = false;

void extract_eth_path(uint32_t rx, uint32_t offset) {
    tx_initialized = false;

    const uint8_t path_len = *(G_io_apdu_buffer + offset);

    if (path_len > HDPATH_LEN_DEFAULT || path_len < 3) THROW(APDU_CODE_WRONG_LENGTH);

    if ((rx - offset - 1) < sizeof(uint32_t) * path_len) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    // first byte at OFFSET_DATA is the path len, so we skip this
    uint8_t *path_data = G_io_apdu_buffer + offset + 1;

    // hw-app-eth serializes path as BE numbers
    for (uint8_t i = 0; i < path_len; i++) {
        hdPathEth[i] = U4BE(path_data, 0);
        path_data += sizeof(uint32_t);
    }

    const bool mainnet = hdPathEth[0] == HDPATH_ETH_0_DEFAULT && hdPathEth[1] == HDPATH_ETH_1_DEFAULT;

    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // set the hdPath len
    hdPathEth_len = path_len;
}

static void handle_first_chunk(uint32_t rx, uint8_t **data, uint32_t *len) {
    tx_initialize();
    tx_reset();
    extract_eth_path(rx, OFFSET_DATA);

    const uint32_t path_len_bytes = sizeof(uint32_t) * hdPathEth_len;

    if (*len < path_len_bytes + 1) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    *data += path_len_bytes + 1;
    *len -= path_len_bytes + 1;

    tx_initialized = true;
}

uint32_t bytes_to_read;

bool process_chunk_eip191(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint8_t *data = &(G_io_apdu_buffer[OFFSET_DATA]);
    uint32_t len = rx - OFFSET_DATA;
    uint64_t added;
    switch (payloadType) {
        case P1_ETH_FIRST: {
            handle_first_chunk(rx, &data, &len);

            // now process the chunk
            bytes_to_read = U4BE(data, 0);
            bytes_to_read -= len - sizeof(uint32_t);
            added = tx_append(data, len);
            if (added != len) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            if (bytes_to_read == 0) {
                tx_initialized = false;
                return true;
            }

            return false;
        }
        case P1_ETH_MORE: {
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }

            // either the entire buffer of the remaining bytes we expect
            bytes_to_read -= len;
            added = tx_append(data, len);
            if (added != len) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            // check if this chunk was the last one
            if (bytes_to_read == 0) {
                tx_initialized = false;
                return true;
            }

            return false;
        }
    }

    THROW(APDU_CODE_INVALIDP1P2);
    return false;
}

bool process_chunk_eth(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint64_t read = 0;
    uint64_t to_read = 0;
    uint64_t max_len = 0;

    uint8_t *data = &(G_io_apdu_buffer[OFFSET_DATA]);
    uint32_t len = rx - OFFSET_DATA;

    uint64_t added;
    switch (payloadType) {
        case P1_ETH_FIRST: {
            handle_first_chunk(rx, &data, &len);

            if (get_tx_rlp_len(data, len, &read, &to_read) != rlp_ok) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            // get remaining data len
            max_len = saturating_add(read, to_read);
            max_len = MIN(max_len, len);

            added = tx_append(data, max_len);
            if (added != max_len) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            // if the number of bytes read and the number of bytes to read
            //  is the same as what we read...
            if ((saturating_add(read, to_read) - len) == 0) {
                return true;
            }
            return false;
        }
        case P1_ETH_MORE: {
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }

            uint64_t buff_len = tx_get_buffer_length();
            uint8_t *buff_data = tx_get_buffer();

            if (get_tx_rlp_len(buff_data, buff_len, &read, &to_read) != rlp_ok) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            uint64_t rlp_read = buff_len - read;

            // either the entire buffer of the remaining bytes we expect
            uint64_t missing = to_read - rlp_read;
            max_len = len;

            if (missing < len) {
                max_len = missing;
            }
            added = tx_append(data, max_len);

            if (added != max_len) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            // check if this chunk was the last one
            if (missing - len == 0) {
                tx_initialized = false;
                return true;
            }

            return false;
        }
    }
    THROW(APDU_CODE_INVALIDP1P2);
    return false;
}

void handleGetAddrEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetAddrEth\n");
    extract_eth_path(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    uint8_t with_code = G_io_apdu_buffer[OFFSET_P2];

    if (with_code != P2_CHAINCODE && with_code != P2_NO_CHAINCODE) THROW(APDU_CODE_INVALIDP1P2);

    evm_chain_code = with_code;

    zxerr_t zxerr = app_fill_eth_address();
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(eth_addr_getItem, eth_addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

void handleSignEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleSignEth");
    if (!process_chunk_eth(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    // Reset BLS UI for next transaction
    app_mode_skip_blindsign_ui();

    CHECK_APP_CANARY()

    uint8_t error_code;
    const char *error_msg = tx_parse_eth(&error_code);

    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);

        if (error_code == parser_blindsign_mode_required) {
            *flags |= IO_ASYNCH_REPLY;
            view_blindsign_error_show();
        }

        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItemEth, tx_getNumItemsEth, app_sign_eth);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

void handleSignEip191(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleSignEip191");
    if (!process_chunk_eip191(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    // Reset BLS UI for next transaction
    app_mode_skip_blindsign_ui();

    CHECK_APP_CANARY()
    if (!eip191_msg_parse()) {
        const char *error_msg = parser_getErrorDescription(parser_blindsign_mode_required);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        *flags |= IO_ASYNCH_REPLY;
        view_blindsign_error_show();
        THROW(APDU_CODE_DATA_INVALID);
    }
    CHECK_APP_CANARY()

    view_review_init(eip191_msg_getItem, eip191_msg_getNumItems, app_sign_evm_eip191);
    view_review_show(REVIEW_MSG);
    *flags |= IO_ASYNCH_REPLY;
}
