/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdio.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "apdu_handler_evm.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin.h"
#include "coin_evm.h"
#include "crypto.h"
#include "evm_addr.h"
#include "evm_utils.h"
#include "fvm_eip191.h"
#include "parser.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

static bool tx_initialized = false;
static uint32_t msg_counter = 0;

void extractHDPath(uint32_t rx, uint32_t offset, uint32_t path_len) {
    if (path_len == 0 || path_len > MAX_BIP32_PATH) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    if (rx < offset) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    if ((rx - offset) < sizeof(uint32_t) * path_len) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * path_len);
    hdPath_len = path_len;
}

void extract_fil_path(uint32_t rx, uint32_t offset) {
    tx_initialized = false;
    extractHDPath(rx, offset, HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extract_fil_path(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return true;
    }

    THROW(APDU_CODE_INVALIDP1P2);
    return false;
}

__Z_INLINE bool process_rawbytes_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extract_fil_path(rx, OFFSET_DATA);
            tx_initialized = true;
            msg_counter = 0;
            return false;
        case P1_ADD:
        case P1_LAST: {
            size_t msg_len = rx - OFFSET_DATA;
            uint8_t *buf = G_io_apdu_buffer + OFFSET_DATA;

            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }

            // initialize if this is the first message, as P1_INIT is the first chunk containing only the PATH
            // if this is not the first message, then, just update our state with this data
            if (msg_counter == 1) {
                if (tx_rawbytes_init_state(buf, msg_len) != zxerr_ok) {
                    tx_initialized = false;
                    THROW(APDU_CODE_DATA_INVALID);
                }
            } else {
                if (tx_rawbytes_update(buf, msg_len) != zxerr_ok) {
                    tx_initialized = false;
                    THROW(APDU_CODE_EXECUTION_ERROR);
                }
            }

            if (payloadType == P1_LAST) {
                return true;
            }

            return false;
        }
    }

    tx_initialized = false;
    THROW(APDU_CODE_INVALIDP1P2);
    return false;
}

__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extract_fil_path(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = app_fill_address();
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSign(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("HandleSignFil\n");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    tx_context_fil();

    CHECK_APP_CANARY()

    uint8_t error_code;
    const char *error_msg = tx_parse(&error_code);
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);

        // Check if expert mode is needed
        if (error_code == parser_expert_mode_required) {
            *flags |= IO_ASYNCH_REPLY;
            view_custom_error_show("Expert Mode", "Required");
        }
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignRawBytes(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleSignRawBytes");

    msg_counter += 1;

    if (!process_rawbytes_chunk(tx, rx)) {
        char message[100] = {0};
        snprintf(message, sizeof(message), "Chunk %d\n", msg_counter);
        if ((msg_counter % 5) == 0) {
            char prompt[] = {"RawBytes:"};
            view_message_show(prompt, message);
#if !defined(TARGET_STAX) && !defined(TARGET_FLEX)
            UX_WAIT_DISPLAYED();
#endif
        }
        THROW(APDU_CODE_OK);
    }

    tx_context_raw_bytes();

    view_idle_show(0, NULL);

    CHECK_APP_CANARY()

    uint8_t error_code;
    const char *error_msg = tx_parse(&error_code);
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
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignFvmEip191(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignFvmEip191\n");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    const parser_error_t error = fvm_eip191_msg_parse();
    if (error != parser_ok) {
        const char *error_msg = parser_getErrorDescription(error);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        if (error == parser_blindsign_mode_required) {
            *flags |= IO_ASYNCH_REPLY;
            view_blindsign_error_show();
        }
        THROW(APDU_CODE_DATA_INVALID);
    }
    CHECK_APP_CANARY()

    view_review_init(fvm_eip191_msg_getItem, fvm_eip191_msg_getNumItems, app_sign_fvm_eip191);
    view_review_show(REVIEW_MSG);
    *flags |= IO_ASYNCH_REPLY;
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            const uint8_t cla = G_io_apdu_buffer[OFFSET_CLA];

            if ((cla != CLA) && (cla != CLA_ETH)) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            const uint8_t instruction = G_io_apdu_buffer[OFFSET_INS];

            // Handle this case as ins number is the same as normal fil sign
            // instruction
            if (instruction == INS_GET_ADDR_ETH && cla == CLA_ETH) handleGetAddrEth(flags, tx, rx);

            // Reset BLS UI for next transaction
            app_mode_skip_blindsign_ui();

            switch (instruction) {
                case INS_GET_VERSION: {
#ifdef TESTING_ENABLED
                    G_io_apdu_buffer[0] = 0xFF;
#else
                    G_io_apdu_buffer[0] = 0;
#endif
                    G_io_apdu_buffer[1] = MAJOR_VERSION;
                    G_io_apdu_buffer[2] = MINOR_VERSION;
                    G_io_apdu_buffer[3] = PATCH_VERSION;
                    G_io_apdu_buffer[4] = !IS_UX_ALLOWED;

                    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
                    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
                    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
                    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

                    *tx += 9;
                    THROW(APDU_CODE_OK);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleSign(flags, tx, rx);
                    break;
                }

                case INS_SIGN_RAW_BYTES: {
                    CHECK_PIN_VALIDATED()
                    handleSignRawBytes(flags, tx, rx);
                    break;
                }
                case INS_SIGN_ETH: {
                    CHECK_PIN_VALIDATED()
                    if (cla != CLA_ETH) {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    tx_context_eth();
                    handleSignEth(flags, tx, rx);
                    break;
                }
                case INS_SIGN_PERSONAL_MESSAGE: {
                    CHECK_PIN_VALIDATED()
                    if (cla == CLA_ETH) {
                        tx_context_eth();
                        handleSignEip191(flags, tx, rx);
                    } else if (cla == CLA) {
                        tx_context_fil();
                        handleSignFvmEip191(flags, tx, rx);
                    } else {
                        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
                    }
                    break;
                }
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY {}
    }
    END_TRY;
}
