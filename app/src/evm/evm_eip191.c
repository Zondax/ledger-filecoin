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
#include "evm_eip191.h"

#include "actions.h"
#include "apdu_handler_evm.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin_evm.h"
#include "zxformat.h"
#include "zxmacros.h"

#if defined(LEDGER_SPECIFIC)
#include "cx.h"
#else
#define CX_SHA256_SIZE 32
#define CX_RIPEMD160_SIZE 20
#endif

static const char SIGN_MAGIC[] =
    "\x19"
    "Ethereum Signed Message:\n";

zxerr_t eip191_msg_getNumItems(uint8_t *num_items) {
    zemu_log_stack("msg_getNumItems");
    *num_items = 2;
    return zxerr_ok;
}

zxerr_t eip191_msg_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                           uint8_t pageIdx, uint8_t *pageCount) {
    ZEMU_LOGF(200, "[msg_getItem] %d/%d\n", displayIdx, pageIdx)

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 1;

    if (tx_get_buffer_length() < sizeof(uint32_t) || tx_get_buffer() == NULL) {
        return zxerr_unknown;
    }

    const uint8_t *message = tx_get_buffer() + sizeof(uint32_t);
    const uint16_t messageLength = tx_get_buffer_length() - sizeof(uint32_t);

    switch (displayIdx) {
        case 0: {
            snprintf(outKey, outKeyLen, "Sign");
            snprintf(outVal, outValLen, "Personal Message");
            return zxerr_ok;
        }
        case 1: {
            snprintf(outKey, outKeyLen, "Msg hex");
            uint8_t is_printable = 1;

            // Check if all characters are printable
            for (uint16_t i = 0; i < messageLength; i++) {
                if (!IS_PRINTABLE(message[i])) {
                    is_printable = 0;
                    break;
                }
            }

            if (messageLength > 0 && is_printable == 0) {
                pageStringHex(outVal, outValLen, (const char *)message, messageLength, pageIdx, pageCount);
                return zxerr_ok;
            }

            // print message
            snprintf(outKey, outKeyLen, "Msg");
            pageString(outVal, outValLen, (const char *)message, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}

bool eip191_msg_parse() {
    const uint8_t *message = tx_get_buffer() + sizeof(uint32_t);
    const uint16_t messageLength = tx_get_buffer_length() - sizeof(uint32_t);
    // Check if all characters are printable
    for (uint16_t i = 0; i < messageLength; i++) {
        if (!IS_PRINTABLE(message[i])) {
            if (!app_mode_blindsign()) {
                return false;
            }
            break;
        }
    }

    return true;
}

zxerr_t eip191_hash_message(const uint8_t *message, uint16_t messageLen, uint8_t *hash) {
    if (message == NULL || messageLen == 0) {
        return zxerr_unknown;
    }
    MEMZERO(hash, 32);

#if defined(LEDGER_SPECIFIC)
    cx_sha3_t sha3;
    CHECK_CX_OK(cx_keccak_init_no_throw(&sha3, 256));
    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&sha3, 0, (uint8_t *)SIGN_MAGIC, sizeof(SIGN_MAGIC) - 1, NULL, 0));

    uint32_t msg_len = U4BE(message, 0);
    char len_str[12] = {0};
    uint32_to_str(len_str, sizeof(len_str), msg_len);
    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&sha3, 0, (uint8_t *)len_str, strlen(len_str), NULL, 0));

    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&sha3, CX_LAST, message + sizeof(uint32_t), messageLen - sizeof(uint32_t),
                                 hash, 32));

#endif

    return zxerr_ok;
}
