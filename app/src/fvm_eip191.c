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
#include "actions.h"
#include "apdu_handler_evm.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin_evm.h"
#include "crypto_helper.h"
#include "evm_eip191.h"
#include "zxformat.h"
#include "zxmacros.h"

#if defined(LEDGER_SPECIFIC)
#include "cx.h"
cx_blake2b_t ctx_blake2b_fvm;
#else
#define CX_SHA256_SIZE 32
#define CX_RIPEMD160_SIZE 20
#endif

static const char FVM_SIGN_MAGIC[] =
    "\x19"
    "Filecoin Signed Message:\n";

zxerr_t fvm_eip191_msg_getNumItems(uint8_t *num_items) {
    zemu_log_stack("fvm_eip191_msg_getNumItems");
    *num_items = 2;
    return zxerr_ok;
}

zxerr_t fvm_eip191_msg_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
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
            snprintf(outVal, outValLen, "FVM Personal Message");
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

bool fvm_eip191_msg_parse() {
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

zxerr_t fvm_eip191_hash_message(const uint8_t *message, uint16_t messageLen, uint8_t *hash) {
    if (message == NULL || messageLen == 0) {
        return zxerr_unknown;
    }
    MEMZERO(hash, 32);

#if defined(LEDGER_SPECIFIC)
    // Setup hasher pointer. This will reduce stack usage
    if (blake_hash_setup(&ctx_blake2b_fvm) != zxerr_ok) {
        return zxerr_unknown;
    }
#endif

    // Initialize BLAKE2 hash context
    CHECK_ZXERR(blake_hash_init());

    // First add the FVM_SIGN_MAGIC prefix
    CHECK_ZXERR(blake_hash_update((uint8_t *)FVM_SIGN_MAGIC, sizeof(FVM_SIGN_MAGIC) - 1));

    // | len(message) | message |
    CHECK_ZXERR(blake_hash_update(message, messageLen));
    // Finalize the hash
    CHECK_ZXERR(blake_hash_finish(hash, 32));

    return zxerr_ok;
}
