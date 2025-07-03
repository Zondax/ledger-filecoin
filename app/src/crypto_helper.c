/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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
#include "crypto_helper.h"

#include "base32.h"
#include "stdbool.h"
#include "zxformat.h"

uint32_t hdPath[MAX_BIP32_PATH];
uint32_t hdPath_len;
uint8_t fil_chain_code;

bool isTestnet() { return hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET; }

uint16_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v) {
    uint16_t i = 0;

    *v = 0;
    uint16_t shift = 0;
    while (i < 10u && i < inputSize) {
        uint64_t b = input[i] & 0x7fu;

        if ((shift == 63 && b > 1) || (shift > 63 && b > 0)) {
            // This will overflow uint64_t, break and return
            break;
        }

        *v |= b << shift;

        if (!(input[i] & 0x80u)) {
            return i + 1;
        }

        shift += 7;
        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return 0;
}

uint16_t formatProtocol(const uint8_t *addressBytes, uint16_t addressSize, uint8_t *formattedAddress,
                        uint16_t formattedAddressSize) {
    if (formattedAddress == NULL || formattedAddressSize < 2u) {
        return 0;
    }
    if (addressBytes == NULL || addressSize < 2u) {
        return 0;
    }

    // Clean output buffer
    MEMZERO(formattedAddress, formattedAddressSize);

    const uint8_t protocol = addressBytes[0];

    formattedAddress[0] = isTestnet() ? 't' : 'f';
    formattedAddress[1] = (char)(protocol + '0');

    uint16_t payloadSize = 0;
    switch (protocol) {
        case ADDRESS_PROTOCOL_ID: {
            uint64_t val = 0;

            if (!decompressLEB128(addressBytes + 1, addressSize - 1, &val) ||
                uint64_to_str((char *)formattedAddress + 2, formattedAddressSize - 2, val) != NULL) {
                return 0;
            }
            return strnlen((const char *)formattedAddress, formattedAddressSize);
        }
        case ADDRESS_PROTOCOL_SECP256K1: {  // NOLINT(bugprone-branch-clone)
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_SECP256K1_PAYLOAD_LEN;
            break;
        }
        case ADDRESS_PROTOCOL_ACTOR: {  // NOLINT(bugprone-branch-clone)
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_ACTOR_PAYLOAD_LEN;
            break;
        }
        case ADDRESS_PROTOCOL_BLS: {
            // payload 20 bytes + 4 bytes checksum
            payloadSize = ADDRESS_PROTOCOL_BLS_PAYLOAD_LEN;
            break;
        }
        case ADDRESS_PROTOCOL_DELEGATED: {
            uint64_t actorId = 0;
            const uint16_t actorIdSize = decompressLEB128(addressBytes + 1, addressSize - 1, &actorId);

            // Check missing actor id or missing sub-address
            if (actorIdSize == 0 || (addressSize <= actorIdSize + 1)) {
                return 0;
            }

            char actorId_str[25] = {0};
            if (uint64_to_str(actorId_str, sizeof(actorId_str), actorId) != NULL) {
                return 0;
            }
            // Copy Actor ID
            snprintf((char *)formattedAddress + 2, formattedAddressSize - 2, "%sf", actorId_str);

            payloadSize = addressSize - 1 - actorIdSize;
            break;
        }
        default:
            return 0;
    }

    // Keep only one crc buffer using the biggest size
    uint8_t payload_crc[ADDRESS_PROTOCOL_DELEGATED_MAX_SUBADDRESS_LEN + CHECKSUM_LENGTH] = {0};

    // f4 addresses contain actorID
    const uint16_t actorIdSize = (protocol == ADDRESS_PROTOCOL_DELEGATED) ? (addressSize - payloadSize - 1) : 0;
    if (addressSize != payloadSize + 1 + actorIdSize || payloadSize > ADDRESS_PROTOCOL_DELEGATED_MAX_SUBADDRESS_LEN) {
        return 0;
    }
    MEMCPY(payload_crc, addressBytes + 1 + actorIdSize, payloadSize);

    blake_hash(addressBytes, addressSize, payload_crc + payloadSize, CHECKSUM_LENGTH);

    const uint16_t offset = strnlen((char *)formattedAddress, formattedAddressSize);
    // Now prepare the address output
    if (base32_encode(payload_crc, (uint32_t)(payloadSize + CHECKSUM_LENGTH), (char *)(formattedAddress + offset),
                      (uint32_t)(formattedAddressSize - offset)) == 0) {
        return 0;
    }

    return strnlen((char *)formattedAddress, formattedAddressSize);
}
