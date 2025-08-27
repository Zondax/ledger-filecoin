// Modified by Zondax AG
//
// Base32 implementation
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "base32.h"

#include <string.h>

uint32_t base32_encode(const uint8_t *data, uint32_t length, char *result, uint32_t resultLen) {
    static const char *alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    if (data == NULL || result == NULL || length == 0 || resultLen == 0 || length > (1u << 28)) {
        return 0;
    }

    uint64_t buffer = 0;
    uint32_t bitsLeft = 0;
    uint32_t count = 0;

    for (uint32_t i = 0; i < length; i++) {
        buffer = (buffer << 8) | data[i];
        bitsLeft += 8;

        while (bitsLeft >= 5) {
            if (count >= resultLen) {
                return count;
            }
            bitsLeft -= 5;
            uint32_t index = (uint32_t)((buffer >> bitsLeft) & 0x1F);
            result[count++] = alphabet[index];
        }
        // keep only the remaining bits in buffer to avoid overflow
        buffer &= ((1ULL << bitsLeft) - 1);
    }

    // Handle the remaining bits (if any)
    if (bitsLeft > 0 && count < resultLen) {
        buffer <<= (5 - bitsLeft);
        uint32_t index = (uint32_t)(buffer & 0x1F);
        result[count++] = alphabet[index];
    }

    if (count < resultLen) {
        result[count] = '\0';
    }
    return count;
}
