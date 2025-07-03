// Modified by Zondax GmbH
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
    if (data == NULL || result == NULL || length > (1 << 28) || length == 0 || resultLen == 0) {
        return 0;
    }
    uint32_t count = 0;
    uint32_t buffer = data[0];
    uint32_t next = 1;
    uint32_t bitsLeft = 8;
    while (count < resultLen && (bitsLeft > 0 || next < length)) {
        if (bitsLeft < 5) {
            if (next < length) {
                buffer <<= 8;
                buffer |= data[next++] & 0xFF;
                bitsLeft += 8;
            } else {
                uint32_t pad = 5u - bitsLeft;
                buffer <<= pad;
                bitsLeft += pad;
            }
        }
        uint32_t index = 0x1Fu & (buffer >> (bitsLeft - 5u));
        bitsLeft -= 5;
        result[count++] = "abcdefghijklmnopqrstuvwxyz234567"[index];
    }

    if (count < resultLen) {
        result[count] = '\000';
    }
    return count;
}
