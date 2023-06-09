/*******************************************************************************
*  (c) 2018 - 2023 Zondax AG
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
#include "eth_utils.h"
#include <stdio.h>
#include <zxmacros.h>

#define CHECK_RLP_LEN(BUFF_LEN, RLP_LEN)                                       \
    {                                                                          \
        uint64_t buff_len = BUFF_LEN;                                          \
        uint64_t rlp_len = RLP_LEN;                                            \
        if (buff_len < rlp_len)                                                \
            return rlp_no_data;                                                \
    }

uint64_t
saturating_add(uint64_t a, uint64_t b)
{

    uint64_t num = a + b;
    if (num < a || num < b)
        return UINT64_MAX;

    return num;
}

uint32_t
saturating_add_u32(uint32_t a, uint32_t b)
{

    uint32_t num = a + b;

    if (num < a || num < b)
        return UINT32_MAX;

    return num;
}

int
be_bytes_to_u64(const uint8_t *bytes, uint8_t len, uint64_t *num)
{
    if (bytes == NULL || num == NULL || len == 0 || len > sizeof(uint64_t)) {
        return -1;
    }

    *num = 0;

    // fast path
    if (len == 1) {
        *num = bytes[0];
        return 0;
    }

    uint8_t *num_ptr = (uint8_t *)num;
    for (uint8_t i = 0; i < len; i++) {
        *num_ptr = bytes[len - i - 1];
        num_ptr++;
    }

    return 0;
}

rlp_error_t
get_tx_rlp_len(const uint8_t *buffer, uint32_t len, uint64_t *read, uint64_t *to_read)
{
    if (buffer == NULL || len == 0)
        return rlp_no_data;

    if (read == NULL || to_read == NULL)
        return rlp_no_data;

    // get alias
    const uint8_t *data = buffer;
    uint64_t offset = 0;

    *read = 0;
    *to_read = 0;

    // skip version if present/recognized
    //  otherwise tx is probably legacy so no version, just rlp data
    uint8_t version = data[offset];
    if (version == 1 || version == 2 ) {
        offset += 1;
        *read += 1;
    }

    // get rlp marker
    uint8_t marker = data[offset];

    if ((marker - 0xC0) * (marker - 0xF7) <= 0) {
        *read += 1;
        uint8_t l = marker - 0xC0;
        *to_read = l;
        return rlp_ok;
    }

    if (marker >= 0xF8) {
        offset += 1;

        // For lists longer than 55 bytes the length is encoded
        // differently.
        // The number of bytes that compose the length is encoded
        // in the marker
        // And then the length is just the number BE encoded
        uint64_t num_bytes = (marker - 0xF7);

        uint64_t num;
        if (be_bytes_to_u64(&data[offset], num_bytes, &num) != 0)
            return rlp_invalid_data;


        // marker byte + number of bytes used to encode the len
        *read += 1 + num_bytes;
        *to_read = num;

        return rlp_ok;
    }

    // should not happen as previous conditional covers all possible values
    return rlp_invalid_data;
}

rlp_error_t
parse_rlp_item(const uint8_t *data,
               uint32_t dataLen,
               uint32_t *read,
               uint32_t *item_len)
{
    *item_len = 0;
    *read = 0;

    if (dataLen == 0)
        return rlp_no_data;

    uint8_t marker = data[0];

    if (marker <= 0x7F) {
        // first case item is just one byte
        *read = 0;
        *item_len = 1;
        return rlp_ok;

    } else if (marker <= 0xB7) {
        // second case it is a string with a fixed length
        uint8_t len = marker - 0x80;
        *read = 1;
        CHECK_RLP_LEN(dataLen, len + 1)
        *item_len = len;
        return rlp_ok;

    } else if (marker <= 0xBF) {
        // For strings longer than 55 bytes the length is encoded
        // differently.
        // The number of bytes that compose the length is encoded
        // in the marker
        // And then the length is just the number BE encoded
        uint8_t num_bytes = marker - 0xB7;
        uint64_t len = 0;
        if (be_bytes_to_u64(&data[1], num_bytes, &len) != 0)
            return rlp_invalid_data;

        CHECK_RLP_LEN(dataLen, len + 1 + num_bytes)
        *read = 1 + num_bytes;
        *item_len = len;

        return rlp_ok;

    } else if (marker <= 0xF7) {
        // simple list
        uint8_t len = marker - 0xC0;

        *read = 1;
        CHECK_RLP_LEN(dataLen, len + 1)
        *item_len = len;
        return rlp_ok;
    }

    // marker >= 0xF8
    // For lists longer than 55 bytes the length is encoded
    // differently.
    // The number of bytes that compose the length is encoded
    // in the marker
    // And then the length is just the number BE encoded
    uint8_t num_bytes = marker - 0xF7;
    uint64_t len = 0;
    if (be_bytes_to_u64(&data[1], num_bytes, &len) != 0)
        return rlp_invalid_data;

    CHECK_RLP_LEN(dataLen, len + 1 + num_bytes)

    *read = 1 + num_bytes;
    *item_len = len;

    return rlp_ok;
}
