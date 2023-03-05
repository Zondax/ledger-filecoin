/*******************************************************************************
 *   (c) 2019 Zondax GmbH
 *   (c) 2022 Zondax GmbH
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
#include <stdio.h>
#include <zxmacros.h>
#include "eth_utils.h"

#define CHECK_RLP_LEN(BUFF_LEN, RLP_LEN) { \
    uint64_t buff_len = BUFF_LEN;  \
    uint64_t rlp_len = RLP_LEN;  \
    if (buff_len<rlp_len) return rlp_no_data;}

uint64_t saturating_add(uint64_t a, uint64_t b) {
    
   uint64_t num = a+b;
   if (num < a || num < b) 
     return UINT64_MAX;

   return num;
}

int be_bytes_to_u64(uint8_t *bytes, uint8_t len, uint64_t *num) {
  uint64_t u64_size = sizeof(uint64_t);

  if (bytes == NULL || len == 0 || num == NULL)
    return -1;

  if (len > u64_size)
    return -1;

  *num = 0;
  uint8_t *num_ptr = (uint8_t *)&num;

  for (int i = len; i--; i > 0) {
    *num_ptr = bytes[i];
    num_ptr += 1;
  }

  return 0;
}

rlp_error_t get_tx_rlp_len(uint8_t *buffer, uint32_t len, uint64_t *read,
                           uint64_t *to_read) {
  zemu_log_stack("rlp_len***");
  uint8_t m[100] = {0};
  snprintf(m, 100, "len: %d\n", len);
  zemu_log_stack(m);
  MEMZERO(m, 100);
  snprintf(m, 100, "last tx_byte: %X\n", buffer[len]);
  zemu_log_stack(m);
  MEMZERO(m, 100);

  if (buffer == NULL || len == 0)
    return rlp_no_data;

  if (read == NULL || to_read == NULL)
    return rlp_no_data;

  // get alias
  uint8_t *data = buffer;
  uint64_t offset = 0;

  *read = 0;
  *to_read = 0;
  zemu_log_stack("read and to_read initialized");


  // skip version if present/recognized
  //  otherwise tx is probably legacy so no version, just rlp data
  uint8_t version = data[offset];
  if (version == 0x01 || version == 0x02) {
    zemu_log_stack("skipping version");
    offset += 1;
    *read += 1;
  }

  // get rlp marker
  uint8_t marker = data[offset];
  snprintf(m, 20, "%X\n", marker);
  zemu_log_stack(m);

  if ((marker - 0xC0) * (marker - 0xF7) <= 0) {
    zemu_log_stack("C0-F7");
    *read += 1;
    uint8_t l = marker - 0xC0;
    CHECK_RLP_LEN(len, l + 1)
    zemu_log_stack("after macro");
    *to_read = l;
    snprintf(m, 100, "to_read: %d\n", l);
    zemu_log_stack(m);
    return rlp_ok;
  }

  if (marker >= 0xF8) {
    zemu_log_stack(">F8");
    offset += 1;

    // For lists longer than 55 bytes the length is encoded
    // differently.
    // The number of bytes that compose the length is encoded
    // in the marker
    // And then the length is just the number BE encoded
    uint64_t num_bytes = (uint64_t)(marker - 0xF7);

    CHECK_RLP_LEN(len, num_bytes + 1)
    zemu_log_stack("good_len");

    uint64_t num;
    if (be_bytes_to_u64(&data[offset], num_bytes, &num) != 0)
      return rlp_invalid_data;
    zemu_log_stack("got be_uint64");

    // marker byte + number of bytes used to encode the len
    CHECK_RLP_LEN(len, num_bytes + 1 + num)
    *read += 1 + num_bytes;
    *to_read = num;

    return rlp_ok;
  }

  // should not happen as previous conditional covers all possible values
  return rlp_invalid_data;
}

rlp_error_t parse_rlp_item(uint8_t *bytes, uint32_t dataLen, uint8_t *item, uint32_t *item_len) {
    uint8_t *data = bytes;
    *item_len = 0;
    item = NULL;

    if (dataLen == 0)
        return rlp_no_data;

    uint8_t marker = data[0];
    // first case item is just one byte
    if ((marker - 0x00) * (marker - 0x7F) <= 0) {
        item = &data[0];
        *item_len = 1;
        return rlp_ok;
    }

    // second case it is a sstring with a fixed length
    if ((marker - 0x80) * (marker - 0xB7) <= 0) {
        uint8_t len = marker - 0x80; 

        item = &data[1];
        CHECK_RLP_LEN(dataLen, len + 1)
        *item_len = len;
        return rlp_ok;
    }

    // For strings longer than 55 bytes the length is encoded
    // differently.
    // The number of bytes that compose the length is encoded
    // in the marker
    // And then the length is just the number BE encoded
    if ((marker - 0xB8) * (marker - 0xBF) <= 0) {
        uint8_t num_bytes = marker - 0xB7;
        uint64_t len = 0;
        if (be_bytes_to_u64(&data[1], num_bytes, &len) != 0)
            return rlp_invalid_data;

        CHECK_RLP_LEN(dataLen, len + 1 + num_bytes)
        item = data + 1 + num_bytes;
        *item_len = len;

        return rlp_ok;
    }

    // simple list
    if ((marker - 0xC0) * (marker - 0xF7) <= 0) {
        uint8_t len = marker - 0xC0;

        item = &data[1];
        CHECK_RLP_LEN(dataLen, len + 1)
        *item_len = len;
        return rlp_ok;
    }

    // For lists longer than 55 bytes the length is encoded 
    // differently.
    // The number of bytes that compose the length is encoded
    // in the marker
    // And then the length is just the number BE encoded
    if (marker >= 0xF8) {
        uint8_t num_bytes = marker - 0xF7;
        uint64_t len = 0;
        if (be_bytes_to_u64(&data[1], num_bytes, &len) != 0)
            return rlp_invalid_data;

        CHECK_RLP_LEN(dataLen, len + 1 + num_bytes)

        item = data + 1 + num_bytes;
        *item_len = len;

        return rlp_ok;
    }

    return rlp_invalid_data;
}
