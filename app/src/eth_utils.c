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

#include "eth_utils.h"

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

  for (int i = len; i--; i >= 0) {
    *num_ptr = bytes[i];
    num_ptr += 1;
  }

  return 0;
}

rlp_error_t get_tx_rlp_len(uint8_t *buffer, uint64_t len, uint64_t *read,
                           uint64_t *to_read) {

  if (buffer == NULL || len == 0)
    return empty_buffer;

  if (read == NULL || to_read == NULL)
    return empty_buffer;

  // get alias
  uint8_t *data = buffer;

  *read = 0;
  *to_read = 0;

  // skip version if present/recognized
  //  otherwise tx is probably legacy so no version, just rlp data
  uint8_t version = data[0];
  if (version == 0x01 || version == 0x02) {
    data += 1;
    *read += 1;
  }

  if (*read == len)
    return no_rlp_data;

  // get rlp marker
  uint8_t marker = data[0];

  if ((marker - 0xC0) * (marker - 0xF7) <= 0) {
    *read += 1;
    *to_read = (uint64_t)marker - 0xC0;
    return rlp_ok;
  }

  if (marker >= 0xF8) {
    data += 1;

    // For lists longer than 55 bytes the length is encoded
    // differently.
    // The number of bytes that compose the length is encoded
    // in the marker
    // And then the length is just the number BE encoded
    uint64_t num_bytes = (uint64_t)marker - 0xF7;

    if ((len - 1) < num_bytes)
      return no_rlp_data;

    uint64_t num;
    if (be_bytes_to_u64(data, num_bytes, &num) != 0)
      return invalid_rlp_data;

    // marker byte + number of bytes used to encode the len
    *read += 1 + num_bytes;
    *to_read = num;

    return rlp_ok;
  }

  // should not happen as previous conditional covers all possible values
  return invalid_rlp_data;
}
