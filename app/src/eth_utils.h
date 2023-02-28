
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

#pragma once

#include <stdio.h>
#include <zxmacros.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RlpError {
  rlp_ok = 0,
  empty_buffer,
  invalid_rlp_data,
  no_rlp_data
} rlp_error_t;

// Add two numbers returning UINT64_MAX if overflows
uint64_t saturating_add(uint64_t a, uint64_t b);

/// Returns the number of bytes read and the number of bytes to read
// Gets the number of bytes read and the number of bytes to read
//
// Returns false if there is a error in the rlp encoded data, true otherwise.
rlp_error_t get_tx_rlp_len(uint8_t *buffer, uint64_t len, uint64_t *read,
                           uint64_t *to_read);

// converts a big endian stream of bytes to an u64 number.
// returns 0 on success, a negative number otherwise
int be_bytes_to_u64(uint8_t *bytes, uint8_t len, uint64_t *num);

#ifdef __cplusplus
}
#endif
