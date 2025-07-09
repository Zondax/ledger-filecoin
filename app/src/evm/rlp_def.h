/*******************************************************************************
 *   (c) 2018 - 2024 ZondaX AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum {
    RLP_KIND_BYTE = 0,
    RLP_KIND_STRING,
    RLP_KIND_LIST,
} rlp_kind_e;

#define RLP_KIND_BYTE_PREFIX 0x7F

#define RLP_KIND_STRING_SHORT_MIN 0x80
#define RLP_KIND_STRING_SHORT_MAX 0xB7

#define RLP_KIND_STRING_LONG_MIN 0x80
#define RLP_KIND_STRING_LONG_MAX 0xBF

#define RLP_KIND_LIST_SHORT_MIN 0xC0
#define RLP_KIND_LIST_SHORT_MAX 0xF7

#define RLP_KIND_LIST_LONG_MIN 0xF8
#define RLP_KIND_LIST_LONG_MAX 0xFF

typedef struct {
    uint8_t kind;
    uint16_t fieldOffset;
    uint16_t valueOffset;
    uint16_t valueLen;
} rlp_field_t;

typedef struct {
    rlp_kind_e kind;
    const uint8_t *ptr;
    uint64_t rlpLen;
    uint64_t chain_id_decoded;
} rlp_t;

#ifdef __cplusplus
}
#endif
