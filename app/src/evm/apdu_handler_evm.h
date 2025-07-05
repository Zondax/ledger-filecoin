/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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
#include <stdint.h>

void handleGetAddrEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);
void handleSignEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);
void handleSignEip191(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);

#ifdef __cplusplus
}
#endif
