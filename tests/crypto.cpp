/*******************************************************************************
*   (c) 2019 ZondaX GmbH
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

#include "gmock/gmock.h"

#include <iostream>
#include <hexutils.h>
#include <lib/crypto.h>

using ::testing::TestWithParam;
using ::testing::Values;

extern const char *crypto_testPubKey;

/// Test that we can generate the address from a known mnemonic
TEST(CRYPTO, fillAddress) {
    uint8_t buffer[100];

// FIXME: use real values from Lotus and confirm functionality
//    wage retreat alpha skull cactus inform device despair finish enforce chief young
//    derived using 44'/461'/0'/0/0
//    Public key (hex): 03cd4569c4fe16556d74dfd1372a2f3ae7b6c43121c7c2902f9ae935b80a7c254b
//    Address: f1Z2UF3VZDJGPOZBG3IHFNWKHX3DMM6MOPKFHQOYY

    crypto_testPubKey = "03cd4569c4fe16556d74dfd1372a2f3ae7b6c43121c7c2902f9ae935b80a7c254b";

    uint16_t addrLen = crypto_fillAddress(buffer, 100);

    EXPECT_THAT(addrLen, ::testing::Eq(74));

    std::cout << std::endl;

    char pk[100];
    array_to_hexstr(pk, buffer, 33);
    char *addr = (char *) (buffer + 33);

    EXPECT_THAT(std::string(pk),
        ::testing::Eq("03CD4569C4FE16556D74DFD1372A2F3AE7B6C43121C7C2902F9AE935B80A7C254B"));

    EXPECT_THAT(std::string(addr),
                ::testing::Eq("f1z2uf3vzdjgpozbg3ihfnwkhx3dmm6mopkfhqoyy"));

    std::cout << pk << std::endl;
    std::cout << addr << std::endl;
}

/// Test that we can generate the address from a known mnemonic (use default = test mnemonic)
TEST(CRYPTO, fillAddressTestMnemonic) {
    uint8_t buffer[100];

    crypto_testPubKey = nullptr;   // Use default test mnemonic

    uint16_t addrLen = crypto_fillAddress(buffer, 100);

    EXPECT_THAT(addrLen, ::testing::Eq(74));

    std::cout << std::endl;

    char pk[100];
    array_to_hexstr(pk, buffer, 33);
    char *addr = (char *) (buffer + 33);

    EXPECT_THAT(std::string(pk),
                ::testing::Eq("8D16D62802CA55326EC52BF76A8543B90E2ABA5BCF6CD195C0D6FC1EF38FA1B300"));

    EXPECT_THAT(std::string(addr),
                ::testing::Eq("f1f5qrfe6fzjstz52ljd47ger4besc7j2g5hfv4lq"));

    std::cout << pk << std::endl;
    std::cout << addr << std::endl;
}
