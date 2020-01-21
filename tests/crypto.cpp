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
#include <bignum.h>

using ::testing::TestWithParam;
using ::testing::Values;

extern const char *crypto_testPubKey;
#define ADDRESS_BYTE_TO_STRING_LEN    (42 + 1)

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

    EXPECT_THAT(addrLen, ::testing::Eq(97));

    std::cout << std::endl;

    char pk[100];
    array_to_hexstr(pk, buffer, 33);
    uint8_t *addrByte = (buffer + 33 + 1);
    char addrByteToHexStr[ADDRESS_BYTE_TO_STRING_LEN];
    array_to_hexstr(addrByteToHexStr, addrByte, 21);
    char *addrString = (char *) (addrByte + 21 + 1);

    EXPECT_THAT(std::string(pk),
                ::testing::Eq("03CD4569C4FE16556D74DFD1372A2F3AE7B6C43121C7C2902F9AE935B80A7C254B"));

    EXPECT_THAT(std::string(addrByteToHexStr),
                ::testing::Eq("01CEA85DD723499EEC84DB41CADB28F7D8D8CF31CF"));


    EXPECT_THAT(std::string(addrString),
                ::testing::Eq("f1z2uf3vzdjgpozbg3ihfnwkhx3dmm6mop6d4vlii"));

    std::cout << pk << std::endl;
    std::cout << addrByteToHexStr << std::endl;
    std::cout << addrString << std::endl;
}

/// Test that we can generate the address from a known mnemonic (use default = test mnemonic)
TEST(CRYPTO, fillAddressTestMnemonic) {
    uint8_t buffer[100];

    crypto_testPubKey = nullptr;   // Use default test mnemonic

    uint16_t addrLen = crypto_fillAddress(buffer, 100);

    EXPECT_THAT(addrLen, ::testing::Eq(97));

    std::cout << std::endl;

    char pk[100];
    array_to_hexstr(pk, buffer, 33);
    uint8_t *addrByte = (buffer + 33 + 1);
    char addrByteToHexStr[ADDRESS_BYTE_TO_STRING_LEN];
    array_to_hexstr(addrByteToHexStr, addrByte, 21);
    char *addrString = (char *) (addrByte + 21 + 1);

    EXPECT_THAT(std::string(pk),
                ::testing::Eq("8D16D62802CA55326EC52BF76A8543B90E2ABA5BCF6CD195C0D6FC1EF38FA1B300"));

    EXPECT_THAT(std::string(addrByteToHexStr),
                ::testing::Eq("012F611293C5CA653CF74B48F9F3123C09242FA746"));

    EXPECT_THAT(std::string(addrString),
                ::testing::Eq("f1f5qrfe6fzjstz52ljd47ger4besc7j2gzz3e4ea"));

    std::cout << pk << std::endl;
    std::cout << addrByteToHexStr << std::endl;
    std::cout << addrString << std::endl;
}

TEST(CRYPTO, extractBitsFromLEB128_small) {
    uint8_t input[] = {0x81, 0x01};
    uint64_t output;

    auto ret = decompressLEB128(input, &output);

    EXPECT_THAT(ret, ::testing::Eq(1));
    EXPECT_THAT(output, ::testing::Eq(0x81));

    char bufferUI[300];
    uint64_to_str(bufferUI, sizeof(bufferUI), output);

    auto expected = std::string("129");
    EXPECT_THAT(std::string(bufferUI), testing::Eq(expected)) << "decimal output not matching";
}

TEST(CRYPTO, extractBitsFromLEB128_1byte) {
    uint8_t input[] = {0xc1, 0x0d};
    uint64_t output;

    auto ret = decompressLEB128(input, &output);

    EXPECT_THAT(ret, ::testing::Eq(1));
    EXPECT_THAT(output, ::testing::Eq(1729));

    char bufferUI[300];
    uint64_to_str(bufferUI, sizeof(bufferUI), output);

    auto expected = std::string("1729");
    EXPECT_THAT(std::string(bufferUI), testing::Eq(expected)) << "decimal output not matching";
}

TEST(CRYPTO, extractBitsFromLEB128_big) {
    uint8_t input[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    uint64_t output;

    auto ret = decompressLEB128(input, &output);

    EXPECT_THAT(ret, ::testing::Eq(1));
    EXPECT_THAT(output, ::testing::Eq(18446744073709551615u));

    char bufferUI[300];
    uint64_to_str(bufferUI, sizeof(bufferUI), output);

    auto expected = std::string("18446744073709551615");
    EXPECT_THAT(std::string(bufferUI), testing::Eq(expected)) << "decimal output not matching";
}

TEST(CRYPTO, extractBitsFromLEB128_tooBig) {
    uint8_t input[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02};
    uint64_t output;

    auto ret = decompressLEB128(input, &output);

    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(output, ::testing::Eq(0));

    char bufferUI[300];
    uint64_to_str(bufferUI, sizeof(bufferUI), output);

    auto expected = std::string("0");
    EXPECT_THAT(std::string(bufferUI), testing::Eq(expected)) << "decimal output not matching";
}
