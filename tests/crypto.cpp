/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
#include <crypto.h>
#include <bignum.h>

using ::testing::TestWithParam;
using ::testing::Values;

extern const char *crypto_testPubKey;
#define ADDRESS_BYTE_TO_STRING_LEN    (42 + 1)

/// Test that we can generate the address from a known mnemonic
TEST(CRYPTO, fillAddress) {
    uint8_t buffer[200];

// FIXME: use real values from Lotus and confirm functionality
//    wage retreat alpha skull cactus inform device despair finish enforce chief young
//    derived using 44'/461'/0'/0/0
//    Public key (hex): 03cd4569c4fe16556d74dfd1372a2f3ae7b6c43121c7c2902f9ae935b80a7c254b
//    Address: f1Z2UF3VZDJGPOZBG3IHFNWKHX3DMM6MOPKFHQOYY

    crypto_testPubKey = "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a";

    uint16_t addrLen = crypto_fillAddress(buffer, sizeof(buffer));

    ASSERT_THAT(addrLen, ::testing::Eq(129));

    std::cout << std::endl;

    char pk[200];
    array_to_hexstr(pk, sizeof(pk), buffer, SECP256K1_PK_LEN);
    uint8_t *addrByte = (buffer + SECP256K1_PK_LEN + 1);
    char addrByteToHexStr[ADDRESS_BYTE_TO_STRING_LEN];
    array_to_hexstr(addrByteToHexStr, sizeof(addrByteToHexStr), addrByte, 21);
    char *addrString = (char *) (addrByte + 21 + 1);

    EXPECT_THAT(std::string(pk),
                ::testing::Eq("0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a"));

    EXPECT_THAT(std::string(addrByteToHexStr),
                ::testing::Eq("01dfe49184d46adc8f89d44638beb45f78fcad2590"));


    EXPECT_THAT(std::string(addrString),
                ::testing::Eq("f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"));

    std::cout << pk << std::endl;
    std::cout << addrByteToHexStr << std::endl;
    std::cout << addrString << std::endl;
}

/// Test that we can generate the address from a known mnemonic (use default = test mnemonic)
TEST(CRYPTO, fillAddressTestMnemonic) {
    uint8_t buffer[200];

    crypto_testPubKey = nullptr;   // Use default test mnemonic

    uint16_t addrLen = crypto_fillAddress(buffer, sizeof(buffer));

    ASSERT_THAT(addrLen, ::testing::Eq(129));

    std::cout << std::endl;

    char pk[200];
    array_to_hexstr(pk, sizeof(pk), buffer, SECP256K1_PK_LEN);
    uint8_t *addrByte = (buffer + SECP256K1_PK_LEN + 1);
    char addrByteToHexStr[ADDRESS_BYTE_TO_STRING_LEN];
    array_to_hexstr(addrByteToHexStr, sizeof(addrByteToHexStr), addrByte, 21);
    char *addrString = (char *) (addrByte + 21 + 1);

    EXPECT_THAT(std::string(pk),
                ::testing::Eq("0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a"));

    EXPECT_THAT(std::string(addrByteToHexStr),
                ::testing::Eq("01dfe49184d46adc8f89d44638beb45f78fcad2590"));

    EXPECT_THAT(std::string(addrString),
                ::testing::Eq("f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"));

    std::cout << pk << std::endl;
    std::cout << addrByteToHexStr << std::endl;
    std::cout << addrString << std::endl;
}

TEST(CRYPTO, extractBitsFromLEB128_small) {
    uint8_t input[] = {0x81, 0x01};
    uint64_t output;

    auto ret = decompressLEB128(input, sizeof(input), &output);

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

    auto ret = decompressLEB128(input, sizeof(input), &output);

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

    auto ret = decompressLEB128(input, sizeof(input), &output);

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

    auto ret = decompressLEB128(input, sizeof(input), &output);

    EXPECT_THAT(ret, ::testing::Eq(0));
    EXPECT_THAT(output, ::testing::Eq(0));

    char bufferUI[300];
    uint64_to_str(bufferUI, sizeof(bufferUI), output);

    auto expected = std::string("0");
    EXPECT_THAT(std::string(bufferUI), testing::Eq(expected)) << "decimal output not matching";
}

TEST(CRYPTO, prepareMessageDigest) {
    uint8_t input[61];
    auto inputLen = parseHexString(input, sizeof(input), "885501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C6285501B882619D46558F3D9E316D11B48DCF211327025A0144000186A0430009C4430061A80040");

    uint8_t output[32];
    auto err = prepareDigestToSign(input, inputLen, output, sizeof(output));

    char message_digest[100];
    array_to_hexstr(message_digest, sizeof(message_digest), output, 32);
    std::cout << message_digest << std::endl;

    EXPECT_THAT(std::string(message_digest),
                ::testing::Eq("5a51287d2e5401b75014da0f050c8db96fe0bacdad75fce964520ca063b697e1"));

    EXPECT_THAT(err, ::testing::Eq(0));

}
