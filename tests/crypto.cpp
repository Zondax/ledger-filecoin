/*******************************************************************************
 *   (c) 2019 Zondax AG
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

#include <bignum.h>
#include <crypto.h>
#include <hexutils.h>
#include <zxformat.h>

#include <iostream>

#include "coin_evm.h"
#include "crypto_helper.h"
#include "gmock/gmock.h"

extern const char *crypto_testPubKey;
#define ADDRESS_BYTE_TO_STRING_LEN (42 + 1)

/// Test that we can generate the address from a known mnemonic
TEST(CRYPTO, fillAddress) {
    uint8_t buffer[200] = {0};

    crypto_testPubKey =
        "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991"
        "c140f664d2978ac0972a";
    uint8_t publicKey[SECP256K1_PK_LEN] = {0};
    parseHexString(publicKey, sizeof(publicKey), crypto_testPubKey);

    // addr bytes
    uint8_t addrBytes[21] = {0};
    addrBytes[0] = ADDRESS_PROTOCOL_SECP256K1;
    blake_hash(publicKey, SECP256K1_PK_LEN, addrBytes + 1, sizeof(addrBytes) - 1);

    // addr str
    char addrStr[42] = {0};  // 41 = because (20+1+4)*8/5 (32 base encoded size)
    const uint16_t addrLen = formatProtocol(addrBytes, sizeof(addrBytes), (uint8_t *)addrStr, sizeof(addrStr));

    std::cout << std::endl;
    EXPECT_THAT(std::string(addrStr), ::testing::Eq("f137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"));
}

TEST(CRYPTO, extractBitsFromLEB128_small) {
    uint8_t input[] = {0x81, 0x01};
    uint64_t output;

    auto ret = decompressLEB128(input, sizeof(input), &output);

    EXPECT_THAT(ret, ::testing::Eq(2));
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

    EXPECT_THAT(ret, ::testing::Eq(2));
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

    EXPECT_THAT(ret, ::testing::Eq(10));
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
