/*******************************************************************************
 *   (c) 2026 Zondax AG
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

#include <app_mode.h>
#include <gtest/gtest.h>
#include <hexutils.h>
#include <parser.h>
#include <parser_evm.h>

#include <array>
#include <cstring>
#include <vector>

namespace {

std::vector<uint8_t> fromHex(const char *hex) {
    std::vector<uint8_t> bytes(strlen(hex) / 2);
    const size_t size = parseHexString(bytes.data(), static_cast<uint16_t>(bytes.size()), hex);
    bytes.resize(size);
    return bytes;
}

void appendByteStringHeader(std::vector<uint8_t> &message, size_t size) {
    if (size < 24) {
        message.push_back(static_cast<uint8_t>(0x40 + size));
    } else if (size <= UINT8_MAX) {
        message.push_back(0x58);
        message.push_back(static_cast<uint8_t>(size));
    } else {
        ASSERT_LE(size, UINT16_MAX);
        message.push_back(0x59);
        message.push_back(static_cast<uint8_t>(size >> 8));
        message.push_back(static_cast<uint8_t>(size));
    }
}

std::vector<uint8_t> filecoinMessageWithParams(const std::vector<uint8_t> &params) {
    // A valid ten-field Filecoin message using protocol-0 addresses. The last
    // field is replaced with the supplied CBOR-encoded parameters.
    static constexpr std::array<uint8_t, 26> prefix = {
        0x8a, 0x00, 0x42, 0x00, 0x00, 0x43, 0x00, 0x96, 0x01, 0x01, 0x44, 0x00, 0x01,
        0x86, 0xa0, 0x19, 0x61, 0xa8, 0x42, 0x00, 0x00, 0x43, 0x00, 0x09, 0xc4, 0x00,
    };
    std::vector<uint8_t> message(prefix.begin(), prefix.end());
    appendByteStringHeader(message, params.size());
    message.insert(message.end(), params.begin(), params.end());
    return message;
}

parser_context_t parseFilecoin(const std::vector<uint8_t> &message) {
    parser_context_t context{};
    context.tx_type = fil_tx;
    EXPECT_EQ(parser_parse(&context, message.data(), message.size()), parser_ok);
    return context;
}

parser_context_t parseEthereum(const char *hex) {
    static std::vector<uint8_t> message;
    message = fromHex(hex);
    parser_context_t context{};
    context.tx_type = eth_tx;
    EXPECT_EQ(parser_parse_eth(&context, message.data(), message.size()), parser_ok);
    return context;
}

}  // namespace

TEST(SecurityRegression, RejectsTrailingParamsRootBytes) {
    app_mode_reset();
    const auto message = filecoinMessageWithParams({0x81, 0x00, 0x00});
    parser_context_t context{};
    context.tx_type = fil_tx;
    EXPECT_EQ(parser_parse(&context, message.data(), message.size()), parser_cbor_unexpected_EOF);
}

TEST(SecurityRegression, CountsBothMapKeysAndValues) {
    app_mode_reset();
    const auto message = filecoinMessageWithParams({0xa1, 0x00, 0x01});
    const auto context = parseFilecoin(message);

    uint8_t itemCount = 0;
    ASSERT_EQ(parser_getNumItems(&context, &itemCount), parser_ok);
    EXPECT_EQ(itemCount, 8);

    char key[40] = {};
    char value[40] = {};
    uint8_t pageCount = 0;
    ASSERT_EQ(parser_getItem(&context, 7, key, sizeof(key), value, sizeof(value), 0, &pageCount), parser_ok);
    EXPECT_STREQ(key, "Params |2| ");
    EXPECT_STREQ(value, "1");
}

TEST(SecurityRegression, RendersNestedContainerBytes) {
    app_mode_reset();
    const auto message = filecoinMessageWithParams({0x81, 0x82, 0x00, 0x01});
    const auto context = parseFilecoin(message);

    char key[40] = {};
    char value[40] = {};
    uint8_t pageCount = 0;
    ASSERT_EQ(parser_getItem(&context, 6, key, sizeof(key), value, sizeof(value), 0, &pageCount), parser_ok);
    EXPECT_STREQ(key, "Params |1| ");
    EXPECT_STREQ(value, "820001");
}

TEST(SecurityRegression, RejectsZeroItemReview) {
    app_mode_reset();
    std::vector<uint8_t> params = {0x98, 0xfa};
    params.resize(252, 0x00);
    const auto message = filecoinMessageWithParams(params);
    const auto context = parseFilecoin(message);
    EXPECT_EQ(parser_validate(&context), parser_unexpected_number_items);
}

TEST(SecurityRegression, HandlesEip1559FeesWithoutGasPrice) {
    app_mode_reset();
    auto context = parseEthereum(
        "02f87082013a80843b9aca00850d8c7b50e68303d09094eb466342c4d449bc9f53a865d5cb90586f40521580b844a9059cbb"
        "0000000000000000000000004e83362442b8d1bec281594cea3050c8eb01311c000000000000000000000000000000000000000"
        "00000000000000000075bca00c0");
    ASSERT_EQ(parser_validate_eth(&context), parser_ok);

    uint8_t itemCount = 0;
    ASSERT_EQ(parser_getNumItemsEth(&context, &itemCount), parser_ok);
    EXPECT_EQ(itemCount, 6);

    char key[40] = {};
    char value[40] = {};
    uint8_t pageCount = 0;
    ASSERT_EQ(parser_getItemEth(&context, 3, key, sizeof(key), value, sizeof(value), 0, &pageCount), parser_ok);
    EXPECT_STREQ(key, "Max fee per gas");
    ASSERT_EQ(parser_getItemEth(&context, 4, key, sizeof(key), value, sizeof(value), 0, &pageCount), parser_ok);
    EXPECT_STREQ(key, "Max priority fee");
}

TEST(SecurityRegression, RequiresBlindSigningForERC20WithNativeValue) {
    app_mode_reset();
    auto context = parseEthereum(
        "f87480856d6e2edc00832dc6c0944e83362442b8d1bec281594cea3050c8eb01311c880de0b6b3a7640000b844a9059cbb0000"
        "00000000000000000000eb466342c4d449bc9f53a865d5cb90586f405215000000000000000000000000000000000000000000"
        "00000000000000075bca0082013a8080");
    EXPECT_EQ(parser_validate_eth(&context), parser_blindsign_mode_required);

    app_mode_set_blindsign(1);
    ASSERT_EQ(parser_validate_eth(&context), parser_ok);
    uint8_t itemCount = 0;
    ASSERT_EQ(parser_getNumItemsEth(&context, &itemCount), parser_ok);
    EXPECT_EQ(itemCount, 1);
}
