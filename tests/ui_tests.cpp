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
#include <fstream>
#include <nlohmann/json.hpp>
#include <hexutils.h>
#include <app_mode.h>
#include "parser.h"
#include "common.h"
#include <memory>
#include "testcases.h"
#include "expected_output.h"

using ::testing::TestWithParam;

class JsonTests : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

std::string CleanTestname(std::string s) {
    s.erase(remove_if(s.begin(), s.end(), [](char v) -> bool {
        return v == ':' || v == ' ' || v == '/' || v == '-' || v == '.' || v == '_' || v == '#';
    }), s.end());
    return s;
}

template <typename Generator>
std::vector<testcase_t> GetJsonTestCases(const std::string &jsonFile, Generator gen_ui_output) {
    auto answer = std::vector<testcase_t>();

    std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    nlohmann::json obj;
    inFile >> obj;
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (auto &i : obj) {
        // auto outputs = GenerateExpectedUIOutput(i, false);
        // auto outputs_expert = GenerateExpectedUIOutput(i, true);
        auto outputs = gen_ui_output(i, false);
        auto outputs_expert = gen_ui_output(i, true);

        bool valid = i.value("valid", true);

        auto name = CleanTestname(i.value("description", std::string("")));

        answer.push_back(testcase_t{
                answer.size() + 1,
                name,
                i.value("encoded_tx_hex", std::string("")),
                valid,
                i.value("testnet", false),
                i.value("error", std::string("")),
                outputs,
                outputs_expert
        });
    }

    return answer;
}

void check_testcase(const testcase_t &tc, bool a, parser_context_t ctx) {
    app_mode_set_expert(a);

    parser_error_t err;

    uint8_t buffer[10000];
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    hdPath[0] = HDPATH_0_DEFAULT;
    hdPath[1] = HDPATH_1_DEFAULT;
    if (tc.testnet) {
        hdPath[0] = HDPATH_0_TESTNET;
        hdPath[1] = HDPATH_1_TESTNET;
    }

    err = parser_parse(&ctx, buffer, bufferLen);

    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok);
        ASSERT_EQ(tc.error, parser_getErrorDescription(err));
        return;
    }

    err = parser_validate(&ctx);
    ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);

    auto output = dumpUI(&ctx, 40, 37);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() ? tc.expected_expert : tc.expected;
    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(expected[i]));
        }
    }
}

void check_testcase_fil_eth(const testcase_t &tc, bool a) {
    parser_context_t ctx;
    ctx.tx_type = eth_tx;
    check_testcase(tc, a, ctx);
}

void check_testcase_fil_base(const testcase_t &tc, bool a) {
    parser_context_t ctx;
    ctx.tx_type = fil_tx;
    check_testcase(tc, a, ctx);
}

///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

class VerifyTestVectors : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << std::setfill('0') << std::setw(5) << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

class VerifyEvmTransactions: public JsonTests{};

class VerifyInvokeContract: public JsonTests{};

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(VerifyTestVectors);

INSTANTIATE_TEST_SUITE_P(
        EVMTransactions,
        VerifyEvmTransactions,
        ::testing::ValuesIn(GetJsonTestCases("testvectors/evm.json", EVMGenerateExpectedUIOutput)), VerifyTestVectors::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        InvokeContract,
        VerifyInvokeContract,
        ::testing::ValuesIn(GetJsonTestCases("testvectors/invoke_contracts.json", InvokeContractGenerateExpectedUIOutput)), VerifyTestVectors::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        Multisig,
        VerifyTestVectors,
        ::testing::ValuesIn(GetJsonTestCases("testvectors/manual.json", GenerateExpectedUIOutput)), VerifyTestVectors::PrintToStringParamName()
);

TEST_P(VerifyTestVectors, CheckUIOutput_CurrentTX_Normal) { check_testcase_fil_base(GetParam(), true); }

TEST_P(VerifyTestVectors, CheckUIOutput_CurrentTX_Expert) { check_testcase_fil_base(GetParam(), true); }

TEST_P(VerifyEvmTransactions, CheckUIOutput_CurrentTX_Normal) { check_testcase_fil_eth(GetParam(), false); }

TEST_P(VerifyInvokeContract, CheckUIOutput_CurrentTX_Normal) { check_testcase_fil_base(GetParam(), true); }
