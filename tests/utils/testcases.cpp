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
#include "testcases.h"
#include "expected_output.h"
#include <fmt/core.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <hexutils.h>

testcaseData_t ReadRawTestCase(const std::shared_ptr<Json::Value> &jsonSource, int index) {
    testcaseData_t answer;
    auto v = (*jsonSource)[index];
    auto description = std::string("");

    description = v["kind"].asString();
    if (v.isMember("description")) {
        description = v["description"].asString();
    }
    description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

    auto bytes_hexstring = v["encoded_tx_hex"].asString();
    assert(bytes_hexstring.size() % 2 == 0);
    auto blob = std::vector<uint8_t>(bytes_hexstring.size() / 2);
    parseHexString(blob.data(), blob.size(), bytes_hexstring.c_str());

    auto message = v["message"];

    return {
            description,
            //////
            message["to"].asString(),
            message["from"].asString(),
            message["nonce"].asUInt64(),
            message["value"].asString(),
            message["gaslimit"].asString(),
            message["gaspremium"].asString(),
            message["gasfeecap"].asString(),
            message["method"].asUInt64(),
            v["encoded_tx"].asString(),
            v["valid"].asBool(),
            v["testnet"].asBool(),
            v["expert"].asBool(),
            blob
    };
}

testcaseData_t ReadTestCaseData(const std::shared_ptr<Json::Value> &jsonSource, int index) {
    testcaseData_t tcd = ReadRawTestCase(jsonSource, index);
    // Anotate with expected ui output
    tcd.expected_ui_output = GenerateExpectedUIOutput(tcd);
    return tcd;
}

std::vector<testcase_t> GetJsonTestCases(const std::string &filename) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    std::shared_ptr<Json::Value> obj(new Json::Value());

    std::ifstream inFile(filename);
    EXPECT_TRUE(inFile.is_open())
                        << "\n"
                        << "******************\n"
                        << "Failed to open : " << filename << std::endl
                        << "Check that your working directory points to the tests directory\n"
                        << "In CLion use $PROJECT_DIR$\\tests\n"
                        << "******************\n";
    if (!inFile.is_open()) { return answer; }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, obj.get(), &errs);
    std::cout << "Number of testcases: " << obj->size() << std::endl;
    answer.reserve(obj->size());

    for (int i = 0; i < obj->size(); i++) {
        auto v = (*obj)[i];

        auto description = std::string("");

        description = v["description"].asString();
        description.erase(remove_if(description.begin(), description.end(), [](char v) -> bool {
            return v == ':' || v == ' ' || v == '/';
        }), description.end());

        answer.push_back(testcase_t{obj, i, description});
    }

    return answer;
}
