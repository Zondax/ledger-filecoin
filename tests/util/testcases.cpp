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
#include "testcases.h"
#include "base64.h"
#include <zxmacros.h>
#include <fmt/core.h>
#include <gtest/gtest.h>
#include <algorithm>

bool TestcaseIsValid(const Json::Value &tc) {
    return true;
}

template<typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&... args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::vector<uint8_t> prepareBlob(const std::string &base64Cbor) {
    std::string cborString;
    macaron::Base64::Decode(base64Cbor, cborString);

    // Allocate and prepare buffer
    // CBOR payload
    auto bufferAllocation = std::vector<uint8_t>(cborString.size());

    MEMCPY(bufferAllocation.data(), cborString.c_str(), cborString.size());

    return bufferAllocation;
}

std::vector<std::string> GenerateExpectedUIOutput(const Json::Value &j) {
    auto answer = std::vector<std::string>();

    if (!TestcaseIsValid(j)) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    return answer;
}

testcaseData_t ReadTestCaseData(const std::shared_ptr<Json::Value> &jsonSource, int index) {
    testcaseData_t answer;
    auto v = (*jsonSource)[index];
    auto description = std::string("");

    if (v.isMember("description")) {
        description = v["description"].asString();
    } else {
        description = v["kind"].asString();
    }
    description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

    return {
            description,
            //////
            v["to"].asString(),
            v["from"].asString(),
            v["nonce"].asUInt64(),
            v["value"].asString(),
            v["gasprice"].asString(),
            v["gaslimit"].asString(),
            v["method"].asUInt64(),
            v["encoded_tx"].asString(),
            v["valid"].asBool() && TestcaseIsValid(v),
            GenerateExpectedUIOutput(v)
    };
}

std::vector<testcase_t> GetJsonTestCases(const std::string &filename) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    std::shared_ptr<Json::Value> obj(new Json::Value());

    std::ifstream inFile(filename);
    EXPECT_TRUE(inFile.is_open())
                        << "\n"
                        << "******************\n"
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
        description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

        answer.push_back(testcase_t{obj, i, description});
    }

    return answer;
}
