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
#pragma once

typedef struct {
    std::string description;
    std::string to;
    std::string from;
    uint64_t nonce;
    std::string value;
    std::string gasprice;
    std::string gaslimit;
    uint64_t method;

    std::string encoded_tx;
    bool valid;
    bool testnet;

    std::vector<uint8_t> blob;
    std::vector<std::string> expected_ui_output;
} testcaseData_t;

typedef struct {
    std::shared_ptr<Json::Value> testcases;
    int64_t index;
    std::string description;
} testcase_t;
