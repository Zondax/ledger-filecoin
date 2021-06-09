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
#include <json/json.h>
#include <fstream>

typedef struct {
    bool valid;

    std::string description;
    std::string to;
    std::string from;
    uint64_t nonce;
    std::string value;
    std::string gaslimit;
    std::string gaspremium;
    std::string gasfeecap;
    uint64_t method;
} testcase_inputs_t;

typedef struct {
    uint64_t index;
    std::string name;
    std::string blob;
    bool valid;
    bool testnet;
    std::string error;

    std::vector<std::string> expected;
    std::vector<std::string> expected_expert;
} testcase_t;
