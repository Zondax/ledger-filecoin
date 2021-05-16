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
#include <fmt/core.h>
#include <coin.h>
#include "testcases.h"
#include "zxmacros.h"

bool TestcaseIsValid(const Json::Value &) {
    return true;
}

template<typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&... args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::string FormatAddress(const std::string &address, uint8_t idx, uint8_t *pageCount) {
    char outBuffer[40];
    pageString(outBuffer, sizeof(outBuffer), address.c_str(), idx, pageCount);

    return std::string(outBuffer);
}

std::string FormatAmount(const std::string &amount) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    fpstr_to_str(buffer, sizeof(buffer), amount.c_str(), COIN_AMOUNT_DECIMAL_PLACES);
    return std::string(buffer);
}

std::vector<std::string> GenerateExpectedUIOutput(const Json::Value &json, bool expertMode) {
    auto answer = std::vector<std::string>();

    bool valid = true;
    if (json.isMember("value")) {
        valid = json["valid"].asBool();
    }

    if (!valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    ///

    ///

    uint8_t dummy;

    if (tc.to.length() > 40) {
        addTo(answer, "0 | To : {}", FormatAddress(tc.to, 0, &dummy));
        addTo(answer, "0 | To : {}", FormatAddress(tc.to, 1, &dummy));
        if (tc.to.length() > 80) {
            addTo(answer, "0 | To : {}", FormatAddress(tc.to, 2, &dummy));
        }
    } else {
        // To print protocol 0 addresses which seems to be always less than 20char
        addTo(answer, "0 | To : {}", FormatAddress(tc.to, 0, &dummy));
    }

    if (tc.from.length() > 40) {
        addTo(answer, "1 | From : {}", FormatAddress(tc.from, 0, &dummy));
        addTo(answer, "1 | From : {}", FormatAddress(tc.from, 1, &dummy));
        if (tc.from.length() > 80) {
            addTo(answer, "1 | From : {}", FormatAddress(tc.from, 2, &dummy));
        }
    } else {
        // To print protocol 0 addresses which seems to be always less than 20char
        addTo(answer, "1 | From : {}", FormatAddress(tc.from, 0, &dummy));
    }

    addTo(answer, "2 | Nonce : {}", tc.nonce);

    addTo(answer, "3 | Value : {}", FormatAmount(tc.value));

    addTo(answer, "4 | Gas Limit : {}", tc.gaslimit);

    addTo(answer, "5 | Gas Premium : {}", FormatAmount(tc.gaspremium));

    addTo(answer, "6 | Gas Fee Cap : {}", FormatAmount(tc.gasfeecap));

    if (tc.method != 0) {
        addTo(answer, "7 | Method : Method{}", tc.method);
    } else {
        addTo(answer, "7 | Method : Transfer", tc.method);
    }

    // If 0 we have a no parameters
    if (tc.method != 0) {
        addTo(answer, "8 | Params : Not Available");
    }

    return answer;
}
