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
#include "zxformat.h"

const uint32_t fieldSize = 37;

template<typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&... args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::vector<std::string> FormatAddress(uint32_t prefix, const std::string &name, const std::string &address) {
    auto answer = std::vector<std::string>();
    uint8_t numPages = 0;
    char outBuffer[100];

    pageString(outBuffer, fieldSize, address.c_str(), 0, &numPages);

    for (auto i = 0; i < numPages; i++) {
        MEMZERO(outBuffer, sizeof(outBuffer));
        pageString(outBuffer, fieldSize, address.c_str(), i, &numPages);

        auto pages = std::string("");

        if (numPages > 1) {
            pages = fmt::format("[{}/{}] ", i + 1, numPages);
        }

        addTo(answer, "{} | {}{}: {}", prefix, name, pages, outBuffer);
    }

    return answer;
}

std::string FormatAmount(const std::string &amount) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    fpstr_to_str(buffer, sizeof(buffer), amount.c_str(), COIN_AMOUNT_DECIMAL_PLACES);
    return std::string(buffer);
}

std::vector<std::string> GenerateExpectedUIOutput(const Json::Value &json, bool) {
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

    auto message = json["message"];
    auto from = message["from"].asString();

    auto to = message["to"].asString();
    auto nonce = message["nonce"].asUInt64();

    auto value = message["value"].asString();
    auto gaslimit = message["gaslimit"].asString();
    auto gaspremium = message["gaspremium"].asString();
    auto gasfeecap = message["gasfeecap"].asString();
    auto method = message["method"].asUInt64();

    ///

    auto toAddress = FormatAddress(0, "To ", to);
    answer.insert(answer.end(), toAddress.begin(), toAddress.end());

    auto fromAddress = FormatAddress(1, "From ", from);
    answer.insert(answer.end(), fromAddress.begin(), fromAddress.end());


    addTo(answer, "2 | Nonce : {}", nonce);

    addTo(answer, "3 | Value : {}", FormatAmount(value));

    addTo(answer, "4 | Gas Limit : {}", gaslimit);

    addTo(answer, "5 | Gas Premium : {}", FormatAmount(gaspremium));

    addTo(answer, "6 | Gas Fee Cap : {}", FormatAmount(gasfeecap));

    if (method != 0) {
        addTo(answer, "7 | Method : Method{}", method);
    } else {
        addTo(answer, "7 | Method : Transfer", method);
    }

    // If 0 we have a no parameters
    if (method != 0) {
        addTo(answer, "8 | Params : Not Available");
    }

    return answer;
}
