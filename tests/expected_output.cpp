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
#include <iostream>
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

    if(numPages == 0) {
        auto pages = std::string("");
        snprintf(outBuffer, sizeof(outBuffer), "-- EMPTY --");
        addTo(answer, "{} | {}{}: {}", prefix, name, pages, outBuffer);
        return answer;
    }

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

    auto numparams = message["numparams"].asUInt64();
    auto params = message["params"];
    ///

    auto toAddress = FormatAddress(0, "To ", to);
    answer.insert(answer.end(), toAddress.begin(), toAddress.end());

    auto fromAddress = FormatAddress(1, "From ", from);
    answer.insert(answer.end(), fromAddress.begin(), fromAddress.end());


    addTo(answer, "2 | Value : {}", FormatAmount(value));

    addTo(answer, "3 | Gas Limit : {}", gaslimit);

    addTo(answer, "4 | Gas Fee Cap : {}", FormatAmount(gasfeecap));

    addTo(answer, "5 | Gas Premium : {}", FormatAmount(gaspremium));

    addTo(answer, "6 | Nonce : {}", nonce);

    if (method != 0) {
        addTo(answer, "7 | Method : {}", method);
    } else {
        addTo(answer, "7 | Method : Transfer", method);
    }

    int paramIdx = 1;
    for(auto value : params) {
        std::string paramText = "Params |" + std::to_string(paramIdx) + "| ";
        auto paramsAddress = FormatAddress(8 + paramIdx - 1, paramText, value.asString());
        answer.insert(answer.end(), paramsAddress.begin(), paramsAddress.end());
        paramIdx++;
    }

    return answer;
}

std::vector<std::string> ClientDealGenerateExpectedUIOutput(const Json::Value &json, bool) {
    auto answer = std::vector<std::string>();

    auto valid = json["valid"].asBool();

    if (!valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    ///
    ///

    auto message = json["message"];

    auto pieceCID = message["PieceCID"].asString();
    auto client = message["Client"].asString();
    auto provider = message["Provider"].asString();

    auto pieceSize = message["PieceSize(B)"].asUInt64();
    auto dealLabel = message["DealLabel"].asString();
    auto startEpoch = message["StartEpoch"].asUInt64();
    auto endEpoch = message["EndEpoch"].asUInt64();
    auto provCollateral = message["ProvCollateral"].asString();
    auto clientCollateral = message["ClientCollateral"].asString();
    auto verifiedDeal = message["VerifiedDeal"].asBool();

    auto cid = FormatAddress(0, "PieceCID ", pieceCID);
    answer.insert(answer.end(), cid.begin(), cid.end());

    auto clientAddress = FormatAddress(1, "Client ", client);
    answer.insert(answer.end(), clientAddress.begin(), clientAddress.end());

    auto providerAddress = FormatAddress(2, "Provider ", provider);
    answer.insert(answer.end(), providerAddress.begin(), providerAddress.end());


    addTo(answer, "3 | PieceSize(B): {}", pieceSize);

    addTo(answer, "4 | DealLabel: {}", dealLabel);

    addTo(answer, "5 | StartEpoch: {}", startEpoch);

    addTo(answer, "6 | EndEpoch: {}", endEpoch);

    addTo(answer, "7 | ProvCollateral: {}", FormatAmount(provCollateral));

    addTo(answer, "8 | ClientCollateral: {}", FormatAmount( clientCollateral ));

    addTo(answer, "9 | VerifiedDeal : {}", verifiedDeal);

    return answer;
}
