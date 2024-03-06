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

std::vector<std::string> FormatEthAddress(const uint32_t idx, const std::string &name, const std::string &address) {
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

        addTo(answer, "{} | {}{}: {}", idx, name, pages, outBuffer);
    }

    return answer;
}

std::string FormatAmount(const std::string &amount) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    fpstr_to_str(buffer, sizeof(buffer), amount.c_str(), COIN_AMOUNT_DECIMAL_PLACES);
    z_str3join(buffer, sizeof(buffer), "FIL ", NULL);
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
    auto from0x = message["from0x"].asString();
    auto from = message["from"].asString();

    auto to0x = message["to0x"].asString();
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

    uint8_t idx = 0;
    if (!to0x.empty()) {
        auto to0xAddress = FormatAddress(idx, "To ", to0x);
        answer.insert(answer.end(), to0xAddress.begin(), to0xAddress.end());
        // addTo(answer, "{} | To : {}", idx, to0xAddress);
        idx++;
    }

    auto toAddress = FormatAddress(idx, "To ", to);
    answer.insert(answer.end(), toAddress.begin(), toAddress.end());
    idx++;

    if (!from0x.empty()) {
        auto fromAddress0x = FormatAddress(idx, "From ", from0x);
        answer.insert(answer.end(), fromAddress0x.begin(), fromAddress0x.end());
        idx++;
    }

    auto fromAddress = FormatAddress(idx, "From ", from);
    answer.insert(answer.end(), fromAddress.begin(), fromAddress.end());
    idx++;

    addTo(answer, "{} | Value : {}", idx, FormatAmount(value));
    idx++;

    addTo(answer, "{} | Gas Limit : {}", idx, FormatAmount(gaslimit));
    idx++;

    addTo(answer, "{} | Gas Fee Cap : {}", idx, FormatAmount(gasfeecap));
    idx++;

    addTo(answer, "{} | Gas Premium : {}", idx, FormatAmount(gaspremium));
    idx++;

    addTo(answer, "{} | Nonce : {}", idx, nonce);
    idx++;

    if (method != 0) {
        addTo(answer, "{} | Method : {}", idx, method);
        idx++;
    } else {
        addTo(answer, "{} | Method : Transfer", idx, method);
        idx++;
    }

    int paramIdx = 1;
    for(auto value : params) {
        std::string paramText = "Params |" + std::to_string(paramIdx) + "| ";
        auto paramsAddress = FormatAddress(idx + paramIdx - 1, paramText, value.asString());
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

std::vector<std::string> EVMGenerateExpectedUIOutput(const Json::Value &json, bool) {
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
    auto to = message["To"].asString();
    auto contract = message["Contract"].asString();
    auto value = message["Value"].asString();
    auto nonce = message["Nonce"].asString();
    auto gasPrice = message["GasPrice"].asString();
    auto gasLimit = message["GasLimit"].asString();
    ///

    uint8_t idx = 0;
    auto destAddress = FormatEthAddress(idx, "To", to);
    answer.insert(answer.end(), destAddress.begin(), destAddress.end());

    if (value.starts_with("??")) {
        idx++;
        auto contractAddress = FormatEthAddress(idx, "Contract", contract);
        answer.insert(answer.end(), contractAddress.begin(), contractAddress.end());
    }

    idx++;
    addTo(answer, "{} | Value: {}", idx, value);

    idx++;
    addTo(answer, "{} | Nonce: {}", idx, nonce);

    idx++;
    addTo(answer, "{} | Gas price: {}", idx, gasPrice);

    idx++;
    addTo(answer, "{} | Gas limit: {}", idx, gasLimit);

    return answer;
}

std::vector<std::string> InvokeContractGenerateExpectedUIOutput(const Json::Value &json, bool expertMode) {
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
    auto from0x = message["from0x"].asString();
    auto from = message["from"].asString();

    auto to0x = message["to0x"].asString();
    auto to = message["to"].asString();
    auto nonce = message["nonce"].asUInt64();

    auto method = message["method"].asString();
    auto value = message["value"].asString();
    auto contract = message["Contract"].asString();
    auto contractF4 = message["ContractF4"].asString();


    auto gaslimit = message["gaslimit"].asString();
    auto gaspremium = message["gaspremium"].asString();
    auto gasfeecap = message["gasfeecap"].asString();

    ///

    uint8_t idx = 0;
    addTo(answer, "{} | Method: {}", idx, method);
    idx++;

    if (!from0x.empty()) {
        auto fromAddress0x = FormatAddress(idx, "From", from0x);
        answer.insert(answer.end(), fromAddress0x.begin(), fromAddress0x.end());
        idx++;
    }

    auto fromAddress = FormatAddress(idx, "From", from);
    answer.insert(answer.end(), fromAddress.begin(), fromAddress.end());
    idx++;

    auto toF0 = FormatAddress(idx, "To", to0x);
    answer.insert(answer.end(), toF0.begin(), toF0.end());
    idx++;

    if (!to.empty()) {
        auto toAddress = FormatAddress(idx, "To", to);
        answer.insert(answer.end(), toAddress.begin(), toAddress.end());
        idx++;
    }

    if (value.starts_with("??")) {
        auto contractAddress = FormatEthAddress(idx, "Contract", contract);
        answer.insert(answer.end(), contractAddress.begin(), contractAddress.end());
        idx++;

        auto contractAddressF4 = FormatEthAddress(idx, "Contract", contractF4);
        answer.insert(answer.end(), contractAddressF4.begin(), contractAddressF4.end());
        idx++;
    }

    addTo(answer, "{} | Value: {}", idx, value);
    idx++;

    addTo(answer, "{} | Gas Limit: {}", idx, FormatAmount(gaslimit));
    idx++;

    if (expertMode) {
        addTo(answer, "{} | Gas Fee Cap: {}", idx, FormatAmount(gasfeecap));
        idx++;

        addTo(answer, "{} | Gas Premium: {}", idx, FormatAmount(gaspremium));
        idx++;

        addTo(answer, "{} | Nonce: {}", idx, nonce);
        idx++;
    }

    return answer;
}
