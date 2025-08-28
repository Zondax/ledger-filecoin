/*******************************************************************************
 *   (c) 2019 Zondax AG
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
#include <coin.h>
#include <fmt/core.h>

#include <iostream>

#include "testcases.h"
#include "zxformat.h"
#include "zxmacros.h"
const uint32_t fieldSize = 37;

// Helper function to safely get string from JSON value (handles both string and number types)
std::string getStringValue(const nlohmann::json &obj, const std::string &key, const std::string &defaultValue = "") {
    if (!obj.contains(key)) {
        return defaultValue;
    }
    if (obj[key].is_string()) {
        return obj[key].get<std::string>();
    } else if (obj[key].is_number()) {
        return std::to_string(obj[key].get<uint64_t>());
    }
    return defaultValue;
}

// Helper function to safely get uint64_t from JSON value
uint64_t getUint64Value(const nlohmann::json &obj, const std::string &key, uint64_t defaultValue = 0) {
    if (!obj.contains(key)) {
        return defaultValue;
    }
    if (obj[key].is_number()) {
        return obj[key].get<uint64_t>();
    } else if (obj[key].is_string()) {
        try {
            return std::stoull(obj[key].get<std::string>());
        } catch (...) {
            return defaultValue;
        }
    }
    return defaultValue;
}

template <typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&...args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::vector<std::string> FormatAddress(uint32_t prefix, const std::string &name, const std::string &address) {
    auto answer = std::vector<std::string>();
    uint8_t numPages = 0;
    char outBuffer[100];

    pageString(outBuffer, fieldSize, address.c_str(), 0, &numPages);

    if (numPages == 0) {
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

std::vector<std::string> GenerateExpectedUIOutput(const nlohmann::json &json, bool) {
    auto answer = std::vector<std::string>();

    bool valid = json.value("valid", true);

    if (!valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    ///

    auto message = json["message"];
    auto from0x = getStringValue(message, "from0x");
    auto from = getStringValue(message, "from");

    auto to0x = getStringValue(message, "to0x");
    auto to = getStringValue(message, "to");
    auto nonce = getUint64Value(message, "nonce");

    auto value = getStringValue(message, "value", "0");
    auto gaslimit = getStringValue(message, "gaslimit", "0");
    auto gaspremium = getStringValue(message, "gaspremium", "0");
    auto gasfeecap = getStringValue(message, "gasfeecap", "0");
    auto method = getUint64Value(message, "method");

    auto numparams = getUint64Value(message, "numparams");
    auto params = message.value("params", nlohmann::json::array());
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

    // Transfer method
    if (method == 0) {
        addTo(answer, "{} | Method : Transfer", idx, method);
        // Invoke EVM method
    } else if (method == 3844450837) {
        addTo(answer, "{} | Method : Invoke EVM", idx, method);
    } else {
        addTo(answer, "{} | Method : {}", idx, method);
    }
    idx++;

    int paramIdx = 1;
    for (auto value : params) {
        std::string paramText = "Params |" + std::to_string(paramIdx) + "| ";
        std::string paramValue;
        if (value.is_string()) {
            paramValue = value.get<std::string>();
        } else if (value.is_number()) {
            paramValue = std::to_string(value.get<uint64_t>());
        } else {
            paramValue = "";
        }
        auto paramsAddress = FormatAddress(idx + paramIdx - 1, paramText, paramValue);
        answer.insert(answer.end(), paramsAddress.begin(), paramsAddress.end());
        paramIdx++;
    }

    return answer;
}

std::vector<std::string> EVMGenerateExpectedUIOutput(const nlohmann::json &json, bool) {
    auto answer = std::vector<std::string>();

    bool valid = json.value("valid", true);

    if (!valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    ///
    auto message = json["message"];
    auto to = getStringValue(message, "To");
    auto contract = getStringValue(message, "Contract");
    auto value = getStringValue(message, "Value");
    auto nonce = getStringValue(message, "Nonce");
    auto gasPrice = getStringValue(message, "GasPrice");
    auto gasLimit = getStringValue(message, "GasLimit");
    ///

    uint8_t idx = 0;
    auto destAddress = FormatEthAddress(idx, "To", to);
    answer.insert(answer.end(), destAddress.begin(), destAddress.end());

    if (value.starts_with("??")) {
        idx++;
        auto contractAddress = FormatEthAddress(idx, "Token Contract", contract);
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

std::vector<std::string> InvokeContractGenerateExpectedUIOutput(const nlohmann::json &json, bool expertMode) {
    auto answer = std::vector<std::string>();

    bool valid = json.value("valid", true);

    if (!valid) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    ///

    auto message = json["message"];
    auto from0x = getStringValue(message, "from0x");
    auto from = getStringValue(message, "from");

    auto to0x = getStringValue(message, "to0x");
    auto to = getStringValue(message, "to");
    auto nonce = getUint64Value(message, "nonce");

    auto method = getStringValue(message, "method");
    auto value = getStringValue(message, "value");
    auto contract = getStringValue(message, "Contract");
    auto contractF4 = getStringValue(message, "ContractF4");

    auto gaslimit = getStringValue(message, "gaslimit", "0");
    auto gaspremium = getStringValue(message, "gaspremium", "0");
    auto gasfeecap = getStringValue(message, "gasfeecap", "0");

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
        auto contractAddress = FormatEthAddress(idx, "Token Contract", contract);
        answer.insert(answer.end(), contractAddress.begin(), contractAddress.end());
        idx++;

        auto contractAddressF4 = FormatEthAddress(idx, "Token Contract", contractF4);
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
