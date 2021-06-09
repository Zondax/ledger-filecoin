
//testcaseData_t ReadRawTestCase(const std::shared_ptr<Json::Value> &jsonSource, int index) {
//    testcaseData_t answer;
//    auto v = (*jsonSource)[index];
//    auto description = std::string("");
//
//    description = v["kind"].asString();
//    if (v.isMember("description")) {
//        description = v["description"].asString();
//    }
//    description.erase(remove_if(description.begin(), description.end(), isspace), description.end());
//
//    auto bytes_hexstring = v["encoded_tx_hex"].asString();
//    assert(bytes_hexstring.size() % 2 == 0);
//    auto blob = std::vector<uint8_t>(bytes_hexstring.size() / 2);
//    parseHexString(blob.data(), blob.size(), bytes_hexstring.c_str());
//
//    auto message = v["message"];
//
//    return {
//            description,
//            //////
//            message["to"].asString(),
//            message["from"].asString(),
//            message["nonce"].asUInt64(),
//            message["value"].asString(),
//            message["gaslimit"].asString(),
//            message["gaspremium"].asString(),
//            message["gasfeecap"].asString(),
//            message["method"].asUInt64(),
//            v["encoded_tx"].asString(),
//            v["valid"].asBool(),
//            v["testnet"].asBool(),
//            v["expert"].asBool(),
//            blob
//    };
//}
