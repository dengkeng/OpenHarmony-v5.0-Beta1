/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "standardize_utils.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::string StandardizeUtils::RemoveSeparatorsPhoneNumber(const std::string &phoneString)
{
    std::string newString;

    if (phoneString.empty()) {
        TELEPHONY_LOGE("RemoveSeparatorsPhoneNumber return, phoneStr is empty.");
        return newString;
    }

    for (char c : phoneString) {
        if ((c >= '0' && c <= '9') || c == '*' || c == '#' || c == '+' || c == 'N' || c == ',' || c == ';') {
            newString += c;
        }
    }

    return newString;
}

std::string StandardizeUtils::FormatNumberAndToa(const std::string &phoneNumber, const int32_t callToa)
{
    if (phoneNumber.empty()) {
        TELEPHONY_LOGE("FormatNumberAndToa return, phoneNumber is empty.");
        return phoneNumber;
    }
    std::string newString;
    const int32_t TOA_INTER = 145;
    if (callToa == TOA_INTER && !phoneNumber.empty() && phoneNumber.front() != '+') {
        newString += '+';
        for (char c : phoneNumber) {
            newString += c;
        }
    } else {
        newString = phoneNumber;
    }
    return newString;
}

void StandardizeUtils::ExtractAddressAndPostDial(const std::string &phoneString, std::string &networkAddress,
                                                 std::string &postDial)
{
    if (phoneString.empty()) {
        TELEPHONY_LOGE("ExtractAddressAndPostDial return, phoneStr is empty.");
        return;
    }

    size_t postDialIndex = phoneString.length();
    for (size_t i = 0; i < phoneString.length(); i++) {
        char c = phoneString.at(i);
        if ((c >= '0' && c <= '9') || c == '*' || c == '#' || c == '+' || c == 'N') {
            networkAddress += c;
        } else if (c == ',' || c == ';') {
            postDialIndex = i;
            break;
        }
    }

    for (size_t i = postDialIndex; i < phoneString.length(); i++) {
        char c = phoneString.at(i);
        postDial += c;
    }
}

std::vector<std::string> StandardizeUtils::Split(const std::string &str, const std::string &flag)
{
    std::vector<std::string> vec;
    std::string::size_type start = 0;
    std::string::size_type pos = 0;
    while ((pos = str.find(flag, start)) != str.npos) {
        vec.push_back(str.substr(start, pos - start));
        start = pos + flag.size();
    }
    if (start != str.size()) {
        vec.push_back(str.substr(start, str.size() - start));
    }
    return vec;
}
} // namespace Telephony
} // namespace OHOS
