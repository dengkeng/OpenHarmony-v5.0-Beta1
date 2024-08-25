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

#ifndef TELEPHONY_CELLULAR_CALL_STANDARDIZE_UTILS_H
#define TELEPHONY_CELLULAR_CALL_STANDARDIZE_UTILS_H

#include <string>

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class StandardizeUtils {
public:
    /**
     * StandardizeUtils constructor
     */
    StandardizeUtils() = default;

    /**
     * ~StandardizeUtils destructor
     */
    ~StandardizeUtils() = default;

    /**
     * Strips separators from a phone number string
     *
     * @param string phone number to strip
     * @return phone string stripped of separators.
     */
    std::string RemoveSeparatorsPhoneNumber(const std::string &phoneNum);

    /**
     * make sure there is a + in front of toa_international phone number
     *
     * @param string phone number
     * @param int32_t toa
    */
    std::string FormatNumberAndToa(const std::string &phoneNumber, const int32_t callToa);

    void ExtractAddressAndPostDial(const std::string &phoneString, std::string &networkAddress, std::string &postDial);

    static std::vector<std::string> Split(const std::string &str, const std::string &flag);

    typedef std::uint64_t hash_t64;

    static hash_t64 Hash_(char const *hashStr)
    {
        hash_t64 result {cellular_call_b};
        while (*hashStr) {
            result ^= *hashStr;
            result *= cellular_call_p;
            hashStr++;
        }
        return result;
    }

    static constexpr hash_t64 HashCompileTime(char const *str, hash_t64 last_value = cellular_call_b)
    {
        return *str ? HashCompileTime(str + 1, (*str ^ last_value) * cellular_call_p) : last_value;
    }

    static bool IsDtmfKey(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'D') || c == '*' || c == '#';
    }

    static bool IsPauseKey(char c)
    {
        return c == ',';
    }

    static bool IsWaitKey(char c)
    {
        return c == ';';
    }

private:
    static constexpr hash_t64 cellular_call_p = 0x100000001B3ull;
    static constexpr hash_t64 cellular_call_b = 0xCBF29CE484222325ull;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_CELLULAR_CALL_STANDARDIZE_UTILS_H
