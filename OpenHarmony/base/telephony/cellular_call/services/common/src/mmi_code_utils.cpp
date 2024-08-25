/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "mmi_code_utils.h"

#include <regex>

#include "cellular_call_supplement.h"
#include "standardize_utils.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
// 3GPP TS 22.030 V16.0.0 (2020-07) 6.5.3.2	Handling of not-implemented supplementary services
constexpr unsigned long long operator"" _hash(char const *p, size_t s)
{
    return StandardizeUtils::HashCompileTime(p);
}

bool MMICodeUtils::IsNeedExecuteMmi(const std::string &analyseString, bool isNeedUseIms)
{
    isNeedUseIms_ = isNeedUseIms;
    if (analyseString.empty()) {
        TELEPHONY_LOGE("analyseString is empty.");
        return false;
    }
    if (RegexMatchMmi(analyseString)) {
        return true;
    }

    // 3GPP TS 22.030 V16.0.0 (2020-07) 6.5.3.2	Handling of not-implemented supplementary services
    if ((analyseString.front() == '*' || analyseString.front() == '#') && analyseString.back() == '#') {
        TELEPHONY_LOGI("analyseString start with * or # and end with #");
        mmiData_.fullString = analyseString;
        return true;
    }

    return false;
}

void InitMmiCodeFunc(std::map<std::uint64_t,
    void (CellularCallSupplement::*)(int32_t slotId, const MMIData &mmiData)> &mmiCodeFunc)
{
    /**
     * "30" Processing caller ID
     * "31" Processing calling number display
     * "21" Deal with unconditional transfer
     * "61" Handling no answer transfer
     * "62" Handling no signal transfer
     * "67" Deal with busy transfer
     * "002" Process all transfers
     * "004" Handle transfer under all conditions
     * "33" Processing limits all outgoing calls
     * "330" Processing all restrictions
     * "331" Processing limits all international calls
     * "332" Handling international outgoing calls belonging to foreign countries when roaming is
     * restricted
     * "333" Processing limits outgoing calls
     * "35" Processing limits all incoming calls
     * "351" Handle all incoming calls when roaming is restricted
     * "353" Processing limits incoming calls
     * "43" Handling call waiting
     * "04" Change pin password
     * "05" Use puk unlock sim and change pin password
     * "042" Change pin2 password
     * "052" Use puk2 unlock sim and change pin2 password
     */
    mmiCodeFunc["30"_hash] = &CellularCallSupplement::HandleClip;
    mmiCodeFunc["31"_hash] = &CellularCallSupplement::HandleClir;
    mmiCodeFunc["21"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["61"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["62"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["67"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["002"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["004"_hash] = &CellularCallSupplement::HandleCallTransfer;
    mmiCodeFunc["33"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["330"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["331"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["332"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["333"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["35"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["351"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["353"_hash] = &CellularCallSupplement::HandleCallRestriction;
    mmiCodeFunc["43"_hash] = &CellularCallSupplement::HandleCallWaiting;
    mmiCodeFunc["04"_hash] = &CellularCallSupplement::AlterPinPassword;
    mmiCodeFunc["05"_hash] = &CellularCallSupplement::UnlockPuk;
    mmiCodeFunc["042"_hash] = &CellularCallSupplement::AlterPin2Password;
    mmiCodeFunc["052"_hash] = &CellularCallSupplement::UnlockPuk2;
}

void InitImsMmiCodeFunc(
    std::map<std::uint64_t, void (CellularCallSupplement::*)(int32_t slotId, const MMIData &mmiData)> &mmiCodeFunc)
{
    /**
     * "76" Connected line identification presentation
     * "77" Connected line identification restriction
     */
    mmiCodeFunc["76"_hash] = &CellularCallSupplement::HandleColp;
    mmiCodeFunc["77"_hash] = &CellularCallSupplement::HandleColr;
}

bool MMICodeUtils::ExecuteMmiCode(int32_t slotId)
{
    using MmiCodeFunc = void (CellularCallSupplement::*)(int32_t slotId, const MMIData &mmiData);
    std::map<std::uint64_t, MmiCodeFunc> mmiCodeFunc;
    InitMmiCodeFunc(mmiCodeFunc);
    if (isNeedUseIms_) {
        InitImsMmiCodeFunc(mmiCodeFunc);
    }

    CellularCallSupplement supplement;
    if (!mmiData_.serviceCode.empty()) {
        auto serviceCode = StandardizeUtils::Hash_(mmiData_.serviceCode.c_str());
        // "03" Processing network password
        if (serviceCode == "03"_hash) {
            return true;
        }
        auto itFunc = mmiCodeFunc.find(serviceCode);
        if (itFunc != mmiCodeFunc.end()) {
            auto func = itFunc->second;
            if (func != nullptr) {
                (supplement.*func)(slotId, mmiData_);
                return true;
            }
        }
        TELEPHONY_LOGI("Function not found, need check serviceCode.");
    }
    if (!mmiData_.fullString.empty()) {
        TELEPHONY_LOGD("fullString is not empty.");
        supplement.SendUssd(slotId, mmiData_.fullString);
        return true;
    }

    TELEPHONY_LOGW("default case, need check.");
    return false;
}

bool MMICodeUtils::RegexMatchMmi(const std::string &analyseString)
{
    std::string symbols =
        "((\\*|#|\\*#|\\*\\*|##)(\\d{2,3})(\\*([^*#]*)(\\*([^*#]*)(\\*([^*#]*)(\\*([^*#]*))?)?)?)?#)(.*)";
    std::regex pattern(symbols);
    std::smatch results;
    if (regex_match(analyseString, results, pattern)) {
        TELEPHONY_LOGD("regex_match ture");

        /**
         * The following sequence of functions shall be used for the control of Supplementary Services:
         *  SELECT:	Entry of the procedure information (may be a digit or a sequence of characters).
         *  SEND: Transmission of the information to the network.
         *  INDICATION:	Call progress indications.
         */
        int32_t fullString = 1;
        int32_t action = 2;
        // 3GPP TS 22.030 V4.0.0 (2001-03)  6.5.2 Structure of the MMI
        // This structure consists of the following parts:
        //     Service Code, SC( (2 or 3 digits)
        //     Supplementary Information, SI (variable length).
        int32_t serviceCode = 3;
        int32_t sia = 5;
        int32_t sib = 7;
        int32_t sic = 9;
        int32_t pwdConfirm = 11;
        int32_t dialingNumber = 12;
        mmiData_.fullString = results.str(fullString);
        mmiData_.actionString = results.str(action);
        mmiData_.serviceCode = results.str(serviceCode);
        mmiData_.serviceInfoA = results.str(sia);
        mmiData_.serviceInfoB = results.str(sib);
        mmiData_.serviceInfoC = results.str(sic);
        mmiData_.pwdString = results.str(pwdConfirm);
        mmiData_.dialString = results.str(dialingNumber);

        /* 3GPP TS 22.030 V4.0.0 (2001-03)  6.5.2 Structure of the MMI
         * The procedure always starts with *, #, **, ## or *# and is finished by #.
         * Each part within the procedure is separated by *.
         */
        if (analyseString.back() == '#' && !mmiData_.dialString.empty() && mmiData_.dialString.back() == '#') {
            mmiData_.fullString = analyseString;
        }
        return true;
    }
    return false;
}

MMIData MMICodeUtils::GetMMIData()
{
    return mmiData_;
}
} // namespace Telephony
} // namespace OHOS
