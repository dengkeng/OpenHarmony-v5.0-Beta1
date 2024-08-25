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

#ifndef TELEPHONY_BASE_CONNECTION_H
#define TELEPHONY_BASE_CONNECTION_H

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "core_manager_inner.h"
#include "call_manager_inner_type.h"
#include "cellular_call_data_struct.h"

namespace OHOS {
namespace Telephony {
constexpr static const int64_t PAUSE_DELAY_TIME = 3 * 1000;
class BaseConnection {
public:
    /**
     * Constructor
     */
    BaseConnection();

    /**
     * Destructor
     */
    virtual ~BaseConnection() = default;

    /**
     * Set or Update CallReportInfo
     *
     * @param CallReportInfo
     */
    void SetOrUpdateCallReportInfo(CallReportInfo &callReportInfo);

    /**
     * Get CallReportInfo
     *
     * @return CallReportInfo
     */
    CallReportInfo GetCallReportInfo();

    /**
     * SetStatus
     *
     * @param state
     */
    void SetStatus(TelCallState state);

    /**
     * Get connection Status
     *
     * @return TelCallState
     */
    TelCallState GetStatus() const;

    /**
     * IsRingingState.
     *
     * @return bool
     */
    bool IsRingingState() const;

    /**
     * Set Flag
     *
     * @param bool
     */
    void SetFlag(bool flag);

    /**
     * Get Flag
     *
     * @return bool
     */
    bool GetFlag() const;

    /**
     * Set Index
     *
     * @param int32_t
     */
    void SetIndex(int32_t index);

    /**
     * Get Index
     *
     * @return int32_t
     */
    int32_t GetIndex() const;

    void SetNumber(const std::string &number);

    std::string GetNumber() const;

    PostDialCallState ProcessNextChar(int32_t slotId, char &c);

    void SetPostDialCallState(PostDialCallState s);

    void UpdateCallNumber(std::string phoneNum);

    std::string GetLeftPostDialCallString();

private:
    virtual int32_t ProcessPostDialCallChar(int32_t slotId, char c);

protected:
    std::string phoneNumber_;

private:
    bool flag_ = false;
    int32_t index_ = 1;
    std::string number_;
    CallReportInfo callReportInfo_;
    PostDialCallState postDialCalltate_ = PostDialCallState::POST_DIAL_CALL_NOT_STARTED;
    int32_t nextPostDialCallCode_ = 0;
    std::string postDialCallString_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_BASE_CONNECTION_H
