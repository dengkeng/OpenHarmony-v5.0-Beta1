/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dialog_session_record.h"

#include <random>
#include <string>
#include <chrono>
#include "ability_record.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "int_wrapper.h"
#include "parameters.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace AAFwk {
using OHOS::AppExecFwk::BundleInfo;
std::string DialogSessionRecord::GenerateDialogSessionId()
{
    auto timestamp = std::chrono::system_clock::now().time_since_epoch();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(timestamp).count();
    std::random_device seed;
    std::mt19937 rng(seed());
    std::uniform_int_distribution<int> uni(0, INT_MAX);
    int randomDigit = uni(rng);
    return std::to_string(time) + "_" + std::to_string(randomDigit);
    std::string dialogSessionId = std::to_string(time) + "_" + std::to_string(randomDigit);

    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    auto iter = dialogSessionInfoMap_.find(dialogSessionId);
    while (iter != dialogSessionInfoMap_.end()) {
        dialogSessionId += "_1";
        iter = dialogSessionInfoMap_.find(dialogSessionId);
    }
    return dialogSessionId;
}

void DialogSessionRecord::SetDialogSessionInfo(const std::string dialogSessionId,
    sptr<DialogSessionInfo> &dilogSessionInfo, std::shared_ptr<DialogCallerInfo> &dialogCallerInfo)
{
    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    dialogSessionInfoMap_[dialogSessionId] = dilogSessionInfo;
    dialogCallerInfoMap_[dialogSessionId] = dialogCallerInfo;
}

sptr<DialogSessionInfo> DialogSessionRecord::GetDialogSessionInfo(const std::string dialogSessionId) const
{
    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    auto it = dialogSessionInfoMap_.find(dialogSessionId);
    if (it != dialogSessionInfoMap_.end()) {
        return it->second;
    }
    TAG_LOGI(AAFwkTag::DIALOG, "not find");
    return nullptr;
}

std::shared_ptr<DialogCallerInfo> DialogSessionRecord::GetDialogCallerInfo(const std::string dialogSessionId) const
{
    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    auto it = dialogCallerInfoMap_.find(dialogSessionId);
    if (it != dialogCallerInfoMap_.end()) {
        return it->second;
    }
    TAG_LOGI(AAFwkTag::DIALOG, "not find");
    return nullptr;
}

void DialogSessionRecord::ClearDialogContext(const std::string dialogSessionId)
{
    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    auto it = dialogSessionInfoMap_.find(dialogSessionId);
    if (it != dialogSessionInfoMap_.end()) {
        dialogSessionInfoMap_.erase(it);
    }
    auto iter = dialogCallerInfoMap_.find(dialogSessionId);
    if (iter != dialogCallerInfoMap_.end()) {
        dialogCallerInfoMap_.erase(iter);
    }
    return;
}

void DialogSessionRecord::ClearAllDialogContexts()
{
    std::lock_guard<ffrt::mutex> guard(dialogSessionRecordLock_);
    dialogSessionInfoMap_.clear();
    dialogCallerInfoMap_.clear();
}

bool DialogSessionRecord::GenerateDialogSessionRecord(AbilityRequest &abilityRequest, int32_t userId,
    std::string &dialogSessionId, std::vector<DialogAppInfo> &dialogAppInfos, bool isSelector)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto dialogSessionInfo = sptr<DialogSessionInfo>::MakeSptr();
    CHECK_POINTER_AND_RETURN(dialogSessionInfo, ERR_INVALID_VALUE);
    sptr<IRemoteObject> callerToken = abilityRequest.callerToken;
    if (callerToken != nullptr) {
        auto callerRecord = Token::GetAbilityRecordByToken(callerToken);
        CHECK_POINTER_AND_RETURN(callerRecord, ERR_INVALID_VALUE);
        dialogSessionInfo->callerAbilityInfo.bundleName = callerRecord->GetAbilityInfo().bundleName;
        dialogSessionInfo->callerAbilityInfo.moduleName = callerRecord->GetAbilityInfo().moduleName;
        dialogSessionInfo->callerAbilityInfo.abilityName = callerRecord->GetAbilityInfo().name;
        dialogSessionInfo->callerAbilityInfo.abilityIconId = callerRecord->GetAbilityInfo().iconId;
        dialogSessionInfo->callerAbilityInfo.abilityLabelId = callerRecord->GetAbilityInfo().labelId;
        dialogSessionInfo->callerAbilityInfo.bundleIconId = callerRecord->GetApplicationInfo().iconId;
        dialogSessionInfo->callerAbilityInfo.bundleLabelId = callerRecord->GetApplicationInfo().labelId;
    }
    dialogSessionInfo->parameters.SetParam("deviceType", AAFwk::String::Box(OHOS::system::GetDeviceType()));
    dialogSessionInfo->parameters.SetParam("userId", AAFwk::Integer::Box(userId));
    for (auto &dialogAppInfo : dialogAppInfos) {
        DialogAbilityInfo targetDialogAbilityInfo;
        targetDialogAbilityInfo.bundleName = dialogAppInfo.bundleName;
        targetDialogAbilityInfo.moduleName = dialogAppInfo.moduleName;
        targetDialogAbilityInfo.abilityName = dialogAppInfo.abilityName;
        targetDialogAbilityInfo.abilityIconId = dialogAppInfo.abilityIconId;
        targetDialogAbilityInfo.abilityLabelId = dialogAppInfo.abilityLabelId;
        targetDialogAbilityInfo.bundleIconId = dialogAppInfo.bundleIconId;
        targetDialogAbilityInfo.bundleLabelId = dialogAppInfo.bundleLabelId;
        targetDialogAbilityInfo.visible = dialogAppInfo.visible;
        dialogSessionInfo->targetAbilityInfos.emplace_back(targetDialogAbilityInfo);
    }
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    if (isSelector) {
        dialogSessionInfo->parameters.SetParam("action", AAFwk::String::Box(abilityRequest.want.GetAction()));
        dialogSessionInfo->parameters.SetParam("wantType", AAFwk::String::Box(abilityRequest.want.GetType()));
        dialogSessionInfo->parameters.SetParam("uri", AAFwk::String::Box(abilityRequest.want.GetUriString()));
        dialogCallerInfo->isSelector = true;
    }
    dialogCallerInfo->callerToken = callerToken;
    dialogCallerInfo->requestCode = abilityRequest.requestCode;
    dialogCallerInfo->targetWant = abilityRequest.want;
    dialogCallerInfo->userId = userId;
    dialogSessionId = GenerateDialogSessionId();
    SetDialogSessionInfo(dialogSessionId, dialogSessionInfo, dialogCallerInfo);
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS
