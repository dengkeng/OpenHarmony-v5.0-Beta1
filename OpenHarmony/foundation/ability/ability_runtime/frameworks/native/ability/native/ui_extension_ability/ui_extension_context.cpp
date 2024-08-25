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

#include "ui_extension_context.h"

#include "ability_manager_client.h"
#include "connection_manager.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AbilityRuntime {
const size_t UIExtensionContext::CONTEXT_TYPE_ID(std::hash<const char*> {} ("UIExtensionContext"));
int UIExtensionContext::ILLEGAL_REQUEST_CODE(-1);

ErrCode UIExtensionContext::StartAbility(const AAFwk::Want &want) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "Start ability begin, ability:%{public}s.", want.GetElement().GetAbilityName().c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, ILLEGAL_REQUEST_CODE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "StartAbility is failed %{public}d", err);
    }
    return err;
}

ErrCode UIExtensionContext::StartAbility(const AAFwk::Want &want, int requestCode) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "Start ability begin, requestCode:%{public}d.", requestCode);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "StartAbility is failed %{public}d", err);
    }
    return err;
}

ErrCode UIExtensionContext::StartAbility(const AAFwk::Want &want, const AAFwk::StartOptions &startOptions) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "Start ability begin, ability:%{public}s.", want.GetElement().GetAbilityName().c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, startOptions, token_,
        ILLEGAL_REQUEST_CODE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "StartAbility is failed %{public}d", err);
    }
    return err;
}

ErrCode UIExtensionContext::TerminateSelf()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelf begin.");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, -1, nullptr);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelf is failed %{public}d", err);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelf end.");
    return err;
}

ErrCode UIExtensionContext::ConnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    TAG_LOGD(AAFwkTag::UI_EXT, "Connect ability begin, ability:%{public}s.",
        want.GetElement().GetAbilityName().c_str());
    ErrCode ret =
        ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    TAG_LOGD(AAFwkTag::UI_EXT, "UIExtensionContext::ConnectAbility ErrorCode = %{public}d", ret);
    return ret;
}

ErrCode UIExtensionContext::DisconnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    TAG_LOGD(AAFwkTag::UI_EXT, "%{public}s begin.", __func__);
    ErrCode ret =
        ConnectionManager::GetInstance().DisconnectAbility(token_, want, connectCallback);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "%{public}s end DisconnectAbility error, ret=%{public}d", __func__, ret);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "%{public}s end DisconnectAbility", __func__);
    return ret;
}

ErrCode UIExtensionContext::StartAbilityForResult(const AAFwk::Want &want, int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin.");
    {
        std::lock_guard<std::mutex> lock(mutexlock_);
        resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end.");
    return err;
}

void UIExtensionContext::InsertResultCallbackTask(int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "InsertResultCallbackTask");
    {
        std::lock_guard<std::mutex> lock(mutexlock_);
        resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    }
}

ErrCode UIExtensionContext::StartAbilityForResult(
    const AAFwk::Want &want, const AAFwk::StartOptions &startOptions, int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin.");
    {
        std::lock_guard<std::mutex> lock(mutexlock_);
        resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, startOptions, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end.");
    return err;
}

ErrCode UIExtensionContext::StartAbilityForResultAsCaller(const AAFwk::Want &want, int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "Called.");
    {
        std::lock_guard<std::mutex> lock(mutexlock_);
        resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityForResultAsCaller(want, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "The result = %{public}d.", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "End.");
    return err;
}

ErrCode UIExtensionContext::StartAbilityForResultAsCaller(
    const AAFwk::Want &want, const AAFwk::StartOptions &startOptions, int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "Called.");
    {
        std::lock_guard<std::mutex> lock(mutexlock_);
        resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityForResultAsCaller(
        want, startOptions, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "The result = %{public}d.", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "End.");
    return err;
}

ErrCode UIExtensionContext::ReportDrawnCompleted()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin.");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->ReportDrawnCompleted(token_);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret=%{public}d", err);
    }
    return err;
}

void UIExtensionContext::OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin.");
    std::lock_guard<std::mutex> lock(mutexlock_);
    auto callback = resultCallbacks_.find(requestCode);
    if (callback != resultCallbacks_.end()) {
        if (callback->second) {
            callback->second(resultCode, resultData, false);
        }
        resultCallbacks_.erase(requestCode);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end.");
}

AppExecFwk::AbilityType UIExtensionContext::GetAbilityInfoType() const
{
    std::shared_ptr<AppExecFwk::AbilityInfo> info = GetAbilityInfo();
    if (info == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "GetAbilityInfoType info is nullptr");
        return AppExecFwk::AbilityType::UNKNOWN;
    }

    return info->type;
}

void UIExtensionContext::OnAbilityResultInner(int requestCode, int resultCode, const AAFwk::Want &resultData)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin.");
    std::lock_guard<std::mutex> lock(mutexlock_);
    auto callback = resultCallbacks_.find(requestCode);
    if (callback != resultCallbacks_.end()) {
        if (callback->second) {
            callback->second(resultCode, resultData, true);
        }
        resultCallbacks_.erase(requestCode);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end.");
}

int UIExtensionContext::GenerateCurRequestCode()
{
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    return curRequestCode_;
}

void UIExtensionContext::SetWindow(sptr<Rosen::Window> window)
{
    window_ = window;
}
sptr<Rosen::Window> UIExtensionContext::GetWindow()
{
    return window_;
}
Ace::UIContent* UIExtensionContext::GetUIContent()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "called");
    if (window_ == nullptr) {
        return nullptr;
    }
    return window_->GetUIContent();
}

ErrCode UIExtensionContext::OpenAtomicService(AAFwk::Want& want, const AAFwk::StartOptions &options, int requestCode,
    RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OpenAtomicService");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->OpenAtomicService(want, options, token_, requestCode);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::UI_EXT, "OpenAtomicService. ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    return err;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
