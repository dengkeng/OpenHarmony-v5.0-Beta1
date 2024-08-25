/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ROSEN_WINDOW_EXTENSION_SESSION_IMPL_H
#define OHOS_ROSEN_WINDOW_EXTENSION_SESSION_IMPL_H

#include <list>

#include "accessibility_element_info.h"
#include "window_session_impl.h"

namespace OHOS {
namespace Rosen {
class WindowExtensionSessionImpl : public WindowSessionImpl {
public:
    explicit WindowExtensionSessionImpl(const sptr<WindowOption>& option);
    ~WindowExtensionSessionImpl();

    WMError Create(const std::shared_ptr<AbilityRuntime::Context>& context,
        const sptr<Rosen::ISession>& iSession, const std::string& identityToken = "") override;
    WMError MoveTo(int32_t x, int32_t y) override;
    WMError Resize(uint32_t width, uint32_t height) override;
    WMError TransferAbilityResult(uint32_t resultCode, const AAFwk::Want& want) override;
    WMError TransferExtensionData(const AAFwk::WantParams& wantParams) override;
    WSError NotifyTransferComponentData(const AAFwk::WantParams& wantParams) override;
    void RegisterTransferComponentDataListener(const NotifyTransferComponentDataFunc& func) override;
    WSErrorCode NotifyTransferComponentDataSync(
        const AAFwk::WantParams& wantParams, AAFwk::WantParams& reWantParams) override;
    void RegisterTransferComponentDataForResultListener(
        const NotifyTransferComponentDataForResultFunc& func) override;
    void TriggerBindModalUIExtension() override;
    WMError SetPrivacyMode(bool isPrivacyMode) override;
    WMError NapiSetUIContent(const std::string& contentInfo, napi_env env,
        napi_value storage, bool isdistributed, sptr<IRemoteObject> token, AppExecFwk::Ability* ability) override;
    WSError UpdateRect(const WSRect& rect, SizeChangeReason reason,
        const std::shared_ptr<RSTransaction>& rsTransaction = nullptr) override;

    WMError GetAvoidAreaByType(AvoidAreaType type, AvoidArea& avoidArea) override;
    WSError NotifySearchElementInfoByAccessibilityId(int64_t elementId, int32_t mode, int64_t baseParent,
        std::list<Accessibility::AccessibilityElementInfo>& infos) override;
    WSError NotifySearchElementInfosByText(int64_t elementId, const std::string& text, int64_t baseParent,
        std::list<Accessibility::AccessibilityElementInfo>& infos) override;
    WSError NotifyFindFocusedElementInfo(int64_t elementId, int32_t focusType, int64_t baseParent,
        Accessibility::AccessibilityElementInfo& info) override;
    WSError NotifyFocusMoveSearch(int64_t elementId, int32_t direction, int64_t baseParent,
        Accessibility::AccessibilityElementInfo& info) override;
    WSError NotifyExecuteAction(int64_t elementId, const std::map<std::string, std::string>& actionAguments,
        int32_t action, int64_t baseParent) override;
    WSError NotifyAccessibilityHoverEvent(float pointX, float pointY, int32_t sourceType, int32_t eventType,
        int64_t timeMs) override;
    WMError TransferAccessibilityEvent(const Accessibility::AccessibilityEventInfo& info,
        int64_t uiExtensionIdLevel) override;
    WMError Destroy(bool needNotifyServer, bool needClearListener = true) override;

    WMError RegisterAvoidAreaChangeListener(sptr<IAvoidAreaChangedListener>& listener) override;
    WMError UnregisterAvoidAreaChangeListener(sptr<IAvoidAreaChangedListener>& listener) override;

    void NotifyFocusActiveEvent(bool isFocusActive) override;
    void NotifyFocusStateEvent(bool focusState) override;
    void NotifyBackpressedEvent(bool& isConsumed) override;
    void NotifyKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool& isConsumed,
        bool notifyInputMethod = true) override;
    void NotifySessionForeground(uint32_t reason, bool withAnimation) override;
    void NotifySessionBackground(uint32_t reason, bool withAnimation, bool isFromInnerkits) override;
    void NotifyOccupiedAreaChangeInfo(sptr<OccupiedAreaChangeInfo> info) override;
    WMError RegisterOccupiedAreaChangeListener(const sptr<IOccupiedAreaChangeListener>& listener) override;
    WMError UnregisterOccupiedAreaChangeListener(const sptr<IOccupiedAreaChangeListener>& listener) override;
    void UpdateConfiguration(const std::shared_ptr<AppExecFwk::Configuration>& configuration) override;
    static void UpdateConfigurationForAll(const std::shared_ptr<AppExecFwk::Configuration>& configuration);
    WMError Show(uint32_t reason = 0, bool withAnimation = false) override;
    WMError Hide(uint32_t reason, bool withAnimation, bool isFromInnerkits) override;
    WSError NotifyDensityFollowHost(bool isFollowHost, float densityValue) override;
    float GetVirtualPixelRatio(sptr<DisplayInfo> displayInfo) override;
    WMError HideNonSecureWindows(bool shouldHide) override;
    WMError SetWaterMarkFlag(bool isEnable) override;
    Rect GetHostWindowRect(int32_t hostWindowId) override;

protected:
    NotifyTransferComponentDataFunc notifyTransferComponentDataFunc_;
    NotifyTransferComponentDataForResultFunc notifyTransferComponentDataForResultFunc_;

private:
    void AddExtensionWindowStageToSCB();
    void UpdateRectForRotation(const Rect& wmRect, const Rect& preRect, WindowSizeChangeReason wmReason,
        const std::shared_ptr<RSTransaction>& rsTransaction = nullptr);

    void InputMethodKeyEventResultCallback(const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool consumed,
        std::shared_ptr<std::promise<bool>> isConsumedPromise, std::shared_ptr<bool> isTimeout);
    void CheckAndAddExtWindowFlags();
    void CheckAndRemoveExtWindowFlags();
    WMError UpdateExtWindowFlags(const ExtensionWindowFlags& flags, const ExtensionWindowFlags& actions);

    std::atomic<bool> isDensityFollowHost_ { false };
    std::optional<std::atomic<float>> hostDensityValue_ = std::nullopt;
    sptr<IOccupiedAreaChangeListener> occupiedAreaChangeListener_;
    std::optional<std::atomic<bool>> focusState_ = std::nullopt;
    static std::set<sptr<WindowSessionImpl>> windowExtensionSessionSet_;
    static std::shared_mutex windowExtensionSessionMutex_;
    int16_t rotationAnimationCount_ { 0 };
    ExtensionWindowFlags extensionWindowFlags_ { 0 };
};
} // namespace Rosen
} // namespace OHOS

#endif // OHOS_ROSEN_WINDOW_EXTENSION_SESSION_IMPL_H
