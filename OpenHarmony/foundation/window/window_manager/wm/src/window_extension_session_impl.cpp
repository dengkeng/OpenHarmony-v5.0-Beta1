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

#include "window_extension_session_impl.h"

#include <transaction/rs_interfaces.h>
#include <transaction/rs_transaction.h>
#ifdef IMF_ENABLE
#include <input_method_controller.h>
#endif
#include "window_manager_hilog.h"
#include "display_info.h"
#include "parameters.h"
#include "anr_handler.h"
#include "hitrace_meter.h"
#include "session_permission.h"
#include "singleton_container.h"
#include "window_adapter.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, HILOG_DOMAIN_WINDOW, "WindowExtensionSessionImpl"};
constexpr int32_t ANIMATION_TIME = 400;
constexpr int64_t DISPATCH_KEY_EVENT_TIMEOUT_TIME_MS = 1000;
}

std::set<sptr<WindowSessionImpl>> WindowExtensionSessionImpl::windowExtensionSessionSet_;
std::shared_mutex WindowExtensionSessionImpl::windowExtensionSessionMutex_;

WindowExtensionSessionImpl::WindowExtensionSessionImpl(const sptr<WindowOption>& option) : WindowSessionImpl(option)
{
}

WindowExtensionSessionImpl::~WindowExtensionSessionImpl()
{
}

WMError WindowExtensionSessionImpl::Create(const std::shared_ptr<AbilityRuntime::Context>& context,
    const sptr<Rosen::ISession>& iSession, const std::string& identityToken)
{
    WLOGFI("In");
    if (!context || !iSession) {
        WLOGFE("context is nullptr: %{public}u or sessionToken is nullptr: %{public}u",
            context == nullptr, iSession == nullptr);
        return WMError::WM_ERROR_NULLPTR;
    }
    SetDefaultDisplayIdIfNeed();
    hostSession_ = iSession;
    context_ = context;
    WMError ret = Connect();
    if (ret == WMError::WM_OK) {
        MakeSubOrDialogWindowDragableAndMoveble();
        std::unique_lock<std::shared_mutex> lock(windowExtensionSessionMutex_);
        windowExtensionSessionSet_.insert(this);
    }
    AddExtensionWindowStageToSCB();
    state_ = WindowState::STATE_CREATED;
    isUIExtensionAbilityProcess_ = true;
    return WMError::WM_OK;
}

void WindowExtensionSessionImpl::AddExtensionWindowStageToSCB()
{
    sptr<ISessionStage> iSessionStage(this);
    SingletonContainer::Get<WindowAdapter>().AddExtensionWindowStageToSCB(iSessionStage, property_->GetPersistentId(),
        property_->GetParentId());
}

void WindowExtensionSessionImpl::UpdateConfiguration(const std::shared_ptr<AppExecFwk::Configuration>& configuration)
{
    if (uiContent_ != nullptr) {
        WLOGFD("notify ace winId:%{public}u", GetWindowId());
        uiContent_->UpdateConfiguration(configuration);
    }
}

void WindowExtensionSessionImpl::UpdateConfigurationForAll(const std::shared_ptr<AppExecFwk::Configuration>& configuration)
{
    WLOGD("notify scene ace update config");
    std::unique_lock<std::shared_mutex> lock(windowExtensionSessionMutex_);
    for (const auto& window : windowExtensionSessionSet_) {
        window->UpdateConfiguration(configuration);
    }
}

WMError WindowExtensionSessionImpl::Destroy(bool needNotifyServer, bool needClearListener)
{
    TLOGI(WmsLogTag::WMS_LIFE, "Id: %{public}d Destroy, state_:%{public}u, needNotifyServer: %{public}d, "
        "needClearListener: %{public}d", GetPersistentId(), state_, needNotifyServer, needClearListener);
    if (IsWindowSessionInvalid()) {
        TLOGE(WmsLogTag::WMS_LIFE, "session is invalid");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    CheckAndRemoveExtWindowFlags();
    if (hostSession_ != nullptr) {
        hostSession_->Disconnect();
    }
    NotifyBeforeDestroy(GetWindowName());
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        state_ = WindowState::STATE_DESTROYED;
        requestState_ = WindowState::STATE_DESTROYED;
    }
    hostSession_ = nullptr;
    {
        std::unique_lock<std::shared_mutex> lock(windowExtensionSessionMutex_);
        windowExtensionSessionSet_.erase(this);
    }
    DelayedSingleton<ANRHandler>::GetInstance()->OnWindowDestroyed(GetPersistentId());
    NotifyAfterDestroy();
    if (needClearListener) {
        ClearListenersById(GetPersistentId());
    }
    if (context_) {
        context_.reset();
    }
    return WMError::WM_OK;
}

WMError WindowExtensionSessionImpl::MoveTo(int32_t x, int32_t y)
{
    WLOGFD("Id:%{public}d MoveTo %{public}d %{public}d", property_->GetPersistentId(), x, y);
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    const auto& rect = property_->GetWindowRect();
    WSRect wsRect = { x, y, rect.width_, rect.height_ };
    WSError error = UpdateRect(wsRect, SizeChangeReason::MOVE);
    return static_cast<WMError>(error);
}

WMError WindowExtensionSessionImpl::Resize(uint32_t width, uint32_t height)
{
    WLOGFD("Id:%{public}d Resize %{public}u %{public}u", property_->GetPersistentId(), width, height);
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    const auto& rect = property_->GetWindowRect();
    WSRect wsRect = { rect.posX_, rect.posY_, width, height };
    WSError error = UpdateRect(wsRect, SizeChangeReason::RESIZE);
    return static_cast<WMError>(error);
}

WMError WindowExtensionSessionImpl::TransferAbilityResult(uint32_t resultCode, const AAFwk::Want& want)
{
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return WMError::WM_ERROR_REPEAT_OPERATION;
    }
    return static_cast<WMError>(hostSession_->TransferAbilityResult(resultCode, want));
}

WMError WindowExtensionSessionImpl::TransferExtensionData(const AAFwk::WantParams& wantParams)
{
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return WMError::WM_ERROR_REPEAT_OPERATION;
    }
    return static_cast<WMError>(hostSession_->TransferExtensionData(wantParams));
}

void WindowExtensionSessionImpl::RegisterTransferComponentDataListener(const NotifyTransferComponentDataFunc& func)
{
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return;
    }
    notifyTransferComponentDataFunc_ = std::move(func);
    hostSession_->NotifyAsyncOn();
}

WSError WindowExtensionSessionImpl::NotifyTransferComponentData(const AAFwk::WantParams& wantParams)
{
    if (notifyTransferComponentDataFunc_) {
        notifyTransferComponentDataFunc_(wantParams);
    }
    return WSError::WS_OK;
}

WSErrorCode WindowExtensionSessionImpl::NotifyTransferComponentDataSync(
    const AAFwk::WantParams& wantParams, AAFwk::WantParams& reWantParams)
{
    if (notifyTransferComponentDataForResultFunc_) {
        reWantParams = notifyTransferComponentDataForResultFunc_(wantParams);
        return WSErrorCode::WS_OK;
    }
    return WSErrorCode::WS_ERROR_NOT_REGISTER_SYNC_CALLBACK;
}

void WindowExtensionSessionImpl::RegisterTransferComponentDataForResultListener(
    const NotifyTransferComponentDataForResultFunc& func)
{
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return;
    }
    notifyTransferComponentDataForResultFunc_ = std::move(func);
    hostSession_->NotifySyncOn();
}

void WindowExtensionSessionImpl::TriggerBindModalUIExtension()
{
    WLOGFD("called");
    if (hostSession_ == nullptr) {
        WLOGFE("hostSession_ is nullptr");
        return;
    }
    hostSession_->TriggerBindModalUIExtension();
}

WMError WindowExtensionSessionImpl::SetPrivacyMode(bool isPrivacyMode)
{
    TLOGD(WmsLogTag::WMS_UIEXT, "id: %{public}u, isPrivacyMode: %{public}u", GetWindowId(), isPrivacyMode);
    if (surfaceNode_ == nullptr) {
        TLOGE(WmsLogTag::WMS_UIEXT, "surfaceNode_ is nullptr");
        return WMError::WM_ERROR_NULLPTR;
    }
    surfaceNode_->SetSecurityLayer(isPrivacyMode);
    RSTransaction::FlushImplicitTransaction();

    if (state_ != WindowState::STATE_SHOWN) {
        extensionWindowFlags_.privacyModeFlag = isPrivacyMode;
        return WMError::WM_OK;
    }
    if (isPrivacyMode == extensionWindowFlags_.privacyModeFlag) {
        return WMError::WM_OK;
    }

    auto updateFlags = extensionWindowFlags_;
    updateFlags.privacyModeFlag = isPrivacyMode;
    ExtensionWindowFlags actions(0);
    actions.privacyModeFlag = true;
    auto ret = UpdateExtWindowFlags(updateFlags, actions);
    if (ret == WMError::WM_OK) {
        extensionWindowFlags_ = updateFlags;
    }
    return ret;
}

void WindowExtensionSessionImpl::NotifyFocusStateEvent(bool focusState)
{
    if (uiContent_) {
        focusState ? uiContent_->Focus() : uiContent_->UnFocus();
    }
    if (focusState) {
        NotifyWindowAfterFocused();
    } else {
        NotifyWindowAfterUnfocused();
    }
    focusState_ = focusState;
}

void WindowExtensionSessionImpl::NotifyFocusActiveEvent(bool isFocusActive)
{
    if (uiContent_) {
        uiContent_->SetIsFocusActive(isFocusActive);
    }
}

void WindowExtensionSessionImpl::NotifyBackpressedEvent(bool& isConsumed)
{
    if (uiContent_) {
        WLOGFD("Transfer backpressed event to uiContent");
        isConsumed = uiContent_->ProcessBackPressed();
    }
    WLOGFD("Backpressed event is not cosumed");
}

void WindowExtensionSessionImpl::InputMethodKeyEventResultCallback(const std::shared_ptr<MMI::KeyEvent>& keyEvent,
    bool consumed, std::shared_ptr<std::promise<bool>> isConsumedPromise, std::shared_ptr<bool> isTimeout)
{
    if (keyEvent == nullptr) {
        WLOGFW("keyEvent is null, consumed:%{public}" PRId32, consumed);
        if (isConsumedPromise != nullptr) {
            isConsumedPromise->set_value(consumed);
        }
        return;
    }

    auto id = keyEvent->GetId();
    if (isConsumedPromise == nullptr || isTimeout == nullptr) {
        WLOGFW("Shared point isConsumedPromise or isTimeout is null, id:%{public}" PRId32, id);
        keyEvent->MarkProcessed();
        return;
    }

    if (*isTimeout) {
        WLOGFW("DispatchKeyEvent timeout id:%{public}" PRId32, id);
        keyEvent->MarkProcessed();
        return;
    }

    if (consumed) {
        isConsumedPromise->set_value(consumed);
        WLOGD("Input method has processed key event, id:%{public}" PRId32, id);
        return;
    }

    bool isConsumed = false;
    DispatchKeyEventCallback(const_cast<std::shared_ptr<MMI::KeyEvent>&>(keyEvent), isConsumed);
    isConsumedPromise->set_value(isConsumed);
}

void WindowExtensionSessionImpl::NotifyKeyEvent(const std::shared_ptr<MMI::KeyEvent>& keyEvent, bool& isConsumed,
    bool notifyInputMethod)
{
    if (keyEvent == nullptr) {
        WLOGFE("keyEvent is nullptr");
        return;
    }

#ifdef IMF_ENABLE
    bool isKeyboardEvent = IsKeyboardEvent(keyEvent);
    if (isKeyboardEvent && notifyInputMethod) {
        WLOGD("Async dispatch keyEvent to input method, id:%{public}" PRId32, keyEvent->GetId());
        auto isConsumedPromise = std::make_shared<std::promise<bool>>();
        auto isConsumedFuture = isConsumedPromise->get_future().share();
        auto isTimeout = std::make_shared<bool>(false);
        auto ret = MiscServices::InputMethodController::GetInstance()->DispatchKeyEvent(keyEvent,
            std::bind(&WindowExtensionSessionImpl::InputMethodKeyEventResultCallback, this,
                std::placeholders::_1, std::placeholders::_2, isConsumedPromise, isTimeout));
        if (ret != 0) {
            WLOGFW("DispatchKeyEvent failed, ret:%{public}" PRId32 ", id:%{public}" PRId32, ret, keyEvent->GetId());
            DispatchKeyEventCallback(keyEvent, isConsumed);
            return;
        }
        if (isConsumedFuture.wait_for(std::chrono::milliseconds(DISPATCH_KEY_EVENT_TIMEOUT_TIME_MS)) ==
            std::future_status::timeout) {
            *isTimeout = true;
            isConsumed = true;
            WLOGFE("DispatchKeyEvent timeout, id:%{public}" PRId32, keyEvent->GetId());
        } else {
            isConsumed = isConsumedFuture.get();
        }
        WLOGFD("Input Method DispatchKeyEvent isConsumed:%{public}" PRId32, isConsumed);
        return;
    }
#endif // IMF_ENABLE
    DispatchKeyEventCallback(keyEvent, isConsumed);
}

WMError WindowExtensionSessionImpl::NapiSetUIContent(const std::string& contentInfo,
    napi_env env, napi_value storage, bool isdistributed, sptr<IRemoteObject> token, AppExecFwk::Ability* ability)
{
    WLOGFD("WindowExtensionSessionImpl NapiSetUIContent: %{public}s state:%{public}u", contentInfo.c_str(), state_);
    if (uiContent_) {
        uiContent_->Destroy();
    }
    std::unique_ptr<Ace::UIContent> uiContent;
    if (ability != nullptr) {
        uiContent = Ace::UIContent::Create(ability);
    } else {
        uiContent = Ace::UIContent::Create(context_.get(), reinterpret_cast<NativeEngine*>(env));
    }
    if (uiContent == nullptr) {
        WLOGFE("fail to NapiSetUIContent id: %{public}d", GetPersistentId());
        return WMError::WM_ERROR_NULLPTR;
    }
    uiContent->SetParentToken(token);
    uiContent->Initialize(this, contentInfo, storage, property_->GetParentId());
    // make uiContent available after Initialize/Restore
    uiContent_ = std::move(uiContent);

    if (focusState_ != std::nullopt) {
        focusState_.value() ? uiContent_->Focus() : uiContent_->UnFocus();
    }

    uint32_t version = 0;
    if ((context_ != nullptr) && (context_->GetApplicationInfo() != nullptr)) {
        version = context_->GetApplicationInfo()->apiCompatibleVersion;
    }
    // 10 ArkUI new framework support after API10
    if (version < 10) {
        SetLayoutFullScreenByApiVersion(isIgnoreSafeArea_);
        if (!isSystembarPropertiesSet_) {
            SetSystemBarProperty(WindowType::WINDOW_TYPE_STATUS_BAR, SystemBarProperty());
        }
    } else if (isIgnoreSafeAreaNeedNotify_) {
        SetLayoutFullScreenByApiVersion(isIgnoreSafeArea_);
    }

    UpdateDecorEnable(true);
    if (state_ == WindowState::STATE_SHOWN) {
        // UIContent may be nullptr when show window, need to notify again when window is shown
        uiContent_->Foreground();
        UpdateTitleButtonVisibility();
    }
    UpdateViewportConfig(GetRect(), WindowSizeChangeReason::UNDEFINED);
    WLOGFD("notify uiContent window size change end");
    return WMError::WM_OK;
}

WSError WindowExtensionSessionImpl::UpdateRect(const WSRect& rect, SizeChangeReason reason,
    const std::shared_ptr<RSTransaction>& rsTransaction)
{
    auto wmReason = static_cast<WindowSizeChangeReason>(reason);
    Rect wmRect = {rect.posX_, rect.posY_, rect.width_, rect.height_};
    auto preRect = GetRect();
    if (rect.width_ == static_cast<int>(preRect.width_) && rect.height_ == static_cast<int>(preRect.height_)) {
        WLOGFD("WindowExtensionSessionImpl Update rect [%{public}d, %{public}d, reason: %{public}d]", rect.width_,
            rect.height_, static_cast<int>(reason));
    } else {
        WLOGFI("WindowExtensionSessionImpl Update rect [%{public}d, %{public}d, reason: %{public}d]", rect.width_,
            rect.height_, static_cast<int>(reason));
    }
    property_->SetWindowRect(wmRect);
    if (wmReason == WindowSizeChangeReason::ROTATION) {
        UpdateRectForRotation(wmRect, preRect, wmReason, rsTransaction);
    } else {
        NotifySizeChange(wmRect, wmReason);
        UpdateViewportConfig(wmRect, wmReason);
    }
    return WSError::WS_OK;
}

void WindowExtensionSessionImpl::UpdateRectForRotation(const Rect& wmRect, const Rect& preRect,
    WindowSizeChangeReason wmReason, const std::shared_ptr<RSTransaction>& rsTransaction)
{
    if (!handler_) {
        return;
    }
    auto task = [weak = wptr(this), wmReason, wmRect, preRect, rsTransaction]() mutable {
        HITRACE_METER_NAME(HITRACE_TAG_WINDOW_MANAGER, "WindowExtensionSessionImpl::UpdateRectForRotation");
        auto window = weak.promote();
        if (!window) {
            return;
        }
        int32_t duration = ANIMATION_TIME;
        if (rsTransaction) {
            duration = rsTransaction->GetDuration() ? rsTransaction->GetDuration() : duration;
            RSTransaction::FlushImplicitTransaction();
            rsTransaction->Begin();
        }
        RSSystemProperties::SetDrawTextAsBitmap(true);
        RSInterfaces::GetInstance().EnableCacheForRotation();
        window->rotationAnimationCount_++;
        RSAnimationTimingProtocol protocol;
        protocol.SetDuration(duration);
        auto curve = RSAnimationTimingCurve::CreateCubicCurve(0.2, 0.0, 0.2, 1.0);
        RSNode::OpenImplicitAnimation(protocol, curve, [weak]() {
            auto window = weak.promote();
            if (!window) {
                return;
            }
            window->rotationAnimationCount_--;
            if (window->rotationAnimationCount_ == 0) {
                RSSystemProperties::SetDrawTextAsBitmap(false);
                RSInterfaces::GetInstance().DisableCacheForRotation();
            }
        });
        if (wmRect != preRect) {
            window->NotifySizeChange(wmRect, wmReason);
        }
        window->UpdateViewportConfig(wmRect, wmReason, rsTransaction);
        RSNode::CloseImplicitAnimation();
        if (rsTransaction) {
            rsTransaction->Commit();
        } else {
            RSTransaction::FlushImplicitTransaction();
        }
    };
    handler_->PostTask(task, "WMS_WindowExtensionSessionImpl_UpdateRectForRotation");
}

WSError WindowExtensionSessionImpl::NotifySearchElementInfoByAccessibilityId(int64_t elementId, int32_t mode,
    int64_t baseParent, std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifySearchElementInfoByAccessibilityId error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    uiContent_->SearchElementInfoByAccessibilityId(elementId, mode, baseParent, infos);
    return WSError::WS_OK;
}

WSError WindowExtensionSessionImpl::NotifySearchElementInfosByText(int64_t elementId, const std::string& text,
    int64_t baseParent, std::list<Accessibility::AccessibilityElementInfo>& infos)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifySearchElementInfosByText error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    uiContent_->SearchElementInfosByText(elementId, text, baseParent, infos);
    return WSError::WS_OK;
}

WSError WindowExtensionSessionImpl::NotifyFindFocusedElementInfo(int64_t elementId, int32_t focusType,
    int64_t baseParent, Accessibility::AccessibilityElementInfo& info)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifyFindFocusedElementInfo error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    uiContent_->FindFocusedElementInfo(elementId, focusType, baseParent, info);
    return WSError::WS_OK;
}

WSError WindowExtensionSessionImpl::NotifyFocusMoveSearch(int64_t elementId, int32_t direction, int64_t baseParent,
    Accessibility::AccessibilityElementInfo& info)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifyFocusMoveSearch error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    uiContent_->FocusMoveSearch(elementId, direction, baseParent, info);
    return WSError::WS_OK;
}

WSError WindowExtensionSessionImpl::NotifyExecuteAction(int64_t elementId,
    const std::map<std::string, std::string>& actionAguments, int32_t action,
    int64_t baseParent)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifyExecuteAction error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    bool ret = uiContent_->NotifyExecuteAction(elementId, actionAguments, action, baseParent);
    if (!ret) {
        WLOGFE("NotifyExecuteAction fail");
        return WSError::WS_ERROR_INTERNAL_ERROR;
    }
    return WSError::WS_OK;
}

WSError WindowExtensionSessionImpl::NotifyAccessibilityHoverEvent(float pointX, float pointY, int32_t sourceType,
    int32_t eventType, int64_t timeMs)
{
    if (uiContent_ == nullptr) {
        WLOGFE("NotifyExecuteAction error, no uiContent_");
        return WSError::WS_ERROR_NO_UI_CONTENT_ERROR;
    }
    uiContent_->HandleAccessibilityHoverEvent(pointX, pointY, sourceType, eventType, timeMs);
    return WSError::WS_OK;
}

WMError WindowExtensionSessionImpl::TransferAccessibilityEvent(const Accessibility::AccessibilityEventInfo& info,
    int64_t uiExtensionIdLevel)
{
    if (IsWindowSessionInvalid()) {
        WLOGFE("Window session invalid.");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    return static_cast<WMError>(hostSession_->TransferAccessibilityEvent(info, uiExtensionIdLevel));
}

void WindowExtensionSessionImpl::NotifySessionForeground(uint32_t reason, bool withAnimation)
{
}

void WindowExtensionSessionImpl::NotifySessionBackground(uint32_t reason, bool withAnimation, bool isFromInnerkits)
{
}

void WindowExtensionSessionImpl::NotifyOccupiedAreaChangeInfo(sptr<OccupiedAreaChangeInfo> info)
{
    TLOGI(WmsLogTag::WMS_KEYBOARD, "TextFieldPosY = %{public}f, KeyBoardHeight = %{public}d",
        info->textFieldPositionY_, info->rect_.height_);
    if (occupiedAreaChangeListener_) {
        occupiedAreaChangeListener_->OnSizeChange(info);
    }
}

WMError WindowExtensionSessionImpl::RegisterOccupiedAreaChangeListener(
    const sptr<IOccupiedAreaChangeListener>& listener)
{
    occupiedAreaChangeListener_ = listener;
    return WMError::WM_OK;
}

WMError WindowExtensionSessionImpl::UnregisterOccupiedAreaChangeListener(
    const sptr<IOccupiedAreaChangeListener>& listener)
{
    occupiedAreaChangeListener_ = nullptr;
    return WMError::WM_OK;
}

WMError WindowExtensionSessionImpl::GetAvoidAreaByType(AvoidAreaType type, AvoidArea& avoidArea)
{
    WLOGFI("Window Extension Session Get Avoid Area Type");
    if (hostSession_ == nullptr) {
        return WMError::WM_ERROR_NULLPTR;
    }
    avoidArea = hostSession_->GetAvoidAreaByType(type);
    return WMError::WM_OK;
}

WMError WindowExtensionSessionImpl::RegisterAvoidAreaChangeListener(sptr<IAvoidAreaChangedListener>& listener)
{
    return RegisterExtensionAvoidAreaChangeListener(listener);
}

WMError WindowExtensionSessionImpl::UnregisterAvoidAreaChangeListener(sptr<IAvoidAreaChangedListener>& listener)
{
    return UnregisterExtensionAvoidAreaChangeListener(listener);
}

WMError WindowExtensionSessionImpl::Show(uint32_t reason, bool withAnimation)
{
    CheckAndAddExtWindowFlags();

    auto display = SingletonContainer::Get<DisplayManager>().GetDisplayById(property_->GetDisplayId());
    if (display == nullptr || display->GetDisplayInfo() == nullptr) {
        TLOGE(WmsLogTag::WMS_LIFE, "WindowExtensionSessionImpl::Show display is null!");
        return WMError::WM_ERROR_NULLPTR;
    }
    auto displayInfo = display->GetDisplayInfo();
    float density = GetVirtualPixelRatio(displayInfo);
    if (virtualPixelRatio_ != density) {
        UpdateDensity();
    }

    return this->WindowSessionImpl::Show(reason, withAnimation);
}

WMError WindowExtensionSessionImpl::Hide(uint32_t reason, bool withAnimation, bool isFromInnerkits)
{
    TLOGI(WmsLogTag::WMS_LIFE, "id:%{public}d WindowExtensionSessionImpl Hide, reason:%{public}u, state:%{public}u",
        GetPersistentId(), reason, state_);
    if (IsWindowSessionInvalid()) {
        WLOGFE("session is invalid");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    CheckAndRemoveExtWindowFlags();
    if (state_ == WindowState::STATE_HIDDEN || state_ == WindowState::STATE_CREATED) {
        TLOGD(WmsLogTag::WMS_LIFE, "window extension session is already hidden \
            [name:%{public}s,id:%{public}d,type: %{public}u]",
            property_->GetWindowName().c_str(), GetPersistentId(), property_->GetWindowType());
        NotifyBackgroundFailed(WMError::WM_DO_NOTHING);
        return WMError::WM_OK;
    }
    WSError ret = hostSession_->Background();
    WMError res = static_cast<WMError>(ret);
    if (res == WMError::WM_OK) {
        state_ = WindowState::STATE_HIDDEN;
        requestState_ = WindowState::STATE_HIDDEN;
        NotifyAfterBackground();
    } else {
        TLOGD(WmsLogTag::WMS_LIFE, "window extension session Hide to Background is error");
    }
    return WMError::WM_OK;
}

WSError WindowExtensionSessionImpl::NotifyDensityFollowHost(bool isFollowHost, float densityValue)
{
    TLOGI(WmsLogTag::WMS_UIEXT, "isFollowHost:%{public}d densityValue:%{public}f", isFollowHost, densityValue);

    if (!isFollowHost && !isDensityFollowHost_) {
        TLOGI(WmsLogTag::WMS_UIEXT, "isFollowHost is false and not change");
        return WSError::WS_OK;
    }

    if (isFollowHost) {
        if (std::islessequal(densityValue, 0.0f)) {
            TLOGE(WmsLogTag::WMS_UIEXT, "densityValue is invalid");
            return WSError::WS_ERROR_INVALID_PARAM;
        }
        if (hostDensityValue_ != std::nullopt &&
            std::abs(hostDensityValue_->load() - densityValue) < std::numeric_limits<float>::epsilon()) {
            TLOGI(WmsLogTag::WMS_UIEXT, "densityValue not change");
            return WSError::WS_OK;
        }
        hostDensityValue_ = densityValue;
    }

    isDensityFollowHost_ = isFollowHost;

    UpdateViewportConfig(GetRect(), WindowSizeChangeReason::UNDEFINED);
    return WSError::WS_OK;
}

float WindowExtensionSessionImpl::GetVirtualPixelRatio(sptr<DisplayInfo> displayInfo)
{
    float vpr = 1.0f;
    if (displayInfo == nullptr) {
        TLOGE(WmsLogTag::WMS_UIEXT, "displayInfo is nullptr");
        return vpr;
    }
    if (isDensityFollowHost_ && hostDensityValue_ != std::nullopt) {
        vpr = hostDensityValue_->load();
    } else {
        vpr = displayInfo->GetVirtualPixelRatio();
    }
    return vpr;
}

WMError WindowExtensionSessionImpl::HideNonSecureWindows(bool shouldHide)
{
    if (state_ != WindowState::STATE_SHOWN) {
        extensionWindowFlags_.hideNonSecureWindowsFlag = shouldHide;
        return WMError::WM_OK;
    }
    if (shouldHide == extensionWindowFlags_.hideNonSecureWindowsFlag) {
        return WMError::WM_OK;
    }

    auto updateFlags = extensionWindowFlags_;
    updateFlags.hideNonSecureWindowsFlag = shouldHide;
    ExtensionWindowFlags actions(0);
    actions.hideNonSecureWindowsFlag = true;
    auto ret = UpdateExtWindowFlags(updateFlags, actions);
    if (ret == WMError::WM_OK) {
        extensionWindowFlags_ = updateFlags;
    }
    return ret;
}

WMError WindowExtensionSessionImpl::SetWaterMarkFlag(bool isEnable)
{
    if (state_ != WindowState::STATE_SHOWN) {
        extensionWindowFlags_.waterMarkFlag = isEnable;
        return WMError::WM_OK;
    }
    if (isEnable == extensionWindowFlags_.waterMarkFlag) {
        return WMError::WM_OK;
    }

    auto updateFlags = extensionWindowFlags_;
    updateFlags.waterMarkFlag = isEnable;
    ExtensionWindowFlags actions(0);
    actions.waterMarkFlag = true;
    auto ret = UpdateExtWindowFlags(updateFlags, actions);
    if (ret == WMError::WM_OK) {
        extensionWindowFlags_ = updateFlags;
    }
    return ret;
}

void WindowExtensionSessionImpl::CheckAndAddExtWindowFlags()
{
    if (extensionWindowFlags_.bitData != 0) {
        // If flag is true, make it active when foreground
        UpdateExtWindowFlags(extensionWindowFlags_, extensionWindowFlags_);
    }
}

void WindowExtensionSessionImpl::CheckAndRemoveExtWindowFlags()
{
    if (extensionWindowFlags_.bitData != 0) {
        // If flag is true, make it inactive when background
        UpdateExtWindowFlags(ExtensionWindowFlags(), extensionWindowFlags_);
    }
}

WMError WindowExtensionSessionImpl::UpdateExtWindowFlags(const ExtensionWindowFlags& flags,
    const ExtensionWindowFlags& actions)
{
    // action is true when the corresponding flag should be updated
    if (IsWindowSessionInvalid()) {
        TLOGI(WmsLogTag::WMS_UIEXT, "session is invalid");
        return WMError::WM_ERROR_INVALID_WINDOW;
    }
    return SingletonContainer::Get<WindowAdapter>().UpdateExtWindowFlags(property_->GetParentId(), GetPersistentId(),
        flags.bitData, actions.bitData);
}

Rect WindowExtensionSessionImpl::GetHostWindowRect(int32_t hostWindowId)
{
    Rect rect;
    if (hostWindowId != property_->GetParentId()) {
        TLOGE(WmsLogTag::WMS_UIEXT, "hostWindowId is invalid");
        return rect;
    }
    SingletonContainer::Get<WindowAdapter>().GetHostWindowRect(hostWindowId, rect);
    return rect;
}
} // namespace Rosen
} // namespace OHOS
