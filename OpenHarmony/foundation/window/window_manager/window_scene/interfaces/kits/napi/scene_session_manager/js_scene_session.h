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

#ifndef OHOS_WINDOW_SCENE_JS_SCENE_SESSION_H
#define OHOS_WINDOW_SCENE_JS_SCENE_SESSION_H

#include <map>

#include <js_runtime_utils.h>
#include <native_engine/native_engine.h>
#include <native_engine/native_value.h>
#include <refbase.h>

#include "interfaces/include/ws_common.h"
#include "session/host/include/scene_session.h"
#include "js_scene_utils.h"
#include "task_scheduler.h"

namespace OHOS::Rosen {
class SceneSession;
class JsSceneSession : public std::enable_shared_from_this<JsSceneSession> {
public:
    JsSceneSession(napi_env env, const sptr<SceneSession>& session);
    ~JsSceneSession();

    static napi_value Create(napi_env env, const sptr<SceneSession>& session);
    static void Finalizer(napi_env env, void* data, void* hint);

    void ClearCbMap(bool needRemove, int32_t persistentId);
    sptr<SceneSession> GetNativeSession() const;

private:
    static napi_value RegisterCallback(napi_env env, napi_callback_info info);
    static napi_value UpdateNativeVisibility(napi_env env, napi_callback_info info);
    static napi_value SetShowRecent(napi_env env, napi_callback_info info);
    static napi_value SetZOrder(napi_env env, napi_callback_info info);
    static napi_value SetTouchable(napi_env env, napi_callback_info info);
    static napi_value SetSystemActive(napi_env env, napi_callback_info info);
    static napi_value SetPrivacyMode(napi_env env, napi_callback_info info);
    static napi_value SetFloatingScale(napi_env env, napi_callback_info info);
    static napi_value SetSystemSceneOcclusionAlpha(napi_env env, napi_callback_info info);
    static napi_value SetFocusable(napi_env env, napi_callback_info info);
    static napi_value SetSystemSceneBlockingFocus(napi_env env, napi_callback_info info);
    static napi_value UpdateSizeChangeReason(napi_env env, napi_callback_info info);
    static napi_value SetScale(napi_env env, napi_callback_info info);
    static napi_value RequestHideKeyboard(napi_env env, napi_callback_info info);
    static napi_value SetSCBKeepKeyboard(napi_env env, napi_callback_info info);
    static napi_value SetOffset(napi_env env, napi_callback_info info);
    static napi_value SetWaterMarkFlag(napi_env env, napi_callback_info info);
    static napi_value SetPipActionEvent(napi_env env, napi_callback_info info);
    static napi_value NotifyDisplayStatusBarTemporarily(napi_env env, napi_callback_info info);
    static napi_value SetTemporarilyShowWhenLocked(napi_env env, napi_callback_info info);
    static void BindNativeMethod(napi_env env, napi_value objValue, const char* moduleName);

    napi_value OnRegisterCallback(napi_env env, napi_callback_info info);
    napi_value OnUpdateNativeVisibility(napi_env env, napi_callback_info info);
    napi_value OnSetShowRecent(napi_env env, napi_callback_info info);
    napi_value OnSetZOrder(napi_env env, napi_callback_info info);
    napi_value OnSetTouchable(napi_env env, napi_callback_info info);
    napi_value OnSetSystemActive(napi_env env, napi_callback_info info);
    napi_value OnSetPrivacyMode(napi_env env, napi_callback_info info);
    napi_value OnSetFloatingScale(napi_env env, napi_callback_info info);
    napi_value OnSetSystemSceneOcclusionAlpha(napi_env env, napi_callback_info info);
    napi_value OnSetFocusable(napi_env env, napi_callback_info info);
    napi_value OnSetSystemSceneBlockingFocus(napi_env env, napi_callback_info info);
    napi_value OnUpdateSizeChangeReason(napi_env env, napi_callback_info info);
    napi_value OnSetScale(napi_env env, napi_callback_info info);
    napi_value OnRequestHideKeyboard(napi_env env, napi_callback_info info);
    napi_value OnSetSCBKeepKeyboard(napi_env env, napi_callback_info info);
    napi_value OnSetOffset(napi_env env, napi_callback_info info);
    napi_value OnSetWaterMarkFlag(napi_env env, napi_callback_info info);
    napi_value OnSetPipActionEvent(napi_env env, napi_callback_info info);
    napi_value OnNotifyDisplayStatusBarTemporarily(napi_env env, napi_callback_info info);
    napi_value OnSetTemporarilyShowWhenLocked(napi_env env, napi_callback_info info);

    bool IsCallbackRegistered(napi_env env, const std::string& type, napi_value jsListenerObject);
    void ProcessChangeSessionVisibilityWithStatusBarRegister();
    bool IsCallbackTypeSupported(const std::string& type);

    void InitListenerFuncs();
    void ProcessPendingSceneSessionActivationRegister();
    void ProcessSessionStateChangeRegister();
    void ProcessBufferAvailableChangeRegister();
    void ProcessSessionEventRegister();
    void ProcessCreateSubSessionRegister();
    void ProcessBindDialogTargetRegister();
    void ProcessSessionRectChangeRegister();
    void ProcessRaiseToTopRegister();
    void ProcessRaiseToTopForPointDownRegister();
    void ProcessBackPressedRegister();
    void ProcessSessionFocusableChangeRegister();
    void ProcessSessionTouchableChangeRegister();
    void ProcessSessionTopmostChangeRegister();
    void ProcessClickRegister();
    void ProcessTerminateSessionRegister();
    void ProcessTerminateSessionRegisterNew();
    void ProcessTerminateSessionRegisterTotal();
    void ProcessSessionExceptionRegister();
    void ProcessUpdateSessionLabelRegister();
    void ProcessUpdateSessionIconRegister();
    void ProcessSystemBarPropertyChangeRegister();
    void ProcessNeedAvoidRegister();
    void ProcessPendingSessionToForegroundRegister();
    void ProcessPendingSessionToBackgroundForDelegatorRegister();
    void ProcessSessionDefaultAnimationFlagChangeRegister();
    void ProcessIsCustomAnimationPlaying();
    void ProcessShowWhenLockedRegister();
    void ProcessRequestedOrientationChange();
    void ProcessRaiseAboveTargetRegister();
    void ProcessForceHideChangeRegister();
    void ProcessWindowDragHotAreaRegister();
    void ProcessTouchOutsideRegister();
    void ProcessSessionInfoLockedStateChangeRegister();
    void ProcessPrepareClosePiPSessionRegister();
    void ProcessLandscapeMultiWindowRegister();
    void ProcessContextTransparentRegister();
    void ProcessKeyboardGravityChangeRegister();
    void ProcessAdjustKeyboardLayoutRegister();

    void ChangeSessionVisibilityWithStatusBar(SessionInfo& info, bool visible);
    void ChangeSessionVisibilityWithStatusBarInner(std::shared_ptr<SessionInfo> sessionInfo, bool visible);
    sptr<SceneSession> GenSceneSession(SessionInfo& info);
    void PendingSessionActivation(SessionInfo& info);
    void PendingSessionActivationInner(std::shared_ptr<SessionInfo> sessionInfo);
    void OnSessionStateChange(const SessionState& state);
    void OnBufferAvailableChange(const bool isBufferAvailable);
    void OnSessionEvent(uint32_t eventId, const SessionEventParam& param);
    void OnCreateSubSession(const sptr<SceneSession>& sceneSession);
    void OnBindDialogTarget(const sptr<SceneSession>& sceneSession);
    void OnSessionRectChange(const WSRect& rect, const SizeChangeReason& reason = SizeChangeReason::UNDEFINED);
    void OnRaiseToTop();
    void OnRaiseToTopForPointDown();
    void OnRaiseAboveTarget(int32_t subWindowId);
    void OnBackPressed(bool needMoveToBackground);
    void OnSessionFocusableChange(bool isFocusable);
    void OnSessionTouchableChange(bool touchable);
    void OnSessionTopmostChange(bool topmost);
    void OnClick();
    void TerminateSession(const SessionInfo& info);
    void TerminateSessionNew(const SessionInfo& info, bool needStartCaller, bool isFromBroker);
    void TerminateSessionTotal(const SessionInfo& info, TerminateType terminateType);
    void UpdateSessionLabel(const std::string &label);
    void UpdateSessionIcon(const std::string &iconPath);
    void OnSessionException(const SessionInfo& info, bool needRemoveSession);
    void OnSystemBarPropertyChange(const std::unordered_map<WindowType, SystemBarProperty>& propertyMap);
    void OnNeedAvoid(bool status);
    void PendingSessionToForeground(const SessionInfo& info);
    void PendingSessionToBackgroundForDelegator(const SessionInfo& info);
    void OnDefaultAnimationFlagChange(bool isNeedDefaultAnimationFlag);
    void OnIsCustomAnimationPlaying(bool status);
    void OnShowWhenLocked(bool showWhenLocked);
    void OnReuqestedOrientationChange(uint32_t orientation);
    void OnForceHideChange(bool hide);
    void OnWindowDragHotArea(uint32_t type, const SizeChangeReason& reason);
    void OnTouchOutside();
    void OnSessionInfoLockedStateChange(bool lockedState);
    void OnPrepareClosePiPSession();
    void OnContextTransparent();
    void SetLandscapeMultiWindow(bool isLandscapeMultiWindow);
    void OnKeyboardGravityChange(SessionGravity gravity);
    void OnAdjustKeyboardLayout(const KeyboardLayoutParams& params);

    napi_env env_;
    wptr<SceneSession> weakSession_ = nullptr;
    wptr<SceneSession::SessionChangeCallback> sessionchangeCallback_ = nullptr;
    std::shared_mutex jsCbMapMutex_;
    std::map<std::string, std::shared_ptr<NativeReference>> jsCbMap_;
    using Func = void(JsSceneSession::*)();
    std::map<std::string, Func> listenerFunc_;
    std::shared_ptr<MainThreadScheduler> taskScheduler_;
    static std::map<int32_t, napi_ref> jsSceneSessionMap_;
};
} // namespace OHOS::Rosen

#endif // OHOS_WINDOW_SCENE_JS_SCENE_SESSION_H
