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

#include "session/host/include/scene_session.h"
#include <parameters.h>

#include <algorithm>
#include <hitrace_meter.h>
#ifdef IMF_ENABLE
#include <input_method_controller.h>
#endif // IMF_ENABLE
#include <ipc_skeleton.h>
#include <pointer_event.h>
#include <transaction/rs_transaction.h>
#include <ui/rs_surface_node.h>

#include "proxy/include/window_info.h"

#include "common/include/session_permission.h"
#include "interfaces/include/ws_common.h"
#include "pixel_map.h"
#include "session/screen/include/screen_session.h"
#include "screen_session_manager/include/screen_session_manager_client.h"
#include "session/host/include/scene_persistent_storage.h"
#include "session/host/include/session_utils.h"
#include "display_manager.h"
#include "session_helper.h"
#include "window_helper.h"
#include "window_manager_hilog.h"
#include "wm_math.h"
#include <running_lock.h>
#include "screen_manager.h"
#include "screen.h"
#include "singleton_container.h"
#include "screen_session_manager/include/screen_session_manager_client.h"

namespace OHOS::Rosen {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, HILOG_DOMAIN_WINDOW, "SceneSession" };
const std::string DLP_INDEX = "ohos.dlp.params.index";
constexpr const char* APP_TWIN_INDEX = "ohos.extra.param.key.appTwinIndex";
} // namespace

MaximizeMode SceneSession::maximizeMode_ = MaximizeMode::MODE_RECOVER;
wptr<SceneSession> SceneSession::enterSession_ = nullptr;
std::mutex SceneSession::enterSessionMutex_;
std::shared_mutex SceneSession::windowDragHotAreaMutex_;
std::map<uint32_t, WSRect> SceneSession::windowDragHotAreaMap_;
static bool g_enableForceUIFirst = system::GetParameter("window.forceUIFirst.enabled", "1") == "1";

SceneSession::SceneSession(const SessionInfo& info, const sptr<SpecificSessionCallback>& specificCallback)
    : Session(info)
{
    GeneratePersistentId(false, info.persistentId_);
    specificCallback_ = specificCallback;
    SetCollaboratorType(info.collaboratorType_);
    TLOGI(WmsLogTag::WMS_LIFE, "Create session, id: %{public}d", GetPersistentId());
}

SceneSession::~SceneSession()
{
    TLOGI(WmsLogTag::WMS_LIFE, "~SceneSession, id: %{public}d", GetPersistentId());
}

WSError SceneSession::Connect(const sptr<ISessionStage>& sessionStage, const sptr<IWindowEventChannel>& eventChannel,
    const std::shared_ptr<RSSurfaceNode>& surfaceNode, SystemSessionConfig& systemConfig,
    sptr<WindowSessionProperty> property, sptr<IRemoteObject> token, int32_t pid, int32_t uid,
    const std::string& identityToken)
{
    // Get pid and uid before posting task.
    pid = pid == -1 ? IPCSkeleton::GetCallingRealPid() : pid;
    uid = uid == -1 ? IPCSkeleton::GetCallingUid() : uid;
    auto task = [weakThis = wptr(this), sessionStage, eventChannel, surfaceNode, &systemConfig, property, token, pid,
        uid, identityToken]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (SessionHelper::IsMainWindow(session->GetWindowType()) && !identityToken.empty() &&
            !session->clientIdentityToken_.empty() && identityToken != session->clientIdentityToken_) {
            TLOGW(WmsLogTag::WMS_LIFE,
                "Identity Token vaildate failed, clientIdentityToken_: %{public}s, "
                "identityToken: %{public}s, bundleName: %{public}s",
                session->clientIdentityToken_.c_str(), identityToken.c_str(),
                session->GetSessionInfo().bundleName_.c_str());
            return WSError::WS_OK;
        }
        if (property) {
            property->SetCollaboratorType(session->GetCollaboratorType());
        }
        auto ret = session->Session::Connect(
            sessionStage, eventChannel, surfaceNode, systemConfig, property, token, pid, uid);
        if (ret != WSError::WS_OK) {
            return ret;
        }
        session->NotifyPropertyWhenConnect();
        return ret;
    };
    return PostSyncTask(task, "Connect");
}

WSError SceneSession::Reconnect(const sptr<ISessionStage>& sessionStage, const sptr<IWindowEventChannel>& eventChannel,
    const std::shared_ptr<RSSurfaceNode>& surfaceNode, sptr<WindowSessionProperty> property, sptr<IRemoteObject> token,
    int32_t pid, int32_t uid)
{
    return PostSyncTask([weakThis = wptr(this), sessionStage, eventChannel, surfaceNode, property, token, pid, uid]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        return session->Session::Reconnect(sessionStage, eventChannel, surfaceNode, property, token, pid, uid);
    });
}

WSError SceneSession::Foreground(sptr<WindowSessionProperty> property, bool isFromClient)
{
    // return when screen is locked and show without ShowWhenLocked flag
    if (false && GetWindowType() == WindowType::WINDOW_TYPE_APP_MAIN_WINDOW &&
        GetStateFromManager(ManagerState::MANAGER_STATE_SCREEN_LOCKED) && !IsShowWhenLocked() &&
        sessionInfo_.bundleName_.find("startupguide") == std::string::npos &&
        sessionInfo_.bundleName_.find("samplemanagement") == std::string::npos) {
        TLOGW(WmsLogTag::WMS_LIFE, "failed: Screen is locked, session %{public}d show without ShowWhenLocked flag",
            GetPersistentId());
        return WSError::WS_ERROR_INVALID_SESSION;
    }
    if (isFromClient && SessionHelper::IsMainWindow(GetWindowType())) {
        int32_t callingPid = IPCSkeleton::GetCallingPid();
        if (callingPid != -1 && callingPid != GetCallingPid()) {
            TLOGW(WmsLogTag::WMS_LIFE,
                "Foreground failed, callingPid_: %{public}d, callingPid: %{public}d, bundleName: %{public}s",
                GetCallingPid(), callingPid, GetSessionInfo().bundleName_.c_str());
            return WSError::WS_OK;
        }
    }

    auto task = [weakThis = wptr(this), property]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session or property is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }

        if (property && session->GetSessionProperty()) {
            session->GetSessionProperty()->SetWindowMode(property->GetWindowMode());
            session->GetSessionProperty()->SetDecorEnable(property->IsDecorEnable());
        }

        auto ret = session->Session::Foreground(property);
        if (ret != WSError::WS_OK) {
            return ret;
        }
        auto sessionProperty = session->GetSessionProperty();
        auto leashWinSurfaceNode = session->GetLeashWinSurfaceNode();
        if (leashWinSurfaceNode && sessionProperty) {
            bool lastPrivacyMode = sessionProperty->GetPrivacyMode() || sessionProperty->GetSystemPrivacyMode();
            leashWinSurfaceNode->SetSecurityLayer(lastPrivacyMode);
        }
        if (session->specificCallback_ != nullptr) {
            session->specificCallback_->onUpdateAvoidArea_(session->GetPersistentId());
            session->specificCallback_->onWindowInfoUpdate_(
                session->GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_ADDED);
            session->specificCallback_->onHandleSecureSessionShouldHide_(session);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "Foreground");
    return WSError::WS_OK;
}

WSError SceneSession::Background(bool isFromClient)
{
    if (isFromClient && SessionHelper::IsMainWindow(GetWindowType())) {
        int32_t callingPid = IPCSkeleton::GetCallingPid();
        if (callingPid != -1 && callingPid != GetCallingPid()) {
            TLOGW(WmsLogTag::WMS_LIFE,
                "Background failed, callingPid_: %{public}d, callingPid: %{public}d, bundleName: %{public}s",
                GetCallingPid(), callingPid, GetSessionInfo().bundleName_.c_str());
            return WSError::WS_OK;
        }
    }
    return BackgroundTask(true);
}

WSError SceneSession::BackgroundTask(const bool isSaveSnapshot)
{
    auto task = [weakThis = wptr(this), isSaveSnapshot]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        auto state = session->GetSessionState();
        if (state == SessionState::STATE_BACKGROUND) {
            return WSError::WS_OK;
        }
        auto ret = session->Session::Background();
        if (ret != WSError::WS_OK) {
            return ret;
        }
        if (WindowHelper::IsMainWindow(session->GetWindowType()) && isSaveSnapshot) {
            session->snapshot_ = session->Snapshot();
            if (session->scenePersistence_ && session->snapshot_) {
                const std::function<void()> func = std::bind(&Session::ResetSnapshot, session);
                session->scenePersistence_->SaveSnapshot(session->snapshot_, func);
            } else {
                session->snapshot_.reset();
            }
        }
        if (session->specificCallback_ != nullptr) {
            session->specificCallback_->onUpdateAvoidArea_(session->GetPersistentId());
            session->specificCallback_->onWindowInfoUpdate_(
                session->GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_REMOVED);
            session->specificCallback_->onHandleSecureSessionShouldHide_(session);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "Background");
    return WSError::WS_OK;
}

void SceneSession::ClearSpecificSessionCbMap()
{
    auto task = [weakThis = wptr(this)]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_SYSTEM, "session is null");
            return;
        }
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->clearCallbackFunc_) {
            session->sessionChangeCallback_->clearCallbackFunc_(true, session->GetPersistentId());
            TLOGD(WmsLogTag::WMS_SYSTEM, "ClearCallbackMap, id: %{public}d", session->GetPersistentId());
        } else {
            TLOGE(WmsLogTag::WMS_SYSTEM, "get callback failed, id: %{public}d", session->GetPersistentId());
        }
    };
    PostTask(task, "ClearSpecificSessionCbMap");
}

WSError SceneSession::Disconnect(bool isFromClient)
{
    if (isFromClient && SessionHelper::IsMainWindow(GetWindowType())) {
        int32_t callingPid = IPCSkeleton::GetCallingPid();
        if (callingPid != -1 && callingPid != GetCallingPid()) {
            TLOGW(WmsLogTag::WMS_LIFE,
                "Disconnect failed, callingPid_: %{public}d, callingPid: %{public}d, bundleName: %{public}s",
                GetCallingPid(), callingPid, GetSessionInfo().bundleName_.c_str());
            return WSError::WS_OK;
        }
    }
    PostTask([weakThis = wptr(this), isFromClient]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (isFromClient) {
            TLOGI(WmsLogTag::WMS_LIFE, "Client need notify destroy session, id: %{public}d",
                session->GetPersistentId());
            session->SetSessionState(SessionState::STATE_DISCONNECT);
            return WSError::WS_OK;
        }
        auto state = session->GetSessionState();
        auto isMainWindow = SessionHelper::IsMainWindow(session->GetWindowType());
        if (session->needSnapshot_ || (state == SessionState::STATE_ACTIVE && isMainWindow)) {
            session->snapshot_ = session->Snapshot();
            if (session->scenePersistence_ && session->snapshot_) {
                const std::function<void()> func = std::bind(&Session::ResetSnapshot, session);
                session->scenePersistence_->SaveSnapshot(session->snapshot_, func);
            } else {
                session->snapshot_.reset();
            }
        }
        session->Session::Disconnect(isFromClient);
        session->isTerminating = false;
        if (session->specificCallback_ != nullptr) {
            session->specificCallback_->onHandleSecureSessionShouldHide_(session);
        }
        return WSError::WS_OK;
    },
        "Disconnect");
    return WSError::WS_OK;
}

WSError SceneSession::UpdateActiveStatus(bool isActive)
{
    auto task = [weakThis = wptr(this), isActive]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("[WMSCom] session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (!session->IsSessionValid()) {
            return WSError::WS_ERROR_INVALID_SESSION;
        }
        if (isActive == session->isActive_) {
            WLOGFD("[WMSCom] Session active do not change: %{public}d", isActive);
            return WSError::WS_DO_NOTHING;
        }

        WSError ret = WSError::WS_DO_NOTHING;
        if (isActive && session->GetSessionState() == SessionState::STATE_FOREGROUND) {
            session->UpdateSessionState(SessionState::STATE_ACTIVE);
            session->isActive_ = isActive;
            ret = WSError::WS_OK;
        }
        if (!isActive && session->GetSessionState() == SessionState::STATE_ACTIVE) {
            session->UpdateSessionState(SessionState::STATE_INACTIVE);
            session->isActive_ = isActive;
            ret = WSError::WS_OK;
        }
        WLOGFI("[WMSCom] UpdateActiveStatus, isActive: %{public}d, state: %{public}u",
            session->isActive_, session->GetSessionState());
        return ret;
    };
    PostTask(task, "UpdateActiveStatus:" + std::to_string(isActive));
    return WSError::WS_OK;
}

WSError SceneSession::OnSessionEvent(SessionEvent event)
{
    auto task = [weakThis = wptr(this), event]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("[WMSCom] session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        WLOGFI("[WMSCom] SceneSession OnSessionEvent event: %{public}d", static_cast<int32_t>(event));
        if (event == SessionEvent::EVENT_START_MOVE && session->moveDragController_ &&
            !session->moveDragController_->GetStartDragFlag()) {
            HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER, "SceneSession::StartMove");
            session->moveDragController_->InitMoveDragProperty();
            session->moveDragController_->SetStartMoveFlag(true);
            session->moveDragController_->ClacFirstMoveTargetRect(session->winRect_);
            session->SetSessionEventParam({session->moveDragController_->GetOriginalPointerPosX(),
                session->moveDragController_->GetOriginalPointerPosY()});
        }
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->OnSessionEvent_) {
            session->sessionChangeCallback_->OnSessionEvent_(static_cast<uint32_t>(event), session->sessionEventParam_);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "OnSessionEvent:" + std::to_string(static_cast<int>(event)));
    return WSError::WS_OK;
}

uint32_t SceneSession::GetWindowDragHotAreaType(uint32_t type, int32_t pointerX, int32_t pointerY)
{
    std::shared_lock<std::shared_mutex> lock(windowDragHotAreaMutex_);
    for (auto it = windowDragHotAreaMap_.begin(); it != windowDragHotAreaMap_.end(); ++it) {
        uint32_t key = it->first;
        WSRect rect = it->second;
        if (rect.IsInRegion(pointerX, pointerY)) {
            type |= key;
        }
    }
    return type;
}

void SceneSession::AddOrUpdateWindowDragHotArea(uint32_t type, const WSRect& area)
{
    std::unique_lock<std::shared_mutex> lock(windowDragHotAreaMutex_);
    auto const result = windowDragHotAreaMap_.insert({type, area});
    if (!result.second) {
        result.first->second = area;
    }
}

void SceneSession::SetSessionEventParam(SessionEventParam param)
{
    sessionEventParam_ = param;
}

void SceneSession::RegisterSessionChangeCallback(const sptr<SceneSession::SessionChangeCallback>&
    sessionChangeCallback)
{
    std::lock_guard<std::mutex> guard(sessionChangeCbMutex_);
    sessionChangeCallback_ = sessionChangeCallback;
}

WSError SceneSession::SetGlobalMaximizeMode(MaximizeMode mode)
{
    auto task = [weakThis = wptr(this), mode]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("[WMSCom] session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        WLOGFD("[WMSCom] mode: %{public}u", static_cast<uint32_t>(mode));
        session->maximizeMode_ = mode;
        ScenePersistentStorage::Insert("maximize_state", static_cast<int32_t>(session->maximizeMode_),
            ScenePersistentStorageType::MAXIMIZE_STATE);
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "SetGlobalMaximizeMode");
}

WSError SceneSession::GetGlobalMaximizeMode(MaximizeMode &mode)
{
    auto task = [weakThis = wptr(this), &mode]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("[WMSCom] session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        mode = maximizeMode_;
        WLOGFD("[WMSCom] mode: %{public}u", static_cast<uint32_t>(mode));
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "GetGlobalMaximizeMode");
}

WSError SceneSession::SetAspectRatio(float ratio)
{
    auto task = [weakThis = wptr(this), ratio]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("[WMSCom] session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (!session->GetSessionProperty()) {
            WLOGE("[WMSCom] SetAspectRatio failed because property is null");
            return WSError::WS_ERROR_NULLPTR;
        }
        WLOGFI("[WMSCom] ratio: %{public}f", ratio);
        float vpr = 1.5f; // 1.5f: default virtual pixel ratio
        auto display = DisplayManager::GetInstance().GetDefaultDisplay();
        if (display) {
            vpr = display->GetVirtualPixelRatio();
            WLOGD("vpr = %{public}f", vpr);
        }
        if (!MathHelper::NearZero(ratio)) {
            auto limits = session->GetSessionProperty()->GetWindowLimits();
            if (session->IsDecorEnable()) {
                if (limits.minWidth_ && limits.maxHeight_ &&
                    MathHelper::LessNotEqual(ratio, SessionUtils::ToLayoutWidth(limits.minWidth_, vpr) /
                    SessionUtils::ToLayoutHeight(limits.maxHeight_, vpr))) {
                    WLOGE("Failed, because aspectRatio is smaller than minWidth/maxHeight");
                    return WSError::WS_ERROR_INVALID_PARAM;
                } else if (limits.minHeight_ && limits.maxWidth_ &&
                    MathHelper::GreatNotEqual(ratio, SessionUtils::ToLayoutWidth(limits.maxWidth_, vpr) /
                    SessionUtils::ToLayoutHeight(limits.minHeight_, vpr))) {
                    WLOGE("Failed, because aspectRatio is bigger than maxWidth/minHeight");
                    return WSError::WS_ERROR_INVALID_PARAM;
                }
            } else {
                if (limits.minWidth_ && limits.maxHeight_ && MathHelper::LessNotEqual(ratio,
                    static_cast<float>(limits.minWidth_) / limits.maxHeight_)) {
                    WLOGE("Failed, because aspectRatio is smaller than minWidth/maxHeight");
                    return WSError::WS_ERROR_INVALID_PARAM;
                } else if (limits.minHeight_ && limits.maxWidth_ && MathHelper::GreatNotEqual(ratio,
                    static_cast<float>(limits.maxWidth_) / limits.minHeight_)) {
                    WLOGE("Failed, because aspectRatio is bigger than maxWidth/minHeight");
                    return WSError::WS_ERROR_INVALID_PARAM;
                }
            }
        }
        session->aspectRatio_ = ratio;
        if (session->moveDragController_) {
            session->moveDragController_->SetAspectRatio(ratio);
        }
        session->SaveAspectRatio(session->aspectRatio_);
        WSRect fixedRect = session->winRect_;
        TLOGI(WmsLogTag::WMS_LAYOUT, "Before fixing, the id:%{public}d, the current rect: %{public}s",
            session->GetPersistentId(), fixedRect.ToString().c_str());
        if (session->FixRectByAspectRatio(fixedRect)) {
            TLOGI(WmsLogTag::WMS_LAYOUT, "After fixing, the id:%{public}d, the fixed rect: %{public}s",
                session->GetPersistentId(), fixedRect.ToString().c_str());
            session->NotifySessionRectChange(fixedRect, SizeChangeReason::RESIZE);
        }
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "SetAspectRatio");
}

WSError SceneSession::UpdateRect(const WSRect& rect, SizeChangeReason reason,
    const std::shared_ptr<RSTransaction>& rsTransaction)
{
    auto task = [weakThis = wptr(this), rect, reason, rsTransaction]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (session->winRect_ == rect && session->reason_ != SizeChangeReason::UNDEFINED &&
            session->reason_ != SizeChangeReason::DRAG_END) {
            TLOGD(WmsLogTag::WMS_LAYOUT, "skip same rect update id:%{public}d rect:%{public}s!",
                session->GetPersistentId(), rect.ToString().c_str());
            return WSError::WS_OK;
        }
        if (rect.IsInvalid()) {
            TLOGE(WmsLogTag::WMS_LAYOUT, "id:%{public}d rect:%{public}s is invalid",
                session->GetPersistentId(), rect.ToString().c_str());
            return WSError::WS_ERROR_INVALID_PARAM;
        }
        HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER,
            "SceneSession::UpdateRect%d [%d, %d, %u, %u]",
            session->GetPersistentId(), rect.posX_, rect.posY_, rect.width_, rect.height_);
        // position change no need to notify client, since frame layout finish will notify
        if (NearEqual(rect.width_, session->winRect_.width_) && NearEqual(rect.height_, session->winRect_.height_) &&
            (session->reason_ != SizeChangeReason::MOVE || !session->rectChangeListenerRegistered_)) {
            TLOGI(WmsLogTag::WMS_LAYOUT, "position change no need notify client id:%{public}d, rect:%{public}s, "
                "preRect: %{public}s",
                session->GetPersistentId(), rect.ToString().c_str(), session->winRect_.ToString().c_str());
            session->winRect_ = rect;
            session->isDirty_ = true;
        } else {
            session->winRect_ = rect;
            session->NotifyClientToUpdateRect(rsTransaction);
        }
        TLOGD(WmsLogTag::WMS_LAYOUT, "id:%{public}d, reason:%{public}d, rect:%{public}s",
            session->GetPersistentId(), session->reason_, rect.ToString().c_str());

        return WSError::WS_OK;
    };
    PostTask(task, "UpdateRect" + GetRectInfo(rect));
    return WSError::WS_OK;
}

void SceneSession::FixKeyboardPositionByKeyboardPanel(sptr<SceneSession> panelSession,
    sptr<SceneSession> keyboardSession)
{
    if (panelSession == nullptr || keyboardSession == nullptr) {
        TLOGE(WmsLogTag::WMS_LAYOUT, "keyboard or panel session is null");
        return;
    }

    SessionGravity gravity = keyboardSession->GetKeyboardGravity();
    if (gravity == SessionGravity::SESSION_GRAVITY_FLOAT) {
        keyboardSession->winRect_.posX_ = panelSession->winRect_.posX_;
    } else {
        if (keyboardSession->GetSessionProperty() == nullptr) {
            TLOGE(WmsLogTag::WMS_LAYOUT, "keyboard property is null");
            return;
        }
        static bool isPhone = system::GetParameter("const.product.devicetype", "unknown") == "phone";
        static bool isFoldable = ScreenSessionManagerClient::GetInstance().IsFoldable();
        bool isFolded = ScreenSessionManagerClient::GetInstance().GetFoldStatus() == OHOS::Rosen::FoldStatus::FOLDED;
        const auto& screenSession = ScreenSessionManagerClient::GetInstance().GetScreenSession(
            keyboardSession->GetSessionProperty()->GetDisplayId());
        Rotation rotation = (screenSession != nullptr) ? screenSession->GetRotation() : Rotation::ROTATION_0;
        bool isKeyboardNeedLeftOffset = (isPhone && (!isFoldable || (isFoldable && isFolded)) &&
            (rotation == Rotation::ROTATION_90 || rotation == Rotation::ROTATION_270));
        if (isKeyboardNeedLeftOffset) {
            keyboardSession->winRect_.posX_ += panelSession->winRect_.posX_;
        } else {
            keyboardSession->winRect_.posX_ = panelSession->winRect_.posX_;
        }
        TLOGI(WmsLogTag::WMS_LAYOUT, "isPhone:%{public}d, isFoldable:%{public}d, isFolded:%{public}d, "
            "rotation:%{public}d, isKeyboardNeedLeftOffset:%{public}d", isPhone, isFoldable,
            isFolded, rotation, isKeyboardNeedLeftOffset);
    }
    keyboardSession->winRect_.posY_ = panelSession->winRect_.posY_;
    TLOGI(WmsLogTag::WMS_LAYOUT, "panelId:%{public}d, keyboardId:%{public}d, panelRect:%{public}s, "
        "keyboardRect:%{public}s, gravity:%{public}d", panelSession->GetPersistentId(),
        keyboardSession->GetPersistentId(), panelSession->winRect_.ToString().c_str(),
        keyboardSession->winRect_.ToString().c_str(), gravity);
}

WSError SceneSession::NotifyClientToUpdateRectTask(
    wptr<SceneSession> weakThis, std::shared_ptr<RSTransaction> rsTransaction)
{
    auto session = weakThis.promote();
    if (!session) {
        WLOGFE("session is null");
        return WSError::WS_ERROR_DESTROYED_OBJECT;
    }
    TLOGD(WmsLogTag::WMS_LAYOUT, "id:%{public}d, reason:%{public}d, rect:%{public}s",
        session->GetPersistentId(), session->reason_, session->winRect_.ToString().c_str());
    bool isMoveOrDrag = session->moveDragController_ &&
        (session->moveDragController_->GetStartDragFlag() || session->moveDragController_->GetStartMoveFlag());
    if (isMoveOrDrag && session->reason_ == SizeChangeReason::UNDEFINED) {
        TLOGD(WmsLogTag::WMS_LAYOUT, "skip redundant rect update!");
        return WSError::WS_ERROR_REPEAT_OPERATION;
    }
    WSError ret = WSError::WS_OK;
    HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER,
        "SceneSession::NotifyClientToUpdateRect%d [%d, %d, %u, %u] reason:%u",
        session->GetPersistentId(), session->winRect_.posX_,
        session->winRect_.posY_, session->winRect_.width_, session->winRect_.height_, session->reason_);

    if (isKeyboardPanelEnabled_) {
        if (session->GetWindowType() == WindowType::WINDOW_TYPE_KEYBOARD_PANEL) {
            const auto& keyboardSession = session->GetKeyboardSession();
            FixKeyboardPositionByKeyboardPanel(session, keyboardSession);
            if (keyboardSession != nullptr) {
                ret = keyboardSession->Session::UpdateRect(keyboardSession->winRect_, session->reason_, rsTransaction);
            }
        }
        if (session->GetWindowType() == WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT) {
            FixKeyboardPositionByKeyboardPanel(session->GetKeyboardPanelSession(), session);
            return WSError::WS_OK;
        }
    }

    // once reason is undefined, not use rsTransaction
    // when rotation, sync cnt++ in marshalling. Although reason is undefined caused by resize
    if (session->reason_ == SizeChangeReason::UNDEFINED || session->reason_ == SizeChangeReason::MOVE ||
        session->reason_ == SizeChangeReason::RESIZE) {
        ret = session->Session::UpdateRect(session->winRect_, session->reason_, nullptr);
    } else {
        ret = session->Session::UpdateRect(session->winRect_, session->reason_, rsTransaction);
    }

    return ret;
}

WSError SceneSession::NotifyClientToUpdateRect(std::shared_ptr<RSTransaction> rsTransaction)
{
    auto task = [weakThis = wptr(this), rsTransaction]() {
        auto session = weakThis.promote();
        WSError ret = session->NotifyClientToUpdateRectTask(weakThis, rsTransaction);
        if (ret == WSError::WS_OK) {
            if (session->specificCallback_ != nullptr) {
                session->specificCallback_->onUpdateAvoidArea_(session->GetPersistentId());
            }
            // clear after use
            if (session->reason_ != SizeChangeReason::DRAG) {
                session->reason_ = SizeChangeReason::UNDEFINED;
                session->isDirty_ = false;
            }
        }
        return ret;
    };
    PostTask(task, "NotifyClientToUpdateRect");
    return WSError::WS_OK;
}

bool SceneSession::UpdateInputMethodSessionRect(const WSRect&rect, WSRect& newWinRect, WSRect& newRequestRect)
{
    SessionGravity gravity;
    uint32_t percent = 0;
    GetSessionProperty()->GetSessionGravity(gravity, percent);
    if (GetWindowType() == WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT &&
        (gravity == SessionGravity::SESSION_GRAVITY_BOTTOM || gravity == SessionGravity::SESSION_GRAVITY_DEFAULT)) {
        auto defaultDisplayInfo = DisplayManager::GetInstance().GetDefaultDisplay();
        if (defaultDisplayInfo == nullptr) {
            TLOGE(WmsLogTag::WMS_KEYBOARD, "defaultDisplayInfo is nullptr");
            return false;
        }

        newWinRect.width_ = (gravity == SessionGravity::SESSION_GRAVITY_BOTTOM) ?
            defaultDisplayInfo->GetWidth() : rect.width_;
        newRequestRect.width_ = newWinRect.width_;
        newWinRect.height_ = (gravity == SessionGravity::SESSION_GRAVITY_BOTTOM && percent != 0) ?
            static_cast<int32_t>(defaultDisplayInfo->GetHeight() * percent / 100u) : rect.height_;
        newRequestRect.height_ = newWinRect.height_;
        newWinRect.posX_ = (gravity == SessionGravity::SESSION_GRAVITY_BOTTOM) ? 0 : newRequestRect.posX_;
        newRequestRect.posX_ = newWinRect.posX_;
        newWinRect.posY_ = defaultDisplayInfo->GetHeight() - static_cast<int32_t>(newWinRect.height_);
        newRequestRect.posY_ = newWinRect.posY_;
        TLOGI(WmsLogTag::WMS_KEYBOARD, "rect: %{public}s, newRequestRect: %{public}s, newWinRect: %{public}s",
            rect.ToString().c_str(), newRequestRect.ToString().c_str(), newWinRect.ToString().c_str());
        return true;
    }
    WLOGFD("There is no need to update input rect");
    return false;
}

void SceneSession::SetSessionRectChangeCallback(const NotifySessionRectChangeFunc& func)
{
    auto task = [weakThis = wptr(this), func]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        session->sessionRectChangeFunc_ = func;
        if (session->sessionRectChangeFunc_ && session->GetWindowType() != WindowType::WINDOW_TYPE_APP_MAIN_WINDOW) {
            auto reason = SizeChangeReason::UNDEFINED;
            auto rect = session->GetSessionRequestRect();
            if (rect.width_ == 0 && rect.height_ == 0) {
                reason = SizeChangeReason::MOVE;
            }
            session->sessionRectChangeFunc_(session->GetSessionRequestRect(), reason);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "SetSessionRectChangeCallback");
}

void SceneSession::UpdateSessionRectInner(const WSRect& rect, const SizeChangeReason& reason)
{
    auto newWinRect = winRect_;
    auto newRequestRect = GetSessionRequestRect();
    SizeChangeReason newReason = reason;
    if (reason == SizeChangeReason::MOVE) {
        newWinRect.posX_ = rect.posX_;
        newWinRect.posY_ = rect.posY_;
        newRequestRect.posX_ = rect.posX_;
        newRequestRect.posY_ = rect.posY_;
        if (!WindowHelper::IsMainWindow(GetWindowType())) {
            SetSessionRect(newWinRect);
        }
        SetSessionRequestRect(newRequestRect);
        NotifySessionRectChange(newRequestRect, reason);
    } else if (reason == SizeChangeReason::RESIZE) {
        bool needUpdateInputMethod = UpdateInputMethodSessionRect(rect, newWinRect, newRequestRect);
        if (needUpdateInputMethod) {
            newReason = SizeChangeReason::UNDEFINED;
            TLOGD(WmsLogTag::WMS_KEYBOARD, "Input rect has totally changed, need to modify reason, id: %{public}d",
                GetPersistentId());
        } else if (rect.width_ > 0 && rect.height_ > 0) {
            newWinRect.width_ = rect.width_;
            newWinRect.height_ = rect.height_;
            newRequestRect.width_ = rect.width_;
            newRequestRect.height_ = rect.height_;
        }
        if (GetWindowType() != WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT) {
            SetSessionRect(newWinRect);
        }
        SetSessionRequestRect(newRequestRect);
        NotifySessionRectChange(newRequestRect, newReason);
    } else {
        SetSessionRect(rect);
        NotifySessionRectChange(rect, reason);
    }
    TLOGI(WmsLogTag::WMS_LAYOUT, "Id: %{public}d, reason: %{public}d, newReason: %{public}d, rect: %{public}s, "
        "newRequestRect: %{public}s, newWinRect: %{public}s", GetPersistentId(), reason,
        newReason, rect.ToString().c_str(), newRequestRect.ToString().c_str(), newWinRect.ToString().c_str());
}

WSError SceneSession::UpdateSessionRect(const WSRect& rect, const SizeChangeReason& reason)
{
    if ((reason == SizeChangeReason::MOVE || reason == SizeChangeReason::RESIZE) &&
        GetWindowType() == WindowType::WINDOW_TYPE_PIP) {
        return WSError::WS_DO_NOTHING;
    }
    auto task = [weakThis = wptr(this), rect, reason]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LAYOUT, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        session->UpdateSessionRectInner(rect, reason);
        return WSError::WS_OK;
    };
    PostTask(task, "UpdateSessionRect" + GetRectInfo(rect));
    return WSError::WS_OK;
}

WSError SceneSession::RaiseToAppTop()
{
    if (!SessionPermission::IsSystemCalling()) {
        WLOGFE("raise to app top permission denied!");
        return WSError::WS_ERROR_NOT_SYSTEM_APP;
    }
    auto task = [weakThis = wptr(this)]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->onRaiseToTop_) {
            TLOGI(WmsLogTag::WMS_SUB, "id: %{public}d", session->GetPersistentId());
            session->sessionChangeCallback_->onRaiseToTop_();
        }
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "RaiseToAppTop");
}

WSError SceneSession::RaiseAboveTarget(int32_t subWindowId)
{
    if (!SessionPermission::IsSystemCalling() && !SessionPermission::IsStartByHdcd()) {
        WLOGFE("RaiseAboveTarget permission denied!");
        return WSError::WS_ERROR_NOT_SYSTEM_APP;
    }
    auto task = [weakThis = wptr(this), subWindowId]() {
        auto session = weakThis.promote();
    if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->onRaiseAboveTarget_) {
            session->sessionChangeCallback_->onRaiseAboveTarget_(subWindowId);
        }
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "RaiseAboveTarget");
}

WSError SceneSession::BindDialogSessionTarget(const sptr<SceneSession>& sceneSession)
{
    if (sceneSession == nullptr) {
        TLOGE(WmsLogTag::WMS_DIALOG, "dialog session is null");
        return WSError::WS_ERROR_NULLPTR;
    }
    if (sessionChangeCallback_ != nullptr && sessionChangeCallback_->onBindDialogTarget_) {
        TLOGI(WmsLogTag::WMS_DIALOG, "id: %{public}d", sceneSession->GetPersistentId());
        sessionChangeCallback_->onBindDialogTarget_(sceneSession);
    }
    return WSError::WS_OK;
}

WSError SceneSession::SetSystemBarProperty(WindowType type, SystemBarProperty systemBarProperty)
{
    TLOGD(WmsLogTag::WMS_IMMS, "persistentId():%{public}u type:%{public}u"
        "enable:%{public}u bgColor:%{public}x Color:%{public}x enableAnimation:%{public}u settingFlag:%{public}u",
        GetPersistentId(), static_cast<uint32_t>(type),
        systemBarProperty.enable_, systemBarProperty.backgroundColor_, systemBarProperty.contentColor_,
        systemBarProperty.enableAnimation_, systemBarProperty.settingFlag_);
    auto property = GetSessionProperty();
    if (property == nullptr) {
        TLOGE(WmsLogTag::WMS_DIALOG, "property is null");
        return WSError::WS_ERROR_NULLPTR;
    }
    property->SetSystemBarProperty(type, systemBarProperty);
    if (sessionChangeCallback_ != nullptr && sessionChangeCallback_->OnSystemBarPropertyChange_) {
        sessionChangeCallback_->OnSystemBarPropertyChange_(property->GetSystemBarProperty());
    }
    return WSError::WS_OK;
}

void SceneSession::NotifyPropertyWhenConnect()
{
    WLOGFI("Notify property when connect.");
    auto property = GetSessionProperty();
    if (property == nullptr) {
        WLOGFD("id: %{public}d property is nullptr", persistentId_);
        return;
    }
    NotifySessionFocusableChange(property->GetFocusable());
    NotifySessionTouchableChange(property->GetTouchable());
    OnShowWhenLocked(GetShowWhenLockedFlagValue());
}

WSError SceneSession::RaiseAppMainWindowToTop()
{
    auto task = [weakThis = wptr(this)]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (session->IsFocusedOnShow()) {
            session->NotifyRequestFocusStatusNotifyManager(true, true);
            session->NotifyClick();
        }
        return WSError::WS_OK;
    };
    PostTask(task, "RaiseAppMainWindowToTop");
    return WSError::WS_OK;
}

WSError SceneSession::OnNeedAvoid(bool status)
{
    auto task = [weakThis = wptr(this), status]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_IMMS, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        TLOGI(WmsLogTag::WMS_IMMS, "SceneSession OnNeedAvoid status:%{public}d, id:%{public}d",
            static_cast<int32_t>(status), session->GetPersistentId());
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->OnNeedAvoid_) {
            session->sessionChangeCallback_->OnNeedAvoid_(status);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "OnNeedAvoid");
    return WSError::WS_OK;
}

WSError SceneSession::OnShowWhenLocked(bool showWhenLocked)
{
    WLOGFD("SceneSession ShowWhenLocked status:%{public}d", static_cast<int32_t>(showWhenLocked));
    if (sessionChangeCallback_ != nullptr && sessionChangeCallback_->OnShowWhenLocked_) {
        sessionChangeCallback_->OnShowWhenLocked_(showWhenLocked);
    }
    return WSError::WS_OK;
}

bool SceneSession::IsShowWhenLocked() const
{
    return (GetSessionProperty()->GetWindowFlags() &
        static_cast<uint32_t>(WindowFlag::WINDOW_FLAG_SHOW_WHEN_LOCKED)) || IsTemporarilyShowWhenLocked();
}

bool SceneSession::GetShowWhenLockedFlagValue() const
{
    return GetSessionProperty()->GetWindowFlags() & static_cast<uint32_t>(WindowFlag::WINDOW_FLAG_SHOW_WHEN_LOCKED);
}

void SceneSession::CalculateAvoidAreaRect(WSRect& rect, WSRect& avoidRect, AvoidArea& avoidArea) const
{
    if (SessionHelper::IsEmptyRect(rect) || SessionHelper::IsEmptyRect(avoidRect)) {
        return;
    }
    Rect avoidAreaRect = SessionHelper::TransferToRect(
        SessionHelper::GetOverlap(rect, avoidRect, rect.posX_, rect.posY_));
    if (WindowHelper::IsEmptyRect(avoidAreaRect)) {
        return;
    }

    uint32_t avoidAreaCenterX = static_cast<uint32_t>(avoidAreaRect.posX_) + (avoidAreaRect.width_ >> 1);
    uint32_t avoidAreaCenterY = static_cast<uint32_t>(avoidAreaRect.posY_) + (avoidAreaRect.height_ >> 1);
    float res1 = float(avoidAreaCenterY) - float(rect.height_) / float(rect.width_) *
        float(avoidAreaCenterX);
    float res2 = float(avoidAreaCenterY) + float(rect.height_) / float(rect.width_) *
        float(avoidAreaCenterX) - float(rect.height_);
    if (res1 < 0) {
        if (res2 < 0) {
            avoidArea.topRect_ = avoidAreaRect;
        } else {
            avoidArea.rightRect_ = avoidAreaRect;
        }
    } else {
        if (res2 < 0) {
            avoidArea.leftRect_ = avoidAreaRect;
        } else {
            avoidArea.bottomRect_ = avoidAreaRect;
        }
    }
}

void SceneSession::GetSystemAvoidArea(WSRect& rect, AvoidArea& avoidArea)
{
    if (GetSessionProperty()->GetWindowFlags() & static_cast<uint32_t>(WindowFlag::WINDOW_FLAG_NEED_AVOID)) {
        return;
    }
    uint64_t displayId = GetSessionProperty()->GetDisplayId();
    auto screenSession = ScreenSessionManagerClient::GetInstance().GetScreenSession(displayId);
    if ((Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING ||
         Session::GetWindowMode() == WindowMode::WINDOW_MODE_SPLIT_PRIMARY ||
         Session::GetWindowMode() == WindowMode::WINDOW_MODE_SPLIT_SECONDARY) &&
        WindowHelper::IsMainWindow(Session::GetWindowType()) &&
        (system::GetParameter("const.product.devicetype", "unknown") == "phone" ||
         system::GetParameter("const.product.devicetype", "unknown") == "tablet") &&
        (!screenSession || screenSession->GetName() != "HiCar")) {
        float miniScale = 0.316f; // Pressed mini floating Scale with 0.001 precision
        if (Session::GetFloatingScale() <= miniScale) {
            return;
        }
        if (Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING &&
            rect.height_ < rect.width_) {
            return;
        }
        float vpr = 3.5f; // 3.5f: default pixel ratio
        auto display = DisplayManager::GetInstance().GetDefaultDisplay();
        if (display == nullptr) {
            WLOGFE("display is null");
            return;
        }
        vpr = display->GetVirtualPixelRatio();
        int32_t floatingBarHeight = 32; // 32: floating windowBar Height
        avoidArea.topRect_.height_ = vpr * floatingBarHeight;
        avoidArea.topRect_.width_ = static_cast<uint32_t>(display->GetWidth());
        return;
    }
    if (isDisplayStatusBarTemporarily_.load()) {
        return;
    }
    std::vector<sptr<SceneSession>> statusBarVector;
    if (specificCallback_ != nullptr && specificCallback_->onGetSceneSessionVectorByType_) {
        statusBarVector = specificCallback_->onGetSceneSessionVectorByType_(
            WindowType::WINDOW_TYPE_STATUS_BAR, GetSessionProperty()->GetDisplayId());
    }
    for (auto& statusBar : statusBarVector) {
        if (!(statusBar->isVisible_)) {
            continue;
        }
        WSRect statusBarRect = statusBar->GetSessionRect();
        CalculateAvoidAreaRect(rect, statusBarRect, avoidArea);
    }

    return;
}

void SceneSession::GetKeyboardAvoidArea(WSRect& rect, AvoidArea& avoidArea)
{
    if (((Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING &&
          WindowHelper::IsMainWindow(Session::GetWindowType())) ||
         (WindowHelper::IsSubWindow(Session::GetWindowType()) && GetParentSession() != nullptr &&
          GetParentSession()->GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING)) &&
        (system::GetParameter("const.product.devicetype", "unknown") == "phone" ||
         system::GetParameter("const.product.devicetype", "unknown") == "tablet")) {
        return;
    }
    if (!GetSessionProperty()) {
        TLOGE(WmsLogTag::WMS_IMMS, "Failed to get session property");
        return;
    }
    std::vector<sptr<SceneSession>> inputMethodVector;
    if (specificCallback_ != nullptr && specificCallback_->onGetSceneSessionVectorByType_) {
        inputMethodVector = specificCallback_->onGetSceneSessionVectorByType_(
            WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT, GetSessionProperty()->GetDisplayId());
    }
    for (auto& inputMethod : inputMethodVector) {
        if (inputMethod->GetSessionState() != SessionState::STATE_FOREGROUND &&
            inputMethod->GetSessionState() != SessionState::STATE_ACTIVE) {
            continue;
        }
        SessionGravity gravity = inputMethod->GetKeyboardGravity();
        if (gravity == SessionGravity::SESSION_GRAVITY_FLOAT) {
            continue;
        }
        if (isKeyboardPanelEnabled_) {
            WSRect keyboardRect = {0, 0, 0, 0};
            if (inputMethod && inputMethod->GetKeyboardPanelSession()) {
                keyboardRect = inputMethod->GetKeyboardPanelSession()->GetSessionRect();
            }
            CalculateAvoidAreaRect(rect, keyboardRect, avoidArea);
        } else {
            WSRect inputMethodRect = inputMethod->GetSessionRect();
            CalculateAvoidAreaRect(rect, inputMethodRect, avoidArea);
        }
    }

    return;
}

void SceneSession::GetCutoutAvoidArea(WSRect& rect, AvoidArea& avoidArea)
{
    auto display = DisplayManager::GetInstance().GetDisplayById(GetSessionProperty()->GetDisplayId());
    if (display == nullptr) {
        TLOGE(WmsLogTag::WMS_IMMS, "Failed to get display");
        return;
    }
    sptr<CutoutInfo> cutoutInfo = display->GetCutoutInfo();
    if (cutoutInfo == nullptr) {
        TLOGI(WmsLogTag::WMS_IMMS, "There is no CutoutInfo");
        return;
    }
    std::vector<DMRect> cutoutAreas = cutoutInfo->GetBoundingRects();
    if (cutoutAreas.empty()) {
        TLOGI(WmsLogTag::WMS_IMMS, "There is no cutoutAreas");
        return;
    }
    for (auto& cutoutArea : cutoutAreas) {
        WSRect cutoutAreaRect = {
            cutoutArea.posX_,
            cutoutArea.posY_,
            cutoutArea.width_,
            cutoutArea.height_
        };
        CalculateAvoidAreaRect(rect, cutoutAreaRect, avoidArea);
    }

    return;
}

void SceneSession::GetAINavigationBarArea(WSRect rect, AvoidArea& avoidArea)
{
    if (isDisplayStatusBarTemporarily_.load()) {
        return;
    }
    if (Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING ||
        Session::GetWindowMode() == WindowMode::WINDOW_MODE_PIP) {
        return;
    }
    if (!GetSessionProperty()) {
        TLOGE(WmsLogTag::WMS_IMMS, "Failed to get session property");
        return;
    }
    WSRect barArea;
    if (specificCallback_ != nullptr && specificCallback_->onGetAINavigationBarArea_) {
        barArea = specificCallback_->onGetAINavigationBarArea_(GetSessionProperty()->GetDisplayId());
    }
    CalculateAvoidAreaRect(rect, barArea, avoidArea);
}

bool SceneSession::CheckGetAvoidAreaAvailable(AvoidAreaType type)
{
    WindowMode mode = GetWindowMode();
    WindowType winType = GetWindowType();

    if (type == AvoidAreaType::TYPE_KEYBOARD) {
        return true;
    }
    if (WindowHelper::IsMainWindow(winType)) {
        if (mode != WindowMode::WINDOW_MODE_FLOATING ||
            system::GetParameter("const.product.devicetype", "unknown") == "phone" ||
            system::GetParameter("const.product.devicetype", "unknown") == "tablet") {
            return true;
        }
    }
    if (WindowHelper::IsSubWindow(winType)) {
        if (GetParentSession() && GetParentSession()->GetSessionRect() == GetSessionRect()) {
            return true;
        }
    }
    TLOGI(WmsLogTag::WMS_IMMS, "Window [%{public}u, %{public}s] type %{public}d "
        "avoidAreaType %{public}u windowMode %{public}u, return default avoid area.",
        GetPersistentId(), GetWindowName().c_str(), static_cast<uint32_t>(winType),
        static_cast<uint32_t>(type), static_cast<uint32_t>(mode));
    return false;
}

AvoidArea SceneSession::GetAvoidAreaByType(AvoidAreaType type)
{
    auto task = [weakThis = wptr(this), type]() -> AvoidArea {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_IMMS, "session is null");
            return {};
        }

        if (!session->CheckGetAvoidAreaAvailable(type)) {
            return {};
        }

        AvoidArea avoidArea;
        WSRect rect = session->GetSessionRect();
        TLOGD(WmsLogTag::WMS_IMMS, "GetAvoidAreaByType avoidAreaType:%{public}u", type);
        switch (type) {
            case AvoidAreaType::TYPE_SYSTEM: {
                session->GetSystemAvoidArea(rect, avoidArea);
                return avoidArea;
            }
            case AvoidAreaType::TYPE_CUTOUT: {
                session->GetCutoutAvoidArea(rect, avoidArea);
                return avoidArea;
            }
            case AvoidAreaType::TYPE_SYSTEM_GESTURE: {
                return avoidArea;
            }
            case AvoidAreaType::TYPE_KEYBOARD: {
                session->GetKeyboardAvoidArea(rect, avoidArea);
                return avoidArea;
            }
            case AvoidAreaType::TYPE_NAVIGATION_INDICATOR: {
                session->GetAINavigationBarArea(rect, avoidArea);
                return avoidArea;
            }
            default: {
                TLOGE(WmsLogTag::WMS_IMMS, "cannot find avoidAreaType:%{public}u, id:%{public}d",
                    type, session->GetPersistentId());
                return avoidArea;
            }
        }
    };
    return PostSyncTask(task, "GetAvoidAreaByType");
}

WSError SceneSession::UpdateAvoidArea(const sptr<AvoidArea>& avoidArea, AvoidAreaType type)
{
    if (!sessionStage_) {
        return WSError::WS_ERROR_NULLPTR;
    }
    return sessionStage_->UpdateAvoidArea(avoidArea, type);
}

WSError SceneSession::SetPipActionEvent(const std::string& action, int32_t status)
{
    TLOGI(WmsLogTag::WMS_PIP, "action: %{public}s, status: %{public}d", action.c_str(), status);
    if (GetWindowType() != WindowType::WINDOW_TYPE_PIP || GetWindowMode() != WindowMode::WINDOW_MODE_PIP) {
        return WSError::WS_ERROR_INVALID_TYPE;
    }
    if (!sessionStage_) {
        return WSError::WS_ERROR_NULLPTR;
    }
    return sessionStage_->SetPipActionEvent(action, status);
}

void SceneSession::HandleStyleEvent(MMI::WindowArea area)
{
    static std::pair<int32_t, MMI::WindowArea> preWindowArea =
        std::make_pair(INVALID_WINDOW_ID, MMI::WindowArea::EXIT);
    if (preWindowArea.first == Session::GetWindowId() && preWindowArea.second == area) {
        return;
    }
    if (area != MMI::WindowArea::EXIT) {
        if (Session::SetPointerStyle(area) != WSError::WS_OK) {
            WLOGFE("Failed to set the cursor style, WSError:%{public}d", Session::SetPointerStyle(area));
        }
    }
    preWindowArea = { Session::GetWindowId(), area };
}

WSError SceneSession::HandleEnterWinwdowArea(int32_t displayX, int32_t displayY)
{
    if (displayX < 0 || displayY < 0) {
        WLOGE("Illegal parameter, displayX:%{public}d, displayY:%{public}d", displayX, displayY);
        return WSError::WS_ERROR_INVALID_PARAM;
    }

    auto windowType = Session::GetWindowType();
    auto iter = Session::windowAreas_.cend();
    if (!IsSystemSession() &&
        Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING &&
        (windowType == WindowType::WINDOW_TYPE_APP_MAIN_WINDOW || WindowHelper::IsSubWindow(windowType))) {
        iter = Session::windowAreas_.cbegin();
        for (;iter != Session::windowAreas_.cend(); ++iter) {
            WSRectF rect = iter->second;
            if (rect.IsInRegion(displayX, displayY)) {
                break;
            }
        }
    }

    MMI::WindowArea area = MMI::WindowArea::EXIT;
    if (iter == Session::windowAreas_.cend()) {
        bool isInRegion = false;
        WSRect rect = Session::winRect_;
        if (Session::GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING &&
            (windowType == WindowType::WINDOW_TYPE_APP_MAIN_WINDOW || WindowHelper::IsSubWindow(windowType))) {
            WSRectF rectF = Session::UpdateHotRect(rect);
            isInRegion = rectF.IsInRegion(displayX, displayY);
        } else {
            isInRegion = rect.IsInRegion(displayX, displayY);
        }
        if (!isInRegion) {
            WLOGFE("The wrong event(%{public}d, %{public}d) could not be matched to the region:"
                "[%{public}d, %{public}d, %{public}d, %{public}d]",
                displayX, displayY, rect.posX_, rect.posY_, rect.width_, rect.height_);
            return WSError::WS_ERROR_INVALID_TYPE;
        }
        area = MMI::WindowArea::FOCUS_ON_INNER;
    } else {
        area = iter->first;
    }
    HandleStyleEvent(area);
    return WSError::WS_OK;
}

WSError SceneSession::HandlePointerStyle(const std::shared_ptr<MMI::PointerEvent>& pointerEvent)
{
    if (pointerEvent == nullptr) {
        WLOGFE("pointerEvent is nullptr");
        return WSError::WS_ERROR_NULLPTR;
    }
    if (pointerEvent->GetSourceType() != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        return WSError::WS_DO_NOTHING;
    }
    if (!(pointerEvent->GetPointerAction() == MMI::PointerEvent::POINTER_ACTION_MOVE &&
         pointerEvent->GetButtonId() == MMI::PointerEvent::BUTTON_NONE)) {
        return WSError::WS_DO_NOTHING;
    }

    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        WLOGFE("Get pointeritem failed");
        pointerEvent->MarkProcessed();
        return WSError::WS_ERROR_INVALID_PARAM;
    }
    int32_t mousePointX = pointerItem.GetDisplayX();
    int32_t mousePointY = pointerItem.GetDisplayY();

    auto displayInfo = DisplayManager::GetInstance().GetDisplayById(pointerEvent->GetTargetDisplayId());
    if (displayInfo != nullptr) {
        float vpr = displayInfo->GetVirtualPixelRatio();
        if (vpr <= 0) {
            vpr = 1.5f;
        }
        Session::SetVpr(vpr);
    }
    return HandleEnterWinwdowArea(mousePointX, mousePointY);
}

WSError SceneSession::ProcessPointDownSession(int32_t posX, int32_t posY)
{
    const auto& id = GetPersistentId();
    WLOGFI("id: %{public}d, type: %{public}d, pos: [%{public}d, %{public}d]", id, GetWindowType(), posX, posY);

    // notify touch outside
    if (specificCallback_ != nullptr && specificCallback_->onSessionTouchOutside_ &&
        sessionInfo_.bundleName_.find("SCBGestureBack") == std::string::npos) {
        specificCallback_->onSessionTouchOutside_(id);
    }

    // notify outside down event
    if (specificCallback_ != nullptr && specificCallback_->onOutsideDownEvent_) {
        specificCallback_->onOutsideDownEvent_(posX, posY);
    }
    return WSError::WS_OK;
}

WSError SceneSession::SendPointEventForMoveDrag(const std::shared_ptr<MMI::PointerEvent>& pointerEvent)
{
    NotifyOutsideDownEvent(pointerEvent);
    TransferPointerEvent(pointerEvent, false);
    return WSError::WS_OK;
}

void SceneSession::NotifyOutsideDownEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent)
{
    // notify touchOutside and touchDown event
    int32_t action = pointerEvent->GetPointerAction();
    if (action != MMI::PointerEvent::POINTER_ACTION_DOWN &&
        action != MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        return;
    }

    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        return;
    }

    // notify outside down event
    if (specificCallback_ != nullptr && specificCallback_->onOutsideDownEvent_) {
        specificCallback_->onOutsideDownEvent_(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    }
}

WSError SceneSession::TransferPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent,
    bool needNotifyClient)
{
    WLOGFD("[WMSCom] TransferPointEvent, id: %{public}d, type: %{public}d, needNotifyClient: %{public}d",
        GetPersistentId(), GetWindowType(), needNotifyClient);
    if (pointerEvent == nullptr) {
        WLOGFE("pointerEvent is null");
        return WSError::WS_ERROR_NULLPTR;
    }

    int32_t action = pointerEvent->GetPointerAction();
    {
        bool isSystemWindow = GetSessionInfo().isSystem_;
        if (action == MMI::PointerEvent::POINTER_ACTION_ENTER_WINDOW) {
            std::lock_guard<std::mutex> guard(enterSessionMutex_);
            WLOGFD("Set enter session, persistentId:%{public}d", GetPersistentId());
            enterSession_ = wptr<SceneSession>(this);
        }
        if ((enterSession_ != nullptr) &&
            (isSystemWindow && (action != MMI::PointerEvent::POINTER_ACTION_ENTER_WINDOW))) {
            std::lock_guard<std::mutex> guard(enterSessionMutex_);
            WLOGFD("Remove enter session, persistentId:%{public}d", GetPersistentId());
            enterSession_ = nullptr;
        }
    }

    if (!CheckPointerEventDispatch(pointerEvent)) {
        WLOGFI("Do not dispatch this pointer event");
        return WSError::WS_DO_NOTHING;
    }
    bool isPointDown = (action == MMI::PointerEvent::POINTER_ACTION_DOWN ||
        action == MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    if (specificCallback_ != nullptr && specificCallback_->onSessionTouchOutside_ != nullptr && isPointDown) {
        specificCallback_->onSessionTouchOutside_(GetPersistentId());
    }

    auto property = GetSessionProperty();
    if (property == nullptr) {
        return Session::TransferPointerEvent(pointerEvent, needNotifyClient);
    }

    auto windowType = property->GetWindowType();
    bool isMovableWindowType = IsMovableWindowType();
    bool isMainWindow = WindowHelper::IsMainWindow(windowType);
    bool isSubWindow = WindowHelper::IsSubWindow(windowType);
    bool isDialog = WindowHelper::IsDialogWindow(windowType);
    bool isMaxModeAvoidSysBar = property->GetMaximizeMode() == MaximizeMode::MODE_AVOID_SYSTEM_BAR;
    if (isMovableWindowType && (isMainWindow || isSubWindow || isDialog) &&
        !isMaxModeAvoidSysBar) {
        if (CheckDialogOnForeground() && isPointDown) {
            HandlePointDownDialog();
            pointerEvent->MarkProcessed();
            TLOGI(WmsLogTag::WMS_DIALOG, "There is dialog window foreground");
            return WSError::WS_OK;
        }
        if (!moveDragController_) {
            WLOGE("moveDragController_ is null");
            return Session::TransferPointerEvent(pointerEvent, needNotifyClient);
        }
        if (property->GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING && property->GetDragEnabled()) {
            auto is2in1 = system::GetParameter("const.product.devicetype", "unknown") == "2in1";
            bool freeMultiWindowSupportDevices = systemConfig_.freeMultiWindowSupport_ &&
                systemConfig_.freeMultiWindowEnable_;
            if ((is2in1 || freeMultiWindowSupportDevices) &&
                moveDragController_->ConsumeDragEvent(pointerEvent, winRect_, property, systemConfig_)) {
                moveDragController_->UpdateGravityWhenDrag(pointerEvent, surfaceNode_);
                PresentFoucusIfNeed(pointerEvent->GetPointerAction());
                pointerEvent->MarkProcessed();
                return WSError::WS_OK;
            }
        }
        if (IsDecorEnable() && moveDragController_->ConsumeMoveEvent(pointerEvent, winRect_)) {
            PresentFoucusIfNeed(pointerEvent->GetPointerAction());
            pointerEvent->MarkProcessed();
            return WSError::WS_OK;
        }
    }

    bool raiseEnabled = property->GetWindowType() == WindowType::WINDOW_TYPE_DIALOG && property->GetRaiseEnabled() &&
        (action == MMI::PointerEvent::POINTER_ACTION_DOWN || action == MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    if (raiseEnabled) {
        RaiseToAppTopForPointDown();
    }
    return Session::TransferPointerEvent(pointerEvent, needNotifyClient);
}

bool SceneSession::IsMovableWindowType()
{
    auto property = GetSessionProperty();
    if (property == nullptr) {
        return false;
    }

    bool existFloating = WindowHelper::IsWindowModeSupported(property->GetModeSupportInfo(),
        WindowMode::WINDOW_MODE_FLOATING);

    return property->GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING ||
        property->GetWindowMode() == WindowMode::WINDOW_MODE_SPLIT_PRIMARY ||
        property->GetWindowMode() == WindowMode::WINDOW_MODE_SPLIT_SECONDARY ||
        (property->GetWindowMode() == WindowMode::WINDOW_MODE_FULLSCREEN && existFloating);
}

WSError SceneSession::RequestSessionBack(bool needMoveToBackground)
{
    auto task = [weakThis = wptr(this), needMoveToBackground]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (!session->backPressedFunc_) {
            WLOGFW("Session didn't register back event consumer!");
            return WSError::WS_DO_NOTHING;
        }
        if (g_enableForceUIFirst) {
            auto rsTransaction = RSTransactionProxy::GetInstance();
            if (rsTransaction) {
                rsTransaction->Begin();
            }
            auto leashWinSurfaceNode = session->GetLeashWinSurfaceNode();
            if (leashWinSurfaceNode) {
                leashWinSurfaceNode->SetForceUIFirst(true);
                WLOGFI("leashWinSurfaceNode_ SetForceUIFirst id:%{public}u!", session->GetPersistentId());
            } else {
                WLOGFI("failed, leashWinSurfaceNode_ null id:%{public}u", session->GetPersistentId());
            }
            if (rsTransaction) {
                rsTransaction->Commit();
            }
        }
        session->backPressedFunc_(needMoveToBackground);
        return WSError::WS_OK;
    };
    PostTask(task, "RequestSessionBack:" + std::to_string(needMoveToBackground));
    return WSError::WS_OK;
}

const wptr<SceneSession> SceneSession::GetEnterWindow()
{
    std::lock_guard<std::mutex> guard(enterSessionMutex_);
    return enterSession_;
}

void SceneSession::ClearEnterWindow()
{
    std::lock_guard<std::mutex> guard(enterSessionMutex_);
    enterSession_ = nullptr;
}

void SceneSession::NotifySessionRectChange(const WSRect& rect, const SizeChangeReason& reason)
{
    auto task = [weakThis = wptr(this), rect, reason]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return;
        }
        if (session->sessionRectChangeFunc_) {
            HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER, "SceneSession::NotifySessionRectChange");
            session->sessionRectChangeFunc_(rect, reason);
        }
    };
    PostTask(task, "NotifySessionRectChange" + GetRectInfo(rect));
}

bool SceneSession::IsDecorEnable() const
{
    auto property = GetSessionProperty();
    if (property == nullptr) {
        WLOGE("property is nullptr");
        return false;
    }
    if (property->GetWindowMode() == WindowMode::WINDOW_MODE_FLOATING
        && system::GetParameter("const.product.devicetype", "unknown") == "phone") {
        /* FloatingWindow skip for Phone */
        return false;
    }
    auto windowType = property->GetWindowType();
    bool isMainWindow = WindowHelper::IsMainWindow(windowType);
    bool isSubWindow = WindowHelper::IsSubWindow(windowType);
    bool isDialogWindow = WindowHelper::IsDialogWindow(windowType);
    bool isValidWindow = isMainWindow ||
        ((isSubWindow || isDialogWindow) && property->IsDecorEnable());
    bool isWindowModeSupported = WindowHelper::IsWindowModeSupported(
        systemConfig_.decorModeSupportInfo_, property->GetWindowMode());
    bool enable = isValidWindow && systemConfig_.isSystemDecorEnable_ && isWindowModeSupported;
    return enable;
}

std::string SceneSession::GetRatioPreferenceKey()
{
    std::string key = sessionInfo_.bundleName_ + sessionInfo_.moduleName_ + sessionInfo_.abilityName_;
    if (key.length() > ScenePersistentStorage::MAX_KEY_LEN) {
        return key.substr(key.length() - ScenePersistentStorage::MAX_KEY_LEN);
    }
    return key;
}

bool SceneSession::SaveAspectRatio(float ratio)
{
    std::string key = GetRatioPreferenceKey();
    if (!key.empty()) {
        ScenePersistentStorage::Insert(key, ratio, ScenePersistentStorageType::ASPECT_RATIO);
        WLOGD("SceneSession save aspectRatio , key %{public}s, value: %{public}f", key.c_str(), aspectRatio_);
        return true;
    }
    return false;
}

void SceneSession::FixRectByLimits(WindowLimits limits, WSRect& rect, float ratio, bool isDecor, float vpr)
{
    if (isDecor) {
        rect.width_ = SessionUtils::ToLayoutWidth(rect.width_, vpr);
        rect.height_ = SessionUtils::ToLayoutHeight(rect.height_, vpr);
        limits.minWidth_ = SessionUtils::ToLayoutWidth(limits.minWidth_, vpr);
        limits.maxWidth_ = SessionUtils::ToLayoutWidth(limits.maxWidth_, vpr);
        limits.minHeight_ = SessionUtils::ToLayoutHeight(limits.minHeight_, vpr);
        limits.maxHeight_ = SessionUtils::ToLayoutHeight(limits.maxHeight_, vpr);
    }
    if (static_cast<uint32_t>(rect.height_) > limits.maxHeight_) {
        rect.height_ = static_cast<int32_t>(limits.maxHeight_);
        rect.width_ = floor(rect.height_ * ratio);
    } else if (static_cast<uint32_t>(rect.width_) > limits.maxWidth_) {
        rect.width_ = static_cast<int32_t>(limits.maxWidth_);
        rect.height_ = floor(rect.width_ / ratio);
    } else if (static_cast<uint32_t>(rect.width_) < limits.minWidth_) {
        rect.width_ = static_cast<int32_t>(limits.minWidth_);
        rect.height_ = ceil(rect.width_ / ratio);
    } else if (static_cast<uint32_t>(rect.height_) < limits.minHeight_) {
        rect.height_ = static_cast<int32_t>(limits.minHeight_);
        rect.width_ = ceil(rect.height_ * ratio);
    }
    if (isDecor) {
        rect.height_ = SessionUtils::ToWinHeight(rect.height_, vpr) ;
        rect.width_ = SessionUtils::ToWinWidth(rect.width_, vpr);
    }
}
bool SceneSession::FixRectByAspectRatio(WSRect& rect)
{
    const int tolerancePx = 2; // 2: tolerance delta pixel value, unit: px
    WSRect originalRect = rect;
    auto property = GetSessionProperty();
    if (!property || property->GetWindowMode() != WindowMode::WINDOW_MODE_FLOATING ||
        !WindowHelper::IsMainWindow(GetWindowType())) {
        return false;
    }

    if (MathHelper::NearZero(aspectRatio_)) {
        return false;
    }
    float vpr = 1.5f; // 1.5f: default virtual pixel ratio
    auto display = DisplayManager::GetInstance().GetDefaultDisplay();
    if (display) {
        vpr = display->GetVirtualPixelRatio();
    }
    int32_t minW;
    int32_t maxW;
    int32_t minH;
    int32_t maxH;
    SessionUtils::CalcFloatWindowRectLimits(property->GetWindowLimits(), systemConfig_.maxFloatingWindowSize_, vpr,
        minW, maxW, minH, maxH);
    rect.width_ = std::max(minW, static_cast<int32_t>(rect.width_));
    rect.width_ = std::min(maxW, static_cast<int32_t>(rect.width_));
    rect.height_ = std::max(minH, static_cast<int32_t>(rect.height_));
    rect.height_ = std::min(maxH, static_cast<int32_t>(rect.height_));
    if (IsDecorEnable()) {
        if (SessionUtils::ToLayoutWidth(rect.width_, vpr) >
                SessionUtils::ToLayoutHeight(rect.height_, vpr) * aspectRatio_) {
            rect.width_ = SessionUtils::ToWinWidth(SessionUtils::ToLayoutHeight(rect.height_, vpr)* aspectRatio_, vpr);
        } else {
            rect.height_ = SessionUtils::ToWinHeight(SessionUtils::ToLayoutWidth(rect.width_, vpr) / aspectRatio_, vpr);
        }
    } else {
        if (rect.width_ > rect.height_ * aspectRatio_) {
            rect.width_ = rect.height_ * aspectRatio_;
        } else {
            rect.height_ = rect.width_ / aspectRatio_;
        }
    }
    FixRectByLimits(property->GetWindowLimits(), rect, aspectRatio_, IsDecorEnable(), vpr);
    if (std::abs(static_cast<int32_t>(originalRect.width_) - static_cast<int32_t>(rect.width_)) <= tolerancePx &&
        std::abs(static_cast<int32_t>(originalRect.height_) - static_cast<int32_t>(rect.height_)) <= tolerancePx) {
        rect = originalRect;
        return false;
    }
    return true;
}

void SceneSession::SetMoveDragCallback()
{
    if (moveDragController_) {
        MoveDragCallback callBack = [this](const SizeChangeReason& reason) {
            this->OnMoveDragCallback(reason);
        };
        moveDragController_->RegisterMoveDragCallback(callBack);
    }
}

void SceneSession::OnMoveDragCallback(const SizeChangeReason& reason)
{
    WSRect rect = moveDragController_->GetTargetRect();
    WLOGFD("OnMoveDragCallback rect: [%{public}d, %{public}d, %{public}u, %{public}u], reason : %{public}d",
        rect.posX_, rect.posY_, rect.width_, rect.height_, reason);
    if (reason == SizeChangeReason::DRAG || reason == SizeChangeReason::DRAG_END) {
        UpdateWinRectForSystemBar(rect);
    }
    HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER,
        "SceneSession::OnMoveDragCallback [%d, %d, %u, %u]", rect.posX_, rect.posY_, rect.width_, rect.height_);
    SetSurfaceBounds(rect);
    UpdateSizeChangeReason(reason);
    if (reason != SizeChangeReason::MOVE) {
        UpdateRect(rect, reason);
    }
    if (reason == SizeChangeReason::DRAG_END) {
        if (!SessionHelper::IsEmptyRect(GetRestoringRectForKeyboard())) {
            TLOGI(WmsLogTag::WMS_KEYBOARD, "Calling session is moved and reset restoringRectForKeyboard_");
            WSRect restoringRect = {0, 0, 0, 0};
            SetRestoringRectForKeyboard(restoringRect);
        }
        NotifySessionRectChange(rect, reason);
        OnSessionEvent(SessionEvent::EVENT_END_MOVE);
    }
    if (reason == SizeChangeReason::DRAG_START) {
        OnSessionEvent(SessionEvent::EVENT_DRAG_START);
    }
}

void SceneSession::UpdateWinRectForSystemBar(WSRect& rect)
{
    if (!specificCallback_) {
        WLOGFE("specificCallback_ is null!");
        return;
    }
    if (!GetSessionProperty()) {
        WLOGFE("get session property is null!");
        return;
    }
    float tmpPosY = 0.0;
    std::vector<sptr<SceneSession>> statusBarVector;
    if (specificCallback_->onGetSceneSessionVectorByType_) {
        statusBarVector = specificCallback_->onGetSceneSessionVectorByType_(
            WindowType::WINDOW_TYPE_STATUS_BAR, GetSessionProperty()->GetDisplayId());
    }
    for (auto& statusBar : statusBarVector) {
        if (!(statusBar->isVisible_)) {
            continue;
        }
        WSRect statusBarRect = statusBar->GetSessionRect();
        if ((rect.posY_ < statusBarRect.posY_ + static_cast<int32_t>(statusBarRect.height_)) &&
            (rect.height_ != winRect_.height_ || rect.width_ != winRect_.width_)) {
            tmpPosY = rect.posY_ + rect.height_;
            rect.posY_ = statusBarRect.posY_ + statusBarRect.height_;
            rect.height_ = tmpPosY - rect.posY_;
        }
    }
    WLOGFD("after UpdateWinRectForSystemBar rect: [%{public}d, %{public}d, %{public}u, %{public}u]",
        rect.posX_, rect.posY_, rect.width_, rect.height_);
}

void SceneSession::SetSurfaceBounds(const WSRect& rect)
{
    auto rsTransaction = RSTransactionProxy::GetInstance();
    if (rsTransaction) {
        rsTransaction->Begin();
    }
    auto leashWinSurfaceNode = GetLeashWinSurfaceNode();
    if (surfaceNode_ && leashWinSurfaceNode) {
        leashWinSurfaceNode->SetBounds(rect.posX_, rect.posY_, rect.width_, rect.height_);
        leashWinSurfaceNode->SetFrame(rect.posX_, rect.posY_, rect.width_, rect.height_);
        surfaceNode_->SetBounds(0, 0, rect.width_, rect.height_);
        surfaceNode_->SetFrame(0, 0, rect.width_, rect.height_);
    } else if (WindowHelper::IsPipWindow(GetWindowType()) && surfaceNode_) {
        TLOGD(WmsLogTag::WMS_PIP, "PipWindow setSurfaceBounds");
        surfaceNode_->SetBounds(rect.posX_, rect.posY_, rect.width_, rect.height_);
        surfaceNode_->SetFrame(rect.posX_, rect.posY_, rect.width_, rect.height_);
    } else if (WindowHelper::IsSubWindow(GetWindowType()) && surfaceNode_) {
        WLOGFD("subwindow setSurfaceBounds");
        surfaceNode_->SetBounds(rect.posX_, rect.posY_, rect.width_, rect.height_);
        surfaceNode_->SetFrame(rect.posX_, rect.posY_, rect.width_, rect.height_);
    } else if (WindowHelper::IsDialogWindow(GetWindowType()) && surfaceNode_) {
        TLOGD(WmsLogTag::WMS_DIALOG, "dialogWindow setSurfaceBounds");
        surfaceNode_->SetBounds(rect.posX_, rect.posY_, rect.width_, rect.height_);
        surfaceNode_->SetFrame(rect.posX_, rect.posY_, rect.width_, rect.height_);
    } else {
        WLOGE("SetSurfaceBounds surfaceNode is null!");
    }
    if (rsTransaction) {
        RSTransaction::FlushImplicitTransaction();
        rsTransaction->Commit();
    }
}

void SceneSession::SetZOrder(uint32_t zOrder)
{
    auto task = [weakThis = wptr(this), zOrder]() {
        auto session = weakThis.promote();
        if (session == nullptr) {
            WLOGFE("session is null");
            return;
        }
        if (session->zOrder_ != zOrder) {
            session->Session::SetZOrder(zOrder);
            if (session->specificCallback_ != nullptr) {
                session->specificCallback_->onWindowInfoUpdate_(session->GetPersistentId(),
                    WindowUpdateType::WINDOW_UPDATE_PROPERTY);
            }
        }
    };
    PostTask(task, "SetZOrder");
}

void SceneSession::SetFloatingScale(float floatingScale)
{
    if (floatingScale_ != floatingScale) {
        Session::SetFloatingScale(floatingScale);
        if (specificCallback_ != nullptr) {
            specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_PROPERTY);
            specificCallback_->onUpdateAvoidArea_(GetPersistentId());
        }
    }
}

void SceneSession::SetParentPersistentId(int32_t parentId)
{
    auto property = GetSessionProperty();
    if (property) {
        property->SetParentPersistentId(parentId);
    }
}

int32_t SceneSession::GetParentPersistentId() const
{
    auto property = GetSessionProperty();
    if (property) {
        return property->GetParentPersistentId();
    }
    return INVALID_SESSION_ID;
}

std::string SceneSession::GetWindowNameAllType() const
{
    if (GetSessionInfo().isSystem_) {
        return GetSessionInfo().abilityName_;
    } else {
        return GetWindowName();
    }
}

WSError SceneSession::SetTurnScreenOn(bool turnScreenOn)
{
    GetSessionProperty()->SetTurnScreenOn(turnScreenOn);
    return WSError::WS_OK;
}

bool SceneSession::IsTurnScreenOn() const
{
    return GetSessionProperty()->IsTurnScreenOn();
}

WSError SceneSession::SetKeepScreenOn(bool keepScreenOn)
{
    GetSessionProperty()->SetKeepScreenOn(keepScreenOn);
    return WSError::WS_OK;
}

bool SceneSession::IsKeepScreenOn() const
{
    return GetSessionProperty()->IsKeepScreenOn();
}

std::string SceneSession::GetSessionSnapshotFilePath() const
{
    WLOGFI("GetSessionSnapshotFilePath id %{public}d", GetPersistentId());
    if (Session::GetSessionState() < SessionState::STATE_BACKGROUND) {
        WLOGFI("GetSessionSnapshotFilePath UpdateSnapshot");
        auto snapshot = Snapshot();
        if (scenePersistence_ != nullptr) {
            scenePersistence_->SaveSnapshot(snapshot);
        }
    }
    if (scenePersistence_ != nullptr) {
        return scenePersistence_->GetSnapshotFilePath();
    }
    return "";
}

void SceneSession::SaveUpdatedIcon(const std::shared_ptr<Media::PixelMap> &icon)
{
    WLOGFI("run SaveUpdatedIcon");
    if (scenePersistence_ != nullptr) {
        scenePersistence_->SaveUpdatedIcon(icon);
    }
}

std::string SceneSession::GetUpdatedIconPath() const
{
    WLOGFI("run GetUpdatedIconPath");
    if (scenePersistence_ != nullptr) {
        return scenePersistence_->GetUpdatedIconPath();
    }
    return "";
}

void SceneSession::UpdateNativeVisibility(bool visible)
{
    WLOGFI("[WMSSCB] name: %{public}s, id: %{public}u, visible: %{public}u",
        sessionInfo_.bundleName_.c_str(), GetPersistentId(), visible);
    isVisible_ = visible;
    if (specificCallback_ == nullptr) {
        WLOGFW("specific callback is null.");
        return;
    }

    if (visible) {
        specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_ADDED);
    } else {
        specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_REMOVED);
    }
    NotifyAccessibilityVisibilityChange();
    specificCallback_->onUpdateAvoidArea_(GetPersistentId());
    // update private state
    if (!GetSessionProperty()) {
        WLOGFE("UpdateNativeVisibility property is null");
        return;
    }
}

bool SceneSession::IsVisible() const
{
    return isVisible_;
}

void SceneSession::UpdateRotationAvoidArea()
{
    if (specificCallback_) {
        specificCallback_->onUpdateAvoidArea_(GetPersistentId());
    }
}

void SceneSession::SetPrivacyMode(bool isPrivacy)
{
    auto property = GetSessionProperty();
    if (!property) {
        WLOGFE("SetPrivacyMode property is null");
        return;
    }
    if (!surfaceNode_) {
        WLOGFE("surfaceNode_ is null");
        return;
    }
    bool lastPrivacyMode = property->GetPrivacyMode() || property->GetSystemPrivacyMode();
    if (lastPrivacyMode == isPrivacy) {
        WLOGFW("privacy mode is not change, do nothing, isPrivacy:%{public}d", isPrivacy);
        return;
    }
    property->SetPrivacyMode(isPrivacy);
    property->SetSystemPrivacyMode(isPrivacy);
    surfaceNode_->SetSecurityLayer(isPrivacy);
    auto leashWinSurfaceNode = GetLeashWinSurfaceNode();
    if (leashWinSurfaceNode != nullptr) {
        leashWinSurfaceNode->SetSecurityLayer(isPrivacy);
    }
    RSTransaction::FlushImplicitTransaction();
}

void SceneSession::SetPiPTemplateInfo(const PiPTemplateInfo& pipTemplateInfo)
{
    pipTemplateInfo_ = pipTemplateInfo;
}

void SceneSession::SetSystemSceneOcclusionAlpha(double alpha)
{
    if (alpha < 0 || alpha > 1.0) {
        WLOGFE("OnSetSystemSceneOcclusionAlpha property is null");
        return;
    }
    if (!surfaceNode_) {
        WLOGFE("surfaceNode_ is null");
        return;
    }
    uint8_t alpha8bit = static_cast<uint8_t>(alpha * 255);
    WLOGFI("surfaceNode SetAbilityBGAlpha=%{public}u.", alpha8bit);
    surfaceNode_->SetAbilityBGAlpha(alpha8bit);
    auto leashWinSurfaceNode = GetLeashWinSurfaceNode();
    if (leashWinSurfaceNode != nullptr) {
        leashWinSurfaceNode->SetAbilityBGAlpha(alpha8bit);
    }
    RSTransaction::FlushImplicitTransaction();
}

WSError SceneSession::UpdateWindowAnimationFlag(bool needDefaultAnimationFlag)
{
    auto task = [weakThis = wptr(this), needDefaultAnimationFlag]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        session->needDefaultAnimationFlag_ = needDefaultAnimationFlag;
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->onWindowAnimationFlagChange_) {
            session->sessionChangeCallback_->onWindowAnimationFlagChange_(needDefaultAnimationFlag);
        }
        return WSError::WS_OK;
    };
    return PostSyncTask(task, "UpdateWindowAnimationFlag");
}

void SceneSession::SetWindowAnimationFlag(bool needDefaultAnimationFlag)
{
    needDefaultAnimationFlag_ = needDefaultAnimationFlag;
    if (sessionChangeCallback_ && sessionChangeCallback_->onWindowAnimationFlagChange_) {
        sessionChangeCallback_->onWindowAnimationFlagChange_(needDefaultAnimationFlag);
    }
    return;
}

bool SceneSession::IsNeedDefaultAnimation() const
{
    return needDefaultAnimationFlag_;
}

bool SceneSession::IsAppSession() const
{
    if (GetWindowType() == WindowType::WINDOW_TYPE_APP_MAIN_WINDOW) {
        return true;
    }
    if (GetParentSession() && GetParentSession()->GetWindowType() == WindowType::WINDOW_TYPE_APP_MAIN_WINDOW) {
        return true;
    }
    return false;
}

void SceneSession::NotifyIsCustomAnimationPlaying(bool isPlaying)
{
    WLOGFI("id %{public}d %{public}u", GetPersistentId(), isPlaying);
    if (sessionChangeCallback_ != nullptr && sessionChangeCallback_->onIsCustomAnimationPlaying_) {
        sessionChangeCallback_->onIsCustomAnimationPlaying_(isPlaying);
    }
}

WSError SceneSession::UpdateWindowSceneAfterCustomAnimation(bool isAdd)
{
    if (!SessionPermission::IsSystemCalling()) {
        TLOGE(WmsLogTag::WMS_SYSTEM, "failed to update with id:%{public}u!", GetPersistentId());
        return WSError::WS_ERROR_NOT_SYSTEM_APP;
    }
    auto task = [weakThis = wptr(this), isAdd]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        WLOGFI("UpdateWindowSceneAfterCustomAnimation, id %{public}d, isAdd: %{public}d",
            session->GetPersistentId(), isAdd);
        if (isAdd) {
            WLOGFE("SetOpacityFunc not register %{public}d", session->GetPersistentId());
            return WSError::WS_ERROR_INVALID_OPERATION;
        } else {
            WLOGFI("background after custom animation id %{public}d", session->GetPersistentId());
            // since background will remove surfaceNode
            session->Background();
            session->NotifyIsCustomAnimationPlaying(false);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "UpdateWindowSceneAfterCustomAnimation:" + std::to_string(isAdd));
    return WSError::WS_OK;
}

bool SceneSession::IsFloatingWindowAppType() const
{
    auto property = GetSessionProperty();
    if (property == nullptr) {
        return false;
    }
    return property->IsFloatingWindowAppType();
}

std::vector<Rect> SceneSession::GetTouchHotAreas() const
{
    std::vector<Rect> touchHotAreas;
    auto property = GetSessionProperty();
    if (property) {
        property->GetTouchHotAreas(touchHotAreas);
    }
    return touchHotAreas;
}

PiPTemplateInfo SceneSession::GetPiPTemplateInfo() const
{
    return pipTemplateInfo_;
}

void SceneSession::DumpSessionElementInfo(const std::vector<std::string>& params)
{
    if (!sessionStage_) {
        return;
    }
    return sessionStage_->DumpSessionElementInfo(params);
}

void SceneSession::NotifyTouchOutside()
{
    WLOGFI("id: %{public}d, type: %{public}d", GetPersistentId(), GetWindowType());
    if (sessionStage_) {
        WLOGFD("Notify sessionStage TouchOutside");
        sessionStage_->NotifyTouchOutside();
    }
    if (sessionChangeCallback_ && sessionChangeCallback_->OnTouchOutside_) {
        WLOGFD("Notify sessionChangeCallback TouchOutside");
        sessionChangeCallback_->OnTouchOutside_();
    }
}

void SceneSession::NotifyWindowVisibility()
{
    if (sessionStage_) {
        sessionStage_->NotifyWindowVisibility(GetVisible());
    } else {
        WLOGFE("Notify window(id:%{public}d) visibility failed, for this session stage is nullptr", GetPersistentId());
    }
}

bool SceneSession::CheckOutTouchOutsideRegister()
{
    if (sessionChangeCallback_ && sessionChangeCallback_->OnTouchOutside_) {
        return true;
    }
    return false;
}

void SceneSession::SetRequestedOrientation(Orientation orientation)
{
    WLOGFI("id: %{public}d orientation: %{public}u", GetPersistentId(), static_cast<uint32_t>(orientation));
    GetSessionProperty()->SetRequestedOrientation(orientation);
    if (sessionChangeCallback_ && sessionChangeCallback_->OnRequestedOrientationChange_) {
        sessionChangeCallback_->OnRequestedOrientationChange_(static_cast<uint32_t>(orientation));
    }
}

void SceneSession::NotifyForceHideChange(bool hide)
{
    WLOGFI("id: %{public}d forceHide: %{public}u", persistentId_, hide);
    auto property = GetSessionProperty();
    if (property == nullptr) {
        WLOGFD("id: %{public}d property is nullptr", persistentId_);
        return;
    }
    property->SetForceHide(hide);
    if (sessionChangeCallback_ && sessionChangeCallback_->OnForceHideChange_) {
        sessionChangeCallback_->OnForceHideChange_(hide);
    }
    SetForceTouchable(!hide);
    SetForceHideState(hide);
}

Orientation SceneSession::GetRequestedOrientation() const
{
    return GetSessionProperty()->GetRequestedOrientation();
}

int32_t SceneSession::GetCollaboratorType() const
{
    return collaboratorType_;
}

void SceneSession::SetCollaboratorType(int32_t collaboratorType)
{
    collaboratorType_ = collaboratorType;
    sessionInfo_.collaboratorType_ = collaboratorType;
}

std::string SceneSession::GetClientIdentityToken() const
{
    return clientIdentityToken_;
}

void SceneSession::SetClientIdentityToken(const std::string& clientIdentityToken)
{
    clientIdentityToken_ = clientIdentityToken;
}

void SceneSession::DumpSessionInfo(std::vector<std::string> &info) const
{
    std::string dumpInfo = "      Session ID #" + std::to_string(persistentId_);
    info.push_back(dumpInfo);
    dumpInfo = "        session name [" + SessionUtils::ConvertSessionName(sessionInfo_.bundleName_,
        sessionInfo_.abilityName_, sessionInfo_.moduleName_, sessionInfo_.appIndex_) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        runningState [" + std::string(isActive_ ? "FOREGROUND" : "BACKGROUND") + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        lockedState [" + std::to_string(sessionInfo_.lockedState) + "]";
    info.push_back(dumpInfo);
    auto abilityInfo = sessionInfo_.abilityInfo;
    dumpInfo = "        continuable [" + (abilityInfo ? std::to_string(abilityInfo->continuable) : " ") + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        timeStamp [" + sessionInfo_.time + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        label [" + (abilityInfo ? abilityInfo->label : " ") + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        iconPath [" + (abilityInfo ? abilityInfo->iconPath : " ") + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        want [" + (sessionInfo_.want ? sessionInfo_.want->ToUri() : " ") + "]";
    info.push_back(dumpInfo);
}

std::shared_ptr<AppExecFwk::AbilityInfo> SceneSession::GetAbilityInfo() const
{
    const SessionInfo& sessionInfo = GetSessionInfo();
    return sessionInfo.abilityInfo;
}

void SceneSession::SetAbilitySessionInfo(std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo)
{
    SetSessionInfoAbilityInfo(abilityInfo);
}

void SceneSession::SetSelfToken(sptr<IRemoteObject> selfToken)
{
    std::unique_lock<std::shared_mutex> lock(selfTokenMutex_);
    selfToken_ = selfToken;
}

sptr<IRemoteObject> SceneSession::GetSelfToken() const
{
    std::shared_lock<std::shared_mutex> lock(selfTokenMutex_);
    return selfToken_;
}

void SceneSession::SetSessionState(SessionState state)
{
    Session::SetSessionState(state);
    NotifyAccessibilityVisibilityChange();
}

void SceneSession::UpdateSessionState(SessionState state)
{
    Session::UpdateSessionState(state);
    NotifyAccessibilityVisibilityChange();
}

bool SceneSession::IsVisibleForAccessibility() const
{
    return GetSystemTouchable() && GetForegroundInteractiveStatus() &&
        (IsVisible() || state_ == SessionState::STATE_ACTIVE || state_ == SessionState::STATE_FOREGROUND);
}

void SceneSession::SetForegroundInteractiveStatus(bool interactive)
{
    Session::SetForegroundInteractiveStatus(interactive);
    NotifyAccessibilityVisibilityChange();
}

void SceneSession::NotifyAccessibilityVisibilityChange()
{
    bool isVisibleForAccessibilityNew = IsVisibleForAccessibility();
    if (isVisibleForAccessibilityNew == isVisibleForAccessibility_.load()) {
        return;
    }
    WLOGFD("[WMSAccess] NotifyAccessibilityVisibilityChange id: %{public}d, visible: %{public}d",
        GetPersistentId(), isVisibleForAccessibilityNew);
    isVisibleForAccessibility_.store(isVisibleForAccessibilityNew);
    if (specificCallback_ && specificCallback_->onWindowInfoUpdate_) {
        if (isVisibleForAccessibilityNew) {
            specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_ADDED);
        } else {
            specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_REMOVED);
        }
    } else {
        WLOGFD("specificCallback_->onWindowInfoUpdate_ not exist, persistent id: %{public}d", GetPersistentId());
    }
}

void SceneSession::SetSystemTouchable(bool touchable)
{
    Session::SetSystemTouchable(touchable);
    NotifyAccessibilityVisibilityChange();
    if (isKeyboardPanelEnabled_ && GetWindowType() == WindowType::WINDOW_TYPE_INPUT_METHOD_FLOAT) {
        const auto& keyboardPanel = GetKeyboardPanelSession();
        if (keyboardPanel != nullptr) {
            keyboardPanel->SetSystemTouchable(touchable);
        }
    }
}

WSError SceneSession::ChangeSessionVisibilityWithStatusBar(
    const sptr<AAFwk::SessionInfo> abilitySessionInfo, bool visible)
{
    if (!SessionPermission::VerifySessionPermission()) {
        WLOGFE("The interface permission failed.");
        return WSError::WS_ERROR_INVALID_PERMISSION;
    }
    auto task = [weakThis = wptr(this), abilitySessionInfo, visible]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (abilitySessionInfo == nullptr) {
            WLOGFE("abilitySessionInfo is null");
            return WSError::WS_ERROR_NULLPTR;
        }

        SessionInfo info;
        info.abilityName_ = abilitySessionInfo->want.GetElement().GetAbilityName();
        info.bundleName_ = abilitySessionInfo->want.GetElement().GetBundleName();
        info.moduleName_ = abilitySessionInfo->want.GetModuleName();
        int32_t appTwinIndex = abilitySessionInfo->want.GetIntParam(APP_TWIN_INDEX, 0);
        info.appIndex_ = appTwinIndex == 0 ? abilitySessionInfo->want.GetIntParam(DLP_INDEX, 0) : appTwinIndex;
        info.persistentId_ = abilitySessionInfo->persistentId;
        info.callerPersistentId_ = session->GetPersistentId();
        info.callerBundleName_ = abilitySessionInfo->want.GetStringParam(AAFwk::Want::PARAM_RESV_CALLER_BUNDLE_NAME);
        info.callerAbilityName_ = abilitySessionInfo->want.GetStringParam(AAFwk::Want::PARAM_RESV_CALLER_ABILITY_NAME);
        info.callState_ = static_cast<uint32_t>(abilitySessionInfo->state);
        info.uiAbilityId_ = abilitySessionInfo->uiAbilityId;
        info.want = std::make_shared<AAFwk::Want>(abilitySessionInfo->want);
        info.requestCode = abilitySessionInfo->requestCode;
        info.callerToken_ = abilitySessionInfo->callerToken;
        info.startSetting = abilitySessionInfo->startSetting;
        info.callingTokenId_ = abilitySessionInfo->callingTokenId;
        info.reuse = abilitySessionInfo->reuse;
        info.processOptions = abilitySessionInfo->processOptions;

        if (session->changeSessionVisibilityWithStatusBarFunc_) {
            session->changeSessionVisibilityWithStatusBarFunc_(info, visible);
        }

        return WSError::WS_OK;
    };
    PostTask(task, "ChangeSessionVisibilityWithStatusBar");
    return WSError::WS_OK;
}

WSError SceneSession::PendingSessionActivation(const sptr<AAFwk::SessionInfo> abilitySessionInfo)
{
    if (!SessionPermission::VerifySessionPermission()) {
        TLOGE(WmsLogTag::WMS_LIFE, "The permission check failed.");
        return WSError::WS_ERROR_INVALID_PERMISSION;
    }
    auto task = [weakThis = wptr(this), abilitySessionInfo]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (abilitySessionInfo == nullptr) {
            TLOGE(WmsLogTag::WMS_LIFE, "abilitySessionInfo is null");
            return WSError::WS_ERROR_NULLPTR;
        }
        auto isPC = system::GetParameter("const.product.devicetype", "unknown") == "2in1";
        bool isFreeMutiWindowMode = session->systemConfig_.freeMultiWindowSupport_ &&
            session->systemConfig_.freeMultiWindowEnable_;
        if (!(isPC || isFreeMutiWindowMode) &&
            (session->GetAbilityInfo() != nullptr) && WindowHelper::IsMainWindow(session->GetWindowType())) {
            if (!(session->GetForegroundInteractiveStatus())) {
                TLOGW(WmsLogTag::WMS_LIFE, "start ability invalid, ForegroundInteractiveStatus: %{public}u",
                    session->GetForegroundInteractiveStatus());
                return WSError::WS_ERROR_INVALID_OPERATION;
            }
            auto callingTokenId = abilitySessionInfo->callingTokenId;
            auto startAbilityBackground = SessionPermission::VerifyPermissionByCallerToken(
                callingTokenId, "ohos.permission.START_ABILITIES_FROM_BACKGROUND") ||
                SessionPermission::VerifyPermissionByCallerToken(callingTokenId,
                "ohos.permission.START_ABILIIES_FROM_BACKGROUND");
            auto sessionState = session->GetSessionState();
            if (sessionState != SessionState::STATE_FOREGROUND && sessionState != SessionState::STATE_ACTIVE &&
                !(startAbilityBackground || abilitySessionInfo->hasContinuousTask)) {
                TLOGW(WmsLogTag::WMS_LIFE, "start ability invalid, window state:%{public}d, "
                    "startAbilityBackground:%{public}u, hasContinuousTask:%{public}u",
                    sessionState, startAbilityBackground, abilitySessionInfo->hasContinuousTask);
                return WSError::WS_ERROR_INVALID_OPERATION;
            }
        }
        session->sessionInfo_.startMethod = StartMethod::START_CALL;
        SessionInfo info;
        info.abilityName_ = abilitySessionInfo->want.GetElement().GetAbilityName();
        info.bundleName_ = abilitySessionInfo->want.GetElement().GetBundleName();
        info.moduleName_ = abilitySessionInfo->want.GetModuleName();
        int32_t appTwinIndex = abilitySessionInfo->want.GetIntParam(APP_TWIN_INDEX, 0);
        info.appIndex_ = appTwinIndex == 0 ? abilitySessionInfo->want.GetIntParam(DLP_INDEX, 0) : appTwinIndex;
        info.persistentId_ = abilitySessionInfo->persistentId;
        info.callerPersistentId_ = session->GetPersistentId();
        info.callerBundleName_ = abilitySessionInfo->want.GetStringParam(AAFwk::Want::PARAM_RESV_CALLER_BUNDLE_NAME);
        info.callerAbilityName_ = abilitySessionInfo->want.GetStringParam(AAFwk::Want::PARAM_RESV_CALLER_ABILITY_NAME);
        info.callState_ = static_cast<uint32_t>(abilitySessionInfo->state);
        info.uiAbilityId_ = abilitySessionInfo->uiAbilityId;
        info.want = std::make_shared<AAFwk::Want>(abilitySessionInfo->want);
        info.requestCode = abilitySessionInfo->requestCode;
        info.callerToken_ = abilitySessionInfo->callerToken;
        info.startSetting = abilitySessionInfo->startSetting;
        info.callingTokenId_ = abilitySessionInfo->callingTokenId;
        info.reuse = abilitySessionInfo->reuse;
        info.processOptions = abilitySessionInfo->processOptions;
        if (info.want != nullptr) {
            info.windowMode = info.want->GetIntParam(AAFwk::Want::PARAM_RESV_WINDOW_MODE, 0);
            info.sessionAffinity = info.want->GetStringParam(Rosen::PARAM_KEY::PARAM_MISSION_AFFINITY_KEY);
            info.screenId_ = static_cast<uint64_t>(info.want->GetIntParam(AAFwk::Want::PARAM_RESV_DISPLAY_ID, -1));
            TLOGI(WmsLogTag::WMS_LIFE, "PendingSessionActivation: want: screenId %{public}" PRIu64, info.screenId_);
        }

        TLOGI(WmsLogTag::WMS_LIFE, "PendingSessionActivation: bundleName:%{public}s, moduleName:%{public}s, "
            "abilityName:%{public}s, appIndex:%{public}d, affinity:%{public}s. "
            "callState:%{public}d, want persistentId:%{public}d, callingTokenId:%{public}d, "
            "uiAbilityId:%{public}" PRIu64 ", windowMode:%{public}d, callerId: %{public}d",
            info.bundleName_.c_str(), info.moduleName_.c_str(), info.abilityName_.c_str(), info.appIndex_,
            info.sessionAffinity.c_str(), info.callState_, info.persistentId_, info.callingTokenId_, info.uiAbilityId_,
            info.windowMode, info.callerPersistentId_);
        session->HandleCastScreenConnection(info, session);
        if (session->pendingSessionActivationFunc_) {
            session->pendingSessionActivationFunc_(info);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "PendingSessionActivation");
    return WSError::WS_OK;
}

void SceneSession::HandleCastScreenConnection(SessionInfo& info, sptr<SceneSession> session)
{
    ScreenId defScreenId = ScreenSessionManagerClient::GetInstance().GetDefaultScreenId();
    if (defScreenId == info.screenId_) {
        return;
    }
    auto flag = Rosen::ScreenManager::GetInstance().GetVirtualScreenFlag(info.screenId_);
    if (flag != VirtualScreenFlag::CAST) {
        return;
    }
    TLOGI(WmsLogTag::WMS_LIFE, "Get exist session state :%{public}d persistentId:%{public}d",
        session->GetSessionState(), info.callerPersistentId_);
    if (session->GetSessionState() != SessionState::STATE_FOREGROUND &&
        session->GetSessionState() != SessionState::STATE_ACTIVE) {
        TLOGI(WmsLogTag::WMS_LIFE, "Get exist session state is not foreground");
        return;
    }
    info.isCastSession_ = true;
    std::vector<uint64_t> mirrorIds { info.screenId_ };
    Rosen::DMError ret = Rosen::ScreenManager::GetInstance().MakeUniqueScreen(mirrorIds);
    if (ret != Rosen::DMError::DM_OK) {
        TLOGE(WmsLogTag::WMS_LIFE, "MakeUniqueScreen failed,ret: %{public}d", ret);
        return;
    }
}

WSError SceneSession::TerminateSession(const sptr<AAFwk::SessionInfo> abilitySessionInfo)
{
    auto task = [weakThis = wptr(this), abilitySessionInfo]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (abilitySessionInfo == nullptr) {
            TLOGE(WmsLogTag::WMS_LIFE, "abilitySessionInfo is null");
            return WSError::WS_ERROR_NULLPTR;
        }
        if (session->isTerminating) {
            TLOGE(WmsLogTag::WMS_LIFE, "TerminateSession: is terminating, return!");
            return WSError::WS_ERROR_INVALID_OPERATION;
        }
        session->isTerminating = true;
        SessionInfo info;
        info.abilityName_ = abilitySessionInfo->want.GetElement().GetAbilityName();
        info.bundleName_ = abilitySessionInfo->want.GetElement().GetBundleName();
        info.callerToken_ = abilitySessionInfo->callerToken;
        info.persistentId_ = static_cast<int32_t>(abilitySessionInfo->persistentId);
        {
            std::lock_guard<std::recursive_mutex> lock(session->sessionInfoMutex_);
            session->sessionInfo_.closeAbilityWant = std::make_shared<AAFwk::Want>(abilitySessionInfo->want);
            session->sessionInfo_.resultCode = abilitySessionInfo->resultCode;
        }
        if (session->terminateSessionFunc_) {
            session->terminateSessionFunc_(info);
        }
        return WSError::WS_OK;
    };
    PostLifeCycleTask(task, "TerminateSession", LifeCycleTaskType::STOP);
    return WSError::WS_OK;
}

WSError SceneSession::NotifySessionException(const sptr<AAFwk::SessionInfo> abilitySessionInfo, bool needRemoveSession)
{
    if (!SessionPermission::VerifySessionPermission()) {
        TLOGE(WmsLogTag::WMS_LIFE, "permission failed.");
        return WSError::WS_ERROR_INVALID_PERMISSION;
    }
    auto task = [weakThis = wptr(this), abilitySessionInfo, needRemoveSession]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LIFE, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (abilitySessionInfo == nullptr) {
            TLOGE(WmsLogTag::WMS_LIFE, "abilitySessionInfo is null");
            return WSError::WS_ERROR_NULLPTR;
        }
        if (session->isTerminating) {
            TLOGE(WmsLogTag::WMS_LIFE, "NotifySessionException: is terminating, return!");
            return WSError::WS_ERROR_INVALID_OPERATION;
        }
        session->isTerminating = true;
        SessionInfo info;
        info.abilityName_ = abilitySessionInfo->want.GetElement().GetAbilityName();
        info.bundleName_ = abilitySessionInfo->want.GetElement().GetBundleName();
        info.callerToken_ = abilitySessionInfo->callerToken;
        info.errorCode = abilitySessionInfo->errorCode;
        info.errorReason = abilitySessionInfo->errorReason;
        info.persistentId_ = static_cast<int32_t>(abilitySessionInfo->persistentId);
        {
            std::lock_guard<std::recursive_mutex> lock(session->sessionInfoMutex_);
            session->sessionInfo_.closeAbilityWant = std::make_shared<AAFwk::Want>(abilitySessionInfo->want);
            session->sessionInfo_.errorCode = abilitySessionInfo->errorCode;
            session->sessionInfo_.errorReason = abilitySessionInfo->errorReason;
        }
        if (session->sessionExceptionFunc_) {
            auto exceptionFunc = *(session->sessionExceptionFunc_);
            exceptionFunc(info, needRemoveSession);
        }
        if (session->jsSceneSessionExceptionFunc_) {
            auto exceptionFunc = *(session->jsSceneSessionExceptionFunc_);
            exceptionFunc(info, needRemoveSession);
        }
        return WSError::WS_OK;
    };
    PostLifeCycleTask(task, "NotifySessionException", LifeCycleTaskType::STOP);
    return WSError::WS_OK;
}

WSRect SceneSession::GetLastSafeRect() const
{
    return lastSafeRect;
}

void SceneSession::SetLastSafeRect(WSRect rect)
{
    lastSafeRect.posX_ = rect.posX_;
    lastSafeRect.posY_ = rect.posY_;
    lastSafeRect.width_ = rect.width_;
    lastSafeRect.height_ = rect.height_;
    return;
}

WSRect SceneSession::GetRestoringRectForKeyboard() const
{
    return restoringRectForKeyboard_;
}

void SceneSession::SetRestoringRectForKeyboard(WSRect rect)
{
    restoringRectForKeyboard_ = rect;
}

bool SceneSession::AddSubSession(const sptr<SceneSession>& subSession)
{
    if (subSession == nullptr) {
        TLOGE(WmsLogTag::WMS_SUB, "subSession is nullptr");
        return false;
    }
    const auto& persistentId = subSession->GetPersistentId();
    auto iter = std::find_if(subSession_.begin(), subSession_.end(),
        [persistentId](sptr<SceneSession> session) {
            bool res = (session != nullptr && session->GetPersistentId() == persistentId) ? true : false;
            return res;
        });
    if (iter != subSession_.end()) {
        TLOGE(WmsLogTag::WMS_SUB, "Sub ession is already exists, id: %{public}d, parentId: %{public}d",
            subSession->GetPersistentId(), GetPersistentId());
        return false;
    }
    TLOGD(WmsLogTag::WMS_SUB, "Success, id: %{public}d, parentId: %{public}d",
        subSession->GetPersistentId(), GetPersistentId());
    subSession_.push_back(subSession);
    return true;
}

bool SceneSession::RemoveSubSession(int32_t persistentId)
{
    auto iter = std::find_if(subSession_.begin(), subSession_.end(),
        [persistentId](sptr<SceneSession> session) {
            bool res = (session != nullptr && session->GetPersistentId() == persistentId) ? true : false;
            return res;
        });
    if (iter == subSession_.end()) {
        TLOGE(WmsLogTag::WMS_SUB, "Could not find subsession, id: %{public}d, parentId: %{public}d",
            persistentId, GetPersistentId());
        return false;
    }
    TLOGD(WmsLogTag::WMS_SUB, "Success, id: %{public}d, parentId: %{public}d", persistentId, GetPersistentId());
    subSession_.erase(iter);
    return true;
}

void SceneSession::NotifyPiPWindowPrepareClose()
{
    TLOGD(WmsLogTag::WMS_PIP, "NotifyPiPWindowPrepareClose");
    auto task = [weakThis = wptr(this)]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_PIP, "session is null");
            return;
        }
        if (session->sessionChangeCallback_ && session->sessionChangeCallback_->onPrepareClosePiPSession_) {
            session->sessionChangeCallback_->onPrepareClosePiPSession_();
        }
        TLOGD(WmsLogTag::WMS_PIP, "NotifyPiPWindowPrepareClose, id: %{public}d", session->GetPersistentId());
        return;
    };
    PostTask(task, "NotifyPiPWindowPrepareClose");
}

WSError SceneSession::SetLandscapeMultiWindow(bool isLandscapeMultiWindow)
{
    WLOGFD("NotifySetLandscapeMultiWindow");
    auto task = [weakThis = wptr(this), isLandscapeMultiWindow]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        if (session->sessionChangeCallback_ &&
            session->sessionChangeCallback_->onSetLandscapeMultiWindowFunc_) {
            session->sessionChangeCallback_->onSetLandscapeMultiWindowFunc_(
                isLandscapeMultiWindow);
        }
        WLOGFD("NotifySetLandscapeMultiWindow, id: %{public}d, isLandscapeMultiWindow: %{public}u",
               session->GetPersistentId(), isLandscapeMultiWindow);
        return WSError::WS_OK;
    };
    PostTask(task, "NotifySetLandscapeMultiWindow");
    return WSError::WS_OK;
}

std::vector<sptr<SceneSession>> SceneSession::GetSubSession() const
{
    return subSession_;
}

WSRect SceneSession::GetSessionTargetRect() const
{
    WSRect rect;
    if (moveDragController_) {
        rect = moveDragController_->GetTargetRect();
    } else {
        WLOGFI("moveDragController_ is null");
    }
    return rect;
}

void SceneSession::SetWindowDragHotAreaListener(const NotifyWindowDragHotAreaFunc& func)
{
    if (moveDragController_) {
        moveDragController_->SetWindowDragHotAreaFunc(func);
    }
}

void SceneSession::NotifySessionForeground(uint32_t reason, bool withAnimation)
{
    if (!sessionStage_) {
        return;
    }
    return sessionStage_->NotifySessionForeground(reason, withAnimation);
}

void SceneSession::NotifySessionBackground(uint32_t reason, bool withAnimation, bool isFromInnerkits)
{
    if (!sessionStage_) {
        return;
    }
    return sessionStage_->NotifySessionBackground(reason, withAnimation, isFromInnerkits);
}

WSError SceneSession::UpdatePiPRect(const Rect& rect, SizeChangeReason reason)
{
    if (!WindowHelper::IsPipWindow(GetWindowType())) {
        return WSError::WS_DO_NOTHING;
    }
    auto task = [weakThis = wptr(this), rect, reason]() {
        auto session = weakThis.promote();
        if (!session || session->isTerminating) {
            TLOGE(WmsLogTag::WMS_PIP, "SceneSession::UpdatePiPRect session is null or is terminating");
            return WSError::WS_ERROR_INVALID_OPERATION;
        }
        WSRect wsRect = SessionHelper::TransferToWSRect(rect);
        if (reason == SizeChangeReason::PIP_START) {
            session->SetSessionRequestRect(wsRect);
        }
        session->NotifySessionRectChange(wsRect, reason);
        return WSError::WS_OK;
    };
    PostTask(task, "UpdatePiPRect");
    return WSError::WS_OK;
}

void SceneSession::SendPointerEventToUI(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    std::lock_guard<std::mutex> lock(pointerEventMutex_);
    if (systemSessionPointerEventFunc_ != nullptr) {
        systemSessionPointerEventFunc_(pointerEvent);
    } else {
        TLOGE(WmsLogTag::WMS_EVENT, "PointerEventFunc_ nullptr, id:%{public}d", pointerEvent->GetId());
        pointerEvent->MarkProcessed();
    }
}

bool SceneSession::SendKeyEventToUI(std::shared_ptr<MMI::KeyEvent> keyEvent, bool isPreImeEvent)
{
    std::shared_lock<std::shared_mutex> lock(keyEventMutex_);
    if (systemSessionKeyEventFunc_ != nullptr) {
        return systemSessionKeyEventFunc_(keyEvent, isPreImeEvent);
    }
    return false;
}

WSError SceneSession::UpdateSizeChangeReason(SizeChangeReason reason)
{
    auto task = [weakThis = wptr(this), reason]() {
        auto session = weakThis.promote();
        if (!session) {
            WLOGFE("session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        session->reason_ = reason;
        if (reason != SizeChangeReason::UNDEFINED) {
            HITRACE_METER_FMT(HITRACE_TAG_WINDOW_MANAGER,
                "SceneSession::UpdateSizeChangeReason%d reason:%d",
                session->GetPersistentId(), static_cast<uint32_t>(reason));
            TLOGD(WmsLogTag::WMS_LAYOUT, "UpdateSizeChangeReason Id: %{public}d, reason: %{public}d",
                session->GetPersistentId(), reason);
        }
        return WSError::WS_OK;
    };
    PostTask(task, "UpdateSizeChangeReason");
    return WSError::WS_OK;
}

bool SceneSession::IsDirtyWindow()
{
    return isDirty_;
}

void SceneSession::NotifyUILostFocus()
{
    if (moveDragController_) {
        moveDragController_->OnLostFocus();
    }
    Session::NotifyUILostFocus();
}

void SceneSession::SetScale(float scaleX, float scaleY, float pivotX, float pivotY)
{
    if (scaleX_ != scaleX || scaleY_ != scaleY || pivotX_ != pivotX || pivotY_ != pivotY) {
        Session::SetScale(scaleX, scaleY, pivotX, pivotY);
        if (specificCallback_ != nullptr) {
            specificCallback_->onWindowInfoUpdate_(GetPersistentId(), WindowUpdateType::WINDOW_UPDATE_PROPERTY);
        }
        if (sessionStage_ != nullptr) {
            Transform transform;
            transform.scaleX_ = scaleX;
            transform.scaleY_ = scaleY;
            transform.pivotX_ = pivotX;
            transform.pivotY_ = pivotY;
            sessionStage_->NotifyTransformChange(transform);
        } else {
            WLOGFE("sessionStage_ is nullptr");
        }
    }
}

void SceneSession::RequestHideKeyboard(bool isAppColdStart)
{
#ifdef IMF_ENABLE
    auto task = [weakThis = wptr(this), isAppColdStart]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_KEYBOARD, "Session is null, notify inputMethod framework hide keyboard failed!");
            return;
        }
        TLOGI(WmsLogTag::WMS_KEYBOARD, "Notify inputMethod framework hide keyboard start, id: %{public}d,"
            "isAppColdStart: %{public}d", session->GetPersistentId(), isAppColdStart);
        if (MiscServices::InputMethodController::GetInstance()) {
            MiscServices::InputMethodController::GetInstance()->RequestHideInput();
        } else {
            TLOGE(WmsLogTag::WMS_KEYBOARD, "Get instance failed, Notify Input framework close keyboard failed.");
        }
    };
    PostExportTask(task, "RequestHideKeyboard");
#endif
}

bool SceneSession::IsStartMoving() const
{
    return isStartMoving_.load();
}

void SceneSession::SetIsStartMoving(const bool startMoving)
{
    isStartMoving_.store(startMoving);
}

void SceneSession::SetShouldHideNonSecureWindows(bool shouldHide)
{
    shouldHideNonSecureWindows_.store(shouldHide);
}

void SceneSession::CalculateCombinedExtWindowFlags()
{
    // Only correct when each flag is true when active, and once a uiextension is active, the host is active
    combinedExtWindowFlags_.bitData = 0;
    for (const auto& iter: extWindowFlagsMap_) {
        combinedExtWindowFlags_.bitData |= iter.second.bitData;
    }
}

void SceneSession::UpdateExtWindowFlags(int32_t extPersistentId, const ExtensionWindowFlags& extWindowFlags,
    const ExtensionWindowFlags& extWindowActions)
{
    auto iter = extWindowFlagsMap_.find(extPersistentId);
    // Each flag is false when inactive, 0 means all flags are inactive
    auto oldFlags = iter != extWindowFlagsMap_.end() ? iter->second : ExtensionWindowFlags();
    ExtensionWindowFlags newFlags((extWindowFlags.bitData & extWindowActions.bitData) |
        (oldFlags.bitData & ~extWindowActions.bitData));
    if (newFlags.bitData == 0) {
        extWindowFlagsMap_.erase(extPersistentId);
    } else {
        extWindowFlagsMap_[extPersistentId] = newFlags;
    }
    CalculateCombinedExtWindowFlags();
}

ExtensionWindowFlags SceneSession::GetCombinedExtWindowFlags() const
{
    auto combinedExtWindowFlags = combinedExtWindowFlags_;
    combinedExtWindowFlags.hideNonSecureWindowsFlag = IsSessionForeground() &&
        (combinedExtWindowFlags.hideNonSecureWindowsFlag || shouldHideNonSecureWindows_.load());
    return combinedExtWindowFlags;
}

void SceneSession::NotifyDisplayMove(DisplayId from, DisplayId to)
{
    if (sessionStage_) {
        sessionStage_->NotifyDisplayMove(from, to);
    } else {
        WLOGFE("Notify display move failed, sessionStage is null");
    }
}

void SceneSession::RemoveExtWindowFlags(int32_t extPersistentId)
{
    extWindowFlagsMap_.erase(extPersistentId);
    CalculateCombinedExtWindowFlags();
}

void SceneSession::ClearExtWindowFlags()
{
    extWindowFlagsMap_.clear();
    combinedExtWindowFlags_.bitData = 0;
}

WSError SceneSession::UpdateRectChangeListenerRegistered(bool isRegister)
{
    auto task = [weakThis = wptr(this), isRegister]() {
        auto session = weakThis.promote();
        if (!session) {
            TLOGE(WmsLogTag::WMS_LAYOUT, "session is null");
            return WSError::WS_ERROR_DESTROYED_OBJECT;
        }
        session->rectChangeListenerRegistered_ = isRegister;
        return WSError::WS_OK;
    };
    PostTask(task, "UpdateRectChangeListenerRegistered");
    return WSError::WS_OK;
}

void SceneSession::SetForceHideState(bool hideFlag)
{
    forceHideState_ = hideFlag;
}

bool SceneSession::GetForceHideState() const
{
    return forceHideState_;
}

void SceneSession::SetIsDisplayStatusBarTemporarily(bool isTemporary)
{
    TLOGI(WmsLogTag::WMS_IMMS, "SetIsTemporarily:%{public}u", isTemporary);
    isDisplayStatusBarTemporarily_.store(isTemporary);
}

bool SceneSession::GetIsDisplayStatusBarTemporarily() const
{
    return isDisplayStatusBarTemporarily_.load();
}

void SceneSession::SetTemporarilyShowWhenLocked(bool isTemporarilyShowWhenLocked)
{
    if (isTemporarilyShowWhenLocked_.load() == isTemporarilyShowWhenLocked) {
        return;
    }
    isTemporarilyShowWhenLocked_.store(isTemporarilyShowWhenLocked);
    TLOGI(WmsLogTag::WMS_SCB, "SetTemporarilyShowWhenLocked successfully, target:%{public}u",
        isTemporarilyShowWhenLocked);
}

bool SceneSession::IsTemporarilyShowWhenLocked() const
{
    return isTemporarilyShowWhenLocked_.load();
}
} // namespace OHOS::Rosen
