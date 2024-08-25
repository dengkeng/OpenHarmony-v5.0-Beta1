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

#ifndef OHOS_ROSEN_WINDOW_SCENE_SESSION_MANAGER_LITE_H
#define OHOS_ROSEN_WINDOW_SCENE_SESSION_MANAGER_LITE_H

#include <functional>
#include <shared_mutex>

#include "session_manager_service_interface.h"
#include "mock_session_manager_service_interface.h"
#include "zidl/scene_session_manager_lite_interface.h"
#include "zidl/screen_session_manager_lite_interface.h"
#include "wm_single_instance.h"
#include "wm_common.h"

namespace OHOS::Rosen {
class SSMDeathRecipientLite : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject>& wptrDeath) override;
};

class SessionManagerLite {
WM_DECLARE_SINGLE_INSTANCE_BASE(SessionManagerLite);
public:
    using UserSwitchCallbackFunc = std::function<void()>;
    void ClearSessionManagerProxy();
    void Clear();

    sptr<ISceneSessionManagerLite> GetSceneSessionManagerLiteProxy();
    sptr<IScreenSessionManagerLite> GetScreenSessionManagerLiteProxy();

    sptr<ISessionManagerService> GetSessionManagerServiceProxy();

    void SaveSessionListener(const sptr<ISessionListener>& listener);
    void DeleteSessionListener(const sptr<ISessionListener>& listener);
    void RecoverSessionManagerService(const sptr<ISessionManagerService>& sessionManagerService);
    void RegisterUserSwitchListener(const UserSwitchCallbackFunc& callbackFunc);
    void OnWMSConnectionChanged(int32_t userId, int32_t screenId, bool isConnected);

protected:
    SessionManagerLite() = default;
    virtual ~SessionManagerLite();

private:
    void InitSessionManagerServiceProxy();
    void InitSceneSessionManagerLiteProxy();
    void InitScreenSessionManagerLiteProxy();
    void OnUserSwitch();
    void DeleteAllSessionListeners();
    void ReregisterSessionListener() const;

    UserSwitchCallbackFunc userSwitchCallbackFunc_ = nullptr;
    sptr<IMockSessionManagerInterface> mockSessionManagerServiceProxy_ = nullptr;
    sptr<ISessionManagerService> sessionManagerServiceProxy_ = nullptr;
    sptr<ISceneSessionManagerLite> sceneSessionManagerLiteProxy_ = nullptr;
    sptr<IScreenSessionManagerLite> screenSessionManagerLiteProxy_ = nullptr;
    sptr<SSMDeathRecipientLite> ssmDeath_ = nullptr;
    sptr<IRemoteObject> smsRecoverListener_ = nullptr;
    bool recoverListenerRegistered_ = false;
    std::recursive_mutex listenerLock_;
    std::vector<sptr<ISessionListener>> sessionListeners_;
    std::recursive_mutex mutex_;
    bool destroyed_ = false;
    int32_t currentWMSUserId_ = INVALID_USER_ID;
};
} // namespace OHOS::Rosen

#endif // OHOS_ROSEN_WINDOW_SCENE_SESSION_MANAGER_LITE_H
