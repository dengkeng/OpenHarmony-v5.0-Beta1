/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "session_service_impl.h"

#include "session_impl.h"
#include "session_mock.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_log.h"

namespace Communication {
namespace SoftBus {
std::shared_mutex ISessionService::instanceMutex_;
std::shared_ptr<ISessionService> ISessionService::instance_ = nullptr;
std::mutex SessionServiceImpl::listenerMutex_;
std::map<std::string, std::shared_ptr<ISessionListener>> SessionServiceImpl::listenerMap_;
std::mutex SessionServiceImpl::sessionMutex_;
std::map<int32_t, std::shared_ptr<Session>> SessionServiceImpl::sessionMap_;

std::shared_ptr<ISessionService> ISessionService::GetInstance()
{
    std::shared_ptr<ISessionService> tmp = instance_;
    if (tmp == nullptr) {
        std::unique_lock<std::shared_mutex> instanceLock(instanceMutex_);
        tmp = instance_;
        if (tmp == nullptr) {
            tmp = std::make_shared<SessionServiceImpl>();
            instance_ = tmp;
        }
    }
    return instance_;
}

int32_t SessionServiceImpl::CreateSessionServer(
    const std::string &pkgName, const std::string &sessionName, std::shared_ptr<ISessionListener> listener)
{
    if (pkgName.empty() || sessionName.empty() || listener == nullptr) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName or listener invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> autoLock(listenerMutex_);
    int32_t ret = CreateSessionServerInner(pkgName.c_str(), sessionName.c_str());
    if (ret == SOFTBUS_OK) {
        listenerMap_.insert(std::pair<std::string, std::shared_ptr<ISessionListener>>(sessionName, listener));
    }
    return ret;
}

int32_t SessionServiceImpl::RemoveSessionServer(const std::string &pkgName, const std::string &sessionName)
{
    if (pkgName.empty() || sessionName.empty()) {
        TRANS_LOGE(TRANS_SDK, "pkgName or sessionName invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> autoLock(listenerMutex_);
    auto iter = listenerMap_.find(sessionName);
    if (iter != listenerMap_.end()) {
        listenerMap_.erase(iter);
        return RemoveSessionServerInner(pkgName.c_str(), sessionName.c_str());
    }
    TRANS_LOGE(TRANS_SDK, "not find session server");
    return SOFTBUS_ERR;
}

std::shared_ptr<Session> SessionServiceImpl::OpenSession(const std::string &mySessionName,
    const std::string &peerSessionName, const std::string &peerNetworkId, const std::string &groupId, int32_t flags)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    if (mySessionName.empty() || peerSessionName.empty() || peerNetworkId.empty()) {
        return nullptr;
    }
    int32_t sessionId =
        OpenSessionInner(mySessionName.c_str(), peerSessionName.c_str(), peerNetworkId.c_str(), groupId.c_str(), flags);
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId.");
        return nullptr;
    }

    std::shared_ptr<Session> session;
    std::lock_guard<std::mutex> autoLock(sessionMutex_);
    auto iter = sessionMap_.find(sessionId);
    if (iter != sessionMap_.end()) {
        session = iter->second;
        TRANS_LOGE(TRANS_SDK, "Session find");
    }
    TRANS_LOGD(TRANS_SDK, "ok");
    return session;
}

int32_t SessionServiceImpl::CloseSession(std::shared_ptr<Session> session)
{
    if (session == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param session");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t sessionId = session->GetSessionId();
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    CloseSessionInner(sessionId);
    std::lock_guard<std::mutex> autoLock(sessionMutex_);
    auto iter = sessionMap_.find(sessionId);
    if (iter != sessionMap_.end()) {
        sessionMap_.erase(sessionId);
    }
    return SOFTBUS_OK;
}

int32_t SessionServiceImpl::GrantPermission(int32_t uid, int32_t pid, const std::string &busName)
{
    if (uid < 0 || pid < 0 || busName.empty()) {
        TRANS_LOGE(TRANS_SDK, "invalid uid or pid or busName");
        return SOFTBUS_INVALID_PARAM;
    }
    return GrantPermissionInner(uid, pid, busName.c_str());
}

int32_t SessionServiceImpl::RemovePermission(const std::string &busName)
{
    if (busName.empty()) {
        TRANS_LOGE(TRANS_SDK, "busName invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return RemovePermissionInner(busName.c_str());
}

int32_t SessionServiceImpl::CreateSession(int32_t sessionId, const std::shared_ptr<Session> &session)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    int32_t isServer;
    if (IsServerSideInner(sessionId, &isServer) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    session->SetSessionId(sessionId);

    char str[SESSION_NAME_SIZE_MAX];
    if (GetMySessionNameInner(sessionId, str, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    std::string mySessionName(str);
    session->SetMySessionName(mySessionName);

    if (GetPeerSessionNameInner(sessionId, str, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    std::string peerSessionName(str);
    session->SetPeerSessionName(peerSessionName);

    char networkId[DEVICE_ID_SIZE_MAX];
    if (GetPeerDeviceIdInner(sessionId, networkId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    std::string peerNetworkId(networkId);
    session->SetPeerDeviceId(peerNetworkId);
    session->SetIsServer(isServer);

    std::lock_guard<std::mutex> autoLock(sessionMutex_);
    sessionMap_.insert(std::pair<int32_t, std::shared_ptr<Session>>(sessionId, session));

    return SOFTBUS_OK;
}

int32_t SessionServiceImpl::OpenSessionCallback(int32_t sessionId)
{
    std::shared_ptr<Session> session = std::make_shared<SessionImpl>();
    if (CreateSession(sessionId, session) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    std::shared_ptr<ISessionListener> listener;
    if (GetSessionListenerOnSessionOpened(sessionId, listener, session) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session listener failed");
        return SOFTBUS_ERR;
    }

    NodeBasicInfo info;
    char pkgName[PKG_NAME_SIZE_MAX];
    if (GetPkgNameInner(sessionId, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK ||
        GetLocalNodeDeviceInfo(pkgName, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get pkgName or deviceInfo failed");
        return SOFTBUS_ERR;
    }
    session->SetDeviceId(info.networkId);

    int32_t tmp;
    if (GetPeerUidInner(sessionId, &tmp) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    session->SetPeerUid(static_cast<uid_t>(tmp));
    if (GetPeerPidInner(sessionId, &tmp) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    session->SetPeerPid(static_cast<pid_t>(tmp));

    TRANS_LOGD(TRANS_SDK, "Ok");
    return listener->OnSessionOpened(session);
}

void SessionServiceImpl::CloseSessionCallback(int32_t sessionId)
{
    std::shared_ptr<ISessionListener> listener;
    std::shared_ptr<Session> session;
    if (GetSessionListener(sessionId, listener, session) != SOFTBUS_OK) {
        return;
    }
    listener->OnSessionClosed(session);
}

void SessionServiceImpl::BytesReceivedCallback(int32_t sessionId, const void *data, uint32_t len)
{
    std::shared_ptr<ISessionListener> listener;
    std::shared_ptr<Session> session;
    if (GetSessionListener(sessionId, listener, session) != SOFTBUS_OK) {
        return;
    }
    const char *msg = static_cast<const char *>(data);
    ssize_t lenMsg = static_cast<ssize_t>(len);
    listener->OnBytesReceived(session, msg, lenMsg);
}

void SessionServiceImpl::MessageReceivedCallback(int32_t sessionId, const void *data, uint32_t len)
{
    std::shared_ptr<ISessionListener> listener;
    std::shared_ptr<Session> session;
    if (GetSessionListener(sessionId, listener, session) != SOFTBUS_OK) {
        return;
    }
    const char *msg = static_cast<const char *>(data);
    ssize_t lenMsg = static_cast<ssize_t>(len);
    listener->OnMessageReceived(session, msg, lenMsg);
}

int32_t SessionServiceImpl::GetSessionListener(
    int32_t sessionId, std::shared_ptr<ISessionListener> &listener, std::shared_ptr<Session> &session)
{
    std::lock_guard<std::mutex> autoLock(sessionMutex_);
    auto iter = sessionMap_.find(sessionId);
    if (iter != sessionMap_.end()) {
        session = iter->second;
        std::lock_guard<std::mutex> autoLock(listenerMutex_);
        auto iterListener = listenerMap_.find(session->GetMySessionName());
        if (iterListener != listenerMap_.end()) {
            listener = iterListener->second;
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}

int32_t SessionServiceImpl::GetSessionListenerOnSessionOpened(
    int32_t sessionId, std::shared_ptr<ISessionListener> &listener, std::shared_ptr<Session> &session)
{
    (void)session;
    char str[SESSION_NAME_SIZE_MAX];
    if (GetMySessionNameInner(sessionId, str, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    std::string mySessionName(str);

    std::lock_guard<std::mutex> autoLock(listenerMutex_);
    auto iterListener = listenerMap_.find(mySessionName);
    if (iterListener != listenerMap_.end()) {
        listener = iterListener->second;
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}
} // namespace SoftBus
} // namespace Communication
