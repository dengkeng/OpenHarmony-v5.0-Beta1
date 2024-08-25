/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

#include "base_server.h"
#include "common/media_log.h"
#include "network/session/base_network_session.h"
#include "utils/utils.h"
namespace OHOS {
namespace Sharing {
BaseServer::~BaseServer()
{
    SHARING_LOGD("trace.");
}

BaseServer::BaseServer()
{
    SHARING_LOGD("trace.");
}

void BaseServer::RegisterCallback(std::weak_ptr<IServerCallback> callback)
{
    SHARING_LOGD("trace.");
    callback_ = callback;
}

std::weak_ptr<IServerCallback> &BaseServer::GetCallback()
{
    MEDIA_LOGD("trace.");
    return callback_;
}

void BaseServerEventListener::OnReadable(int32_t fd)
{
    MEDIA_LOGD("thread_id: %{public}llu.", GetThreadId());
    auto server = server_.lock();
    if (server) {
        server->OnServerReadable(fd);
    }
}

void BaseServerEventListener::OnWritable(int32_t fd)
{
    MEDIA_LOGD("thread_id: %{public}llu.", GetThreadId());
    auto server = server_.lock();
    if (server) {
        auto callback = server->GetCallback().lock();
        if (callback) {
            callback->OnServerWriteable(fd);
        }
    }
}

void BaseServerEventListener::OnShutdown(int32_t fd)
{
    SHARING_LOGD("thread_id: %{public}llu.", GetThreadId());
    auto server = server_.lock();
    if (server) {
        auto callback = server->GetCallback().lock();
        if (callback) {
            callback->OnServerClose(fd);
        }
    }
}

void BaseServerEventListener::OnException(int32_t fd)
{
    SHARING_LOGD("thread_id: %{public}llu.", GetThreadId());
    auto server = server_.lock();
    if (server) {
        auto callback = server->GetCallback().lock();
        if (callback) {
            callback->OnServerException(fd);
        }
    }
}

} // namespace Sharing
} // namespace OHOS