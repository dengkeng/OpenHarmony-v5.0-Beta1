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

#ifndef OHOS_SHARING_ICLIENT_CALLBACK_H
#define OHOS_SHARING_ICLIENT_CALLBACK_H
#include <shared_mutex>
#include "utils/data_buffer.h"
namespace OHOS {
namespace Sharing {

class IClientCallback {
public:
    using Ptr = std::shared_ptr<IClientCallback>;

    IClientCallback() = default;
    virtual ~IClientCallback() = default;

    virtual void OnClientClose(int32_t fd) = 0;
    virtual void OnClientWriteable(int32_t fd) = 0;
    virtual void OnClientException(int32_t fd) = 0;
    virtual void OnClientConnect(bool isSuccess) = 0;
    virtual void OnClientReadData(int32_t fd, DataBuffer::Ptr buf) = 0;
};
} // namespace Sharing
} // namespace OHOS
#endif
