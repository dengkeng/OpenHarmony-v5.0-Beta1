/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_UI_RS_HDR_MANAGER_H
#define RENDER_SERVICE_CLIENT_CORE_UI_RS_HDR_MANAGER_H

#include <functional>
#include <mutex>

#include "ui/rs_node.h"

namespace OHOS {
namespace Rosen {

using HDRFunc = std::function<void(bool, NodeId)>;
class RSHDRManager {
public:
    ~RSHDRManager();

    static RSHDRManager& Instance();
    int IncreaseHDRNum();
    int ReduceHDRNum();
    void ResetHDRNum();
    int getHDRNum();
    void RegisterSetHDRPresent(HDRFunc func, NodeId id);
    void UnRegisterSetHDRPresent(NodeId id);
    
private:
    RSHDRManager();
    HDRFunc setHDRPresent_ = nullptr;
    int hdrNum_ = 0;
    std::mutex mutex_;
    NodeId nodeId_ = INVALID_NODEID;
};
} // namespace Rosen
} // namespace OHOS

#endif //RENDER_SERVICE_CLIENT_CORE_UI_RS_HDR_MANAGER_H