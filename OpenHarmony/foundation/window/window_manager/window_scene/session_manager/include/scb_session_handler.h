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

#ifndef OHOS_ROSEN_WINDOW_SCENE_SCB_SESSION_HANDLER_H
#define OHOS_ROSEN_WINDOW_SCENE_SCB_SESSION_HANDLER_H

#include "session_handler_stub.h"

namespace OHOS {
namespace Rosen {

class ScbSessionHandler : public AAFwk::SessionHandlerStub {
public:
    ScbSessionHandler() = default;
    ~ScbSessionHandler() = default;
    void OnSessionMovedToFront(int32_t sessionId) override;
};
} // namespace Rosen
} // namespace OHOS
#endif //OHOS_ROSEN_WINDOW_SCENE_SCB_SESSION_HANDLER_H