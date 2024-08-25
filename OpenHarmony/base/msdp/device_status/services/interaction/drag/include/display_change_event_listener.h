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

#ifndef DISPLAY_CHANGE_EVENT_LISTENER_H
#define DISPLAY_CHANGE_EVENT_LISTENER_H

#include "display_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DisplayChangeEventListener : public Rosen::DisplayManager::IDisplayListener {
public:
    explicit DisplayChangeEventListener(IContext *context);
    ~DisplayChangeEventListener() = default;
    void OnCreate(Rosen::DisplayId displayId) override;
    void OnDestroy(Rosen::DisplayId displayId) override;
    void OnChange(Rosen::DisplayId displayId) override;

private:
    Rosen::Rotation lastRotation_ { Rosen::Rotation::ROTATION_0 };
    IContext *context_ { nullptr };
};

class DisplayAbilityStatusChange : public SystemAbilityStatusChangeStub {
public:
    explicit DisplayAbilityStatusChange(IContext *context);
    ~DisplayAbilityStatusChange() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    sptr<DisplayChangeEventListener> displayChangeEventListener_ { nullptr };
    IContext *context_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DISPLAY_CHANGE_EVENT_LISTENER_H