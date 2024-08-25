/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef STYLUS_KEY_HANDLER_H
#define STYLUS_KEY_HANDLER_H

#include "key_command_handler.h"
#include "key_event.h"

#include "singleton.h"

namespace OHOS {
namespace MMI {
struct StylusKey {
    int32_t durationTimes { 0 };
    bool lastEventIsStylus { false };
    bool isLaunchAbility { false };
    Ability ability;
};
class StylusKeyHandler final {
    DECLARE_DELAYED_SINGLETON(StylusKeyHandler);
    public:
        DISALLOW_COPY_AND_MOVE(StylusKeyHandler);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
        bool HandleStylusKey(const std::shared_ptr<KeyEvent> keyEvent);
        void IsLaunchAbility();
        void SetLastEventState(bool state);
    private:
        void LaunchAbility(const Ability &ability);
    private:
        StylusKey stylusKey_;
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
};
#define STYLUS_HANDLER ::OHOS::DelayedSingleton<StylusKeyHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // STYLUS_KEY_HANDLER_H