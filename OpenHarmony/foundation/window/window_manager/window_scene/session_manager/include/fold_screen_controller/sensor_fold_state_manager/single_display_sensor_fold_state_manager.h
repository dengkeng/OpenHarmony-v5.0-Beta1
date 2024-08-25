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

#ifndef OHOS_ROSEN_SINGLE_DISPLAY_FOLD_STATE_SENSOR_MANAGER_H
#define OHOS_ROSEN_SINGLE_DISPLAY_FOLD_STATE_SENSOR_MANAGER_H

#include "dm_common.h"
#include "fold_screen_controller/fold_screen_policy.h"
#include "fold_screen_controller/sensor_fold_state_manager/sensor_fold_state_manager.h"

namespace OHOS {
namespace Rosen {
class SingleDisplaySensorFoldStateManager : public SensorFoldStateManager {
public:
    SingleDisplaySensorFoldStateManager();
    virtual ~SingleDisplaySensorFoldStateManager();

    void HandleAngleChange(float angle, int hall, sptr<FoldScreenPolicy> foldScreenPolicy) override;
    void HandleHallChange(float angle, int hall, sptr<FoldScreenPolicy> foldScreenPolicy) override;
    void RegisterApplicationStateObserver() override;

private:
    FoldStatus GetNextFoldState(float angle, int hall);
    void UpdateSwitchScreenBoundaryForLargeFoldDevice(float, int);
    int allowUserSensorForLargeFoldDevice = 0;
};
} // namespace Rosen
} // namespace OHOS
#endif