/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "system_info_collector.h"

#include "device_profile_log.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "securec.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_constants.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SystemInfoCollector";

const std::string SERVICE_ID = "system";
const std::string SERVICE_TYPE = "system";
const std::string SYSTEM_OS_TYPE = "type";
const std::string DEVICE_OHOS_VERSION = "harmonyVersion";
const std::string DEVICE_API_LEVEL = "harmonyApiLevel";
const std::string DEVICE_OHOS_NAME = "OpenHarmony";
constexpr int32_t OHOS_TYPE_UNKNOWN = -1;
constexpr int32_t OHOS_TYPE = 10;
}

bool SystemInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    jsonData[SYSTEM_OS_TYPE] = GetOsType();
    jsonData[DEVICE_OHOS_VERSION] = GetOsVersion();
    jsonData[DEVICE_API_LEVEL] = GetSdkApiVersion();
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}

int32_t SystemInfoCollector::GetOsType()
{
    std::string osFullName = DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainOsFullName();
    if (osFullName.empty() || osFullName.size() >= DistributedDeviceProfile::MAX_STRING_LEN) {
        HILOGI("osFullName size is invalid!");
        return OHOS_TYPE_UNKNOWN;
    }
    size_t found = osFullName.find(DEVICE_OHOS_NAME);
    if (found != std::string::npos) {
        HILOGI("osFullName is invalid!");
        return OHOS_TYPE_UNKNOWN;
    }
    return OHOS_TYPE;
}

std::string SystemInfoCollector::GetOsVersion()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDisplayVersion();
}
} // namespace DeviceProfile
} // namespace OHOS