/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_FEATURE_H
#define TELEPHONY_IMS_FEATURE_H

#include <vector>

#include "ims_reg_types.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Indicates the specific IMS capability type,
 * includes voice, video, UT.
 */
enum ImsCapabilityType {
    /**
     * Indicate the IMS voice capability.
     */
    CAPABILITY_TYPE_VOICE = 0,
    /**
     * Indicate the IMS video capability.
     */
    CAPABILITY_TYPE_VIDEO = 1,
    /**
     * Indicate the IMS UT capability.
     */
    CAPABILITY_TYPE_UT = 2,
};

/**
 * @brief Indicates the IMS capability type, status and the registered RAT.
 */
struct ImsCapability {
    /**
     * Indicates the specific IMS capability type. {@link ImsCapabilityType}
     */
    ImsCapabilityType imsCapabilityType = ImsCapabilityType::CAPABILITY_TYPE_VOICE;
    /**
     * Indicates the IMS register RAT. none, LTE, NR, IWLAN {@link ImsRegTech}
     */
    ImsRegTech imsRadioTech = ImsRegTech::IMS_REG_TECH_NONE;
    /**
     * Indicates whether the specific IMS capability is enabled.
     * true: enabled, false: disabled
     */
    bool enable = false;
};

/**
 * @brief Indicates a list of IMS capability information.
 */
struct ImsCapabilityList {
    /**
     * Indicates a list of IMS capability information. {@link ImsCapability}
     */
    std::vector<ImsCapability> imsCapabilities {};
};

/**
 * @brief Indicate the IMS feature status.
 */
enum ImsFeatureIntResult {
    /**
     * Indicates the IMS feature statue is unknown.
     */
    IMS_FEATURE_INT_RESULT_UNKNOWN = -1,
    /**
     * Indicates the IMS feature statue is disabled.
     */
    IMS_FEATURE_INT_VALUE_DISABLED = 0,
    /**
     * Indicates the IMS feature statue is enabled.
     */
    IMS_FEATURE_INT_VALUE_ENABLED = 1
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_FEATURE_H
