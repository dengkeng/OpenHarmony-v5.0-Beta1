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

#include "ohos_adapter/cpptoc/ark_location_request_config_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_location_request_config_set_scenario(
    struct _ark_location_request_config_t* self, int32_t scenario)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetScenario(scenario);
}

void ARK_WEB_CALLBACK ark_location_request_config_set_fix_number(
    struct _ark_location_request_config_t* self, int32_t number)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetFixNumber(number);
}

void ARK_WEB_CALLBACK ark_location_request_config_set_max_accuracy(
    struct _ark_location_request_config_t* self, int32_t maxAccuary)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetMaxAccuracy(maxAccuary);
}

void ARK_WEB_CALLBACK ark_location_request_config_set_distance_interval(
    struct _ark_location_request_config_t* self, int32_t disInterval)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetDistanceInterval(disInterval);
}

void ARK_WEB_CALLBACK ark_location_request_config_set_time_interval(
    struct _ark_location_request_config_t* self, int32_t timeInterval)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetTimeInterval(timeInterval);
}

void ARK_WEB_CALLBACK ark_location_request_config_set_priority(
    struct _ark_location_request_config_t* self, int32_t priority)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkLocationRequestConfigCppToC::Get(self)->SetPriority(priority);
}

} // namespace

ArkLocationRequestConfigCppToC::ArkLocationRequestConfigCppToC()
{
    GetStruct()->set_scenario = ark_location_request_config_set_scenario;
    GetStruct()->set_fix_number = ark_location_request_config_set_fix_number;
    GetStruct()->set_max_accuracy = ark_location_request_config_set_max_accuracy;
    GetStruct()->set_distance_interval = ark_location_request_config_set_distance_interval;
    GetStruct()->set_time_interval = ark_location_request_config_set_time_interval;
    GetStruct()->set_priority = ark_location_request_config_set_priority;
}

ArkLocationRequestConfigCppToC::~ArkLocationRequestConfigCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkLocationRequestConfigCppToC, ArkLocationRequestConfig,
    ark_location_request_config_t>::kBridgeType = ARK_LOCATION_REQUEST_CONFIG;

} // namespace OHOS::ArkWeb
