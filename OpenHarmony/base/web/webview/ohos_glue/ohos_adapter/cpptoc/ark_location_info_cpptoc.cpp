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

#include "ohos_adapter/cpptoc/ark_location_info_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

double ARK_WEB_CALLBACK ark_location_info_get_latitude(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetLatitude();
}

double ARK_WEB_CALLBACK ark_location_info_get_longitude(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetLongitude();
}

double ARK_WEB_CALLBACK ark_location_info_get_altitude(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetAltitude();
}

float ARK_WEB_CALLBACK ark_location_info_get_accuracy(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetAccuracy();
}

float ARK_WEB_CALLBACK ark_location_info_get_speed(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetSpeed();
}

double ARK_WEB_CALLBACK ark_location_info_get_direction(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetDirection();
}

int64_t ARK_WEB_CALLBACK ark_location_info_get_time_stamp(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetTimeStamp();
}

int64_t ARK_WEB_CALLBACK ark_location_info_get_time_since_boot(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetTimeSinceBoot();
}

ArkWebStringVector ARK_WEB_CALLBACK ark_location_info_get_additions(struct _ark_location_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_vector_default);

    // Execute
    return ArkLocationInfoCppToC::Get(self)->GetAdditions();
}

} // namespace

ArkLocationInfoCppToC::ArkLocationInfoCppToC()
{
    GetStruct()->get_latitude = ark_location_info_get_latitude;
    GetStruct()->get_longitude = ark_location_info_get_longitude;
    GetStruct()->get_altitude = ark_location_info_get_altitude;
    GetStruct()->get_accuracy = ark_location_info_get_accuracy;
    GetStruct()->get_speed = ark_location_info_get_speed;
    GetStruct()->get_direction = ark_location_info_get_direction;
    GetStruct()->get_time_stamp = ark_location_info_get_time_stamp;
    GetStruct()->get_time_since_boot = ark_location_info_get_time_since_boot;
    GetStruct()->get_additions = ark_location_info_get_additions;
}

ArkLocationInfoCppToC::~ArkLocationInfoCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkLocationInfoCppToC, ArkLocationInfo, ark_location_info_t>::kBridgeType =
    ARK_LOCATION_INFO;

} // namespace OHOS::ArkWeb
