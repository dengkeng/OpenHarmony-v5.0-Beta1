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

#include "ohos_nweb/cpptoc/ark_web_touch_point_info_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int ARK_WEB_CALLBACK ark_web_touch_point_info_get_id(struct _ark_web_touch_point_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkWebTouchPointInfoCppToC::Get(self)->GetId();
}

double ARK_WEB_CALLBACK ark_web_touch_point_info_get_x(struct _ark_web_touch_point_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkWebTouchPointInfoCppToC::Get(self)->GetX();
}

double ARK_WEB_CALLBACK ark_web_touch_point_info_get_y(struct _ark_web_touch_point_info_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkWebTouchPointInfoCppToC::Get(self)->GetY();
}

} // namespace

ArkWebTouchPointInfoCppToC::ArkWebTouchPointInfoCppToC()
{
    GetStruct()->get_id = ark_web_touch_point_info_get_id;
    GetStruct()->get_x = ark_web_touch_point_info_get_x;
    GetStruct()->get_y = ark_web_touch_point_info_get_y;
}

ArkWebTouchPointInfoCppToC::~ArkWebTouchPointInfoCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkWebTouchPointInfoCppToC, ArkWebTouchPointInfo, ark_web_touch_point_info_t>::kBridgeType =
        ARK_WEB_TOUCH_POINT_INFO;

} // namespace OHOS::ArkWeb
