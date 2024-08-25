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

#include "ohos_nweb/ctocpp/ark_web_touch_handle_hot_zone_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkWebTouchHandleHotZoneCToCpp::SetWidth(double width)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_hot_zone_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_width, );

    // Execute
    _struct->set_width(_struct, width);
}

ARK_WEB_NO_SANITIZE
void ArkWebTouchHandleHotZoneCToCpp::SetHeight(double height)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_hot_zone_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_height, );

    // Execute
    _struct->set_height(_struct, height);
}

ArkWebTouchHandleHotZoneCToCpp::ArkWebTouchHandleHotZoneCToCpp() {}

ArkWebTouchHandleHotZoneCToCpp::~ArkWebTouchHandleHotZoneCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebTouchHandleHotZoneCToCpp, ArkWebTouchHandleHotZone,
    ark_web_touch_handle_hot_zone_t>::kBridgeType = ARK_WEB_TOUCH_HANDLE_HOT_ZONE;

} // namespace OHOS::ArkWeb
