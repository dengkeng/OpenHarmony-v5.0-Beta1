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

#include "ohos_adapter/ctocpp/ark_frame_available_listener_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void* ArkFrameAvailableListenerCToCpp::GetContext()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_frame_available_listener_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_context, nullptr);

    // Execute
    return _struct->get_context(_struct);
}

ARK_WEB_NO_SANITIZE
void* ArkFrameAvailableListenerCToCpp::GetOnFrameAvailableCb()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_frame_available_listener_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_on_frame_available_cb, nullptr);

    // Execute
    return _struct->get_on_frame_available_cb(_struct);
}

ArkFrameAvailableListenerCToCpp::ArkFrameAvailableListenerCToCpp() {}

ArkFrameAvailableListenerCToCpp::~ArkFrameAvailableListenerCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkFrameAvailableListenerCToCpp, ArkFrameAvailableListener,
    ark_frame_available_listener_t>::kBridgeType = ARK_FRAME_AVAILABLE_LISTENER;

} // namespace OHOS::ArkWeb
