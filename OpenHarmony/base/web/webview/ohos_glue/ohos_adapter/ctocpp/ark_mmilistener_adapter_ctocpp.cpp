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

#include "ohos_adapter/ctocpp/ark_mmilistener_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkMMIListenerAdapterCToCpp::OnDeviceAdded(int32_t deviceId, const ArkWebString& type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmilistener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_device_added, );

    // Execute
    _struct->on_device_added(_struct, deviceId, &type);
}

ARK_WEB_NO_SANITIZE
void ArkMMIListenerAdapterCToCpp::OnDeviceRemoved(int32_t deviceId, const ArkWebString& type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_mmilistener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_device_removed, );

    // Execute
    _struct->on_device_removed(_struct, deviceId, &type);
}

ArkMMIListenerAdapterCToCpp::ArkMMIListenerAdapterCToCpp() {}

ArkMMIListenerAdapterCToCpp::~ArkMMIListenerAdapterCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkMMIListenerAdapterCToCpp, ArkMMIListenerAdapter, ark_mmilistener_adapter_t>::kBridgeType =
        ARK_MMILISTENER_ADAPTER;

} // namespace OHOS::ArkWeb
