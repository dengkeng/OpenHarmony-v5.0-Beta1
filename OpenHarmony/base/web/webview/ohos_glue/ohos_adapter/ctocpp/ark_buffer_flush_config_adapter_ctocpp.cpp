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

#include "ohos_adapter/ctocpp/ark_buffer_flush_config_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkBufferFlushConfigAdapterCToCpp::GetX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_flush_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_x, 0);

    // Execute
    return _struct->get_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferFlushConfigAdapterCToCpp::GetY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_flush_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_y, 0);

    // Execute
    return _struct->get_y(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferFlushConfigAdapterCToCpp::GetW()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_flush_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_w, 0);

    // Execute
    return _struct->get_w(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkBufferFlushConfigAdapterCToCpp::GetH()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_flush_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_h, 0);

    // Execute
    return _struct->get_h(_struct);
}

ARK_WEB_NO_SANITIZE
int64_t ArkBufferFlushConfigAdapterCToCpp::GetTimestamp()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_buffer_flush_config_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_timestamp, 0);

    // Execute
    return _struct->get_timestamp(_struct);
}

ArkBufferFlushConfigAdapterCToCpp::ArkBufferFlushConfigAdapterCToCpp() {}

ArkBufferFlushConfigAdapterCToCpp::~ArkBufferFlushConfigAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkBufferFlushConfigAdapterCToCpp, ArkBufferFlushConfigAdapter,
    ark_buffer_flush_config_adapter_t>::kBridgeType = ARK_BUFFER_FLUSH_CONFIG_ADAPTER;

} // namespace OHOS::ArkWeb
