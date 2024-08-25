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

#include "ohos_nweb/ctocpp/ark_web_media_source_info_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int ArkWebMediaSourceInfoCToCpp::GetType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_source_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_type, 0);

    // Execute
    return _struct->get_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebMediaSourceInfoCToCpp::GetFormat()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_source_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_format, ark_web_string_default);

    // Execute
    return _struct->get_format(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebMediaSourceInfoCToCpp::GetSource()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_media_source_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_source, ark_web_string_default);

    // Execute
    return _struct->get_source(_struct);
}

ArkWebMediaSourceInfoCToCpp::ArkWebMediaSourceInfoCToCpp() {}

ArkWebMediaSourceInfoCToCpp::~ArkWebMediaSourceInfoCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebMediaSourceInfoCToCpp, ArkWebMediaSourceInfo,
    ark_web_media_source_info_t>::kBridgeType = ARK_WEB_MEDIA_SOURCE_INFO;

} // namespace OHOS::ArkWeb
