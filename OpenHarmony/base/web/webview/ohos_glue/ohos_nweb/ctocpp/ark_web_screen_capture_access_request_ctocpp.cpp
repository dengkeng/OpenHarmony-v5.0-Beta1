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

#include "ohos_nweb/ctocpp/ark_web_screen_capture_access_request_ctocpp.h"

#include "ohos_nweb/cpptoc/ark_web_screen_capture_config_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkWebScreenCaptureAccessRequestCToCpp::Agree(ArkWebRefPtr<ArkWebScreenCaptureConfig> config)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_screen_capture_access_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, agree, );

    // Execute
    _struct->agree(_struct, ArkWebScreenCaptureConfigCppToC::Invert(config));
}

ARK_WEB_NO_SANITIZE
void ArkWebScreenCaptureAccessRequestCToCpp::Refuse()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_screen_capture_access_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, refuse, );

    // Execute
    _struct->refuse(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebScreenCaptureAccessRequestCToCpp::Origin()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_screen_capture_access_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, origin, ark_web_string_default);

    // Execute
    return _struct->origin(_struct);
}

ArkWebScreenCaptureAccessRequestCToCpp::ArkWebScreenCaptureAccessRequestCToCpp() {}

ArkWebScreenCaptureAccessRequestCToCpp::~ArkWebScreenCaptureAccessRequestCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebScreenCaptureAccessRequestCToCpp, ArkWebScreenCaptureAccessRequest,
    ark_web_screen_capture_access_request_t>::kBridgeType = ARK_WEB_SCREEN_CAPTURE_ACCESS_REQUEST;

} // namespace OHOS::ArkWeb
