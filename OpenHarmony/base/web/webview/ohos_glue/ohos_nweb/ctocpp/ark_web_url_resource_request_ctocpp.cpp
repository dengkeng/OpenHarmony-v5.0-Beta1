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

#include "ohos_nweb/ctocpp/ark_web_url_resource_request_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceRequestCToCpp::Url()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, url, ark_web_string_default);

    // Execute
    return _struct->url(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceRequestCToCpp::Method()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, method, ark_web_string_default);

    // Execute
    return _struct->method(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebUrlResourceRequestCToCpp::FromGesture()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, from_gesture, false);

    // Execute
    return _struct->from_gesture(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebStringMap ArkWebUrlResourceRequestCToCpp::RequestHeaders()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_map_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, request_headers, ark_web_string_map_default);

    // Execute
    return _struct->request_headers(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebUrlResourceRequestCToCpp::IsAboutMainFrame()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_about_main_frame, false);

    // Execute
    return _struct->is_about_main_frame(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebUrlResourceRequestCToCpp::IsRequestRedirect()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_request_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_request_redirect, false);

    // Execute
    return _struct->is_request_redirect(_struct);
}

ArkWebUrlResourceRequestCToCpp::ArkWebUrlResourceRequestCToCpp() {}

ArkWebUrlResourceRequestCToCpp::~ArkWebUrlResourceRequestCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebUrlResourceRequestCToCpp, ArkWebUrlResourceRequest,
    ark_web_url_resource_request_t>::kBridgeType = ARK_WEB_URL_RESOURCE_REQUEST;

} // namespace OHOS::ArkWeb
