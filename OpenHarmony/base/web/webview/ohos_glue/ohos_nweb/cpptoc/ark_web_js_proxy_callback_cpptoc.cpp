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

#include "ohos_nweb/cpptoc/ark_web_js_proxy_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebString ARK_WEB_CALLBACK ark_web_js_proxy_callback_get_method_name(struct _ark_web_js_proxy_callback_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkWebJsProxyCallbackCppToC::Get(self)->GetMethodName();
}

NativeArkWebOnJavaScriptProxyCallback ARK_WEB_CALLBACK ark_web_js_proxy_callback_get_method_callback(
    struct _ark_web_js_proxy_callback_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkWebJsProxyCallbackCppToC::Get(self)->GetMethodCallback();
}

} // namespace

ArkWebJsProxyCallbackCppToC::ArkWebJsProxyCallbackCppToC()
{
    GetStruct()->get_method_name = ark_web_js_proxy_callback_get_method_name;
    GetStruct()->get_method_callback = ark_web_js_proxy_callback_get_method_callback;
}

ArkWebJsProxyCallbackCppToC::~ArkWebJsProxyCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebJsProxyCallbackCppToC, ArkWebJsProxyCallback,
    ark_web_js_proxy_callback_t>::kBridgeType = ARK_WEB_JS_PROXY_CALLBACK;

} // namespace OHOS::ArkWeb
