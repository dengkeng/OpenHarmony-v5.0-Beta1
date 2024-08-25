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

#include "ohos_nweb/cpptoc/ark_web_js_result_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebValue ARK_WEB_CALLBACK ark_web_js_result_callback_get_java_script_result(
    struct _ark_web_js_result_callback_t* self, ArkWebValueVector args, const ArkWebString* method,
    const ArkWebString* object_name, int32_t routing_id, int32_t object_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_value_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(method, ark_web_value_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(object_name, ark_web_value_default);

    // Execute
    return ArkWebJsResultCallbackCppToC::Get(self)->GetJavaScriptResult(
        args, *method, *object_name, routing_id, object_id);
}

bool ARK_WEB_CALLBACK ark_web_js_result_callback_has_java_script_object_methods(
    struct _ark_web_js_result_callback_t* self, int32_t object_id, const ArkWebString* method_name)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(method_name, false);

    // Execute
    return ArkWebJsResultCallbackCppToC::Get(self)->HasJavaScriptObjectMethods(object_id, *method_name);
}

ArkWebValue ARK_WEB_CALLBACK ark_web_js_result_callback_get_java_script_object_methods(
    struct _ark_web_js_result_callback_t* self, int32_t object_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_value_default);

    // Execute
    return ArkWebJsResultCallbackCppToC::Get(self)->GetJavaScriptObjectMethods(object_id);
}

void ARK_WEB_CALLBACK ark_web_js_result_callback_remove_java_script_object_holder(
    struct _ark_web_js_result_callback_t* self, int32_t holder, int32_t object_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebJsResultCallbackCppToC::Get(self)->RemoveJavaScriptObjectHolder(holder, object_id);
}

void ARK_WEB_CALLBACK ark_web_js_result_callback_remove_transient_java_script_object(
    struct _ark_web_js_result_callback_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebJsResultCallbackCppToC::Get(self)->RemoveTransientJavaScriptObject();
}

ArkWebValue ARK_WEB_CALLBACK ark_web_js_result_callback_get_java_script_result_flowbuf(
    struct _ark_web_js_result_callback_t* self, ArkWebValueVector args, const ArkWebString* method,
    const ArkWebString* object_name, int fd, int32_t routing_id, int32_t object_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_value_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(method, ark_web_value_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(object_name, ark_web_value_default);

    // Execute
    return ArkWebJsResultCallbackCppToC::Get(self)->GetJavaScriptResultFlowbuf(
        args, *method, *object_name, fd, routing_id, object_id);
}

} // namespace

ArkWebJsResultCallbackCppToC::ArkWebJsResultCallbackCppToC()
{
    GetStruct()->get_java_script_result = ark_web_js_result_callback_get_java_script_result;
    GetStruct()->has_java_script_object_methods = ark_web_js_result_callback_has_java_script_object_methods;
    GetStruct()->get_java_script_object_methods = ark_web_js_result_callback_get_java_script_object_methods;
    GetStruct()->remove_java_script_object_holder = ark_web_js_result_callback_remove_java_script_object_holder;
    GetStruct()->remove_transient_java_script_object = ark_web_js_result_callback_remove_transient_java_script_object;
    GetStruct()->get_java_script_result_flowbuf = ark_web_js_result_callback_get_java_script_result_flowbuf;
}

ArkWebJsResultCallbackCppToC::~ArkWebJsResultCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebJsResultCallbackCppToC, ArkWebJsResultCallback,
    ark_web_js_result_callback_t>::kBridgeType = ARK_WEB_JS_RESULT_CALLBACK;

} // namespace OHOS::ArkWeb
