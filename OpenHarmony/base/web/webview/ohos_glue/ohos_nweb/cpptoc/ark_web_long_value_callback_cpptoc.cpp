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

#include "ohos_nweb/cpptoc/ark_web_long_value_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_web_long_value_callback_on_receive_value(
    struct _ark_web_long_value_callback_t* self, long value)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebLongValueCallbackCppToC::Get(self)->OnReceiveValue(value);
}

} // namespace

ArkWebLongValueCallbackCppToC::ArkWebLongValueCallbackCppToC()
{
    GetStruct()->on_receive_value = ark_web_long_value_callback_on_receive_value;
}

ArkWebLongValueCallbackCppToC::~ArkWebLongValueCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebLongValueCallbackCppToC, ArkWebLongValueCallback,
    ark_web_long_value_callback_t>::kBridgeType = ARK_WEB_LONG_VALUE_CALLBACK;

} // namespace OHOS::ArkWeb
