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

#include "ohos_nweb/cpptoc/ark_web_accessibility_event_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_web_accessibility_event_callback_on_accessibility_event(
    struct _ark_web_accessibility_event_callback_t* self, int64_t accessibility_id, uint32_t event_type)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkWebAccessibilityEventCallbackCppToC::Get(self)->OnAccessibilityEvent(accessibility_id, event_type);
}

} // namespace

ArkWebAccessibilityEventCallbackCppToC::ArkWebAccessibilityEventCallbackCppToC()
{
    GetStruct()->on_accessibility_event = ark_web_accessibility_event_callback_on_accessibility_event;
}

ArkWebAccessibilityEventCallbackCppToC::~ArkWebAccessibilityEventCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebAccessibilityEventCallbackCppToC, ArkWebAccessibilityEventCallback,
    ark_web_accessibility_event_callback_t>::kBridgeType = ARK_WEB_ACCESSIBILITY_EVENT_CALLBACK;

} // namespace OHOS::ArkWeb
