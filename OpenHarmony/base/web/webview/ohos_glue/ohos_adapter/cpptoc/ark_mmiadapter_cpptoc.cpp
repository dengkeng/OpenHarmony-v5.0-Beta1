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

#include "ohos_adapter/cpptoc/ark_mmiadapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_mmidevice_info_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_mmiinput_listener_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_mmilistener_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

char* ARK_WEB_CALLBACK ark_mmiadapter_key_code_to_string(struct _ark_mmiadapter_t* self, int32_t keyCode)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->KeyCodeToString(keyCode);
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_register_mmiinput_listener(
    struct _ark_mmiadapter_t* self, ark_mmiinput_listener_adapter_t* eventCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->RegisterMMIInputListener(
        ArkMMIInputListenerAdapterCToCpp::Invert(eventCallback));
}

void ARK_WEB_CALLBACK ark_mmiadapter_unregister_mmiinput_listener(struct _ark_mmiadapter_t* self, int32_t monitorId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkMMIAdapterCppToC::Get(self)->UnregisterMMIInputListener(monitorId);
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_register_dev_listener(
    struct _ark_mmiadapter_t* self, ArkWebString type, ark_mmilistener_adapter_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->RegisterDevListener(type, ArkMMIListenerAdapterCToCpp::Invert(listener));
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_unregister_dev_listener(struct _ark_mmiadapter_t* self, ArkWebString type)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->UnregisterDevListener(type);
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_get_keyboard_type(
    struct _ark_mmiadapter_t* self, int32_t deviceId, int32_t* type)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(type, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->GetKeyboardType(deviceId, *type);
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_get_device_ids(struct _ark_mmiadapter_t* self, ArkWebInt32Vector* ids)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(ids, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->GetDeviceIds(*ids);
}

int32_t ARK_WEB_CALLBACK ark_mmiadapter_get_device_info(
    struct _ark_mmiadapter_t* self, int32_t deviceId, ark_mmidevice_info_adapter_t* info)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMMIAdapterCppToC::Get(self)->GetDeviceInfo(deviceId, ArkMMIDeviceInfoAdapterCToCpp::Invert(info));
}

} // namespace

ArkMMIAdapterCppToC::ArkMMIAdapterCppToC()
{
    GetStruct()->key_code_to_string = ark_mmiadapter_key_code_to_string;
    GetStruct()->register_mmiinput_listener = ark_mmiadapter_register_mmiinput_listener;
    GetStruct()->unregister_mmiinput_listener = ark_mmiadapter_unregister_mmiinput_listener;
    GetStruct()->register_dev_listener = ark_mmiadapter_register_dev_listener;
    GetStruct()->unregister_dev_listener = ark_mmiadapter_unregister_dev_listener;
    GetStruct()->get_keyboard_type = ark_mmiadapter_get_keyboard_type;
    GetStruct()->get_device_ids = ark_mmiadapter_get_device_ids;
    GetStruct()->get_device_info = ark_mmiadapter_get_device_info;
}

ArkMMIAdapterCppToC::~ArkMMIAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkMMIAdapterCppToC, ArkMMIAdapter, ark_mmiadapter_t>::kBridgeType =
    ARK_MMIADAPTER;

} // namespace OHOS::ArkWeb
