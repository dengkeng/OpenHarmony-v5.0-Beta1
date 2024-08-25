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

#include "ohos_adapter/cpptoc/ark_audio_device_desc_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_audio_device_desc_adapter_get_device_id(struct _ark_audio_device_desc_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioDeviceDescAdapterCppToC::Get(self)->GetDeviceId();
}

ArkWebString ARK_WEB_CALLBACK ark_audio_device_desc_adapter_get_device_name(
    struct _ark_audio_device_desc_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkAudioDeviceDescAdapterCppToC::Get(self)->GetDeviceName();
}

} // namespace

ArkAudioDeviceDescAdapterCppToC::ArkAudioDeviceDescAdapterCppToC()
{
    GetStruct()->get_device_id = ark_audio_device_desc_adapter_get_device_id;
    GetStruct()->get_device_name = ark_audio_device_desc_adapter_get_device_name;
}

ArkAudioDeviceDescAdapterCppToC::~ArkAudioDeviceDescAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAudioDeviceDescAdapterCppToC, ArkAudioDeviceDescAdapter,
    ark_audio_device_desc_adapter_t>::kBridgeType = ARK_AUDIO_DEVICE_DESC_ADAPTER;

} // namespace OHOS::ArkWeb
