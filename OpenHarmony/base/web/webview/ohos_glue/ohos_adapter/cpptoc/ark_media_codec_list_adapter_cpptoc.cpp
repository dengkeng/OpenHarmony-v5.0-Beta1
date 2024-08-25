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

#include "ohos_adapter/cpptoc/ark_media_codec_list_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_capability_data_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ark_capability_data_adapter_t* ARK_WEB_CALLBACK ark_media_codec_list_adapter_get_codec_capability(
    struct _ark_media_codec_list_adapter_t* self, const ArkWebString mime, const bool isCodec)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkCapabilityDataAdapter> _retval =
        ArkMediaCodecListAdapterCppToC::Get(self)->GetCodecCapability(mime, isCodec);

    // Return type: refptr_same
    return ArkCapabilityDataAdapterCppToC::Invert(_retval);
}

} // namespace

ArkMediaCodecListAdapterCppToC::ArkMediaCodecListAdapterCppToC()
{
    GetStruct()->get_codec_capability = ark_media_codec_list_adapter_get_codec_capability;
}

ArkMediaCodecListAdapterCppToC::~ArkMediaCodecListAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkMediaCodecListAdapterCppToC, ArkMediaCodecListAdapter,
    ark_media_codec_list_adapter_t>::kBridgeType = ARK_MEDIA_CODEC_LIST_ADAPTER;

} // namespace OHOS::ArkWeb
