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

#include "ohos_adapter/cpptoc/ark_media_codec_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_producer_surface_adapter_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_codec_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_codec_config_para_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_create_video_codec_by_mime(
    struct _ark_media_codec_adapter_t* self, const ArkWebString mimetype)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->CreateVideoCodecByMime(mimetype);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_create_video_codec_by_name(
    struct _ark_media_codec_adapter_t* self, const ArkWebString name)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->CreateVideoCodecByName(name);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_set_codec_callback(
    struct _ark_media_codec_adapter_t* self, ark_codec_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->SetCodecCallback(ArkCodecCallbackAdapterCToCpp::Invert(callback));
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_configure(
    struct _ark_media_codec_adapter_t* self, ark_codec_config_para_adapter_t* config)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Configure(ArkCodecConfigParaAdapterCToCpp::Invert(config));
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_prepare(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Prepare();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_start(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Start();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_stop(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Stop();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_reset(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Reset();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_release(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->Release();
}

ark_producer_surface_adapter_t* ARK_WEB_CALLBACK ark_media_codec_adapter_create_input_surface(
    struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkProducerSurfaceAdapter> _retval = ArkMediaCodecAdapterCppToC::Get(self)->CreateInputSurface();

    // Return type: refptr_same
    return ArkProducerSurfaceAdapterCppToC::Invert(_retval);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_release_output_buffer(
    struct _ark_media_codec_adapter_t* self, uint32_t index, bool isRender)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->ReleaseOutputBuffer(index, isRender);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_adapter_request_key_frame_soon(struct _ark_media_codec_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecAdapterCppToC::Get(self)->RequestKeyFrameSoon();
}

} // namespace

ArkMediaCodecAdapterCppToC::ArkMediaCodecAdapterCppToC()
{
    GetStruct()->create_video_codec_by_mime = ark_media_codec_adapter_create_video_codec_by_mime;
    GetStruct()->create_video_codec_by_name = ark_media_codec_adapter_create_video_codec_by_name;
    GetStruct()->set_codec_callback = ark_media_codec_adapter_set_codec_callback;
    GetStruct()->configure = ark_media_codec_adapter_configure;
    GetStruct()->prepare = ark_media_codec_adapter_prepare;
    GetStruct()->start = ark_media_codec_adapter_start;
    GetStruct()->stop = ark_media_codec_adapter_stop;
    GetStruct()->reset = ark_media_codec_adapter_reset;
    GetStruct()->release = ark_media_codec_adapter_release;
    GetStruct()->create_input_surface = ark_media_codec_adapter_create_input_surface;
    GetStruct()->release_output_buffer = ark_media_codec_adapter_release_output_buffer;
    GetStruct()->request_key_frame_soon = ark_media_codec_adapter_request_key_frame_soon;
}

ArkMediaCodecAdapterCppToC::~ArkMediaCodecAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkMediaCodecAdapterCppToC, ArkMediaCodecAdapter, ark_media_codec_adapter_t>::kBridgeType =
        ARK_MEDIA_CODEC_ADAPTER;

} // namespace OHOS::ArkWeb
