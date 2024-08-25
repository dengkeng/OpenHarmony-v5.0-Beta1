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

#include "ohos_adapter/cpptoc/ark_media_codec_decoder_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_decoder_callback_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_decoder_format_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_create_video_decoder_by_mime(
    struct _ark_media_codec_decoder_adapter_t* self, const ArkWebString* mimetype)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(mimetype, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->CreateVideoDecoderByMime(*mimetype);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_create_video_decoder_by_name(
    struct _ark_media_codec_decoder_adapter_t* self, const ArkWebString* name)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(name, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->CreateVideoDecoderByName(*name);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_configure_decoder(
    struct _ark_media_codec_decoder_adapter_t* self, ark_decoder_format_adapter_t* format)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->ConfigureDecoder(
        ArkDecoderFormatAdapterCToCpp::Invert(format));
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_set_parameter_decoder(
    struct _ark_media_codec_decoder_adapter_t* self, ark_decoder_format_adapter_t* format)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->SetParameterDecoder(
        ArkDecoderFormatAdapterCToCpp::Invert(format));
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_set_output_surface(
    struct _ark_media_codec_decoder_adapter_t* self, void* window)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(window, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->SetOutputSurface(window);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_prepare_decoder(
    struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->PrepareDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_start_decoder(struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->StartDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_stop_decoder(struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->StopDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_flush_decoder(struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->FlushDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_reset_decoder(struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->ResetDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_release_decoder(
    struct _ark_media_codec_decoder_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->ReleaseDecoder();
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_queue_input_buffer_dec(
    struct _ark_media_codec_decoder_adapter_t* self, uint32_t index, int64_t presentationTimeUs, int32_t size,
    int32_t offset, uint32_t flag)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->QueueInputBufferDec(
        index, presentationTimeUs, size, offset, flag);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_get_output_format_dec(
    struct _ark_media_codec_decoder_adapter_t* self, ark_decoder_format_adapter_t* format)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->GetOutputFormatDec(
        ArkDecoderFormatAdapterCToCpp::Invert(format));
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_release_output_buffer_dec(
    struct _ark_media_codec_decoder_adapter_t* self, uint32_t index, bool isRender)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->ReleaseOutputBufferDec(index, isRender);
}

int32_t ARK_WEB_CALLBACK ark_media_codec_decoder_adapter_set_callback_dec(
    struct _ark_media_codec_decoder_adapter_t* self, ark_decoder_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkMediaCodecDecoderAdapterCppToC::Get(self)->SetCallbackDec(
        ArkDecoderCallbackAdapterCToCpp::Invert(callback));
}

} // namespace

ArkMediaCodecDecoderAdapterCppToC::ArkMediaCodecDecoderAdapterCppToC()
{
    GetStruct()->create_video_decoder_by_mime = ark_media_codec_decoder_adapter_create_video_decoder_by_mime;
    GetStruct()->create_video_decoder_by_name = ark_media_codec_decoder_adapter_create_video_decoder_by_name;
    GetStruct()->configure_decoder = ark_media_codec_decoder_adapter_configure_decoder;
    GetStruct()->set_parameter_decoder = ark_media_codec_decoder_adapter_set_parameter_decoder;
    GetStruct()->set_output_surface = ark_media_codec_decoder_adapter_set_output_surface;
    GetStruct()->prepare_decoder = ark_media_codec_decoder_adapter_prepare_decoder;
    GetStruct()->start_decoder = ark_media_codec_decoder_adapter_start_decoder;
    GetStruct()->stop_decoder = ark_media_codec_decoder_adapter_stop_decoder;
    GetStruct()->flush_decoder = ark_media_codec_decoder_adapter_flush_decoder;
    GetStruct()->reset_decoder = ark_media_codec_decoder_adapter_reset_decoder;
    GetStruct()->release_decoder = ark_media_codec_decoder_adapter_release_decoder;
    GetStruct()->queue_input_buffer_dec = ark_media_codec_decoder_adapter_queue_input_buffer_dec;
    GetStruct()->get_output_format_dec = ark_media_codec_decoder_adapter_get_output_format_dec;
    GetStruct()->release_output_buffer_dec = ark_media_codec_decoder_adapter_release_output_buffer_dec;
    GetStruct()->set_callback_dec = ark_media_codec_decoder_adapter_set_callback_dec;
}

ArkMediaCodecDecoderAdapterCppToC::~ArkMediaCodecDecoderAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkMediaCodecDecoderAdapterCppToC, ArkMediaCodecDecoderAdapter,
    ark_media_codec_decoder_adapter_t>::kBridgeType = ARK_MEDIA_CODEC_DECODER_ADAPTER;

} // namespace OHOS::ArkWeb
