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

#include "ohos_adapter/cpptoc/ark_native_image_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_frame_available_listener_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_native_image_adapter_create_native_image(
    struct _ark_native_image_adapter_t* self, uint32_t textureId, uint32_t textureTarget)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkNativeImageAdapterCppToC::Get(self)->CreateNativeImage(textureId, textureTarget);
}

void* ARK_WEB_CALLBACK ark_native_image_adapter_aquire_native_window_from_native_image(
    struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->AquireNativeWindowFromNativeImage();
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_attach_context(
    struct _ark_native_image_adapter_t* self, uint32_t textureId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->AttachContext(textureId);
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_detach_context(struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->DetachContext();
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_update_surface_image(struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->UpdateSurfaceImage();
}

int64_t ARK_WEB_CALLBACK ark_native_image_adapter_get_timestamp(struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->GetTimestamp();
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_get_transform_matrix(
    struct _ark_native_image_adapter_t* self, float matrix[16])
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->GetTransformMatrix(matrix);
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_get_surface_id(
    struct _ark_native_image_adapter_t* self, uint64_t* surfaceId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(surfaceId, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->GetSurfaceId(surfaceId);
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_set_on_frame_available_listener(
    struct _ark_native_image_adapter_t* self, ark_frame_available_listener_t* listener)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->SetOnFrameAvailableListener(
        ArkFrameAvailableListenerCToCpp::Invert(listener));
}

int32_t ARK_WEB_CALLBACK ark_native_image_adapter_unset_on_frame_available_listener(
    struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkNativeImageAdapterCppToC::Get(self)->UnsetOnFrameAvailableListener();
}

void ARK_WEB_CALLBACK ark_native_image_adapter_destroy_native_image(struct _ark_native_image_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkNativeImageAdapterCppToC::Get(self)->DestroyNativeImage();
}

} // namespace

ArkNativeImageAdapterCppToC::ArkNativeImageAdapterCppToC()
{
    GetStruct()->create_native_image = ark_native_image_adapter_create_native_image;
    GetStruct()->aquire_native_window_from_native_image =
        ark_native_image_adapter_aquire_native_window_from_native_image;
    GetStruct()->attach_context = ark_native_image_adapter_attach_context;
    GetStruct()->detach_context = ark_native_image_adapter_detach_context;
    GetStruct()->update_surface_image = ark_native_image_adapter_update_surface_image;
    GetStruct()->get_timestamp = ark_native_image_adapter_get_timestamp;
    GetStruct()->get_transform_matrix = ark_native_image_adapter_get_transform_matrix;
    GetStruct()->get_surface_id = ark_native_image_adapter_get_surface_id;
    GetStruct()->set_on_frame_available_listener = ark_native_image_adapter_set_on_frame_available_listener;
    GetStruct()->unset_on_frame_available_listener = ark_native_image_adapter_unset_on_frame_available_listener;
    GetStruct()->destroy_native_image = ark_native_image_adapter_destroy_native_image;
}

ArkNativeImageAdapterCppToC::~ArkNativeImageAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkNativeImageAdapterCppToC, ArkNativeImageAdapter,
    ark_native_image_adapter_t>::kBridgeType = ARK_NATIVE_IMAGE_ADAPTER;

} // namespace OHOS::ArkWeb
