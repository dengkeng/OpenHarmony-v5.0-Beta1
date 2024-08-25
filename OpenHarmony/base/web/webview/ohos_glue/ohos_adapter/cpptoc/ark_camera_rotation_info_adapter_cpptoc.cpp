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

#include "ohos_adapter/cpptoc/ark_camera_rotation_info_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_camera_rotation_info_adapter_get_rotation(struct _ark_camera_rotation_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCameraRotationInfoAdapterCppToC::Get(self)->GetRotation();
}

bool ARK_WEB_CALLBACK ark_camera_rotation_info_adapter_get_is_flip_x(struct _ark_camera_rotation_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkCameraRotationInfoAdapterCppToC::Get(self)->GetIsFlipX();
}

bool ARK_WEB_CALLBACK ark_camera_rotation_info_adapter_get_is_flip_y(struct _ark_camera_rotation_info_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkCameraRotationInfoAdapterCppToC::Get(self)->GetIsFlipY();
}

} // namespace

ArkCameraRotationInfoAdapterCppToC::ArkCameraRotationInfoAdapterCppToC()
{
    GetStruct()->get_rotation = ark_camera_rotation_info_adapter_get_rotation;
    GetStruct()->get_is_flip_x = ark_camera_rotation_info_adapter_get_is_flip_x;
    GetStruct()->get_is_flip_y = ark_camera_rotation_info_adapter_get_is_flip_y;
}

ArkCameraRotationInfoAdapterCppToC::~ArkCameraRotationInfoAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkCameraRotationInfoAdapterCppToC, ArkCameraRotationInfoAdapter,
    ark_camera_rotation_info_adapter_t>::kBridgeType = ARK_CAMERA_ROTATION_INFO_ADAPTER;

} // namespace OHOS::ArkWeb
