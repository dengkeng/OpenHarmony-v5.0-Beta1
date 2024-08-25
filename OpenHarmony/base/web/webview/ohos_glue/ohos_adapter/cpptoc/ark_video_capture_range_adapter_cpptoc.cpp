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

#include "ohos_adapter/cpptoc/ark_video_capture_range_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

double ARK_WEB_CALLBACK ark_video_capture_range_adapter_get_min(struct _ark_video_capture_range_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoCaptureRangeAdapterCppToC::Get(self)->GetMin();
}

double ARK_WEB_CALLBACK ark_video_capture_range_adapter_get_max(struct _ark_video_capture_range_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoCaptureRangeAdapterCppToC::Get(self)->GetMax();
}

double ARK_WEB_CALLBACK ark_video_capture_range_adapter_get_step(struct _ark_video_capture_range_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoCaptureRangeAdapterCppToC::Get(self)->GetStep();
}

double ARK_WEB_CALLBACK ark_video_capture_range_adapter_get_current(struct _ark_video_capture_range_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkVideoCaptureRangeAdapterCppToC::Get(self)->GetCurrent();
}

} // namespace

ArkVideoCaptureRangeAdapterCppToC::ArkVideoCaptureRangeAdapterCppToC()
{
    GetStruct()->get_min = ark_video_capture_range_adapter_get_min;
    GetStruct()->get_max = ark_video_capture_range_adapter_get_max;
    GetStruct()->get_step = ark_video_capture_range_adapter_get_step;
    GetStruct()->get_current = ark_video_capture_range_adapter_get_current;
}

ArkVideoCaptureRangeAdapterCppToC::~ArkVideoCaptureRangeAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkVideoCaptureRangeAdapterCppToC, ArkVideoCaptureRangeAdapter,
    ark_video_capture_range_adapter_t>::kBridgeType = ARK_VIDEO_CAPTURE_RANGE_ADAPTER;

} // namespace OHOS::ArkWeb
