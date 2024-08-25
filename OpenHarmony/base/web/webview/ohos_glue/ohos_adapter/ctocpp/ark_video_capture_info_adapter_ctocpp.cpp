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

#include "ohos_adapter/ctocpp/ark_video_capture_info_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
uint64_t ArkVideoCaptureInfoAdapterCToCpp::GetDisplayId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_display_id, 0);

    // Execute
    return _struct->get_display_id(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebInt32List ArkVideoCaptureInfoAdapterCToCpp::GetTaskIDs()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_int32_list_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_task_ids, ark_web_int32_list_default);

    // Execute
    return _struct->get_task_ids(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkVideoCaptureInfoAdapterCToCpp::GetVideoFrameWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_frame_width, 0);

    // Execute
    return _struct->get_video_frame_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkVideoCaptureInfoAdapterCToCpp::GetVideoFrameHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_frame_height, 0);

    // Execute
    return _struct->get_video_frame_height(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkVideoCaptureInfoAdapterCToCpp::GetVideoSourceType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_capture_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_source_type, 0);

    // Execute
    return _struct->get_video_source_type(_struct);
}

ArkVideoCaptureInfoAdapterCToCpp::ArkVideoCaptureInfoAdapterCToCpp() {}

ArkVideoCaptureInfoAdapterCToCpp::~ArkVideoCaptureInfoAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkVideoCaptureInfoAdapterCToCpp, ArkVideoCaptureInfoAdapter,
    ark_video_capture_info_adapter_t>::kBridgeType = ARK_VIDEO_CAPTURE_INFO_ADAPTER;

} // namespace OHOS::ArkWeb
