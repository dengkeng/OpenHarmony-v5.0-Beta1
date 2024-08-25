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

#include "ohos_adapter/ctocpp/ark_video_enc_info_adapter_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkVideoEncInfoAdapterCToCpp::GetVideoCodecFormat()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_enc_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_codec_format, 0);

    // Execute
    return _struct->get_video_codec_format(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkVideoEncInfoAdapterCToCpp::GetVideoBitrate()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_enc_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_bitrate, 0);

    // Execute
    return _struct->get_video_bitrate(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkVideoEncInfoAdapterCToCpp::GetVideoFrameRate()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_video_enc_info_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_video_frame_rate, 0);

    // Execute
    return _struct->get_video_frame_rate(_struct);
}

ArkVideoEncInfoAdapterCToCpp::ArkVideoEncInfoAdapterCToCpp() {}

ArkVideoEncInfoAdapterCToCpp::~ArkVideoEncInfoAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkVideoEncInfoAdapterCToCpp, ArkVideoEncInfoAdapter,
    ark_video_enc_info_adapter_t>::kBridgeType = ARK_VIDEO_ENC_INFO_ADAPTER;

} // namespace OHOS::ArkWeb
