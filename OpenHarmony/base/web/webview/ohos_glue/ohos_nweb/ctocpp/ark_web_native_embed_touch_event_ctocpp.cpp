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

#include "ohos_nweb/ctocpp/ark_web_native_embed_touch_event_ctocpp.h"

#include "ohos_nweb/ctocpp/ark_web_gesture_event_result_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_x, 0);

    // Execute
    return _struct->get_x(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_y, 0);

    // Execute
    return _struct->get_y(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebNativeEmbedTouchEventCToCpp::GetId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_id, 0);

    // Execute
    return _struct->get_id(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkWebNativeEmbedTouchEventCToCpp::GetType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_type, 0);

    // Execute
    return _struct->get_type(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetOffsetX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_offset_x, 0);

    // Execute
    return _struct->get_offset_x(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetOffsetY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_offset_y, 0);

    // Execute
    return _struct->get_offset_y(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetScreenX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_screen_x, 0);

    // Execute
    return _struct->get_screen_x(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebNativeEmbedTouchEventCToCpp::GetScreenY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_screen_y, 0);

    // Execute
    return _struct->get_screen_y(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebNativeEmbedTouchEventCToCpp::GetEmbedId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_embed_id, ark_web_string_default);

    // Execute
    return _struct->get_embed_id(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebGestureEventResult> ArkWebNativeEmbedTouchEventCToCpp::GetResult()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_native_embed_touch_event_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_result, nullptr);

    // Execute
    ark_web_gesture_event_result_t* _retval = _struct->get_result(_struct);

    // Return type: refptr_same
    return ArkWebGestureEventResultCToCpp::Invert(_retval);
}

ArkWebNativeEmbedTouchEventCToCpp::ArkWebNativeEmbedTouchEventCToCpp() {}

ArkWebNativeEmbedTouchEventCToCpp::~ArkWebNativeEmbedTouchEventCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebNativeEmbedTouchEventCToCpp, ArkWebNativeEmbedTouchEvent,
    ark_web_native_embed_touch_event_t>::kBridgeType = ARK_WEB_NATIVE_EMBED_TOUCH_EVENT;

} // namespace OHOS::ArkWeb
