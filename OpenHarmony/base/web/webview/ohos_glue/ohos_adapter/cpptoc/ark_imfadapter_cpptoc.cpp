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

#include "ohos_adapter/cpptoc/ark_imfadapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_imfcursor_info_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_imftext_config_adapter_ctocpp.h"
#include "ohos_adapter/ctocpp/ark_imftext_listener_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_imfadapter_attach1(
    struct _ark_imfadapter_t* self, ark_imftext_listener_adapter_t* listener, bool isShowKeyboard)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkIMFAdapterCppToC::Get(self)->Attach(ArkIMFTextListenerAdapterCToCpp::Invert(listener), isShowKeyboard);
}

bool ARK_WEB_CALLBACK ark_imfadapter_attach2(struct _ark_imfadapter_t* self, ark_imftext_listener_adapter_t* listener,
    bool isShowKeyboard, ark_imftext_config_adapter_t* config)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkIMFAdapterCppToC::Get(self)->Attach(ArkIMFTextListenerAdapterCToCpp::Invert(listener), isShowKeyboard,
        ArkIMFTextConfigAdapterCToCpp::Invert(config));
}

void ARK_WEB_CALLBACK ark_imfadapter_show_current_input(struct _ark_imfadapter_t* self, const int32_t* inputType)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(inputType, );

    // Execute
    ArkIMFAdapterCppToC::Get(self)->ShowCurrentInput(*inputType);
}

void ARK_WEB_CALLBACK ark_imfadapter_hide_text_input(struct _ark_imfadapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkIMFAdapterCppToC::Get(self)->HideTextInput();
}

void ARK_WEB_CALLBACK ark_imfadapter_close(struct _ark_imfadapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkIMFAdapterCppToC::Get(self)->Close();
}

void ARK_WEB_CALLBACK ark_imfadapter_on_cursor_update(
    struct _ark_imfadapter_t* self, ark_imfcursor_info_adapter_t* cursorInfo)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkIMFAdapterCppToC::Get(self)->OnCursorUpdate(ArkIMFCursorInfoAdapterCToCpp::Invert(cursorInfo));
}

void ARK_WEB_CALLBACK ark_imfadapter_on_selection_change(
    struct _ark_imfadapter_t* self, ArkWebU16String* text, int start, int end)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(text, );

    // Execute
    ArkIMFAdapterCppToC::Get(self)->OnSelectionChange(*text, start, end);
}

} // namespace

ArkIMFAdapterCppToC::ArkIMFAdapterCppToC()
{
    GetStruct()->attach1 = ark_imfadapter_attach1;
    GetStruct()->attach2 = ark_imfadapter_attach2;
    GetStruct()->show_current_input = ark_imfadapter_show_current_input;
    GetStruct()->hide_text_input = ark_imfadapter_hide_text_input;
    GetStruct()->close = ark_imfadapter_close;
    GetStruct()->on_cursor_update = ark_imfadapter_on_cursor_update;
    GetStruct()->on_selection_change = ark_imfadapter_on_selection_change;
}

ArkIMFAdapterCppToC::~ArkIMFAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkIMFAdapterCppToC, ArkIMFAdapter, ark_imfadapter_t>::kBridgeType =
    ARK_IMFADAPTER;

} // namespace OHOS::ArkWeb
