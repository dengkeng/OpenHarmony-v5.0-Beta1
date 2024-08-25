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

#include "ohos_adapter/ctocpp/ark_imftext_listener_adapter_ctocpp.h"

#include "ohos_adapter/cpptoc/ark_imfadapter_function_key_adapter_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::InsertText(const ArkWebU16String& text)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, insert_text, );

    // Execute
    _struct->insert_text(_struct, &text);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::DeleteForward(int32_t length)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_forward, );

    // Execute
    _struct->delete_forward(_struct, length);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::DeleteBackward(int32_t length)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_backward, );

    // Execute
    _struct->delete_backward(_struct, length);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::SendKeyEventFromInputMethod()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, send_key_event_from_input_method, );

    // Execute
    _struct->send_key_event_from_input_method(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::SendKeyboardStatus(const int32_t& keyboardStatus)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, send_keyboard_status, );

    // Execute
    _struct->send_keyboard_status(_struct, &keyboardStatus);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::SendFunctionKey(ArkWebRefPtr<ArkIMFAdapterFunctionKeyAdapter> functionKey)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, send_function_key, );

    // Execute
    _struct->send_function_key(_struct, ArkIMFAdapterFunctionKeyAdapterCppToC::Invert(functionKey));
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::SetKeyboardStatus(bool status)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_keyboard_status, );

    // Execute
    _struct->set_keyboard_status(_struct, status);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::MoveCursor(const uint32_t direction)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, move_cursor, );

    // Execute
    _struct->move_cursor(_struct, direction);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::HandleSetSelection(int32_t start, int32_t end)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_set_selection, );

    // Execute
    _struct->handle_set_selection(_struct, start, end);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::HandleExtendAction(int32_t action)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_extend_action, );

    // Execute
    _struct->handle_extend_action(_struct, action);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::HandleSelect(int32_t keyCode, int32_t cursorMoveSkip)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, handle_select, );

    // Execute
    _struct->handle_select(_struct, keyCode, cursorMoveSkip);
}

ARK_WEB_NO_SANITIZE
int32_t ArkIMFTextListenerAdapterCToCpp::GetTextIndexAtCursor()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_text_index_at_cursor, 0);

    // Execute
    return _struct->get_text_index_at_cursor(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebU16String ArkIMFTextListenerAdapterCToCpp::GetLeftTextOfCursor(int32_t number)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_u16string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_left_text_of_cursor, ark_web_u16string_default);

    // Execute
    return _struct->get_left_text_of_cursor(_struct, number);
}

ARK_WEB_NO_SANITIZE
ArkWebU16String ArkIMFTextListenerAdapterCToCpp::GetRightTextOfCursor(int32_t number)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_u16string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_right_text_of_cursor, ark_web_u16string_default);

    // Execute
    return _struct->get_right_text_of_cursor(_struct, number);
}

ARK_WEB_NO_SANITIZE
int32_t ArkIMFTextListenerAdapterCToCpp::SetPreviewText(const ArkWebU16String& text, int32_t start, int32_t end)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_preview_text, 0);

    // Execute
    return _struct->set_preview_text(_struct, &text, start, end);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::FinishTextPreview()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, finish_text_preview, );

    // Execute
    _struct->finish_text_preview(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkIMFTextListenerAdapterCToCpp::SetNeedUnderLine(bool isNeedUnderline)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_imftext_listener_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_need_under_line, );

    // Execute
    _struct->set_need_under_line(_struct, isNeedUnderline);
}

ArkIMFTextListenerAdapterCToCpp::ArkIMFTextListenerAdapterCToCpp() {}

ArkIMFTextListenerAdapterCToCpp::~ArkIMFTextListenerAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkIMFTextListenerAdapterCToCpp, ArkIMFTextListenerAdapter,
    ark_imftext_listener_adapter_t>::kBridgeType = ARK_IMFTEXT_LISTENER_ADAPTER;

} // namespace OHOS::ArkWeb
