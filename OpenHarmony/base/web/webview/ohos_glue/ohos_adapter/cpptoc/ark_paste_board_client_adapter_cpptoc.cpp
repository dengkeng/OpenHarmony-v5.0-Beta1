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

#include "ohos_adapter/cpptoc/ark_paste_board_client_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_paste_board_observer_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_paste_board_client_adapter_get_paste_data(
    struct _ark_paste_board_client_adapter_t* self, ArkPasteRecordVector* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(data, false);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->GetPasteData(*data);
}

void ARK_WEB_CALLBACK ark_paste_board_client_adapter_set_paste_data(
    struct _ark_paste_board_client_adapter_t* self, ArkPasteRecordVector* data, int32_t copyOption)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteBoardClientAdapterCppToC::Get(self)->SetPasteData(*data, copyOption);
}

bool ARK_WEB_CALLBACK ark_paste_board_client_adapter_has_paste_data(struct _ark_paste_board_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->HasPasteData();
}

void ARK_WEB_CALLBACK ark_paste_board_client_adapter_clear(struct _ark_paste_board_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkPasteBoardClientAdapterCppToC::Get(self)->Clear();
}

int32_t ARK_WEB_CALLBACK ark_paste_board_client_adapter_open_remote_uri(
    struct _ark_paste_board_client_adapter_t* self, const ArkWebString* path)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(path, 0);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->OpenRemoteUri(*path);
}

bool ARK_WEB_CALLBACK ark_paste_board_client_adapter_is_local_paste(struct _ark_paste_board_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->IsLocalPaste();
}

uint32_t ARK_WEB_CALLBACK ark_paste_board_client_adapter_get_token_id(struct _ark_paste_board_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->GetTokenId();
}

int32_t ARK_WEB_CALLBACK ark_paste_board_client_adapter_add_pasteboard_changed_observer(
    struct _ark_paste_board_client_adapter_t* self, ark_paste_board_observer_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPasteBoardClientAdapterCppToC::Get(self)->AddPasteboardChangedObserver(
        ArkPasteBoardObserverAdapterCToCpp::Invert(callback));
}

void ARK_WEB_CALLBACK ark_paste_board_client_adapter_remove_pasteboard_changed_observer(
    struct _ark_paste_board_client_adapter_t* self, int32_t callbackId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkPasteBoardClientAdapterCppToC::Get(self)->RemovePasteboardChangedObserver(callbackId);
}

} // namespace

ArkPasteBoardClientAdapterCppToC::ArkPasteBoardClientAdapterCppToC()
{
    GetStruct()->get_paste_data = ark_paste_board_client_adapter_get_paste_data;
    GetStruct()->set_paste_data = ark_paste_board_client_adapter_set_paste_data;
    GetStruct()->has_paste_data = ark_paste_board_client_adapter_has_paste_data;
    GetStruct()->clear = ark_paste_board_client_adapter_clear;
    GetStruct()->open_remote_uri = ark_paste_board_client_adapter_open_remote_uri;
    GetStruct()->is_local_paste = ark_paste_board_client_adapter_is_local_paste;
    GetStruct()->get_token_id = ark_paste_board_client_adapter_get_token_id;
    GetStruct()->add_pasteboard_changed_observer = ark_paste_board_client_adapter_add_pasteboard_changed_observer;
    GetStruct()->remove_pasteboard_changed_observer = ark_paste_board_client_adapter_remove_pasteboard_changed_observer;
}

ArkPasteBoardClientAdapterCppToC::~ArkPasteBoardClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkPasteBoardClientAdapterCppToC, ArkPasteBoardClientAdapter,
    ark_paste_board_client_adapter_t>::kBridgeType = ARK_PASTE_BOARD_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb
