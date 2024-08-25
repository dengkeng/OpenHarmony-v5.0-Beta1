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

#include "ohos_adapter/cpptoc/ark_paste_data_record_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_clip_board_image_data_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

ark_paste_data_record_adapter_t* ark_paste_data_record_adapter_new_record1(const ArkWebString* mimeType)
{
    ARK_WEB_CPPTOC_CHECK_PARAM(mimeType, NULL);

    // Execute
    ArkWebRefPtr<ArkPasteDataRecordAdapter> _retval = ArkPasteDataRecordAdapter::NewRecord(*mimeType);

    // Return type: refptr_same
    return ArkPasteDataRecordAdapterCppToC::Invert(_retval);
}

ark_paste_data_record_adapter_t* ark_paste_data_record_adapter_new_record2(
    const ArkWebString* mimeType, void* htmlText, void* plainText)
{
    ARK_WEB_CPPTOC_CHECK_PARAM(mimeType, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(htmlText, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(plainText, NULL);

    // Execute
    ArkWebRefPtr<ArkPasteDataRecordAdapter> _retval =
        ArkPasteDataRecordAdapter::NewRecord(*mimeType, htmlText, plainText);

    // Return type: refptr_same
    return ArkPasteDataRecordAdapterCppToC::Invert(_retval);
}

namespace {

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_set_html_text(
    struct _ark_paste_data_record_adapter_t* self, void* htmlText)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(htmlText, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->SetHtmlText(htmlText);
}

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_set_plain_text(
    struct _ark_paste_data_record_adapter_t* self, void* plainText)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(plainText, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->SetPlainText(plainText);
}

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_set_img_data(
    struct _ark_paste_data_record_adapter_t* self, ark_clip_board_image_data_adapter_t* imageData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->SetImgData(
        ArkClipBoardImageDataAdapterCToCpp::Invert(imageData));
}

ArkWebString ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_mime_type(struct _ark_paste_data_record_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->GetMimeType();
}

void ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_html_text(
    struct _ark_paste_data_record_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataRecordAdapterCppToC::Get(self)->GetHtmlText(data);
}

void ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_plain_text(
    struct _ark_paste_data_record_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataRecordAdapterCppToC::Get(self)->GetPlainText(data);
}

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_img_data(
    struct _ark_paste_data_record_adapter_t* self, ark_clip_board_image_data_adapter_t* imageData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->GetImgData(
        ArkClipBoardImageDataAdapterCToCpp::Invert(imageData));
}

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_set_uri(
    struct _ark_paste_data_record_adapter_t* self, const ArkWebString* uriString)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(uriString, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->SetUri(*uriString);
}

bool ARK_WEB_CALLBACK ark_paste_data_record_adapter_set_custom_data(
    struct _ark_paste_data_record_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(data, false);

    // Execute
    return ArkPasteDataRecordAdapterCppToC::Get(self)->SetCustomData(data);
}

void ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_uri(struct _ark_paste_data_record_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataRecordAdapterCppToC::Get(self)->GetUri(data);
}

void ARK_WEB_CALLBACK ark_paste_data_record_adapter_get_custom_data(
    struct _ark_paste_data_record_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataRecordAdapterCppToC::Get(self)->GetCustomData(data);
}

} // namespace

ArkPasteDataRecordAdapterCppToC::ArkPasteDataRecordAdapterCppToC()
{
    GetStruct()->set_html_text = ark_paste_data_record_adapter_set_html_text;
    GetStruct()->set_plain_text = ark_paste_data_record_adapter_set_plain_text;
    GetStruct()->set_img_data = ark_paste_data_record_adapter_set_img_data;
    GetStruct()->get_mime_type = ark_paste_data_record_adapter_get_mime_type;
    GetStruct()->get_html_text = ark_paste_data_record_adapter_get_html_text;
    GetStruct()->get_plain_text = ark_paste_data_record_adapter_get_plain_text;
    GetStruct()->get_img_data = ark_paste_data_record_adapter_get_img_data;
    GetStruct()->set_uri = ark_paste_data_record_adapter_set_uri;
    GetStruct()->set_custom_data = ark_paste_data_record_adapter_set_custom_data;
    GetStruct()->get_uri = ark_paste_data_record_adapter_get_uri;
    GetStruct()->get_custom_data = ark_paste_data_record_adapter_get_custom_data;
}

ArkPasteDataRecordAdapterCppToC::~ArkPasteDataRecordAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkPasteDataRecordAdapterCppToC, ArkPasteDataRecordAdapter,
    ark_paste_data_record_adapter_t>::kBridgeType = ARK_PASTE_DATA_RECORD_ADAPTER;

} // namespace OHOS::ArkWeb

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

ARK_WEB_EXPORT ark_paste_data_record_adapter_t* ark_paste_data_record_adapter_new_record1_static(
    const ArkWebString* mimeType)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_paste_data_record_adapter_new_record1(mimeType);
}

ARK_WEB_EXPORT ark_paste_data_record_adapter_t* ark_paste_data_record_adapter_new_record2_static(
    const ArkWebString* mimeType, void* htmlText, void* plainText)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_paste_data_record_adapter_new_record2(mimeType, htmlText, plainText);
}

#ifdef __cplusplus
}
#endif // __cplusplus
