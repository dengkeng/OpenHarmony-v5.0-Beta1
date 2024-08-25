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

#include "ohos_adapter/cpptoc/ark_paste_data_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_paste_data_record_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_paste_data_adapter_add_html_record(
    struct _ark_paste_data_adapter_t* self, const ArkWebString* html)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(html, );

    // Execute
    ArkPasteDataAdapterCppToC::Get(self)->AddHtmlRecord(*html);
}

void ARK_WEB_CALLBACK ark_paste_data_adapter_add_text_record(
    struct _ark_paste_data_adapter_t* self, const ArkWebString* text)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(text, );

    // Execute
    ArkPasteDataAdapterCppToC::Get(self)->AddTextRecord(*text);
}

ArkWebStringVector ARK_WEB_CALLBACK ark_paste_data_adapter_get_mime_types(struct _ark_paste_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_vector_default);

    // Execute
    return ArkPasteDataAdapterCppToC::Get(self)->GetMimeTypes();
}

void ARK_WEB_CALLBACK ark_paste_data_adapter_get_primary_html(struct _ark_paste_data_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataAdapterCppToC::Get(self)->GetPrimaryHtml(data);
}

void ARK_WEB_CALLBACK ark_paste_data_adapter_get_primary_text(struct _ark_paste_data_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataAdapterCppToC::Get(self)->GetPrimaryText(data);
}

void ARK_WEB_CALLBACK ark_paste_data_adapter_get_primary_mime_type(struct _ark_paste_data_adapter_t* self, void* data)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(data, );

    // Execute
    ArkPasteDataAdapterCppToC::Get(self)->GetPrimaryMimeType(data);
}

ark_paste_data_record_adapter_t* ARK_WEB_CALLBACK ark_paste_data_adapter_get_record_at(
    struct _ark_paste_data_adapter_t* self, size_t index)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkPasteDataRecordAdapter> _retval = ArkPasteDataAdapterCppToC::Get(self)->GetRecordAt(index);

    // Return type: refptr_same
    return ArkPasteDataRecordAdapterCppToC::Invert(_retval);
}

size_t ARK_WEB_CALLBACK ark_paste_data_adapter_get_record_count(struct _ark_paste_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkPasteDataAdapterCppToC::Get(self)->GetRecordCount();
}

ArkPasteRecordVector ARK_WEB_CALLBACK ark_paste_data_adapter_all_records(struct _ark_paste_data_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkPasteDataAdapterCppToC::Get(self)->AllRecords();
}

} // namespace

ArkPasteDataAdapterCppToC::ArkPasteDataAdapterCppToC()
{
    GetStruct()->add_html_record = ark_paste_data_adapter_add_html_record;
    GetStruct()->add_text_record = ark_paste_data_adapter_add_text_record;
    GetStruct()->get_mime_types = ark_paste_data_adapter_get_mime_types;
    GetStruct()->get_primary_html = ark_paste_data_adapter_get_primary_html;
    GetStruct()->get_primary_text = ark_paste_data_adapter_get_primary_text;
    GetStruct()->get_primary_mime_type = ark_paste_data_adapter_get_primary_mime_type;
    GetStruct()->get_record_at = ark_paste_data_adapter_get_record_at;
    GetStruct()->get_record_count = ark_paste_data_adapter_get_record_count;
    GetStruct()->all_records = ark_paste_data_adapter_all_records;
}

ArkPasteDataAdapterCppToC::~ArkPasteDataAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkPasteDataAdapterCppToC, ArkPasteDataAdapter, ark_paste_data_adapter_t>::kBridgeType =
        ARK_PASTE_DATA_ADAPTER;

} // namespace OHOS::ArkWeb
