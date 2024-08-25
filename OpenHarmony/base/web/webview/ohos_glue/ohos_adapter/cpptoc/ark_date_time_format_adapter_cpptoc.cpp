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

#include "ohos_adapter/cpptoc/ark_date_time_format_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_timezone_event_callback_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_date_time_format_adapter_reg_timezone_event(
    struct _ark_date_time_format_adapter_t* self, ark_timezone_event_callback_adapter_t* eventCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkDateTimeFormatAdapterCppToC::Get(self)->RegTimezoneEvent(
        ArkTimezoneEventCallbackAdapterCToCpp::Invert(eventCallback));
}

bool ARK_WEB_CALLBACK ark_date_time_format_adapter_start_listen(struct _ark_date_time_format_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkDateTimeFormatAdapterCppToC::Get(self)->StartListen();
}

void ARK_WEB_CALLBACK ark_date_time_format_adapter_stop_listen(struct _ark_date_time_format_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkDateTimeFormatAdapterCppToC::Get(self)->StopListen();
}

ArkWebString ARK_WEB_CALLBACK ark_date_time_format_adapter_get_timezone(struct _ark_date_time_format_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkDateTimeFormatAdapterCppToC::Get(self)->GetTimezone();
}

} // namespace

ArkDateTimeFormatAdapterCppToC::ArkDateTimeFormatAdapterCppToC()
{
    GetStruct()->reg_timezone_event = ark_date_time_format_adapter_reg_timezone_event;
    GetStruct()->start_listen = ark_date_time_format_adapter_start_listen;
    GetStruct()->stop_listen = ark_date_time_format_adapter_stop_listen;
    GetStruct()->get_timezone = ark_date_time_format_adapter_get_timezone;
}

ArkDateTimeFormatAdapterCppToC::~ArkDateTimeFormatAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkDateTimeFormatAdapterCppToC, ArkDateTimeFormatAdapter,
    ark_date_time_format_adapter_t>::kBridgeType = ARK_DATE_TIME_FORMAT_ADAPTER;

} // namespace OHOS::ArkWeb
