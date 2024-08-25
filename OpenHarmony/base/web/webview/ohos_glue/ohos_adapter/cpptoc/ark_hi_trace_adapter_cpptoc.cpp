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

#include "ohos_adapter/cpptoc/ark_hi_trace_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_hi_trace_adapter_start_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* value, float limit)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(value, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->StartTrace(*value, limit);
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_finish_trace(struct _ark_hi_trace_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->FinishTrace();
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_start_async_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* value, int32_t taskId, float limit)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(value, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->StartAsyncTrace(*value, taskId, limit);
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_finish_async_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* value, int32_t taskId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(value, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->FinishAsyncTrace(*value, taskId);
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_count_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* name, int64_t count)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(name, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->CountTrace(*name, count);
}

bool ARK_WEB_CALLBACK ark_hi_trace_adapter_is_hi_trace_enable(struct _ark_hi_trace_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkHiTraceAdapterCppToC::Get(self)->IsHiTraceEnable();
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_start_ohos_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* value, float limit)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(value, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->StartOHOSTrace(*value, limit);
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_finish_ohos_trace(struct _ark_hi_trace_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->FinishOHOSTrace();
}

void ARK_WEB_CALLBACK ark_hi_trace_adapter_count_ohos_trace(
    struct _ark_hi_trace_adapter_t* self, const ArkWebString* name, int64_t count)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(name, );

    // Execute
    ArkHiTraceAdapterCppToC::Get(self)->CountOHOSTrace(*name, count);
}

} // namespace

ArkHiTraceAdapterCppToC::ArkHiTraceAdapterCppToC()
{
    GetStruct()->start_trace = ark_hi_trace_adapter_start_trace;
    GetStruct()->finish_trace = ark_hi_trace_adapter_finish_trace;
    GetStruct()->start_async_trace = ark_hi_trace_adapter_start_async_trace;
    GetStruct()->finish_async_trace = ark_hi_trace_adapter_finish_async_trace;
    GetStruct()->count_trace = ark_hi_trace_adapter_count_trace;
    GetStruct()->is_hi_trace_enable = ark_hi_trace_adapter_is_hi_trace_enable;
    GetStruct()->start_ohos_trace = ark_hi_trace_adapter_start_ohos_trace;
    GetStruct()->finish_ohos_trace = ark_hi_trace_adapter_finish_ohos_trace;
    GetStruct()->count_ohos_trace = ark_hi_trace_adapter_count_ohos_trace;
}

ArkHiTraceAdapterCppToC::~ArkHiTraceAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkHiTraceAdapterCppToC, ArkHiTraceAdapter, ark_hi_trace_adapter_t>::kBridgeType =
        ARK_HI_TRACE_ADAPTER;

} // namespace OHOS::ArkWeb
