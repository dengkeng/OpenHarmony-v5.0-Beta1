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

#include "ohos_adapter/cpptoc/ark_hi_sys_event_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write1(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write2(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1, key2, value2);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write3(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const ArkWebString value3)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1, key2, value2, key3, value3);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write4(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const ArkWebString value3,
    const ArkWebString key4, const ArkWebString value4)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write5(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const ArkWebString value3,
    const ArkWebString key4, const ArkWebString value4, const ArkWebString key5, const ArkWebString value5)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4, key5, value5);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write6(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const ArkWebString value3,
    const ArkWebString key4, const ArkWebString value4, const ArkWebString key5, const ArkWebString value5,
    const ArkWebString key6, const ArkWebString value6)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4, key5, value5, key6, value6);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write7(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int64_t value1,
    const ArkWebString key2, const int value2, const ArkWebString key3, const ArkWebUint16Vector value3,
    const ArkWebString key4, const int value4)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write8(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int64_t value1,
    const ArkWebString key2, const int64_t value2, const ArkWebString key3, const int value3, const ArkWebString key4,
    const int value4, const ArkWebString key5, const int64_t value5, const ArkWebString key6, const int value6)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4, key5, value5, key6, value6);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write9(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int64_t value1,
    const ArkWebString key2, const int64_t value2, const ArkWebString key3, const uint32_t value3,
    const ArkWebString key4, const int64_t value4, const ArkWebString key5, const int64_t value5,
    const ArkWebString key6, const int64_t value6, const ArkWebString key7, const int64_t value7,
    const ArkWebString key8, const int64_t value8, const ArkWebString key9, const int64_t value9,
    const ArkWebString key10, const int64_t value10, const ArkWebString key11, const int64_t value11,
    const ArkWebString key12, const int64_t value12, const ArkWebString key13, const int64_t value13,
    const ArkWebString key14, const int64_t value14, const ArkWebString key15, const int64_t value15,
    const ArkWebString key16, const int64_t value16, const ArkWebString key17, const int64_t value17,
    const ArkWebString key18, const int64_t value18, const ArkWebString key19, const int64_t value19,
    const ArkWebString key20, const int64_t value20, const ArkWebString key21, const int64_t value21,
    const ArkWebString key22, const int64_t value22, const ArkWebString key23, const int64_t value23)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1, key2, value2, key3, value3,
        key4, value4, key5, value5, key6, value6, key7, value7, key8, value8, key9, value9, key10, value10, key11,
        value11, key12, value12, key13, value13, key14, value14, key15, value15, key16, value16, key17, value17, key18,
        value18, key19, value19, key20, value20, key21, value21, key22, value22, key23, value23);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write10(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const ArkWebString value1,
    const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const ArkWebString value3,
    const ArkWebString key4, const ArkWebString value4, const ArkWebString key5, const ArkWebString value5,
    const ArkWebString key6, const ArkWebString value6, const ArkWebString key7, const ArkWebString value7)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1, key2, value2, key3, value3,
        key4, value4, key5, value5, key6, value6, key7, value7);
}

} // namespace

ArkHiSysEventAdapterCppToC::ArkHiSysEventAdapterCppToC()
{
    GetStruct()->write1 = ark_hi_sys_event_adapter_write1;
    GetStruct()->write2 = ark_hi_sys_event_adapter_write2;
    GetStruct()->write3 = ark_hi_sys_event_adapter_write3;
    GetStruct()->write4 = ark_hi_sys_event_adapter_write4;
    GetStruct()->write5 = ark_hi_sys_event_adapter_write5;
    GetStruct()->write6 = ark_hi_sys_event_adapter_write6;
    GetStruct()->write7 = ark_hi_sys_event_adapter_write7;
    GetStruct()->write8 = ark_hi_sys_event_adapter_write8;
    GetStruct()->write9 = ark_hi_sys_event_adapter_write9;
    GetStruct()->write10 = ark_hi_sys_event_adapter_write10;
}

ArkHiSysEventAdapterCppToC::~ArkHiSysEventAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkHiSysEventAdapterCppToC, ArkHiSysEventAdapter, ark_hi_sys_event_adapter_t>::kBridgeType =
        ARK_HI_SYS_EVENT_ADAPTER;

} // namespace OHOS::ArkWeb
