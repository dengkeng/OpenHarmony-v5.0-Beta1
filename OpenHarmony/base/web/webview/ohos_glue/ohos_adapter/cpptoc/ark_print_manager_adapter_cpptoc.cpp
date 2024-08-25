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

#include "ohos_adapter/cpptoc/ark_print_manager_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_print_document_adapter_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_print_manager_adapter_start_print(struct _ark_print_manager_adapter_t* self,
    const ArkWebStringVector* fileList, const ArkWebUint32Vector* fdList, ArkWebString* taskId)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(fileList, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(fdList, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(taskId, 0);

    // Execute
    return ArkPrintManagerAdapterCppToC::Get(self)->StartPrint(*fileList, *fdList, *taskId);
}

int32_t ARK_WEB_CALLBACK ark_print_manager_adapter_print1(struct _ark_print_manager_adapter_t* self,
    const ArkWebString* printJobName, ark_print_document_adapter_adapter_t* listener,
    const ArkPrintAttributesAdapter* printAttributes)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(printJobName, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(printAttributes, 0);

    // Execute
    return ArkPrintManagerAdapterCppToC::Get(self)->Print(
        *printJobName, ArkPrintDocumentAdapterAdapterCToCpp::Invert(listener), *printAttributes);
}

int32_t ARK_WEB_CALLBACK ark_print_manager_adapter_print2(struct _ark_print_manager_adapter_t* self,
    const ArkWebString* printJobName, ark_print_document_adapter_adapter_t* listener,
    const ArkPrintAttributesAdapter* printAttributes, void* contextToken)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(printJobName, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(printAttributes, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(contextToken, 0);

    // Execute
    return ArkPrintManagerAdapterCppToC::Get(self)->Print(
        *printJobName, ArkPrintDocumentAdapterAdapterCToCpp::Invert(listener), *printAttributes, contextToken);
}

} // namespace

ArkPrintManagerAdapterCppToC::ArkPrintManagerAdapterCppToC()
{
    GetStruct()->start_print = ark_print_manager_adapter_start_print;
    GetStruct()->print1 = ark_print_manager_adapter_print1;
    GetStruct()->print2 = ark_print_manager_adapter_print2;
}

ArkPrintManagerAdapterCppToC::~ArkPrintManagerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkPrintManagerAdapterCppToC, ArkPrintManagerAdapter,
    ark_print_manager_adapter_t>::kBridgeType = ARK_PRINT_MANAGER_ADAPTER;

} // namespace OHOS::ArkWeb
