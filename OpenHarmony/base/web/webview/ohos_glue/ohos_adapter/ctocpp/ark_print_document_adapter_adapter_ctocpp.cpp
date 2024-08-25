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

#include "ohos_adapter/ctocpp/ark_print_document_adapter_adapter_ctocpp.h"

#include "ohos_adapter/cpptoc/ark_print_write_result_callback_adapter_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkPrintDocumentAdapterAdapterCToCpp::OnStartLayoutWrite(const ArkWebString& jobId,
    const ArkPrintAttributesAdapter& oldAttrs, const ArkPrintAttributesAdapter& newAttrs, uint32_t fd,
    ArkWebRefPtr<ArkPrintWriteResultCallbackAdapter> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_print_document_adapter_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_start_layout_write, );

    // Execute
    _struct->on_start_layout_write(
        _struct, &jobId, &oldAttrs, &newAttrs, fd, ArkPrintWriteResultCallbackAdapterCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
void ArkPrintDocumentAdapterAdapterCToCpp::OnJobStateChanged(const ArkWebString& jobId, uint32_t state)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_print_document_adapter_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_job_state_changed, );

    // Execute
    _struct->on_job_state_changed(_struct, &jobId, state);
}

ArkPrintDocumentAdapterAdapterCToCpp::ArkPrintDocumentAdapterAdapterCToCpp() {}

ArkPrintDocumentAdapterAdapterCToCpp::~ArkPrintDocumentAdapterAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkPrintDocumentAdapterAdapterCToCpp, ArkPrintDocumentAdapterAdapter,
    ark_print_document_adapter_adapter_t>::kBridgeType = ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER;

} // namespace OHOS::ArkWeb
