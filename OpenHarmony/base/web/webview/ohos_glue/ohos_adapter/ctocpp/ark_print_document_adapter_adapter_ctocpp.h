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

#ifndef ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_CTOCPP_H_
#define ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_print_manager_adapter_capi.h"
#include "ohos_adapter/include/ark_print_manager_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkPrintDocumentAdapterAdapterCToCpp : public ArkWebCToCppRefCounted<ArkPrintDocumentAdapterAdapterCToCpp,
                                                 ArkPrintDocumentAdapterAdapter, ark_print_document_adapter_adapter_t> {
public:
    ArkPrintDocumentAdapterAdapterCToCpp();
    virtual ~ArkPrintDocumentAdapterAdapterCToCpp();

    // ArkPrintDocumentAdapterAdapter methods.
    void OnStartLayoutWrite(const ArkWebString& jobId, const ArkPrintAttributesAdapter& oldAttrs,
        const ArkPrintAttributesAdapter& newAttrs, uint32_t fd,
        ArkWebRefPtr<ArkPrintWriteResultCallbackAdapter> callback) override;

    void OnJobStateChanged(const ArkWebString& jobId, uint32_t state) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_CTOCPP_H_
