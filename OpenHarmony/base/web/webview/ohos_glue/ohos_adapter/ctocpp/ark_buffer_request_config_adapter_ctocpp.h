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

#ifndef ARK_BUFFER_REQUEST_CONFIG_ADAPTER_CTOCPP_H_
#define ARK_BUFFER_REQUEST_CONFIG_ADAPTER_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_graphic_adapter_capi.h"
#include "ohos_adapter/include/ark_graphic_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkBufferRequestConfigAdapterCToCpp : public ArkWebCToCppRefCounted<ArkBufferRequestConfigAdapterCToCpp,
                                                ArkBufferRequestConfigAdapter, ark_buffer_request_config_adapter_t> {
public:
    ArkBufferRequestConfigAdapterCToCpp();
    virtual ~ArkBufferRequestConfigAdapterCToCpp();

    // ArkBufferRequestConfigAdapter methods.
    int32_t GetWidth() override;

    int32_t GetHeight() override;

    int32_t GetStrideAlignment() override;

    int32_t GetFormat() override;

    uint64_t GetUsage() override;

    int32_t GetTimeout() override;

    int32_t GetColorGamut() override;

    int32_t GetTransformType() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_BUFFER_REQUEST_CONFIG_ADAPTER_CTOCPP_H_
