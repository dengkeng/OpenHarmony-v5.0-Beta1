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

#ifndef ARK_WEB_WEB_STORAGE_CTOCPP_H_
#define ARK_WEB_WEB_STORAGE_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_web_storage_capi.h"
#include "ohos_nweb/include/ark_web_web_storage.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebWebStorageCToCpp
    : public ArkWebCToCppRefCounted<ArkWebWebStorageCToCpp, ArkWebWebStorage, ark_web_web_storage_t> {
public:
    ArkWebWebStorageCToCpp();
    virtual ~ArkWebWebStorageCToCpp();

    // ArkWebWebStorage methods.
    ArkWebWebStorageOriginVector GetOrigins() override;

    void GetOrigins(ArkWebRefPtr<ArkWebWebStorageOriginVectorValueCallback> callback) override;

    long GetOriginQuota(const ArkWebString& origin) override;

    void GetOriginQuota(const ArkWebString& origin, ArkWebRefPtr<ArkWebLongValueCallback> callback) override;

    long GetOriginUsage(const ArkWebString& origin) override;

    void GetOriginUsage(const ArkWebString& origin, ArkWebRefPtr<ArkWebLongValueCallback> callback) override;

    int DeleteOrigin(const ArkWebString& origin) override;

    void DeleteAllData(bool incognito_mode) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_WEB_STORAGE_CTOCPP_H_
