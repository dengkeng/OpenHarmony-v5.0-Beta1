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

#ifndef ARK_WEB_DATA_BASE_CTOCPP_H_
#define ARK_WEB_DATA_BASE_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_data_base_capi.h"
#include "ohos_nweb/include/ark_web_data_base.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebDataBaseCToCpp : public ArkWebCToCppRefCounted<ArkWebDataBaseCToCpp, ArkWebDataBase, ark_web_data_base_t> {
public:
    ArkWebDataBaseCToCpp();
    virtual ~ArkWebDataBaseCToCpp();

    // ArkWebDataBase methods.
    void ClearAllPermission(int type, bool incognito) override;

    void GetHttpAuthCredentials(const ArkWebString& host, const ArkWebString& realm, ArkWebString& user_name,
        char* password, uint32_t password_size) override;

    void SaveHttpAuthCredentials(const ArkWebString& host, const ArkWebString& realm, const ArkWebString& user_name,
        const char* password) override;

    bool ExistHttpAuthCredentials() override;

    void DeleteHttpAuthCredentials() override;

    ArkWebStringVector GetOriginsByPermission(int type, bool incognito) override;

    bool GetPermissionByOrigin(const ArkWebString& origin, int type, bool& result, bool incognito) override;

    int SetPermissionByOrigin(const ArkWebString& origin, int type, bool result, bool incognito) override;

    bool ExistPermissionByOrigin(const ArkWebString& origin, int type, bool incognito) override;

    int ClearPermissionByOrigin(const ArkWebString& origin, int type, bool incognito) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DATA_BASE_CTOCPP_H_
