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

#ifndef ARK_WEB_COOKIE_MANAGER_CTOCPP_H_
#define ARK_WEB_COOKIE_MANAGER_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_cookie_manager_capi.h"
#include "ohos_nweb/include/ark_web_cookie_manager.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebCookieManagerCToCpp
    : public ArkWebCToCppRefCounted<ArkWebCookieManagerCToCpp, ArkWebCookieManager, ark_web_cookie_manager_t> {
public:
    ArkWebCookieManagerCToCpp();
    virtual ~ArkWebCookieManagerCToCpp();

    // ArkWebCookieManager methods.
    bool Store() override;

    void Store(ArkWebRefPtr<ArkWebBoolValueCallback> callback) override;

    int SetCookie(const ArkWebString& url, const ArkWebString& value, bool incognito_mode) override;

    void SetCookie(
        const ArkWebString& url, const ArkWebString& value, ArkWebRefPtr<ArkWebBoolValueCallback> callback) override;

    bool ExistCookies(bool incognito_mode) override;

    void ExistCookies(ArkWebRefPtr<ArkWebBoolValueCallback> callback) override;

    ArkWebString ReturnCookie(const ArkWebString& url, bool& is_valid, bool incognito_mode) override;

    void ReturnCookie(const ArkWebString& url, ArkWebRefPtr<ArkWebStringValueCallback> callback) override;

    void ConfigCookie(
        const ArkWebString& url, const ArkWebString& value, ArkWebRefPtr<ArkWebLongValueCallback> callback) override;

    void DeleteSessionCookies(ArkWebRefPtr<ArkWebBoolValueCallback> callback) override;

    void DeleteCookieEntirely(ArkWebRefPtr<ArkWebBoolValueCallback> callback, bool incognito_mode) override;

    bool IsAcceptCookieAllowed() override;

    void PutAcceptCookieEnabled(bool accept) override;

    bool IsThirdPartyCookieAllowed() override;

    bool IsFileURLSchemeCookiesAllowed() override;

    void PutAcceptThirdPartyCookieEnabled(bool accept) override;

    void PutAcceptFileURLSchemeCookiesEnabled(bool allow) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_COOKIE_MANAGER_CTOCPP_H_
