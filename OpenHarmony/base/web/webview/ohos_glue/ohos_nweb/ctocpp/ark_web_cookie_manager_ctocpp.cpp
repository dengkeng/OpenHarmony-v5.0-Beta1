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

#include "ohos_nweb/ctocpp/ark_web_cookie_manager_ctocpp.h"

#include "ohos_nweb/cpptoc/ark_web_bool_value_callback_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_long_value_callback_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_string_value_callback_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
bool ArkWebCookieManagerCToCpp::Store()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, store1, false);

    // Execute
    return _struct->store1(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::Store(ArkWebRefPtr<ArkWebBoolValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, store2, );

    // Execute
    _struct->store2(_struct, ArkWebBoolValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
int ArkWebCookieManagerCToCpp::SetCookie(const ArkWebString& url, const ArkWebString& value, bool incognito_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_cookie1, 0);

    // Execute
    return _struct->set_cookie1(_struct, &url, &value, incognito_mode);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::SetCookie(
    const ArkWebString& url, const ArkWebString& value, ArkWebRefPtr<ArkWebBoolValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_cookie2, );

    // Execute
    _struct->set_cookie2(_struct, &url, &value, ArkWebBoolValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
bool ArkWebCookieManagerCToCpp::ExistCookies(bool incognito_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, exist_cookies1, false);

    // Execute
    return _struct->exist_cookies1(_struct, incognito_mode);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::ExistCookies(ArkWebRefPtr<ArkWebBoolValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, exist_cookies2, );

    // Execute
    _struct->exist_cookies2(_struct, ArkWebBoolValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebCookieManagerCToCpp::ReturnCookie(const ArkWebString& url, bool& is_valid, bool incognito_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, return_cookie1, ark_web_string_default);

    // Execute
    return _struct->return_cookie1(_struct, &url, &is_valid, incognito_mode);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::ReturnCookie(const ArkWebString& url, ArkWebRefPtr<ArkWebStringValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, return_cookie2, );

    // Execute
    _struct->return_cookie2(_struct, &url, ArkWebStringValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::ConfigCookie(
    const ArkWebString& url, const ArkWebString& value, ArkWebRefPtr<ArkWebLongValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, config_cookie, );

    // Execute
    _struct->config_cookie(_struct, &url, &value, ArkWebLongValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::DeleteSessionCookies(ArkWebRefPtr<ArkWebBoolValueCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_session_cookies, );

    // Execute
    _struct->delete_session_cookies(_struct, ArkWebBoolValueCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::DeleteCookieEntirely(
    ArkWebRefPtr<ArkWebBoolValueCallback> callback, bool incognito_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, delete_cookie_entirely, );

    // Execute
    _struct->delete_cookie_entirely(_struct, ArkWebBoolValueCallbackCppToC::Invert(callback), incognito_mode);
}

ARK_WEB_NO_SANITIZE
bool ArkWebCookieManagerCToCpp::IsAcceptCookieAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_accept_cookie_allowed, false);

    // Execute
    return _struct->is_accept_cookie_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::PutAcceptCookieEnabled(bool accept)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_accept_cookie_enabled, );

    // Execute
    _struct->put_accept_cookie_enabled(_struct, accept);
}

ARK_WEB_NO_SANITIZE
bool ArkWebCookieManagerCToCpp::IsThirdPartyCookieAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_third_party_cookie_allowed, false);

    // Execute
    return _struct->is_third_party_cookie_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebCookieManagerCToCpp::IsFileURLSchemeCookiesAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_file_urlscheme_cookies_allowed, false);

    // Execute
    return _struct->is_file_urlscheme_cookies_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::PutAcceptThirdPartyCookieEnabled(bool accept)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_accept_third_party_cookie_enabled, );

    // Execute
    _struct->put_accept_third_party_cookie_enabled(_struct, accept);
}

ARK_WEB_NO_SANITIZE
void ArkWebCookieManagerCToCpp::PutAcceptFileURLSchemeCookiesEnabled(bool allow)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cookie_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_accept_file_urlscheme_cookies_enabled, );

    // Execute
    _struct->put_accept_file_urlscheme_cookies_enabled(_struct, allow);
}

ArkWebCookieManagerCToCpp::ArkWebCookieManagerCToCpp() {}

ArkWebCookieManagerCToCpp::~ArkWebCookieManagerCToCpp() {}

template<>
ArkWebBridgeType
    ArkWebCToCppRefCounted<ArkWebCookieManagerCToCpp, ArkWebCookieManager, ark_web_cookie_manager_t>::kBridgeType =
        ARK_WEB_COOKIE_MANAGER;

} // namespace OHOS::ArkWeb
