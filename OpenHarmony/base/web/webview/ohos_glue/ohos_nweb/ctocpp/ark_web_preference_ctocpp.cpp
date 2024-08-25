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

#include "ohos_nweb/ctocpp/ark_web_preference_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::UserAgent()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, user_agent, ark_web_string_default);

    // Execute
    return _struct->user_agent(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutUserAgent(const ArkWebString& ua)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_user_agent, );

    // Execute
    _struct->put_user_agent(_struct, &ua);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::DefaultUserAgent()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, default_user_agent, ark_web_string_default);

    // Execute
    return _struct->default_user_agent(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::CacheMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, cache_mode, 0);

    // Execute
    return _struct->cache_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutCacheMode(int flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_cache_mode, );

    // Execute
    _struct->put_cache_mode(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsNetworkBlocked()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_network_blocked, false);

    // Execute
    return _struct->is_network_blocked(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutBlockNetwork(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_block_network, );

    // Execute
    _struct->put_block_network(_struct, flag);
}

ARK_WEB_NO_SANITIZE
uint32_t ArkWebPreferenceCToCpp::GetScrollBarColor()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_scroll_bar_color, 0);

    // Execute
    return _struct->get_scroll_bar_color(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutScrollBarColor(uint32_t color_value)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_scroll_bar_color, );

    // Execute
    _struct->put_scroll_bar_color(_struct, color_value);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::GetOverscrollMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_overscroll_mode, 0);

    // Execute
    return _struct->get_overscroll_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutOverscrollMode(int over_scroll_mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_overscroll_mode, );

    // Execute
    _struct->put_overscroll_mode(_struct, over_scroll_mode);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::DefaultFontSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, default_font_size, 0);

    // Execute
    return _struct->default_font_size(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDefaultFontSize(int size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_default_font_size, );

    // Execute
    _struct->put_default_font_size(_struct, size);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::GetPinchSmoothMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_pinch_smooth_mode, false);

    // Execute
    return _struct->get_pinch_smooth_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutPinchSmoothMode(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_pinch_smooth_mode, );

    // Execute
    _struct->put_pinch_smooth_mode(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsDataBaseEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_data_base_enabled, false);

    // Execute
    return _struct->is_data_base_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDatabaseAllowed(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_database_allowed, );

    // Execute
    _struct->put_database_allowed(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsMultiWindowAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_multi_window_access, false);

    // Execute
    return _struct->is_multi_window_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutMultiWindowAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_multi_window_access, );

    // Execute
    _struct->put_multi_window_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsJavaScriptAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_java_script_allowed, false);

    // Execute
    return _struct->is_java_script_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutJavaScriptEnabled(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_java_script_enabled, );

    // Execute
    _struct->put_java_script_enabled(_struct, flag);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::DarkSchemeEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, dark_scheme_enabled, 0);

    // Execute
    return _struct->dark_scheme_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDarkSchemeEnabled(int dark_scheme)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_dark_scheme_enabled, );

    // Execute
    _struct->put_dark_scheme_enabled(_struct, dark_scheme);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsDomStorageEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_dom_storage_enabled, false);

    // Execute
    return _struct->is_dom_storage_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDomStorageEnabled(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_dom_storage_enabled, );

    // Execute
    _struct->put_dom_storage_enabled(_struct, flag);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::FontSizeLowerLimit()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, font_size_lower_limit, 0);

    // Execute
    return _struct->font_size_lower_limit(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutFontSizeLowerLimit(int size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_font_size_lower_limit, );

    // Execute
    _struct->put_font_size_lower_limit(_struct, size);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::GeoLocationAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, geo_location_allowed, false);

    // Execute
    return _struct->geo_location_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutGeoLocationAllowed(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_geo_location_allowed, );

    // Execute
    _struct->put_geo_location_allowed(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsWebDebuggingAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_web_debugging_access, false);

    // Execute
    return _struct->is_web_debugging_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutWebDebuggingAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_web_debugging_access, );

    // Execute
    _struct->put_web_debugging_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::EnableContentAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, enable_content_access, false);

    // Execute
    return _struct->enable_content_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutEnableContentAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_enable_content_access, );

    // Execute
    _struct->put_enable_content_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::EnableRawFileAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, enable_raw_file_access, false);

    // Execute
    return _struct->enable_raw_file_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutEnableRawFileAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_enable_raw_file_access, );

    // Execute
    _struct->put_enable_raw_file_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsImageLoadingAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_image_loading_allowed, false);

    // Execute
    return _struct->is_image_loading_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutImageLoadingAllowed(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_image_loading_allowed, );

    // Execute
    _struct->put_image_loading_allowed(_struct, flag);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::FixedFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, fixed_font_family_name, ark_web_string_default);

    // Execute
    return _struct->fixed_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutFixedFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_fixed_font_family_name, );

    // Execute
    _struct->put_fixed_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::SerifFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, serif_font_family_name, ark_web_string_default);

    // Execute
    return _struct->serif_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutSerifFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_serif_font_family_name, );

    // Execute
    _struct->put_serif_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::ZoomingForTextFactor()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, zooming_for_text_factor, 0);

    // Execute
    return _struct->zooming_for_text_factor(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutZoomingForTextFactor(int text_zoom)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_zooming_for_text_factor, );

    // Execute
    _struct->put_zooming_for_text_factor(_struct, text_zoom);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::ForceDarkModeEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, force_dark_mode_enabled, 0);

    // Execute
    return _struct->force_dark_mode_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutForceDarkModeEnabled(int force_dark)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_force_dark_mode_enabled, );

    // Execute
    _struct->put_force_dark_mode_enabled(_struct, force_dark);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsLoadWithOverviewMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_load_with_overview_mode, false);

    // Execute
    return _struct->is_load_with_overview_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutLoadWithOverviewMode(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_load_with_overview_mode, );

    // Execute
    _struct->put_load_with_overview_mode(_struct, flag);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::DefaultFixedFontSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, default_fixed_font_size, 0);

    // Execute
    return _struct->default_fixed_font_size(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDefaultFixedFontSize(int size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_default_fixed_font_size, );

    // Execute
    _struct->put_default_fixed_font_size(_struct, size);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::CursiveFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, cursive_font_family_name, ark_web_string_default);

    // Execute
    return _struct->cursive_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutCursiveFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_cursive_font_family_name, );

    // Execute
    _struct->put_cursive_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::FantasyFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, fantasy_font_family_name, ark_web_string_default);

    // Execute
    return _struct->fantasy_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutFantasyFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_fantasy_font_family_name, );

    // Execute
    _struct->put_fantasy_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::ZoomingfunctionEnabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, zoomingfunction_enabled, false);

    // Execute
    return _struct->zoomingfunction_enabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutZoomingFunctionEnabled(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_zooming_function_enabled, );

    // Execute
    _struct->put_zooming_function_enabled(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::GetMediaPlayGestureAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_media_play_gesture_access, false);

    // Execute
    return _struct->get_media_play_gesture_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutMediaPlayGestureAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_media_play_gesture_access, );

    // Execute
    _struct->put_media_play_gesture_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::StandardFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, standard_font_family_name, ark_web_string_default);

    // Execute
    return _struct->standard_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutStandardFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_standard_font_family_name, );

    // Execute
    _struct->put_standard_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::SansSerifFontFamilyName()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, sans_serif_font_family_name, ark_web_string_default);

    // Execute
    return _struct->sans_serif_font_family_name(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutSansSerifFontFamilyName(const ArkWebString& font)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_sans_serif_font_family_name, );

    // Execute
    _struct->put_sans_serif_font_family_name(_struct, &font);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsVerticalScrollBarAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_vertical_scroll_bar_access, false);

    // Execute
    return _struct->is_vertical_scroll_bar_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutVerticalScrollBarAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_vertical_scroll_bar_access, );

    // Execute
    _struct->put_vertical_scroll_bar_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsHorizontalScrollBarAccess()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_horizontal_scroll_bar_access, false);

    // Execute
    return _struct->is_horizontal_scroll_bar_access(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutHorizontalScrollBarAccess(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_horizontal_scroll_bar_access, );

    // Execute
    _struct->put_horizontal_scroll_bar_access(_struct, flag);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::LogicalFontSizeLowerLimit()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, logical_font_size_lower_limit, 0);

    // Execute
    return _struct->logical_font_size_lower_limit(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutLogicalFontSizeLowerLimit(int size)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_logical_font_size_lower_limit, );

    // Execute
    _struct->put_logical_font_size_lower_limit(_struct, size);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebPreferenceCToCpp::DefaultTextEncodingFormat()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, default_text_encoding_format, ark_web_string_default);

    // Execute
    return _struct->default_text_encoding_format(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutDefaultTextEncodingFormat(const ArkWebString& encoding)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_default_text_encoding_format, );

    // Execute
    _struct->put_default_text_encoding_format(_struct, &encoding);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsLoadImageFromNetworkDisabled()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_load_image_from_network_disabled, false);

    // Execute
    return _struct->is_load_image_from_network_disabled(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutLoadImageFromNetworkDisabled(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_load_image_from_network_disabled, );

    // Execute
    _struct->put_load_image_from_network_disabled(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::EnableRawFileAccessFromFileURLs()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, enable_raw_file_access_from_file_urls, false);

    // Execute
    return _struct->enable_raw_file_access_from_file_urls(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutEnableRawFileAccessFromFileURLs(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_enable_raw_file_access_from_file_urls, );

    // Execute
    _struct->put_enable_raw_file_access_from_file_urls(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::EnableUniversalAccessFromFileURLs()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, enable_universal_access_from_file_urls, false);

    // Execute
    return _struct->enable_universal_access_from_file_urls(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutEnableUniversalAccessFromFileURLs(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_enable_universal_access_from_file_urls, );

    // Execute
    _struct->put_enable_universal_access_from_file_urls(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::IsCreateWindowsByJavaScriptAllowed()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_create_windows_by_java_script_allowed, false);

    // Execute
    return _struct->is_create_windows_by_java_script_allowed(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutIsCreateWindowsByJavaScriptAllowed(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_is_create_windows_by_java_script_allowed, );

    // Execute
    _struct->put_is_create_windows_by_java_script_allowed(_struct, flag);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::AccessModeForSecureOriginLoadFromInsecure()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, access_mode_for_secure_origin_load_from_insecure, 0);

    // Execute
    return _struct->access_mode_for_secure_origin_load_from_insecure(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutAccessModeForSecureOriginLoadFromInsecure(int mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_access_mode_for_secure_origin_load_from_insecure, );

    // Execute
    _struct->put_access_mode_for_secure_origin_load_from_insecure(_struct, mode);
}

ARK_WEB_NO_SANITIZE
int ArkWebPreferenceCToCpp::GetCopyOptionMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_copy_option_mode, 0);

    // Execute
    return _struct->get_copy_option_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutCopyOptionMode(int copyOption)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_copy_option_mode, );

    // Execute
    _struct->put_copy_option_mode(_struct, copyOption);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::SetNativeEmbedMode(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_native_embed_mode, );

    // Execute
    _struct->set_native_embed_mode(_struct, flag);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::GetNativeEmbedMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_native_embed_mode, false);

    // Execute
    return _struct->get_native_embed_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::RegisterNativeEmbedRule(const ArkWebString& tag, const ArkWebString& type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, register_native_embed_rule, );

    // Execute
    _struct->register_native_embed_rule(_struct, &tag, &type);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::SetScrollable(bool enable)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_scrollable, );

    // Execute
    _struct->set_scrollable(_struct, enable);
}

ARK_WEB_NO_SANITIZE
bool ArkWebPreferenceCToCpp::GetScrollable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_scrollable, false);

    // Execute
    return _struct->get_scrollable(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::PutTextAutosizingEnabled(bool flag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );
    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_text_autosizing_enabled, );

    // Execute
    _struct->put_text_autosizing_enabled(_struct, flag);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::SetViewportEnable(bool enable)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_viewport_enable, );

    // Execute
    _struct->set_viewport_enable(_struct, enable);
}

ARK_WEB_NO_SANITIZE
void ArkWebPreferenceCToCpp::SetNativeVideoPlayerConfig(bool enable, bool shouldOverlay)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_preference_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );
    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_native_video_player_config, );

    // Execute
    _struct->set_native_video_player_config(_struct, enable, shouldOverlay);
}

ArkWebPreferenceCToCpp::ArkWebPreferenceCToCpp() {}

ArkWebPreferenceCToCpp::~ArkWebPreferenceCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebPreferenceCToCpp, ArkWebPreference, ark_web_preference_t>::kBridgeType =
    ARK_WEB_PREFERENCE;

} // namespace OHOS::ArkWeb
